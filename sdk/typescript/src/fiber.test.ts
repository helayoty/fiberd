import assert from "node:assert/strict";
import { once } from "node:events";
import { mkdtemp, rmdir } from "node:fs/promises";
import { createServer, type Server, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import { createServer as createTlsServer } from "node:tls";
import { Fence, Fiber, KeyMismatch, Kind, NotHandoff, parseEndpoint, type FiberInfo } from "./index.js";
import { identity } from "./testhelpers.js";

function fiber(endpoint: string, fields: Partial<FiberInfo> = {}): Fiber {
  return new Fiber({
    id: "g/1/1", endpoint, fence: new Fence("g", 1n, 1n), kind: Kind.CREATE, session: "", home: "home",
    ...fields,
  });
}

async function listening(t: TestContext, server: Server, path?: string): Promise<string> {
  const sockets = new Set<Socket>();
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  });
  const ready = once(server, "listening");
  if (path) server.listen(path);
  else server.listen(0, "127.0.0.1");
  await ready;
  const address = server.address();
  assert.ok(address);
  return typeof address === "string" ? `unix://${address}` : `tcp://127.0.0.1:${address.port}`;
}

async function echo(socket: Socket): Promise<string> {
  socket.setTimeout(2000, () => socket.destroy(new Error("No reply from the fiber")));
  socket.write("ping");
  for await (const data of socket) {
    assert.ok(Buffer.isBuffer(data));
    return data.toString();
  }
  throw new Error("Connection closed without a reply");
}

test("endpoint parsing handles Unix, IPv4, IPv6 and hostnames without silently dropping URL components", async (t) => {
  assert.deepEqual(parseEndpoint("unix:///run/f.sock"), { kind: "unix", path: "/run/f.sock" });
  assert.deepEqual(parseEndpoint("unix:///run/f %2f.sock"), { kind: "unix", path: "/run/f %2f.sock" });
  assert.deepEqual(parseEndpoint("tcp://10.0.0.7:30012"), { kind: "tcp", host: "10.0.0.7", port: 30012 });
  assert.deepEqual(parseEndpoint("tcp://[fd00::7]:30012"), { kind: "tcp", host: "fd00::7", port: 30012 });
  assert.deepEqual(parseEndpoint("tcp://home:7443"), { kind: "tcp", host: "home", port: 7443 });
  for (const endpoint of [
    "", "/run/f.sock", "http://home:80", "tcp://home", "tcp://home:0", "tcp://home:65536",
    "unix://other/run/f.sock", "unix:///", "unix:/run/f.sock", "unix:///run/f\0.sock",
    "tcp://user:password@host:80", "tcp://home:80/path",
    "tcp://home:80?query", "unix:///run/f.sock#fragment",
  ]) {
    await t.test(JSON.stringify(endpoint), () => assert.throws(() => parseEndpoint(endpoint), TypeError));
  }
});

test("direct fibers dial TCP and Unix endpoints", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "fiberd-ts-"));
  for (const path of [undefined, join(directory, "f %2f.sock")]) {
    await t.test(path ? "Unix" : "TCP", async (t) => {
      const endpoint = await listening(t, createServer((socket) => socket.on("data", () => socket.write("pong"))), path);
      const socket = await fiber(endpoint).dial({ timeoutMs: 0 });
      try {
        assert.equal(await echo(socket), "pong");
      } finally {
        socket.destroy();
      }
    });
  }
  t.after(() => rmdir(directory));
});

test("socket errors after dialing are delivered to the caller", async (t) => {
  const endpoint = await listening(t, createServer((socket) => socket.resume()));
  const socket = await fiber(endpoint).dial();
  const failed = once(socket, "error");
  const reason = new Error("I/O failed after connection");
  socket.destroy(reason);
  assert.equal((await failed)[0], reason);
});

test("handoff is routed with SNI, verifies its certificate and pin, and presents the caller", { timeout: 10_000 }, async (t) => {
  const serverIdentity = await identity("fiberd handoff", true, true);
  const caller = await identity("caller", false);
  const other = await identity("fiberd handoff", true, true);
  const stranger = await identity("stranger", false);
  const names: string[] = [];
  let bytesReceived = 0;
  const server = createTlsServer({
    ...serverIdentity,
    ca: caller.cert,
    requestCert: true,
    rejectUnauthorized: true,
    minVersion: "TLSv1.3",
    allowPartialTrustChain: true,
    SNICallback: (name, done) => { names.push(name); setTimeout(() => done(null), 20); },
  }, (socket) => {
    assert.equal(socket.authorized, true);
    assert.equal(socket.getProtocol(), "TLSv1.3");
    socket.on("data", (data: Buffer) => {
      bytesReceived += data.length;
      socket.write("pong");
    });
  });
  // Expected for the deliberately rejected handshakes below.
  server.on("tlsClientError", () => {});
  const endpoint = await listening(t, server);
  const routed = fiber(endpoint, {
    routingKey: "route", serverKeySha256: serverIdentity.pin, serverCert: serverIdentity.der,
  });
  const socket = await routed.dialHandoff(caller, { timeoutMs: 0 });
  try {
    assert.equal(await echo(socket), "pong");
    assert.equal(socket.authorized, true);
  } finally {
    socket.destroy();
  }
  assert.equal(names[0], "route.fiberd");
  const received = bytesReceived;
  await assert.rejects(fiber(endpoint, { ...routed, serverKeySha256: other.pin }).dialHandoff(caller, { timeoutMs: 2000 }), KeyMismatch);
  await assert.rejects(fiber(endpoint, { ...routed, serverCert: other.der }).dialHandoff(caller, { timeoutMs: 2000 }));
  assert.equal(bytesReceived, received, "a rejected peer must receive no application bytes");
  await assert.rejects(async () => {
    const refused = await routed.dialHandoff(stranger, { timeoutMs: 2000 });
    try {
      await echo(refused);
    } finally {
      refused.destroy();
    }
  });
});

test("the wrong dialing method or a missing handoff certificate fails before connecting", async () => {
  const caller = { cert: Buffer.alloc(0), key: Buffer.alloc(0) };
  await assert.rejects(fiber("tcp://127.0.0.1:1").dialHandoff(caller), NotHandoff);
  const routed = fiber("tcp://127.0.0.1:1", { routingKey: "route" });
  await assert.rejects(routed.dial(), /requires dialHandoff/);
  await assert.rejects(routed.dialHandoff(caller), /no certificate/);
  await assert.rejects(fiber("unix:///tmp/f.sock", { ...routed, endpoint: "unix:///tmp/f.sock" }).dialHandoff(caller), NotHandoff);
});

test("connection failures, timeouts and aborts reject and close pending sockets", { timeout: 10_000 }, async (t) => {
  const serverIdentity = await identity("*.fiberd", true);
  const caller = await identity("caller", false);
  const server = createServer((socket) => socket.resume());
  const endpoint = await listening(t, server);
  const routed = fiber(endpoint, {
    routingKey: "route", serverKeySha256: serverIdentity.pin, serverCert: serverIdentity.der,
  });
  await assert.rejects(routed.dialHandoff(caller, { timeoutMs: 30 }), /timed out/);
  const controller = new AbortController();
  const abortReason = new Error("stop connecting");
  const accepted = once(server, "connection");
  const pending = routed.dialHandoff(caller, { signal: controller.signal });
  const [connection] = await accepted;
  controller.abort(abortReason);
  await assert.rejects(pending, (error) => error === abortReason);
  await assert.rejects(routed.dialHandoff(caller, { signal: controller.signal }), (error) => error === abortReason);
  await assert.rejects(fiber(endpoint).dial({ timeoutMs: -1 }), RangeError);
  if (!connection.destroyed) await once(connection, "close");
});
