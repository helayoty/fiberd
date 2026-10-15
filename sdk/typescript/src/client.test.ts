import assert from "node:assert/strict";
import { EventEmitter, getEventListeners, once } from "node:events";
import test from "node:test";
import { Metadata, ServerCredentials, status } from "@grpc/grpc-js";
import { Client, Deferred, Fence, Kind, NotFound, Shed, TierGap } from "./index.js";
import {
  CloneResponse,
  FibersClient,
  Miss,
  MissCode,
  Status,
  type CloneRequest,
  type ParkRequest,
  type ReleaseRequest,
} from "./generated/grant/v1/grant.js";
import { home, identity, rpcError } from "./testhelpers.js";

test("synchronous unary completion settles without abort listener leaks", async (t) => {
  for (const outcome of ["success", "error", "throw"] as const) {
    await t.test(outcome, async (t) => {
      const controller = new AbortController();
      const failure = rpcError(status.UNAUTHENTICATED, "no");
      const call = Object.assign(new EventEmitter(), {
        cancel: t.mock.fn(),
        getPeer: () => "test",
        getAuthContext: () => null,
      });
      t.mock.method(FibersClient.prototype, "clone", (...args: Parameters<FibersClient["clone"]>) => {
        if (outcome === "throw") throw failure;
        args[3](outcome === "error" ? failure : null, CloneResponse.fromPartial({ fiberId: "g/1/1" }));
        return call;
      });
      const client = Client.dial("localhost:1");
      t.after(() => client.close());
      const pending = client.clone("jwt", { signal: controller.signal });
      if (outcome === "success") assert.equal((await pending).id, "g/1/1");
      else await assert.rejects(pending, (error) => error === failure);
      assert.equal(getEventListeners(controller.signal, "abort").length, 0);
      controller.abort();
      assert.equal(call.cancel.mock.callCount(), 0);
    });
  }
});

test("zero RPC timeouts are unbounded", { timeout: 3000 }, async (t) => {
  const { client } = await home(t, {
    clone: (call, done) => {
      assert.equal(call.getDeadline(), Infinity);
      setTimeout(() => done(null, CloneResponse.fromPartial({ fiberId: "g/1/1" })), 20);
    },
    park: (call, done) => {
      assert.equal(call.getDeadline(), Infinity);
      setTimeout(() => done(null, {}), 20);
    },
    release: (call, done) => {
      assert.equal(call.getDeadline(), Infinity);
      setTimeout(() => done(null, {}), 20);
    },
    watch: (call) => {
      assert.equal(call.getDeadline(), Infinity);
      const timer = setTimeout(() => {
        call.write(Status.fromPartial({ grantUid: "g" }));
        call.end();
      }, 20);
      t.after(() => clearTimeout(timer));
    },
  });
  for (const [name, operation] of Object.entries({
    clone: () => client.clone("jwt", { timeoutMs: 0 }),
    park: () => client.park("g/1/1", { timeoutMs: 0 }),
    release: () => client.release("g/1/1", { timeoutMs: 0 }),
    watch: async () => {
      const stream = client.watch({ timeoutMs: 0 });
      assert.equal((await stream.next()).value?.grantUid, "g");
      assert.equal((await stream.next()).done, true);
    },
  })) {
    await t.test(name, async () => { await operation(); });
  }
});

test("Watch timeout bounds a healthy stream, not just the first message", { timeout: 3000 }, async (t) => {
  const { client } = await home(t, {
    watch: (call) => {
      const timer = setInterval(() => call.write(Status.fromPartial({ grantUid: "g" })), 10);
      call.once("cancelled", () => clearInterval(timer));
      t.after(() => clearInterval(timer));
    },
  });
  let updates = 0;
  await assert.rejects(async () => {
    for await (const value of client.watch({ timeoutMs: 250 })) {
      assert.equal(value.grantUid, "g");
      updates++;
    }
  }, { code: status.DEADLINE_EXCEEDED });
  assert.ok(updates > 1, "the stream must deliver updates before its deadline");
});

test("Clone preserves fields, refreshes the token, and keeps uint64 fences exact", async (t) => {
  const requests: CloneRequest[] = [];
  const largest = 18_446_744_073_709_551_615n;
  const { client, target } = await home(t, {
    clone: (call, done) => {
      requests.push(call.request);
      assert.equal(call.metadata.get("x-request-id")[0], "request-1");
      done(null, CloneResponse.fromPartial({
        fiberId: `g/${largest}/${requests.length}`,
        endpoint: "tcp://127.0.0.1:7444",
        fence: { grantUid: "g", epoch: largest, seq: BigInt(requests.length) },
        kind: requests.length - 1,
        routingKey: "route",
        serverKeySha256: "pin",
        serverCert: Buffer.from([1, 2, 3]),
      }));
    },
  });
  const metadata = new Metadata();
  metadata.set("x-request-id", "request-1");
  let refreshes = 0;
  const token = async () => `token-${++refreshes}`;
  const before = Date.now();
  for (const kind of [Kind.CREATE, Kind.ATTACH, Kind.RESUME]) {
    await t.test(Kind[kind], async () => {
      const fiber = await client.clone(token, {
        session: "session-1", payload: Uint8Array.from([0, 255]), deadlineMs: 500,
        timeoutMs: 2000, metadata,
      });
      assert.equal(fiber.kind, kind);
      assert.equal(fiber.home, target);
      assert.equal(fiber.session, "session-1");
      assert.equal(fiber.fence.epoch, largest);
      assert.equal(fiber.fence.toString(), fiber.id);
      assert.equal(fiber.handoff, true);
      assert.equal(fiber.routingKey, "route");
      assert.equal(fiber.serverKeySha256, "pin");
      assert.deepEqual(fiber.serverCert, Buffer.from([1, 2, 3]));
    });
  }
  assert.equal(refreshes, 3);
  for (const [i, request] of requests.entries()) {
    assert.equal(request.grantJwt, `token-${i + 1}`);
    assert.equal(request.session, "session-1");
    assert.deepEqual(request.payload, Buffer.from([0, 255]));
    assert.ok(request.deadline);
    const deadline = Number(request.deadline.seconds) * 1000 + request.deadline.nanos / 1_000_000;
    assert.ok(deadline >= before + 500 && deadline <= Date.now() + 500);
  }
});

test("anonymous Clone omits the runtime deadline and optional fields", async (t) => {
  const { client } = await home(t, {
    clone: (call, done) => {
      assert.equal(call.request.grantJwt, "jwt");
      assert.equal(call.request.session, "");
      assert.equal(call.request.deadline, undefined);
      assert.equal(call.request.payload.length, 0);
      done(null, CloneResponse.fromPartial({ fiberId: "g/1/1" }));
    },
  });
  for (const deadlineMs of [undefined, 0]) {
    await t.test(deadlineMs === undefined ? "omitted deadline" : "zero deadline", async () => {
      const fiber = await client.clone("jwt", { deadlineMs });
      assert.equal(fiber.session, "");
      assert.equal(fiber.handoff, false);
      assert.deepEqual(fiber.fence, new Fence("", 0n, 0n));
    });
  }
});

test("Park and Release accept fibers or IDs and match Python defaults", async (t) => {
  const parked: ParkRequest[] = [];
  const released: ReleaseRequest[] = [];
  const { client } = await home(t, {
    park: (call, done) => { parked.push(call.request); done(null, {}); },
    release: (call, done) => { released.push(call.request); done(null, {}); },
  });
  const fiber = await client.clone("jwt");
  await client.park(fiber);
  await client.park(fiber.id, { sync: false });
  await client.release(fiber);
  await client.release(fiber.id, { discard: true });
  assert.deepEqual(parked, [{ fiberId: fiber.id, sync: true }, { fiberId: fiber.id, sync: false }]);
  assert.deepEqual(released, [{ fiberId: fiber.id, discard: false }, { fiberId: fiber.id, discard: true }]);
});

test("all four RPCs classify protocol errors without retrying", async (t) => {
  const cases = [
    { error: rpcError(status.RESOURCE_EXHAUSTED, "busy", Miss.fromPartial({ retryAfterS: 2, issuer: "issuer" })), expected: Shed },
    { error: rpcError(status.UNAVAILABLE, "remote", Miss.fromPartial({ code: MissCode.DEFERRED_FALLBACK, preferredHome: "home-b" })), expected: Deferred },
    { error: rpcError(status.FAILED_PRECONDITION, "tier"), expected: TierGap },
    { error: rpcError(status.NOT_FOUND, "gone"), expected: NotFound },
  ];
  for (const { error, expected } of cases) {
    await t.test(expected.name, async (t) => {
      let calls = 0;
      const { client } = await home(t, {
        clone: (_call, done) => { calls++; done(error); },
        park: (_call, done) => { calls++; done(error); },
        release: (_call, done) => { calls++; done(error); },
        watch: (call) => { calls++; call.emit("error", error); },
      });
      for (const [name, operation] of Object.entries({
        clone: () => client.clone("jwt"),
        park: () => client.park("g/1/1"),
        release: () => client.release("g/1/1"),
        watch: () => client.watch({ timeoutMs: 2000 }).next(),
      })) {
        await t.test(name, async () => {
          await assert.rejects(operation, (caught: unknown) => {
            assert.ok(caught instanceof expected);
            assert.ok(caught.cause instanceof Error);
            assert.equal(caught.reason, error.details);
            if (caught instanceof Shed) {
              assert.equal(caught.retryAfterSeconds, 2);
              assert.equal(caught.issuer, "issuer");
            }
            if (caught instanceof Deferred) assert.equal(caught.preferredHome, "home-b");
            return true;
          });
        });
      }
      assert.equal(calls, 4);
    });
  }
});

test("unclassified gRPC errors retain status, details and metadata", async (t) => {
  const error = rpcError(status.UNAUTHENTICATED, "bad token");
  error.metadata.set("x-reason", "expired");
  const { client } = await home(t, { clone: (_call, done) => done(error) });
  await assert.rejects(client.clone("jwt"), {
    code: status.UNAUTHENTICATED, details: "bad token",
  });
  try {
    await client.clone("jwt");
    assert.fail("expected an RPC failure");
  } catch (caught) {
    assert.ok(caught instanceof Error && "metadata" in caught && caught.metadata instanceof Metadata);
    assert.equal(caught.metadata.get("x-reason")[0], "expired");
  }
});

test("Watch streams exact counters and breaking iteration cancels the server call", async (t) => {
  let cancelled: Promise<unknown[]> | undefined;
  const { client } = await home(t, {
    watch: (call) => {
      cancelled = once(call, "cancelled");
      call.write(Status.fromPartial({
        grantUid: "g", running: 1, parked: 2, pooled: 3,
        wUsedBytes: 18_446_744_073_709_551_615n,
        latest: { grantUid: "g", epoch: 9_007_199_254_740_993n, seq: 7n },
      }));
    },
  });
  for await (const value of client.watch({ timeoutMs: 2000 })) {
    assert.deepEqual(value, {
      grantUid: "g", running: 1, parked: 2, pooled: 3,
      wUsedBytes: 18_446_744_073_709_551_615n,
      latest: new Fence("g", 9_007_199_254_740_993n, 7n),
    });
    break;
  }
  assert.ok(cancelled);
  await cancelled;
});

test("Watch ends normally on EOF and surfaces a broken transport", async (t) => {
  const normal = await home(t);
  assert.deepEqual(await normal.client.watch().next(), { value: undefined, done: true });
  const broken = await home(t, { watch: (call) => call.write(Status.fromPartial({ grantUid: "g" })) });
  const stream = broken.client.watch();
  assert.equal((await stream.next()).value?.grantUid, "g");
  broken.server.forceShutdown();
  await assert.rejects(stream.next(), { code: status.CANCELLED });
});

test("RPC deadlines, cancellation and close terminate pending operations", async (t) => {
  const { client } = await home(t, {
    clone: () => {},
    park: () => {},
    release: () => {},
    watch: () => {},
  });
  for (const [name, operation] of Object.entries({
    clone: () => client.clone("jwt", { timeoutMs: 30 }),
    park: () => client.park("f", { timeoutMs: 30 }),
    release: () => client.release("f", { timeoutMs: 30 }),
    watch: () => client.watch({ timeoutMs: 30 }).next(),
  })) {
    await t.test(`${name} deadline`, () => assert.rejects(operation, { code: status.DEADLINE_EXCEEDED }));
  }
  for (const [name, operation] of Object.entries({
    clone: (signal: AbortSignal) => client.clone("jwt", { signal }),
    park: (signal: AbortSignal) => client.park("f", { signal }),
    release: (signal: AbortSignal) => client.release("f", { signal }),
    watch: (signal: AbortSignal) => client.watch({ signal }).next(),
  })) {
    await t.test(`${name} cancellation`, async () => {
      const controller = new AbortController();
      const pending = operation(controller.signal);
      controller.abort(new Error("stop"));
      await assert.rejects(pending, (error) => error === controller.signal.reason);
    });
  }
  const pending = client.clone("jwt");
  client.close();
  await assert.rejects(pending, { code: status.UNAVAILABLE });
  await assert.rejects(client.watch().next());
  client.close();
});

test("aborting a hung token refresh rejects promptly without starting an RPC", { timeout: 2000 }, async (t) => {
  let calls = 0;
  const { client } = await home(t, {
    clone: (_call, done) => { calls++; done(null, CloneResponse.fromPartial({})); },
  });
  for (const outcome of ["resolve", "reject"] as const) {
    await t.test(outcome, async () => {
      const controller = new AbortController();
      let resolveRefresh!: (token: string) => void;
      let rejectRefresh!: (error: Error) => void;
      const refresh = new Promise<string>((resolve, reject) => { resolveRefresh = resolve; rejectRefresh = reject; });
      const pending = client.clone(() => refresh, { signal: controller.signal });
      controller.abort(new Error("stop refreshing"));
      await assert.rejects(pending, (error) => error === controller.signal.reason);
      assert.equal(getEventListeners(controller.signal, "abort").length, 0);
      if (outcome === "resolve") resolveRefresh("late-token");
      else rejectRefresh(new Error("late refresh failure"));
      await new Promise<void>((resolve) => setImmediate(resolve));
      assert.equal(calls, 0);
    });
  }
});

test("in-flight RPC cancellation preserves the caller's abort reason", { timeout: 5000 }, async (t) => {
  for (const method of ["clone", "park", "release", "watch"] as const) {
    await t.test(method, async (t) => {
      let started!: () => void;
      const received = new Promise<void>((resolve) => { started = resolve; });
      const { client } = await home(t, { clone: started, park: started, release: started, watch: started });
      const controller = new AbortController();
      const options = { signal: controller.signal };
      const pending = method === "watch" ? client.watch(options).next() : client[method]("value", options);
      await received;
      const reason = new Error("stop this call");
      controller.abort(reason);
      await assert.rejects(pending, (error) => error === reason);
      assert.equal(getEventListeners(controller.signal, "abort").length, 0);
    });
  }
});

test("invalid durations, failed token refresh and pre-aborted signals do not make an RPC", async (t) => {
  let calls = 0;
  const { client } = await home(t, {
    clone: (_call, done) => { calls++; done(null, CloneResponse.fromPartial({})); },
  });
  for (const value of [-1, NaN, Infinity, 2_147_483_648]) {
    await t.test(String(value), async () => {
      const token = t.mock.fn(() => { assert.fail("must not refresh with invalid durations"); });
      await assert.rejects(client.clone(token, { deadlineMs: value }), RangeError);
      await assert.rejects(client.clone(token, { timeoutMs: value }), RangeError);
      assert.equal(token.mock.callCount(), 0);
      await assert.rejects(client.watch({ timeoutMs: value }).next(), RangeError);
    });
  }
  const failure = new Error("refresh failed");
  await assert.rejects(client.clone(() => { throw failure; }), (error) => error === failure);
  const controller = new AbortController();
  controller.abort(failure);
  await assert.rejects(client.clone(() => { assert.fail("must not refresh"); }, { signal: controller.signal }), (error) => error === failure);
  const refreshing = new AbortController();
  await assert.rejects(client.clone(async () => { refreshing.abort(failure); return "jwt"; }, { signal: refreshing.signal }), (error) => error === failure);
  assert.equal(calls, 0);
});

test("control API verifies the server and presents the caller over mutual TLS", async (t) => {
  const server = await identity("localhost", true);
  const caller = await identity("caller", false);
  const stranger = await identity("stranger", false);
  const { target } = await home(t, {}, ServerCredentials.createSsl(
    caller.cert, [{ private_key: server.key, cert_chain: server.cert }], true,
  ));
  const tlsTarget = target.replace("127.0.0.1", "localhost");
  const client = Client.dialTls(tlsTarget, { ...caller, ca: server.cert });
  t.after(() => client.close());
  assert.equal((await client.clone("jwt", { timeoutMs: 2000 })).id, "g/1/1");
  for (const [name, options] of Object.entries({
    "stranger caller": { ...stranger, ca: server.cert },
    "wrong CA": { ...caller, ca: stranger.cert },
  })) {
    await t.test(name, async (t) => {
      const refused = Client.dialTls(tlsTarget, options);
      t.after(() => refused.close());
      await assert.rejects(refused.clone("jwt", { timeoutMs: 2000 }), { code: status.UNAVAILABLE });
    });
  }
  const wrongHost = Client.dialTls(tlsTarget, { ...caller, ca: server.cert }, { "grpc.ssl_target_name_override": "wrong-home" });
  t.after(() => wrongHost.close());
  await assert.rejects(wrongHost.clone("jwt", { timeoutMs: 2000 }), { code: status.UNAVAILABLE });
});
