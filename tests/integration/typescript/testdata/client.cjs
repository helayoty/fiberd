const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { X509Certificate } = require("node:crypto");
const { Client, Deferred, Fiber, KeyMismatch, Kind, NotFound } = require(process.argv[2]);

async function ping(socket) {
  socket.setTimeout(5000, () => socket.destroy(new Error("fiber did not reply")));
  try {
    socket.write("ping\n");
    let reply = "";
    for await (const data of socket) {
      reply += data.toString();
      if (reply.includes("\n")) return reply.trim();
    }
    throw new Error("fiber closed without a reply");
  } finally {
    socket.destroy();
  }
}

function identity(files) {
  return { cert: readFileSync(files.cert), key: readFileSync(files.key) };
}

async function main() {
  const cfg = JSON.parse(readFileSync(0, "utf8"));
  const caller = cfg.tls ? identity(cfg.tls) : undefined;
  const client = caller
    ? Client.dialTls(cfg.target, { ...caller, ca: readFileSync(cfg.tls.ca) })
    : Client.dial(cfg.target);
  const options = { session: "conv 42", timeoutMs: 20_000, deadlineMs: 15_000 };
  const dial = (fiber) => caller
    ? fiber.dialHandoff(caller, { timeoutMs: 5000 })
    : fiber.dial({ timeoutMs: 5000 });
  try {
    let fiber = await client.clone(cfg.token, options);
    assert.equal(fiber.kind, Kind.CREATE);
    assert.equal(fiber.session, options.session);
    assert.equal(fiber.fence.toString(), fiber.id);
    assert.equal((await client.clone(cfg.token, options)).kind, Kind.ATTACH);
    assert.equal(await ping(await dial(fiber)), "pong");
    await assert.rejects(client.clone(cfg.token, { timeoutMs: 5000 }), (error) => {
      assert.ok(error instanceof Deferred);
      assert.equal(error.issuer, "https://issuer.test");
      assert.ok(error.reason);
      return true;
    });
    let observed = false;
    for await (const state of client.watch({ timeoutMs: 5000 })) {
      assert.equal(state.grantUid, fiber.fence.grantUid);
      assert.equal(state.running, 1);
      assert.equal(state.latest.toString(), fiber.id);
      assert.equal(typeof state.wUsedBytes, "bigint");
      observed = true;
      break;
    }
    assert.ok(observed, "Watch ended without a status");
    if (caller) {
      assert.equal(new X509Certificate(fiber.serverCert).publicKey.asymmetricKeyType, "ed25519");
      await assert.rejects(new Fiber({ ...fiber, serverKeySha256: cfg.otherPin }).dialHandoff(caller), KeyMismatch);
      await assert.rejects(new Fiber({ ...fiber, serverCert: Buffer.from(cfg.otherCert, "base64") }).dialHandoff(caller),
        { code: "DEPTH_ZERO_SELF_SIGNED_CERT" });
      await assert.rejects(async () => ping(await fiber.dialHandoff(identity(cfg.stranger), { timeoutMs: 5000 })));
    }
    const prior = fiber;
    await client.park(fiber, { timeoutMs: 30_000 });
    fiber = await client.clone(cfg.token, options);
    assert.equal(fiber.kind, Kind.RESUME);
    assert.ok(fiber.fence.seq > prior.fence.seq);
    if (caller) {
      assert.notEqual(fiber.routingKey, prior.routingKey);
      assert.equal(fiber.serverKeySha256, prior.serverKeySha256);
    }
    assert.equal(await ping(await dial(fiber)), "pong");
    await client.release(fiber, { discard: true, timeoutMs: 5000 });
    await assert.rejects(client.park(fiber, { timeoutMs: 5000 }), NotFound);
    console.log("Clone, Attach, Park, Resume, Release, Watch, Deferred and NotFound passed");
  } finally {
    client.close();
  }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
