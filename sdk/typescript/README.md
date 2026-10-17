# fiberd for TypeScript

The TypeScript client for callers of fiberd, with the same calls and typed misses as the Go and Python clients. `@fiberd/client` runs on Node.js, not in a browser, and has no template binding.

## Install

Requires Node.js 22.12 or later.

```bash
npm install @fiberd/client
```

The package includes JavaScript and type declarations, and supports both `import` and `require`. Every release publishes it with npm provenance, and pre-releases go to the `next` dist-tag (`npm install @fiberd/client@next`). The same tarball is in the release assets under `SHA256SUMS`.

## Client

A caller holds a signed [grant](../../docs/glossary.md#grant) and asks a [home](../../docs/glossary.md#home) for fibers under it.

```typescript
import { readFileSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";
import { Client, Deferred, Shed } from "@fiberd/client";

const client = Client.dialTls("home:7443", {
  cert: readFileSync("me.pem"),
  key: readFileSync("me-key.pem"),
  ca: readFileSync("ca.pem"),
});
const jwt = readFileSync("grant.jwt", "utf8").trim();

async function clone(session: string) {
  for (;;) {
    try {
      return await client.clone(jwt, { session, payload: Buffer.from('{"task":1}'), timeoutMs: 2000 });
    } catch (error) {
      if (!(error instanceof Shed)) throw error;
      await sleep(error.retryAfterSeconds * 1000);
    }
  }
}

try {
  let fiber = await clone("conv-42");
  await client.park(fiber);
  fiber = await clone("conv-42"); // RESUME, under the next fence
  await client.release(fiber, { discard: true });
} catch (error) {
  if (error instanceof Deferred) {
    console.error("Take the ordinary path or route to:", error.preferredHome, error.reason);
  } else {
    throw error;
  }
} finally {
  client.close();
}
```

`Client.dial(target)` is the plaintext form for a home started with `-insecure-plaintext`. TLS options take PEM buffers, not paths. `await fiber.dial()` connects to a direct Unix or TCP endpoint. A [handoff](../../docs/glossary.md#handoff) fiber uses `await fiber.dialHandoff({ cert, key })`, with the same caller certificate as the control API. It trusts the Clone's certificate and checks its key pin before returning the TLS socket. Attach an `error` listener immediately after awaiting either dial method. Later I/O errors belong to the socket, not the dialing promise. The caller closes the socket.

`TierGap` and `NotFound` are the other typed RPC outcomes. Other failures remain gRPC errors. The token may be a string or a sync/async function returning one, and is never retained or logged. The client does not retry automatically.

Omit `session` for an anonymous fiber. Park waits for durability by default (`sync: true`). Release keeps parked state unless `discard: true`. Both accept a fiber or its ID. `client.watch()` is an async iterator of per-grant status. Breaking the loop cancels the RPC. Fence epochs/sequences and status `wUsedBytes` are `bigint`, so convert them to strings for JSON.

Calls accept `timeoutMs` and `signal: AbortSignal`. Cancellation rejects with `signal.reason`, including while waiting for a token. It does not stop the token provider's own work. Clone's separate `deadlineMs` budgets runtime work. Zero or omission means unbounded for both durations. The RPC timeout starts after token resolution. For Watch it bounds the whole stream, even while statuses arrive, and expires with `DEADLINE_EXCEEDED`. Omit it for a long-lived watch and use a signal to stop. Socket dialing uses the timeout and signal for connection establishment only.

## Build and test

From the repository root, after `npm ci --ignore-scripts --prefix sdk/typescript`:

```bash
make typescript-test
npm --prefix sdk/typescript run test:package
make typescript-proto-check
```

Unit tests live beside the source and use in-process servers. The package test installs the tarball and checks imports, types and licenses. `make typescript-proto` regenerates the checked-in bindings from [grant.proto](../../api/grant/v1/grant.proto). Regeneration needs Go, ordinary builds do not.

`make integration-tests` and `make linux-test` rebuild the SDK on the host before running tests, or leave its suite out and say so when `node_modules` is missing. [tests/integration/typescript](../../tests/integration/typescript) uses that build and its installed dependencies against proc fibers and the handoff router in the Linux dev container. The test runner does not install packages or compile TypeScript. The client design is in [docs/design/sdk.md](../../docs/design/sdk.md).
