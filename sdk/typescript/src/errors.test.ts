import assert from "node:assert/strict";
import test from "node:test";
import { status } from "@grpc/grpc-js";
import { Deferred, FiberdError, NoWorkspace, Shed, TierGap } from "./index.js";
import { classify } from "./errors.js";
import { Miss, MissCode } from "./generated/grant/v1/grant.js";
import { Status } from "./generated/google/rpc/status.js";
import { rpcError } from "./testhelpers.js";

test("miss decoding skips other Any details and accepts a different type URL prefix", () => {
  const error = rpcError(status.UNAVAILABLE, "move");
  error.metadata.set("grpc-status-details-bin", Buffer.from(Status.encode({
    code: status.UNAVAILABLE,
    message: "move",
    details: [
      { typeUrl: "type.googleapis.com/google.rpc.RetryInfo", value: Buffer.from([10, 0]) },
      { typeUrl: "other/fiberd.grant.v1.Miss", value: Buffer.from(Miss.encode(Miss.fromPartial({
        code: MissCode.DEFERRED_FALLBACK, issuer: "issuer", preferredHome: "home-b",
      })).finish()) },
    ],
  }).finish()));
  const classified = classify(error);
  assert.ok(classified instanceof Deferred && classified instanceof FiberdError);
  assert.equal(classified.name, "Deferred");
  assert.equal(classified.issuer, "issuer");
  assert.equal(classified.message, "deferred: move (session lives on home-b)");
  assert.equal(classified.cause, error);
});

test("unknown details, unknown miss codes and mismatched envelopes preserve the original error", async (t) => {
  const cases = {
    "no details": Status.fromPartial({ code: status.UNAVAILABLE }),
    "unknown detail": Status.fromPartial({ code: status.UNAVAILABLE, details: [{ typeUrl: "other", value: Buffer.alloc(0) }] }),
    "unknown miss code": Status.fromPartial({ code: status.UNAVAILABLE, details: [{ typeUrl: "x/fiberd.grant.v1.Miss", value: Buffer.from([8, 99]) }] }),
    "mismatched envelope": Status.fromPartial({ code: status.RESOURCE_EXHAUSTED, details: [{ typeUrl: "x/fiberd.grant.v1.Miss", value: Buffer.alloc(0) }] }),
  };
  for (const [name, envelope] of Object.entries(cases)) {
    await t.test(name, () => {
      const error = rpcError(status.UNAVAILABLE);
      error.metadata.set("grpc-status-details-bin", Buffer.from(Status.encode(envelope).finish()));
      assert.equal(classify(error), error);
    });
  }
  const unrelated = new Error("local");
  assert.equal(classify(unrelated), unrelated);
});

test("malformed trailers retain the RPC error and expose the decoding failure as its cause", async (t) => {
  for (const [name, bytes] of Object.entries({
    "zero tag": Buffer.from([0]),
    "truncated varint": Buffer.from([8, 128]),
    "truncated Any": Buffer.from([26, 5, 0]),
    "truncated miss varint": Buffer.from(Status.encode(Status.fromPartial({
      code: status.UNAVAILABLE,
      details: [{ typeUrl: "x/fiberd.grant.v1.Miss", value: Buffer.from([8, 128]) }],
    })).finish()),
    "zero miss tag": Buffer.from(Status.encode(Status.fromPartial({
      code: status.UNAVAILABLE,
      details: [{ typeUrl: "x/fiberd.grant.v1.Miss", value: Buffer.from([0]) }],
    })).finish()),
  })) {
    await t.test(name, () => {
      const error = rpcError(status.UNAVAILABLE);
      error.metadata.set("grpc-status-details-bin", bytes);
      assert.equal(classify(error), error);
      assert.ok(error.cause instanceof Error);
      assert.match(error.cause.message, /Could not decode/);
    });
  }
});

test("a zero-valued Miss is SHED, not an absent miss", () => {
  const error = rpcError(status.RESOURCE_EXHAUSTED, "busy", Miss.fromPartial({}));
  const classified = classify(error);
  assert.ok(classified instanceof Shed);
  assert.equal(classified.retryAfterSeconds, 0);
  assert.equal(classified.message, "shed: busy, retry after 0s");
});

test("a FailedPrecondition with a NoWorkspace detail is NoWorkspace, and any other is a tier gap", async (t) => {
  const noWorkspace = { typeUrl: "type.googleapis.com/fiberd.grant.v1.NoWorkspace", value: Buffer.alloc(0) };
  const cases: Record<string, { envelope?: Status; want: typeof NoWorkspace | typeof TierGap; message: string }> = {
    "a NoWorkspace detail": {
      envelope: Status.fromPartial({ code: status.FAILED_PRECONDITION, details: [noWorkspace] }),
      want: NoWorkspace, message: "no workspace: why",
    },
    "a NoWorkspace detail after another detail, under another prefix": {
      envelope: Status.fromPartial({ code: status.FAILED_PRECONDITION, details: [
        { typeUrl: "type.googleapis.com/google.rpc.RetryInfo", value: Buffer.from([10, 0]) },
        { typeUrl: "other/fiberd.grant.v1.NoWorkspace", value: Buffer.alloc(0) },
      ] }),
      want: NoWorkspace, message: "no workspace: why",
    },
    "no trailer": { want: TierGap, message: "tier gap: why" },
    "another detail only": {
      envelope: Status.fromPartial({ code: status.FAILED_PRECONDITION, details: [{ typeUrl: "other", value: Buffer.alloc(0) }] }),
      want: TierGap, message: "tier gap: why",
    },
    "a NoWorkspace detail in a mismatched envelope": {
      envelope: Status.fromPartial({ code: status.UNAVAILABLE, details: [noWorkspace] }),
      want: TierGap, message: "tier gap: why",
    },
  };
  for (const [name, { envelope, want, message }] of Object.entries(cases)) {
    await t.test(name, () => {
      const error = rpcError(status.FAILED_PRECONDITION, "why");
      if (envelope) error.metadata.set("grpc-status-details-bin", Buffer.from(Status.encode(envelope).finish()));
      const classified = classify(error);
      assert.ok(classified instanceof want && classified instanceof FiberdError);
      assert.equal(classified.name, want.name);
      assert.equal(classified.message, message);
      assert.equal(classified.cause, error);
    });
  }
});
