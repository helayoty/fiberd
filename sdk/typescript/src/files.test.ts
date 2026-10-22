import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { getEventListeners } from "node:events";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { status, type ServiceError } from "@grpc/grpc-js";
import {
  type Client,
  Download,
  type Fiber,
  FiberdError,
  type FileInfo,
  NoWorkspace,
  NotFound,
  QuotaExceeded,
  Shed,
  SizeMismatch,
} from "./index.js";
import { FileInfo as WireFileInfo, type FibersServer } from "./generated/grant/v1/grant.js";
import { type Files, home, MiB, noWorkspaceError, rpcError } from "./testhelpers.js";

type Data = Uint8Array | AsyncIterable<Uint8Array>;

/** An AsyncIterable of parts, which then ends, hangs or throws. state tells whether it ran its finally. */
function source(parts: unknown[], end: "end" | "hang" | Error = "end") {
  const state = { closed: false };
  async function* generate() {
    try {
      for (const part of parts) yield part;
      if (end === "hang") await new Promise(() => {});
      if (end instanceof Error) throw end;
    } finally {
      state.closed = true;
    }
  }
  return { data: generate() as AsyncIterable<Uint8Array>, state };
}

function split(data: Buffer, size: number): Buffer[] {
  const parts: Buffer[] = [];
  for (let at = 0; at < data.length; at += size) parts.push(data.subarray(at, at + size));
  return parts;
}

function sha256(data: Uint8Array): Buffer {
  return createHash("sha256").update(data).digest();
}

/** Waits for a call to end, or gives up after a while so a slow server cannot hang the test. */
async function settled(ended: Promise<void>): Promise<void> {
  await Promise.race([ended, delay(2000)]);
}

async function collect(download: Download): Promise<Buffer[]> {
  const pieces: Buffer[] = [];
  for await (const piece of download) pieces.push(Buffer.from(piece));
  return pieces;
}

test("upload sends its size in the header and the data in chunks of at most 1 MiB", async (t) => {
  const { client, files } = await home(t);
  const cases = [
    { name: "an empty file is the header alone, its size set to zero", size: 0, chunks: [] },
    { name: "one byte is one chunk", size: 1, chunks: [1] },
    { name: "exactly 1 MiB is one full chunk", size: MiB, chunks: [MiB] },
    { name: "1 MiB and a byte is a full chunk and one byte", size: MiB + 1, chunks: [MiB, 1] },
  ];
  const forms: Record<string, (data: Buffer) => { data: Data; size?: number }> = {
    "a Uint8Array": (data) => ({ data }),
    "an AsyncIterable in uneven pieces": (data) => ({ data: source(split(data, 300_000)).data, size: data.length }),
  };
  for (const { name, size, chunks } of cases) {
    for (const [form, make] of Object.entries(forms)) {
      await t.test(`${name}, from ${form}`, async () => {
        const data = randomBytes(size);
        const digest = sha256(data);
        const before = files.uploads.length;
        const made = make(data);
        const info = await client.upload("g/1/1", "d/data.bin", made.data, { size: made.size, mode: 0o600, sha256: digest });
        assert.equal(files.uploads.length, before + 1);
        const received = files.uploads.at(-1)!;
        assert.deepEqual(received.chunks, chunks);
        assert.equal(received.header?.size, BigInt(size), "the size is set even at zero");
        assert.equal(received.header?.fiberId, "g/1/1");
        assert.equal(received.header?.path, "d/data.bin");
        assert.equal(received.header?.mode, 0o600);
        assert.deepEqual(received.header?.sha256, digest);
        assert.deepEqual(info, { path: "d/data.bin", size: BigInt(size), mode: 0o600, directory: false, sha256: digest });
        assert.deepEqual(files.file("g/1/1", "d/data.bin"), { data, mode: 0o600 });
      });
    }
  }
});

test("upload takes a fiber or its ID and defaults to mode 0 and no sha256", async (t) => {
  const { client, files } = await home(t);
  const cases: Record<string, { fiber: () => Promise<Fiber | string>; mode?: number; wire: number; landed: number }> = {
    "an ID with no options sends mode 0, which fiberd reads as 0644": { fiber: async () => "g/1/1", wire: 0, landed: 0o644 },
    "a fiber from Clone": { fiber: () => client.clone("jwt"), wire: 0, landed: 0o644 },
    "bits past the permission bits are dropped": { fiber: async () => "g/1/1", mode: 0o104755, wire: 0o755, landed: 0o755 },
  };
  for (const [name, { fiber, mode, wire, landed }] of Object.entries(cases)) {
    await t.test(name, async () => {
      const info = await client.upload(await fiber(), "a.txt", Buffer.from("hello"), { mode });
      const header = files.uploads.at(-1)!.header!;
      assert.equal(header.fiberId, "g/1/1");
      assert.equal(header.mode, wire);
      assert.equal(header.sha256.length, 0);
      assert.equal(header.size, 5n);
      assert.deepEqual(info, { path: "a.txt", size: 5n, mode: landed, directory: false, sha256: sha256(Buffer.from("hello")) });
    });
  }
});

test("a source that breaks its size fails locally, and fiberd never holds every declared byte", async (t) => {
  const { client, files } = await home(t);
  const failure = new Error("disk went away");
  const cases: Record<string, {
    data: () => { data: Data; state?: { closed: boolean } };
    size: number;
    error: (caught: unknown) => boolean;
    opens: boolean;
  }> = {
    "a source a byte short": {
      data: () => source([randomBytes(9)]), size: 10, opens: true,
      error: (e) => e instanceof SizeMismatch && /ended 1 bytes short of its size of 10$/.test(e.message),
    },
    "a source short after a full chunk": {
      data: () => source([randomBytes(MiB)]), size: MiB + 5, opens: true,
      error: (e) => e instanceof SizeMismatch && /ended 5 bytes short/.test(e.message),
    },
    "a source that ends at once": {
      data: () => source([]), size: 3, opens: true,
      error: (e) => e instanceof SizeMismatch && /ended 3 bytes short/.test(e.message),
    },
    "a source a byte long": {
      data: () => source([randomBytes(11)]), size: 10, opens: true,
      error: (e) => e instanceof SizeMismatch && /holds more than its size of 10$/.test(e.message),
    },
    "a source long after a full chunk": {
      data: () => source([randomBytes(MiB + 1)]), size: MiB, opens: true,
      error: (e) => e instanceof SizeMismatch && /holds more than its size of 1048576$/.test(e.message),
    },
    "a source long in a later piece": {
      data: () => source([randomBytes(5), randomBytes(5), randomBytes(1)]), size: 10, opens: true,
      error: (e) => e instanceof SizeMismatch,
    },
    "an empty file that is not empty opens no call": {
      data: () => source([randomBytes(1)]), size: 0, opens: false,
      error: (e) => e instanceof SizeMismatch && /holds more than its size of 0$/.test(e.message),
    },
    "an empty piece does not hide the extra byte of an empty file": {
      data: () => source([new Uint8Array(0), randomBytes(1)]), size: 0, opens: false,
      error: (e) => e instanceof SizeMismatch,
    },
    "a source that fails rejects with its own error": {
      data: () => source([randomBytes(3)], failure), size: 10, opens: true,
      error: (e) => e === failure,
    },
    "a source that yields something other than bytes": {
      data: () => source(["text"]), size: 0, opens: false,
      error: (e) => e instanceof TypeError,
    },
    "a Uint8Array with another size": {
      data: () => ({ data: randomBytes(3) }), size: 4, opens: false,
      error: (e) => e instanceof SizeMismatch && e.size === 4n && /is 3 bytes, not its size of 4$/.test(e.message),
    },
  };
  for (const [name, { data, size, error, opens }] of Object.entries(cases)) {
    await t.test(name, async () => {
      const before = files.uploads.length;
      const made = data();
      await assert.rejects(client.upload("g/1/1", "x.bin", made.data, { size }), (caught: unknown) => {
        assert.ok(error(caught), `unexpected ${String(caught)}`);
        if (caught instanceof SizeMismatch) {
          assert.ok(caught instanceof FiberdError);
          assert.equal(caught.name, "SizeMismatch");
          assert.equal(caught.path, "x.bin");
        }
        return true;
      });
      const seen = files.uploads.slice(before);
      if (!opens) assert.equal(seen.length, 0, "no call may open");
      for (const received of seen) {
        await settled(received.ended);
        assert.equal(received.placed, false);
        const got = received.chunks.reduce((sum, n) => sum + n, 0);
        assert.ok(received.header === undefined || got < size, `fiberd got ${got} of ${size} bytes`);
      }
      assert.equal(files.file("g/1/1", "x.bin"), undefined);
      await new Promise<void>((resolve) => setImmediate(resolve));
      if (made.state) assert.equal(made.state.closed, true, "the source must be closed");
    });
  }
});

test("invalid arguments reject without a call", async (t) => {
  const { client, files } = await home(t);
  const cases: Record<string, { call: () => Promise<unknown>; error: typeof RangeError | typeof TypeError }> = {
    "a negative size": { call: () => client.upload("g/1/1", "x", source([]).data, { size: -1 }), error: RangeError },
    "a fractional size": { call: () => client.upload("g/1/1", "x", source([]).data, { size: 1.5 }), error: RangeError },
    "a size past uint64": { call: () => client.upload("g/1/1", "x", source([]).data, { size: 1n << 64n }), error: RangeError },
    "a negative size on a Uint8Array": { call: () => client.upload("g/1/1", "x", randomBytes(1), { size: -1 }), error: RangeError },
    "an AsyncIterable without size": { call: () => client.upload("g/1/1", "x", source([]).data), error: TypeError },
    "data that is neither": { call: () => client.upload("g/1/1", "x", "text" as unknown as Uint8Array), error: TypeError },
    "an invalid upload timeout": { call: () => client.upload("g/1/1", "x", randomBytes(1), { timeoutMs: -1 }), error: RangeError },
    "a negative offset": { call: () => client.download("g/1/1", "x", { offset: -1 }), error: RangeError },
    "an invalid download timeout": { call: () => client.download("g/1/1", "x", { timeoutMs: NaN }), error: RangeError },
  };
  for (const [name, { call, error }] of Object.entries(cases)) {
    await t.test(name, async () => {
      await assert.rejects(call(), error);
      await new Promise<void>((resolve) => setImmediate(resolve));
      assert.equal(files.uploads.length, 0);
      assert.equal(files.downloads.length, 0);
    });
  }
});

test("an aborted or timed out upload rejects and places no file", { timeout: 5000 }, async (t) => {
  const reason = new Error("stop the upload");
  const cases: Record<string, {
    size: number;
    stop: "abort" | "pre-abort" | "timeout";
    opens: boolean;
    error: (caught: unknown) => boolean;
  }> = {
    "a pre-aborted signal makes no call": { size: 5, stop: "pre-abort", opens: false, error: (e) => e === reason },
    "an abort while an empty file's source is read opens no call": { size: 0, stop: "abort", opens: false, error: (e) => e === reason },
    "an abort while a chunk is read cancels the call": { size: 5, stop: "abort", opens: true, error: (e) => e === reason },
    "a timeout while a chunk is read cancels the call": {
      size: 5, stop: "timeout", opens: true,
      error: (e) => e instanceof Error && "code" in e && e.code === status.DEADLINE_EXCEEDED,
    },
  };
  for (const [name, { size, stop, opens, error }] of Object.entries(cases)) {
    await t.test(name, async (t) => {
      const { client, files } = await home(t);
      let headerSeen!: () => void;
      const header = new Promise<void>((resolve) => { headerSeen = resolve; });
      files.onHeader = () => headerSeen();
      const controller = new AbortController();
      if (stop === "pre-abort") controller.abort(reason);
      const made = source([], "hang");
      const pending = client.upload("g/1/1", "x.bin", made.data, {
        size, signal: controller.signal, timeoutMs: stop === "timeout" ? 200 : undefined,
      });
      if (stop === "abort") {
        if (opens) await header;
        else await new Promise<void>((resolve) => setImmediate(resolve));
        controller.abort(reason);
      }
      await assert.rejects(pending, (caught: unknown) => error(caught));
      assert.equal(getEventListeners(controller.signal, "abort").length, 0);
      if (!opens) assert.equal(files.uploads.length, 0);
      for (const received of files.uploads) {
        await settled(received.ended);
        assert.equal(received.placed, false);
      }
      assert.equal(files.file("g/1/1", "x.bin"), undefined);
    });
  }
});

test("fiberd answering before the last byte fails the upload", { timeout: 5000 }, async (t) => {
  const cases: Record<string, { parts: Uint8Array[]; size: number }> = {
    "an answer after the header": { parts: [], size: 5 },
    "an answer after a full chunk": { parts: [randomBytes(MiB)], size: MiB + 1 },
  };
  for (const [name, { parts, size }] of Object.entries(cases)) {
    await t.test(name, async (t) => {
      const { client } = await home(t, {
        upload: (call, done) => call.once("data", () => done(null, WireFileInfo.fromPartial({ path: "x.bin", size: BigInt(size) }))),
      });
      await assert.rejects(client.upload("g/1/1", "x.bin", source(parts, "hang").data, { size }), (caught: unknown) => {
        assert.ok(caught instanceof FiberdError);
        assert.match(caught.message, /fiberd answered the upload of x\.bin before its last byte/);
        return true;
      });
    });
  }
});

test("upload then download returns the same bytes", async (t) => {
  const { client } = await home(t);
  const cases = { "2 MiB and 7 bytes": 2 * MiB + 7, "an empty file": 0 };
  for (const [name, size] of Object.entries(cases)) {
    await t.test(name, async () => {
      const data = randomBytes(size);
      await client.upload("g/1/1", "round/trip.bin", source(split(data, 64 * 1024)).data, { size });
      assert.deepEqual(Buffer.concat(await collect(await client.download("g/1/1", "round/trip.bin"))), data);
    });
  }
});

test("download reassembles the file from its offset and carries its info", async (t) => {
  const { client, files } = await home(t);
  const cases = [
    { name: "an empty file is its info alone", size: 0, chunk: MiB, offset: 0, chunks: [] },
    { name: "a small file is one chunk", size: 5, chunk: MiB, offset: 0, chunks: [5] },
    { name: "a file over many chunks reassembles", size: 25, chunk: 10, offset: 0, chunks: [10, 10, 5] },
    { name: "1 MiB and a byte in full chunks", size: MiB + 1, chunk: MiB, offset: 0, chunks: [MiB, 1] },
    { name: "an offset skips the start, and info still names the whole file", size: 25, chunk: 10, offset: 7, chunks: [10, 8] },
    { name: "an offset at the end is no data", size: 25, chunk: 10, offset: 25, chunks: [] },
    { name: "a bigint offset", size: 25, chunk: 10, offset: 20n, chunks: [5] },
  ];
  for (const { name, size, chunk, offset, chunks } of cases) {
    await t.test(name, async () => {
      const data = randomBytes(size);
      files.put("g/1/1", "out/r.bin", data, 0o640);
      files.downloadChunk = chunk;
      const download = await client.download("g/1/1", "out/r.bin", { offset });
      assert.ok(download instanceof Download);
      const want: FileInfo = { path: "out/r.bin", size: BigInt(size), mode: 0o640, directory: false, sha256: Buffer.alloc(0) };
      assert.deepEqual(download.info, want);
      const pieces = await collect(download);
      assert.deepEqual(pieces.map((piece) => piece.length), chunks);
      assert.deepEqual(Buffer.concat(pieces), data.subarray(Number(offset)));
      assert.deepEqual(files.downloads.at(-1)?.request, { fiberId: "g/1/1", path: "out/r.bin", offset: BigInt(offset) });
    });
  }
});

test("file calls reject with typed errors", async (t) => {
  const calls: Record<string, (client: Client, fiber: string) => Promise<unknown>> = {
    upload: (client, fiber) => client.upload(fiber, "a.txt", Buffer.from("hello")),
    download: (client, fiber) => client.download(fiber, "a.txt"),
    "download a missing file": (client, fiber) => client.download(fiber, "missing.txt"),
    listFiles: (client, fiber) => client.listFiles(fiber),
  };
  const cases: Array<{
    name: string;
    call: string;
    set?: (files: Files) => void;
    fiber?: string;
    want: typeof NotFound | typeof NoWorkspace | typeof QuotaExceeded;
    message: string;
  }> = [
    { name: "an upload to an unknown fiber is NotFound", call: "upload", fiber: "g/1/99", want: NotFound, message: "not found: fiber g/1/99 unknown" },
    { name: "a download from an unknown fiber is NotFound", call: "download", fiber: "g/1/99", want: NotFound, message: "not found: fiber g/1/99 unknown" },
    { name: "listing an unknown fiber is NotFound", call: "listFiles", fiber: "g/1/99", want: NotFound, message: "not found: fiber g/1/99 unknown" },
    {
      name: "an upload with no disk budget is NoWorkspace, not a tier gap", call: "upload", set: (f) => { f.diskBudget = 0; },
      want: NoWorkspace, message: "no workspace: grant has no workspace: fiber g/1/1",
    },
    {
      name: "a download with no disk budget is NoWorkspace", call: "download", set: (f) => { f.diskBudget = 0; },
      want: NoWorkspace, message: "no workspace: grant has no workspace: fiber g/1/1",
    },
    {
      name: "listing with no disk budget is NoWorkspace", call: "listFiles", set: (f) => { f.diskBudget = 0; },
      want: NoWorkspace, message: "no workspace: grant has no workspace: fiber g/1/1",
    },
    {
      name: "an upload over the budget is QuotaExceeded, not Shed", call: "upload", set: (f) => { f.diskBudget = 4; },
      want: QuotaExceeded, message: "quota exceeded: the file is larger than the grant's disk budget: 5 bytes",
    },
    { name: "a missing file is NotFound from download itself", call: "download a missing file", want: NotFound, message: "not found: file missing.txt does not exist" },
    {
      name: "a failure before the first chunk rejects from download itself", call: "download",
      set: (f) => { f.downloadFail = { error: rpcError(status.NOT_FOUND, "gone"), after: 0 }; },
      want: NotFound, message: "not found: gone",
    },
  ];
  for (const { name, call, set, fiber, want, message } of cases) {
    await t.test(name, async (t) => {
      const { client, files } = await home(t);
      files.put("g/1/1", "a.txt", Buffer.from("hello"));
      set?.(files);
      await assert.rejects(calls[call]!(client, fiber ?? "g/1/1"), (caught: unknown) => {
        assert.ok(caught instanceof want && caught instanceof FiberdError, `unexpected ${String(caught)}`);
        assert.ok(!(caught instanceof Shed));
        assert.equal(caught.name, want.name);
        assert.equal(caught.message, message);
        assert.ok(caught.cause instanceof Error);
        return true;
      });
    });
  }
});

test("a download whose first message is not its info rejects from the call", async (t) => {
  const cases: Record<string, { download: FibersServer["download"]; message: RegExp }> = {
    "a stream that ends before its info": { download: (call) => call.end(), message: /ended before its file info/ },
    "a first chunk with no info": {
      download: (call) => { call.write({ info: undefined, data: Buffer.from("x") }); call.end(); },
      message: /carries no file info in its first chunk/,
    },
  };
  for (const [name, { download, message }] of Object.entries(cases)) {
    await t.test(name, async (t) => {
      const { client } = await home(t, { download });
      await assert.rejects(client.download("g/1/1", "a.txt"), (caught: unknown) => {
        assert.ok(caught instanceof FiberdError);
        assert.match(caught.message, message);
        return true;
      });
    });
  }
});

test("a download that fails mid-stream rejects the read with a classified error", async (t) => {
  const cases: Record<string, { error: ServiceError; check: (caught: unknown) => boolean }> = {
    "a fiber gone mid-stream is NotFound": {
      error: rpcError(status.NOT_FOUND, "fiber went away"),
      check: (e) => e instanceof NotFound && e.reason === "fiber went away",
    },
    "a workspace refusal mid-stream is NoWorkspace": {
      error: noWorkspaceError("grant has no workspace"),
      check: (e) => e instanceof NoWorkspace,
    },
    "anything else is the raw gRPC error": {
      error: rpcError(status.ABORTED, "park cancelled the transfer"),
      check: (e) => !(e instanceof FiberdError) && e instanceof Error && "code" in e && e.code === status.ABORTED,
    },
  };
  for (const [name, { error, check }] of Object.entries(cases)) {
    await t.test(name, async (t) => {
      const { client, files } = await home(t);
      const data = randomBytes(30);
      files.put("g/1/1", "big", data);
      files.downloadChunk = 10;
      files.downloadFail = { error, after: 1 };
      const pieces = (await client.download("g/1/1", "big"))[Symbol.asyncIterator]();
      const first = await pieces.next();
      if (first.done) assert.fail("the download ended before its first chunk");
      assert.deepEqual(Buffer.from(first.value), data.subarray(0, 10));
      await assert.rejects(pieces.next(), (caught: unknown) => {
        assert.ok(check(caught), `unexpected ${String(caught)}`);
        return true;
      });
    });
  }
});

test("a download stops on cancel, a break or an abort, and fiberd sees the call cancelled", { timeout: 5000 }, async (t) => {
  const reason = new Error("stop the download");
  const cases: Record<string, (download: Download, pieces: AsyncIterator<Uint8Array>, controller: AbortController) => Promise<void>> = {
    "cancel() stops it, and the next read rejects with CANCELLED": async (download, pieces) => {
      download.cancel();
      await assert.rejects(pieces.next(), { code: status.CANCELLED });
    },
    "breaking out of for-await cancels it": async (_download, pieces) => {
      await pieces.return?.();
    },
    "an abort rejects the read with the signal's reason": async (_download, pieces, controller) => {
      controller.abort(reason);
      await assert.rejects(pieces.next(), (caught: unknown) => caught === reason);
    },
  };
  for (const [name, stop] of Object.entries(cases)) {
    await t.test(name, async (t) => {
      const { client, files } = await home(t);
      files.put("g/1/1", "big", randomBytes(30));
      files.downloadChunk = 10;
      let release!: () => void;
      files.downloadGate = new Promise<void>((resolve) => { release = resolve; });
      t.after(() => release());
      const controller = new AbortController();
      const download = await client.download("g/1/1", "big", { signal: controller.signal });
      const pieces = download[Symbol.asyncIterator]();
      assert.equal((await pieces.next()).value?.length, 10);
      await stop(download, pieces, controller);
      const sent = files.downloads.at(-1)!;
      await settled(sent.ended);
      assert.equal(sent.cancelled, true);
      assert.equal(getEventListeners(controller.signal, "abort").length, 0);
    });
  }
});

test("listFiles lists one directory and converts every field", async (t) => {
  const cases: Array<{ name: string; dir?: string; serve?: WireFileInfo[]; want: FileInfo[] | typeof NotFound }> = [
    {
      name: "the workspace itself, files and directories", dir: "",
      want: [
        { path: "a.txt", size: 2n, mode: 0o600, directory: false, sha256: Buffer.alloc(0) },
        { path: "d", size: 0n, mode: 0o755, directory: true, sha256: Buffer.alloc(0) },
      ],
    },
    {
      name: "the workspace is the default", want: [
        { path: "a.txt", size: 2n, mode: 0o600, directory: false, sha256: Buffer.alloc(0) },
        { path: "d", size: 0n, mode: 0o755, directory: true, sha256: Buffer.alloc(0) },
      ],
    },
    {
      name: "a directory, not recursive", dir: "d",
      want: [
        { path: "d/b.bin", size: 3n, mode: 0o644, directory: false, sha256: Buffer.alloc(0) },
        { path: "d/e", size: 0n, mode: 0o755, directory: true, sha256: Buffer.alloc(0) },
      ],
    },
    { name: "a directory deeper down", dir: "d/e", want: [{ path: "d/e/c", size: 0n, mode: 0o644, directory: false, sha256: Buffer.alloc(0) }] },
    { name: "a directory that is not there is NotFound", dir: "nope", want: NotFound },
    { name: "an empty workspace is no entries", serve: [], want: [] },
    {
      name: "sizes past 2^53 stay exact", serve: [WireFileInfo.fromPartial({ path: "big", size: 18_446_744_073_709_551_615n, mode: 0o640, sha256: Buffer.from([1]) })],
      want: [{ path: "big", size: 18_446_744_073_709_551_615n, mode: 0o640, directory: false, sha256: Buffer.from([1]) }],
    },
  ];
  for (const { name, dir, serve, want } of cases) {
    await t.test(name, async (t) => {
      const { client, files } = await home(t, serve ? { listFiles: (_call, done) => done(null, { files: serve }) } : {});
      files.put("g/1/1", "a.txt", Buffer.from("hi"), 0o600);
      files.put("g/1/1", "d/b.bin", Buffer.from("xyz"));
      files.put("g/1/1", "d/e/c", Buffer.alloc(0));
      const listing = dir === undefined ? client.listFiles("g/1/1") : client.listFiles("g/1/1", dir);
      if (want === NotFound) await assert.rejects(listing, NotFound);
      else assert.deepEqual(await listing, want);
    });
  }
});
