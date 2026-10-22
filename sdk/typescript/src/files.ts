import type {
  CallOptions as GrpcCallOptions,
  ClientReadableStream,
  ClientWritableStream,
  Metadata,
} from "@grpc/grpc-js";
import type {
  FibersClient,
  FileChunk,
  FileInfo as WireFileInfo,
  UploadHeader,
  UploadRequest,
} from "./generated/grant/v1/grant.js";
import { classify, FiberdError, SizeMismatch } from "./errors.js";

/** The most data one Upload or Download message carries, pkg/rpc's MaxChunk. */
const CHUNK = 1 << 20;

/** One entry of a fiber's workspace. */
export interface FileInfo {
  /** Relative to the fiber's /workspace. */
  readonly path: string;
  readonly size: bigint;
  /** The permission bits. */
  readonly mode: number;
  readonly directory: boolean;
  /** The content's SHA-256. Only an upload's answer sets it, and it is empty otherwise. */
  readonly sha256: Buffer;
}

export function fileInfoFrom(info: WireFileInfo): FileInfo {
  return { path: info.path, size: info.size, mode: info.mode, directory: info.directory, sha256: info.sha256 };
}

/** A byte count as a uint64. A RangeError for anything else. */
export function byteCount(value: number | bigint, name: string): bigint {
  if (typeof value === "number" && !Number.isSafeInteger(value)) {
    throw new RangeError(`${name} must be a whole number of bytes`);
  }
  const count = BigInt(value);
  if (count < 0n || count >= 1n << 64n) throw new RangeError(`${name} must be between 0 and 2^64-1 bytes`);
  return count;
}

/** The size an upload declares. A Uint8Array's is its length, and an AsyncIterable needs size. */
export function uploadSize(path: string, data: Uint8Array | AsyncIterable<Uint8Array>, size?: number | bigint): bigint {
  if (data instanceof Uint8Array) {
    const length = BigInt(data.length);
    if (size !== undefined && byteCount(size, "size") !== length) {
      throw new SizeMismatch(path, BigInt(size), `the data of ${path} is ${length} bytes, not its size of ${size}`);
    }
    return length;
  }
  if (typeof data !== "object" || data === null || !(Symbol.asyncIterator in data)) {
    throw new TypeError("upload data must be a Uint8Array or an AsyncIterable of them");
  }
  if (size === undefined) throw new TypeError("an AsyncIterable upload needs size");
  return byteCount(size, "size");
}

/** read(n) over an upload's data, n bytes at a time whatever size the iterable yields. */
export class Source {
  private readonly items: AsyncIterator<unknown> | undefined;
  private buffered: Uint8Array;
  private ended = false;

  constructor(data: Uint8Array | AsyncIterable<Uint8Array>) {
    if (data instanceof Uint8Array) {
      this.buffered = data;
      this.ended = true;
    } else {
      this.items = data[Symbol.asyncIterator]();
      this.buffered = new Uint8Array(0);
    }
  }

  /**
   * n bytes, or fewer only at the end. It is a copy, since an iterable may
   * reuse its buffer once it yields again.
   */
  async read(n: number): Promise<Buffer> {
    const parts: Uint8Array[] = [];
    let have = 0;
    while (have < n) {
      if (this.buffered.length === 0) {
        if (this.ended || !this.items) break;
        const next = await this.items.next();
        if (next.done) {
          this.ended = true;
          break;
        }
        if (!(next.value instanceof Uint8Array)) throw new TypeError("an upload's AsyncIterable must yield Uint8Arrays");
        this.buffered = next.value;
        continue;
      }
      const part = this.buffered.subarray(0, n - have);
      this.buffered = this.buffered.subarray(part.length);
      parts.push(part);
      have += part.length;
    }
    return Buffer.concat(parts, have);
  }

  /** Lets an iterable that did not end clean up. It does not wait, since a pending read holds it up. */
  close(): void {
    if (this.ended || !this.items) return;
    this.ended = true;
    try {
      Promise.resolve(this.items.return?.()).catch(() => {});
    } catch {
      // A throwing return leaves nothing more to clean up.
    }
  }
}

/**
 * Sends one Upload, the header and then the source in chunks of at most
 * CHUNK bytes, and resolves to fiberd's answer.
 *
 * The message that completes the size is held back until the source is
 * read once more and found to end there. For an empty file that message
 * is the header, so no call opens until the source is known to be empty.
 * A source that is short or long rejects with SizeMismatch and cancels
 * the call, so fiberd never places the file.
 */
export async function upload(
  api: FibersClient,
  header: UploadHeader & { size: bigint },
  source: Source,
  metadata: Metadata,
  rpcOptions: Partial<GrpcCallOptions>,
  signal?: AbortSignal,
): Promise<FileInfo> {
  let call: ClientWritableStream<UploadRequest> | undefined;
  let ending = false;
  // The first reason the upload cannot go on. It interrupts whatever the upload awaits.
  let failure: { reason: unknown } | undefined;
  let interrupt: ((reason: unknown) => void) | undefined;
  const fail = (reason: unknown) => {
    if (failure) return;
    failure = { reason };
    interrupt?.(reason);
  };
  // Promise.race would pile a reaction on one long-lived promise per chunk. This keeps one at a time.
  const guard = <T>(pending: Promise<T>): Promise<T> => {
    if (failure) {
      pending.catch(() => {});
      return Promise.reject(failure.reason);
    }
    return new Promise<T>((resolve, reject) => {
      const stop = (reason: unknown) => reject(reason);
      const done = () => { if (interrupt === stop) interrupt = undefined; };
      interrupt = stop;
      pending.then((value) => { done(); resolve(value); }, (reason: unknown) => { done(); reject(reason); });
    });
  };
  let answered!: (info: WireFileInfo) => void;
  const answer = new Promise<WireFileInfo>((resolve) => { answered = resolve; });
  const open = () => api.upload(metadata, rpcOptions, (error, value) => {
    if (signal?.aborted) fail(signal.reason);
    else if (error) fail(classify(error));
    else if (!ending) fail(new FiberdError(`fiberd answered the upload of ${header.path} before its last byte`));
    else answered(value);
  });
  const send = async (request: UploadRequest) => {
    const stream = (call ??= open());
    if (!stream.write(request)) await guard(new Promise<void>((resolve) => stream.once("drain", () => resolve())));
  };
  const aborted = () => {
    fail(signal?.reason);
    call?.cancel();
  };
  signal?.addEventListener("abort", aborted, { once: true });
  try {
    if (signal?.aborted) throw signal.reason;
    const size = header.size;
    let pending: UploadRequest | undefined = { header };
    if (size > 0n) {
      await send(pending);
      pending = undefined;
    }
    let left = size;
    while (left > 0n) {
      const chunk = await guard(source.read(left < BigInt(CHUNK) ? Number(left) : CHUNK));
      if (chunk.length === 0) {
        throw new SizeMismatch(header.path, size, `the source of ${header.path} ended ${left} bytes short of its size of ${size}`);
      }
      left -= BigInt(chunk.length);
      if (pending) await send(pending);
      pending = { data: chunk };
    }
    if ((await guard(source.read(1))).length > 0) {
      throw new SizeMismatch(header.path, size, `the source of ${header.path} holds more than its size of ${size}`);
    }
    // The held message, the header of an empty file or the last chunk, is
    // written and the stream ended in one step, so an answer before it is
    // an early one.
    const stream = (call ??= open());
    stream.write(pending!);
    ending = true;
    stream.end();
    return fileInfoFrom(await guard(answer));
  } catch (error) {
    call?.cancel();
    throw error;
  } finally {
    signal?.removeEventListener("abort", aborted);
    source.close();
  }
}

/**
 * One file coming down from a fiber's workspace, an async iterable of its
 * bytes. info is what the first message carried.
 *
 * Iterate it to its end or cancel it, since an open download holds its
 * stream. Breaking out of for-await cancels it too. A read after cancel()
 * rejects with gRPC's CANCELLED, and a failure mid-stream rejects with the
 * same typed errors as the call.
 */
export class Download implements AsyncIterable<Uint8Array> {
  private first: Buffer;

  constructor(
    public readonly info: FileInfo,
    first: Buffer,
    private readonly chunks: AsyncIterator<FileChunk>,
    private readonly stop: () => void,
    private readonly signal?: AbortSignal,
  ) {
    this.first = first;
  }

  async *[Symbol.asyncIterator](): AsyncGenerator<Uint8Array, void, void> {
    try {
      if (this.first.length > 0) {
        const data = this.first;
        this.first = Buffer.alloc(0);
        yield data;
      }
      for (;;) {
        const next = await this.chunks.next();
        this.signal?.throwIfAborted();
        if (next.done) return;
        if (next.value.data.length > 0) yield next.value.data;
      }
    } catch (error) {
      this.signal?.throwIfAborted();
      throw classify(error);
    } finally {
      this.stop();
    }
  }

  /** Stops the transfer. A download already done is left as it is. */
  cancel(): void {
    this.stop();
  }
}

/** Reads a Download's first message, so a refusal rejects here rather than on the first read. */
export async function openDownload(stream: ClientReadableStream<FileChunk>, path: string, signal?: AbortSignal): Promise<Download> {
  const aborted = () => stream.cancel();
  const stop = () => {
    signal?.removeEventListener("abort", aborted);
    stream.cancel();
  };
  signal?.addEventListener("abort", aborted, { once: true });
  if (signal?.aborted) aborted();
  const chunks = stream[Symbol.asyncIterator]() as AsyncIterator<FileChunk>;
  let first: IteratorResult<FileChunk>;
  try {
    first = await chunks.next();
  } catch (error) {
    stop();
    signal?.throwIfAborted();
    throw classify(error);
  }
  if (first.done) {
    stop();
    throw new FiberdError(`the download of ${path} ended before its file info`);
  }
  if (!first.value.info) {
    stop();
    throw new FiberdError(`the download of ${path} carries no file info in its first chunk`);
  }
  return new Download(fileInfoFrom(first.value.info), first.value.data, chunks, stop, signal);
}
