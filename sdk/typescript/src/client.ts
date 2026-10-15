import {
  credentials,
  Metadata,
  type CallOptions as GrpcCallOptions,
  type ChannelCredentials,
  type ClientOptions,
  type ClientUnaryCall,
  type ServiceError,
} from "@grpc/grpc-js";
import { createSecureContext } from "node:tls";
import { FibersClient, type CloneResponse, type Fence as WireFence } from "./generated/grant/v1/grant.js";
import { classify } from "./errors.js";
import { type CallerIdentity, Fence, Fiber } from "./fiber.js";
import { type OperationOptions, validateDuration } from "./options.js";

export type Token = string | (() => string | Promise<string>);

export interface TlsOptions extends CallerIdentity {
  ca: Buffer;
}

export interface CallOptions extends OperationOptions {
  metadata?: Metadata;
}

export interface CloneOptions extends CallOptions {
  session?: string;
  payload?: Uint8Array;
  /** Budget for runtime work, distinct from the whole RPC's timeoutMs. Zero omits the budget. */
  deadlineMs?: number;
}

export interface ParkOptions extends CallOptions {
  sync?: boolean;
}

export interface ReleaseOptions extends CallOptions {
  discard?: boolean;
}

export interface Status {
  readonly grantUid: string;
  readonly running: number;
  readonly parked: number;
  readonly pooled: number;
  readonly wUsedBytes: bigint;
  readonly latest: Fence;
}

export class Client {
  private readonly api: FibersClient;

  constructor(
    public readonly target: string,
    channelCredentials: ChannelCredentials,
    options?: Partial<ClientOptions>,
  ) {
    this.api = new FibersClient(target, channelCredentials, options);
  }

  /** Plaintext, only for homes started with -insecure-plaintext. */
  static dial(target: string, options?: Partial<ClientOptions>): Client {
    return new Client(target, credentials.createInsecure(), options);
  }

  static dialTls(target: string, tls: TlsOptions, options?: Partial<ClientOptions>): Client {
    const context = createSecureContext({
      ca: tls.ca,
      cert: tls.cert,
      key: tls.key,
      minVersion: "TLSv1.3",
    });
    return new Client(target, credentials.createFromSecureContext(context), options);
  }

  close(): void {
    this.api.close();
  }

  async clone(token: Token, options: CloneOptions = {}): Promise<Fiber> {
    validateDuration(options.deadlineMs, "deadlineMs");
    validateDuration(options.timeoutMs, "timeoutMs");
    const grantJwt = typeof token === "function" ? await resolveToken(token, options.signal) : token;
    const session = options.session ?? "";
    const deadline = options.deadlineMs ? Date.now() + options.deadlineMs : undefined;
    const response = await unary<CloneResponse>((rpcOptions, done) => this.api.clone({
      grantJwt,
      session,
      payload: Buffer.from(options.payload ?? []),
      deadline: deadline === undefined ? undefined : {
        seconds: BigInt(Math.floor(deadline / 1000)),
        nanos: Math.floor((deadline % 1000) * 1_000_000),
      },
    }, options.metadata ?? new Metadata(), rpcOptions, done), options);
    return new Fiber({
      id: response.fiberId,
      endpoint: response.endpoint,
      kind: response.kind,
      fence: fenceFrom(response.fence),
      session,
      home: this.target,
      routingKey: response.routingKey,
      serverKeySha256: response.serverKeySha256,
      serverCert: response.serverCert,
    });
  }

  async park(fiber: Fiber | string, options: ParkOptions = {}): Promise<void> {
    await unary((rpcOptions, done) => this.api.park({
      fiberId: typeof fiber === "string" ? fiber : fiber.id,
      sync: options.sync ?? true,
    }, options.metadata ?? new Metadata(), rpcOptions, done), options);
  }

  async release(fiber: Fiber | string, options: ReleaseOptions = {}): Promise<void> {
    await unary((rpcOptions, done) => this.api.release({
      fiberId: typeof fiber === "string" ? fiber : fiber.id,
      discard: options.discard ?? false,
    }, options.metadata ?? new Metadata(), rpcOptions, done), options);
  }

  /** timeoutMs bounds the whole stream. Breaking out of for-await cancels the RPC. */
  async *watch(options: CallOptions = {}): AsyncGenerator<Status, void, void> {
    const rpcOptions = rpcOptionsFor(options);
    const stream = this.api.watch({}, options.metadata ?? new Metadata(), rpcOptions);
    const aborted = () => stream.cancel();
    options.signal?.addEventListener("abort", aborted, { once: true });
    if (options.signal?.aborted) aborted();
    try {
      for await (const value of stream) {
        options.signal?.throwIfAborted();
        yield {
          grantUid: value.grantUid,
          running: value.running,
          parked: value.parked,
          pooled: value.pooled,
          wUsedBytes: value.wUsedBytes,
          latest: fenceFrom(value.latest),
        };
      }
    } catch (error) {
      options.signal?.throwIfAborted();
      throw classify(error);
    } finally {
      options.signal?.removeEventListener("abort", aborted);
      stream.cancel();
    }
  }
}

function fenceFrom(fence: WireFence | undefined): Fence {
  return new Fence(fence?.grantUid ?? "", fence?.epoch ?? 0n, fence?.seq ?? 0n);
}

function rpcOptionsFor(options: CallOptions): Partial<GrpcCallOptions> {
  validateDuration(options.timeoutMs, "timeoutMs");
  options.signal?.throwIfAborted();
  return options.timeoutMs ? { deadline: Date.now() + options.timeoutMs } : {};
}

function unary<T>(
  start: (options: Partial<GrpcCallOptions>, done: (error: ServiceError | null, value: T) => void) => ClientUnaryCall,
  options: CallOptions,
): Promise<T> {
  const rpcOptions = rpcOptionsFor(options);
  return new Promise((resolve, reject) => {
    let call: ClientUnaryCall | undefined;
    let finished = false;
    const aborted = () => call?.cancel();
    call = start(rpcOptions, (error, value) => {
      finished = true;
      options.signal?.removeEventListener("abort", aborted);
      if (options.signal?.aborted) reject(options.signal.reason);
      else if (error) reject(classify(error));
      else resolve(value);
    });
    if (!finished) {
      options.signal?.addEventListener("abort", aborted, { once: true });
      if (options.signal?.aborted) aborted();
    }
  });
}

async function resolveToken(token: () => string | Promise<string>, signal?: AbortSignal): Promise<string> {
  signal?.throwIfAborted();
  const pending = token();
  if (!signal) return pending;
  return new Promise((resolve, reject) => {
    const aborted = () => reject(signal.reason);
    signal.addEventListener("abort", aborted, { once: true });
    Promise.resolve(pending).then(
      (value) => {
        signal.removeEventListener("abort", aborted);
        if (signal.aborted) reject(signal.reason);
        else resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", aborted);
        reject(signal.aborted ? signal.reason : error);
      },
    );
    if (signal.aborted) {
      signal.removeEventListener("abort", aborted);
      aborted();
    }
  });
}
