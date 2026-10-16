import { Metadata, status, type ServiceError } from "@grpc/grpc-js";
import { BinaryReader } from "@bufbuild/protobuf/wire";
import { Miss, MissCode } from "./generated/grant/v1/grant.js";
import { Status as RpcStatus } from "./generated/google/rpc/status.js";

export class FiberdError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

/** Retry here after retryAfterSeconds; do not take the fallback path. */
export class Shed extends FiberdError {
  constructor(
    public readonly retryAfterSeconds: number,
    public readonly issuer: string,
    public readonly reason: string,
    options?: ErrorOptions,
  ) {
    super(`shed: ${reason}, retry after ${retryAfterSeconds}s`, options);
  }
}

/** Take the ordinary provisioning path, or route to preferredHome if set. */
export class Deferred extends FiberdError {
  constructor(
    public readonly issuer: string,
    public readonly preferredHome: string,
    public readonly reason: string,
    options?: ErrorOptions,
  ) {
    const where = preferredHome ? ` (session lives on ${preferredHome})` : "";
    super(`deferred: ${reason}${where}`, options);
  }
}

export class TierGap extends FiberdError {
  constructor(public readonly reason: string, options?: ErrorOptions) {
    super(`tier gap: ${reason}`, options);
  }
}

export class NotFound extends FiberdError {
  constructor(public readonly reason: string, options?: ErrorOptions) {
    super(`not found: ${reason}`, options);
  }
}

export class NotHandoff extends FiberdError {}
export class KeyMismatch extends FiberdError {}

function isServiceError(error: unknown): error is ServiceError {
  return error instanceof Error
    && "code" in error && typeof error.code === "number"
    && "details" in error && typeof error.details === "string"
    && "metadata" in error && error.metadata instanceof Metadata;
}

export function classify(error: unknown): unknown {
  if (!isServiceError(error)) return error;
  let miss: Miss | undefined;
  const raw = error.metadata.get("grpc-status-details-bin")[0];
  if (Buffer.isBuffer(raw)) {
    try {
      // ts-proto accepts an early zero tag and can overlook a truncated nested
      // message. Check the Status and its Any boundaries before classifying it.
      validateWire(raw, 3);
      const envelope = RpcStatus.decode(raw);
      if (envelope.code === error.code) {
        const detail = envelope.details.find((d) => d.typeUrl.endsWith("/fiberd.grant.v1.Miss"));
        if (detail) {
          validateWire(detail.value);
          miss = Miss.decode(detail.value);
        }
      }
    } catch (cause) {
      if (!(cause instanceof Error)) throw cause;
      error.cause = new Error("Could not decode fiberd's grpc-status-details-bin trailer", { cause });
    }
  }
  const options = { cause: error };
  if (miss?.code === MissCode.SHED) {
    return new Shed(miss.retryAfterS, miss.issuer, error.details, options);
  }
  if (miss?.code === MissCode.DEFERRED_FALLBACK) {
    return new Deferred(miss.issuer, miss.preferredHome, error.details, options);
  }
  if (error.code === status.FAILED_PRECONDITION) return new TierGap(error.details, options);
  if (error.code === status.NOT_FOUND) return new NotFound(error.details, options);
  return error;
}

function validateWire(raw: Uint8Array, nestedField?: number): void {
  const reader = new BinaryReader(raw);
  while (reader.pos < reader.len) {
    const [field, wire] = reader.tag();
    if (field === nestedField && wire === 2) validateWire(reader.bytes());
    else reader.skip(wire, field);
  }
}
