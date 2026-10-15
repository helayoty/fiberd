import { createHash, X509Certificate } from "node:crypto";
import { connect, type Socket } from "node:net";
import { connect as connectTls, type TLSSocket } from "node:tls";
import { CloneKind } from "./generated/grant/v1/grant.js";
import { KeyMismatch, NotHandoff } from "./errors.js";
import { type OperationOptions, validateDuration } from "./options.js";

export { CloneKind as Kind };

/** SHA-256 base64url pin of a DER certificate's SubjectPublicKeyInfo. */
export function keyPin(certificate: Uint8Array): string {
  const spki = new X509Certificate(certificate).publicKey.export({ type: "spki", format: "der" });
  return createHash("sha256").update(spki).digest("base64url");
}

export class Fence {
  constructor(
    public readonly grantUid: string,
    public readonly epoch: bigint,
    public readonly seq: bigint,
  ) {}

  toString(): string {
    return `${this.grantUid}/${this.epoch}/${this.seq}`;
  }
}

export type Endpoint = { kind: "unix"; path: string } | { kind: "tcp"; host: string; port: number };

export function parseEndpoint(endpoint: string): Endpoint {
  const invalid = () => new TypeError(`endpoint ${JSON.stringify(endpoint)} is not unix:///path or tcp://host:port`);
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch (cause) {
    if (!(cause instanceof TypeError)) throw cause;
    throw invalid();
  }
  if (url.username || url.password || url.search || url.hash) throw invalid();
  if (url.protocol === "unix:" && endpoint.startsWith("unix:///") && !url.host && url.pathname.length > 1) {
    // fiberd concatenates the literal path, without URL-encoding it.
    const path = endpoint.slice("unix://".length);
    if (path.includes("\0")) throw invalid();
    return { kind: "unix", path };
  }
  if (url.protocol === "tcp:" && url.hostname && url.port && (!url.pathname || url.pathname === "/")) {
    const port = Number(url.port);
    if (port > 0 && port <= 65535) {
      return { kind: "tcp", host: url.hostname.replace(/^\[|\]$/g, ""), port };
    }
  }
  throw invalid();
}

/** PEM contents, not paths. Use the same caller identity on the control API and handoff. */
export interface CallerIdentity {
  cert: Buffer;
  key: Buffer;
}

export interface FiberInfo {
  id: string;
  endpoint: string;
  fence: Fence;
  kind: CloneKind;
  session: string;
  home: string;
  routingKey?: string;
  serverKeySha256?: string;
  serverCert?: Buffer;
}

export class Fiber {
  readonly id: string;
  readonly endpoint: string;
  readonly fence: Fence;
  readonly kind: CloneKind;
  readonly session: string;
  readonly home: string;
  readonly routingKey: string;
  readonly serverKeySha256: string;
  readonly serverCert: Buffer;

  constructor(info: FiberInfo) {
    this.id = info.id;
    this.endpoint = info.endpoint;
    this.fence = info.fence;
    this.kind = info.kind;
    this.session = info.session;
    this.home = info.home;
    this.routingKey = info.routingKey ?? "";
    this.serverKeySha256 = info.serverKeySha256 ?? "";
    this.serverCert = Buffer.from(info.serverCert ?? []);
  }

  get handoff(): boolean {
    return this.routingKey !== "";
  }

  async dial(options: OperationOptions = {}): Promise<Socket> {
    if (this.handoff) throw new TypeError(`fiber ${this.id} requires dialHandoff, not dial`);
    const endpoint = parseEndpoint(this.endpoint);
    return connected(
      () => endpoint.kind === "unix" ? connect(endpoint.path) : connect(endpoint.port, endpoint.host),
      "connect",
      options,
    );
  }

  async dialHandoff(identity: CallerIdentity, options: OperationOptions = {}): Promise<TLSSocket> {
    if (!this.handoff) throw new NotHandoff(`fiber ${this.id} was not cloned under a HANDOFF grant`);
    const endpoint = parseEndpoint(this.endpoint);
    if (endpoint.kind !== "tcp") throw new NotHandoff(`endpoint ${this.endpoint} is not tcp://`);
    if (this.serverCert.length === 0) throw new TypeError(`fiber ${this.id} carries no certificate to pin`);
    const anchor = new X509Certificate(this.serverCert);
    return connected(() => connectTls({
      host: endpoint.host,
      port: endpoint.port,
      servername: `${this.routingKey}.fiberd`,
      cert: identity.cert,
      key: identity.key,
      minVersion: "TLSv1.3",
      ca: anchor.toString(),
      allowPartialTrustChain: true,
      rejectUnauthorized: true,
      // *.fiberd is a route, not a hostname identity. Trust only the Clone's
      // certificate, then check its SPKI pin before exposing the socket.
      checkServerIdentity: (_host, peer) => {
        const pin = keyPin(peer.raw);
        return pin === this.serverKeySha256 ? undefined : new KeyMismatch(`fiber ${this.id} holds another key than its pin`);
      },
    }), "secureConnect", options);
  }
}

function connected<S extends Socket>(
  create: () => S,
  event: "connect" | "secureConnect",
  { timeoutMs, signal }: OperationOptions,
): Promise<S> {
  validateDuration(timeoutMs, "timeoutMs");
  signal?.throwIfAborted();
  return new Promise((resolve, reject) => {
    const socket = create();
    let timer: NodeJS.Timeout | undefined;
    const cleanup = () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", aborted);
      socket.removeListener(event, ready);
      socket.removeListener("error", failed);
      socket.removeListener("close", closed);
    };
    const failed = (error: unknown) => {
      cleanup();
      socket.destroy();
      reject(error);
    };
    const aborted = () => failed(signal?.reason);
    const closed = () => failed(new Error("Connection closed before it was established"));
    const ready = () => {
      cleanup();
      resolve(socket);
    };
    socket.once("error", failed);
    socket.once("close", closed);
    socket.once(event, ready);
    signal?.addEventListener("abort", aborted, { once: true });
    if (timeoutMs) {
      timer = setTimeout(() => failed(new Error(`Connection timed out after ${timeoutMs}ms`)), timeoutMs);
    }
    if (signal?.aborted) aborted();
  });
}
