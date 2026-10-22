import "reflect-metadata";
import {
  Metadata,
  Server,
  ServerCredentials,
  status,
  type ServiceError,
} from "@grpc/grpc-js";
import { createHash, X509Certificate } from "node:crypto";
import type { TestContext } from "node:test";
import {
  BasicConstraintsExtension,
  ExtendedKeyUsage,
  ExtendedKeyUsageExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  PemConverter,
  SubjectAlternativeNameExtension,
  X509CertificateGenerator,
} from "@peculiar/x509";
import {
  CloneResponse,
  FibersService,
  FileInfo,
  Miss,
  type DownloadRequest,
  type FibersServer,
  type UploadHeader,
} from "./generated/grant/v1/grant.js";
import { Status as RpcStatus } from "./generated/google/rpc/status.js";
import { Client, keyPin } from "./index.js";

export function rpcError(code: status, reason = "full", miss?: Miss): ServiceError {
  const metadata = new Metadata();
  if (miss) {
    metadata.set("grpc-status-details-bin", Buffer.from(RpcStatus.encode({
      code,
      message: reason,
      details: [{ typeUrl: "type.googleapis.com/fiberd.grant.v1.Miss", value: Buffer.from(Miss.encode(miss).finish()) }],
    }).finish()));
  }
  return Object.assign(new Error(reason), { code, details: reason, metadata });
}

export const MiB = 1 << 20;

/** A FailedPrecondition with the NoWorkspace detail, as pkg/rpc refuses a file call on a grant with no workspace. */
export function noWorkspaceError(reason: string): ServiceError {
  const error = rpcError(status.FAILED_PRECONDITION, reason);
  error.metadata.set("grpc-status-details-bin", Buffer.from(RpcStatus.encode({
    code: status.FAILED_PRECONDITION,
    message: reason,
    details: [{ typeUrl: "type.googleapis.com/fiberd.grant.v1.NoWorkspace", value: Buffer.alloc(0) }],
  }).finish()));
  return error;
}

/** What one Upload sent, its header and the size of each data chunk, and whether a file came of it. */
export interface Received {
  header?: UploadHeader;
  chunks: number[];
  placed: boolean;
  /** Resolves once the call ended, whether answered, refused or cancelled. */
  ended: Promise<void>;
}

/** What one Download asked for, and whether the client cancelled it. */
export interface Sent {
  request: DownloadRequest;
  cancelled: boolean;
  /** Resolves once the call ended, whether done, refused or cancelled. */
  ended: Promise<void>;
}

/**
 * A fake of fiberd's file calls over an in-memory workspace per fiber. It
 * checks an upload as pkg/rpc does. The knobs stand in for what a real
 * home's state would decide.
 */
export class Files {
  /** The fibers the home runs. Any other is NotFound. */
  readonly fibers = new Set(["g/1/1"]);
  /** The grant's disk_budget_bytes. Zero means no workspace. */
  diskBudget = 64 * MiB;
  /** The most data one Download message carries. */
  downloadChunk = MiB;
  /** Ends a Download with this error before its chunk number failAfter. */
  downloadFail?: { error: ServiceError; after: number };
  /** Holds every Download chunk after the first until it resolves. */
  downloadGate?: Promise<void>;
  /** Called with each upload's header once it arrives. */
  onHeader?: (header: UploadHeader) => void;
  /** Each fiber's files, a path to its content and mode. */
  readonly workspaces = new Map<string, Map<string, { data: Buffer; mode: number }>>();
  readonly uploads: Received[] = [];
  readonly downloads: Sent[] = [];

  put(fiberId: string, path: string, data: Uint8Array, mode = 0o644): void {
    this.workspace(fiberId).set(path, { data: Buffer.from(data), mode });
  }

  file(fiberId: string, path: string): { data: Buffer; mode: number } | undefined {
    return this.workspaces.get(fiberId)?.get(path);
  }

  private workspace(fiberId: string): Map<string, { data: Buffer; mode: number }> {
    let files = this.workspaces.get(fiberId);
    if (!files) this.workspaces.set(fiberId, files = new Map());
    return files;
  }

  /** The running fiber's workspace, or the error pkg/rpc answers for it. */
  private reach(fiberId: string): Map<string, { data: Buffer; mode: number }> | ServiceError {
    if (!this.fibers.has(fiberId)) return rpcError(status.NOT_FOUND, `fiber ${fiberId} unknown`);
    if (this.diskBudget === 0) return noWorkspaceError(`grant has no workspace: fiber ${fiberId}`);
    return this.workspace(fiberId);
  }

  readonly upload: FibersServer["upload"] = (call, done) => {
    let ended!: () => void;
    const received: Received = { chunks: [], placed: false, ended: new Promise((resolve) => { ended = resolve; }) };
    this.uploads.push(received);
    let finished = false;
    let files: Map<string, { data: Buffer; mode: number }> | undefined;
    const body: Buffer[] = [];
    let got = 0n;
    const answer = (error: ServiceError | null, info?: FileInfo) => {
      if (finished) return;
      finished = true;
      if (error) done(error);
      else done(null, info);
      ended();
    };
    const invalid = (reason: string) => answer(rpcError(status.INVALID_ARGUMENT, reason));
    call.on("data", (request: { header?: UploadHeader; data?: Buffer }) => {
      if (finished) return;
      if (!received.header) {
        const header = request.header;
        if (!header) return invalid("an upload starts with its header");
        received.header = header;
        this.onHeader?.(header);
        if (!header.path || header.size === undefined) return invalid("the upload header names no path or declares no size");
        const reached = this.reach(header.fiberId);
        if (!(reached instanceof Map)) return answer(reached);
        files = reached;
        let used = 0n;
        for (const [path, file] of files) if (path !== header.path) used += BigInt(file.data.length);
        if (used + header.size > BigInt(this.diskBudget)) {
          // pkg/rpc's OverBudget is ResourceExhausted with no Miss.
          return answer(rpcError(status.RESOURCE_EXHAUSTED, `the file is larger than the grant's disk budget: ${header.size} bytes`));
        }
        return;
      }
      if (request.header || !request.data) return invalid("a second header or a message with no part");
      if (request.data.length > MiB) return invalid("a chunk over 1 MiB");
      received.chunks.push(request.data.length);
      body.push(request.data);
      got += BigInt(request.data.length);
      if (got > (received.header.size ?? 0n)) invalid("the upload sent more bytes than its header declared");
    });
    call.on("end", () => {
      const header = received.header;
      if (finished) return;
      if (!header || !files) return invalid("an upload starts with its header");
      if (got !== header.size) return invalid(`the upload ended at ${got} of ${header.size} bytes`);
      const data = Buffer.concat(body);
      const digest = createHash("sha256").update(data).digest();
      if (header.sha256.length > 0 && !digest.equals(header.sha256)) return invalid("sha256 mismatch");
      const mode = header.mode & 0o777 || 0o644;
      files.set(header.path, { data, mode });
      received.placed = true;
      answer(null, FileInfo.fromPartial({ path: header.path, size: header.size, mode, sha256: digest }));
    });
    call.on("cancelled", () => {
      finished = true;
      ended();
    });
    call.on("error", () => {
      finished = true;
      ended();
    });
  };

  readonly download: FibersServer["download"] = (call) => {
    let ended!: () => void;
    const sent: Sent = { request: call.request, cancelled: false, ended: new Promise((resolve) => { ended = resolve; }) };
    this.downloads.push(sent);
    call.on("cancelled", () => {
      sent.cancelled = true;
      ended();
    });
    const fail = (error: ServiceError) => {
      call.emit("error", error);
      ended();
    };
    const reached = this.reach(call.request.fiberId);
    if (!(reached instanceof Map)) return fail(reached);
    const file = reached.get(call.request.path);
    if (!file) return fail(rpcError(status.NOT_FOUND, `file ${call.request.path} does not exist`));
    const info = FileInfo.fromPartial({ path: call.request.path, size: BigInt(file.data.length), mode: file.mode });
    const body = file.data.subarray(Number(call.request.offset));
    const pieces: Buffer[] = [];
    for (let at = 0; at < body.length; at += this.downloadChunk) pieces.push(body.subarray(at, at + this.downloadChunk));
    if (pieces.length === 0) pieces.push(Buffer.alloc(0));
    void (async () => {
      for (const [i, data] of pieces.entries()) {
        if (i > 0 && this.downloadGate) await this.downloadGate;
        if (sent.cancelled) return;
        if (this.downloadFail && i === this.downloadFail.after) return fail(this.downloadFail.error);
        call.write(i === 0 ? { info, data } : { info: undefined, data });
      }
      call.end();
      ended();
    })();
  };

  readonly listFiles: FibersServer["listFiles"] = (call, done) => {
    const reached = this.reach(call.request.fiberId);
    if (!(reached instanceof Map)) return done(reached);
    const dir = call.request.dir.replace(/^\/+|\/+$/g, "");
    const prefix = dir ? `${dir}/` : "";
    const entries = [...reached].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
    if (prefix && !entries.some(([path]) => path.startsWith(prefix))) {
      return done(rpcError(status.NOT_FOUND, `directory ${call.request.dir} does not exist`));
    }
    const files: FileInfo[] = [];
    const dirs = new Set<string>();
    for (const [path, file] of entries) {
      if (!path.startsWith(prefix)) continue;
      const rest = path.slice(prefix.length);
      const slash = rest.indexOf("/");
      if (slash < 0) {
        files.push(FileInfo.fromPartial({ path, size: BigInt(file.data.length), mode: file.mode }));
      } else if (!dirs.has(rest.slice(0, slash))) {
        dirs.add(rest.slice(0, slash));
        files.push(FileInfo.fromPartial({ path: prefix + rest.slice(0, slash), mode: 0o755, directory: true }));
      }
    }
    done(null, { files });
  };
}

export async function home(
  t: TestContext,
  handlers: Partial<FibersServer> = {},
  credentials = ServerCredentials.createInsecure(),
): Promise<{ server: Server; target: string; client: Client; files: Files }> {
  const server = new Server();
  const files = new Files();
  const implementation: FibersServer = {
    clone: (_call, done) => done(null, CloneResponse.fromPartial({
      fiberId: "g/1/1",
      endpoint: "unix:///tmp/f.sock",
      fence: { grantUid: "g", epoch: 1n, seq: 1n },
    })),
    park: (_call, done) => done(null, {}),
    release: (_call, done) => done(null, {}),
    watch: (call) => call.end(),
    upload: files.upload,
    download: files.download,
    listFiles: files.listFiles,
    ...handlers,
  };
  server.addService(FibersService, implementation);
  t.after(() => server.forceShutdown());
  const port = await new Promise<number>((resolve, reject) => {
    server.bindAsync("127.0.0.1:0", credentials, (error, bound) => error ? reject(error) : resolve(bound));
  });
  const target = `127.0.0.1:${port}`;
  const client = Client.dial(target);
  t.after(() => client.close());
  return { server, target, client, files };
}

export async function identity(name: string, server: boolean, handoff = false) {
  const algorithm = handoff ? { name: "Ed25519" } : { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
  const keys = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);
  if (!("privateKey" in keys)) throw new Error("Expected an asymmetric key pair");
  const certificate = await X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: `CN=${name}`,
    notBefore: handoff ? new Date(0) : new Date(Date.now() - 60_000),
    notAfter: handoff ? new Date("9999-12-31T23:59:59Z") : new Date(Date.now() + 86_400_000),
    signingAlgorithm: algorithm,
    keys,
    extensions: [
      ...(handoff ? [] : [new BasicConstraintsExtension(false, undefined, true)]),
      new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
      new ExtendedKeyUsageExtension([server ? ExtendedKeyUsage.serverAuth : ExtendedKeyUsage.clientAuth]),
      new SubjectAlternativeNameExtension(handoff
        ? [{ type: "dns", value: "*.fiberd" }]
        : [{ type: "dns", value: name }, { type: "ip", value: "127.0.0.1" }]),
    ],
  });
  const cert = Buffer.from(certificate.toString("pem"));
  const key = Buffer.from(PemConverter.encode(await crypto.subtle.exportKey("pkcs8", keys.privateKey), "PRIVATE KEY"));
  const parsed = new X509Certificate(cert);
  const pin = keyPin(parsed.raw);
  return { cert, key, der: parsed.raw, pin };
}
