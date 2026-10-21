import "reflect-metadata";
import {
  Metadata,
  Server,
  ServerCredentials,
  status,
  type ServiceError,
} from "@grpc/grpc-js";
import { X509Certificate } from "node:crypto";
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
  Miss,
  type FibersServer,
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

export async function home(
  t: TestContext,
  handlers: Partial<FibersServer> = {},
  credentials = ServerCredentials.createInsecure(),
): Promise<{ server: Server; target: string; client: Client }> {
  const server = new Server();
  const implementation: FibersServer = {
    clone: (_call, done) => done(null, CloneResponse.fromPartial({
      fiberId: "g/1/1",
      endpoint: "unix:///tmp/f.sock",
      fence: { grantUid: "g", epoch: 1n, seq: 1n },
    })),
    park: (_call, done) => done(null, {}),
    release: (_call, done) => done(null, {}),
    watch: (call) => call.end(),
    // The client has no file calls yet, so the test home serves none.
    upload: (_call, done) => done({ code: status.UNIMPLEMENTED, details: "not served" }),
    download: (call) => call.emit("error", { code: status.UNIMPLEMENTED, details: "not served" }),
    listFiles: (_call, done) => done({ code: status.UNIMPLEMENTED, details: "not served" }),
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
  return { server, target, client };
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
