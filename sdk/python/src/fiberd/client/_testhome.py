"""A home in this process for the client's unit tests, with the certificates and fibers they need. Not shipped (see setup.py).

Home serves the four methods over grpc.server with a ledger of a few
lines, answers the two misses and the tier gap the way pkg/rpc does, and
keeps the last CloneRequest so a test can see what went on the wire. No
process starts. The certificates come from cryptography, the fibers are
threads with a socket each.
"""

from __future__ import annotations

import collections
import datetime
import ipaddress
import os
import socket
import ssl
import tempfile
import threading
import time
from concurrent import futures
from dataclasses import dataclass, field
from pathlib import Path

import grpc
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from google.protobuf import empty_pb2

from fiberd.client import _der
from fiberd.client._api import grant_pb2
from fiberd.client._errors import DETAILS_KEY
from fiberd.client._stubs import SERVICE

ISSUER = "https://issuer.test"


def vi(number: int, value: int) -> bytes:
    """A varint field on the wire."""
    out = bytearray([number << 3])
    while value > 0x7F:
        out.append(value & 0x7F | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def ld(number: int, value: bytes) -> bytes:
    """A length-delimited field on the wire."""
    return bytes([number << 3 | 2]) + vi(0, len(value))[1:] + value


def rich_status(code: int, message: str, miss: grant_pb2.Miss) -> bytes:
    """A serialized google.rpc.Status carrying the Miss as its one Any detail, as pkg/rpc sends it."""
    detail = ld(1, b"type.googleapis.com/fiberd.grant.v1.Miss") + ld(2, miss.SerializeToString())
    return vi(1, code) + ld(2, message.encode()) + ld(3, detail)


class _RichStatus(collections.namedtuple("_RichStatus", ("code", "details", "trailing_metadata")), grpc.Status):
    """What abort_with_status takes, as grpcio-status would build it."""


@dataclass
class _Line:
    fiber_id: str
    session: str
    seq: int
    endpoint: str
    parked: bool = False


@dataclass
class Home:
    """A fake fiberd. The knobs stand in for what a real home's state would decide."""

    grant_uid: str = "g1"
    fiber_max: int = 2
    issuer_reachable: bool = True
    retry_after: int = 2
    preferred_home: str = ""
    tier_gap: str = ""
    # bound_to is the PEM certificate the grant is bound to. Another caller is Unauthenticated.
    bound_to: bytes = b""
    # routing_key and server_key_sha256 make every clone a handoff fiber.
    routing_key: str = ""
    server_key_sha256: str = ""
    endpoint: str = "unix:///run/fiberd/g1.sock"
    status_interval: float = 0.02
    last_clone: grant_pb2.CloneRequest | None = None
    seq: int = 0
    lines: dict[str, _Line] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def _miss(self, context: grpc.ServicerContext, message: str) -> None:
        if self.issuer_reachable:
            miss = grant_pb2.Miss(code=grant_pb2.DEFERRED_FALLBACK, issuer=ISSUER, preferred_home=self.preferred_home)
            code = grpc.StatusCode.UNAVAILABLE
        else:
            miss = grant_pb2.Miss(code=grant_pb2.SHED, issuer=ISSUER, retry_after_s=self.retry_after)
            code = grpc.StatusCode.RESOURCE_EXHAUSTED
        trailer = rich_status(code.value[0], message, miss)
        context.abort_with_status(_RichStatus(code, message, ((DETAILS_KEY, trailer),)))

    def _caller_ok(self, context: grpc.ServicerContext) -> bool:
        if not self.bound_to:
            return True
        peer = context.auth_context().get("x509_pem_cert")
        return bool(peer) and peer[0] == self.bound_to

    def clone(self, req: grant_pb2.CloneRequest, context: grpc.ServicerContext) -> grant_pb2.CloneResponse:
        self.last_clone = req
        if not req.grant_jwt or not self._caller_ok(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "grant: not the caller the grant is bound to")
        if self.tier_gap:
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, self.tier_gap)
        with self.lock:
            kind = grant_pb2.CREATE
            line = next((ln for ln in self.lines.values() if req.session and ln.session == req.session), None)
            if line is not None and not line.parked:
                kind = grant_pb2.ATTACH
            else:
                if sum(not ln.parked for ln in self.lines.values()) >= self.fiber_max:
                    self._miss(context, f"grant {self.grant_uid} is at fibers.max")
                if line is not None:
                    kind = grant_pb2.RESUME
                    del self.lines[line.fiber_id]
                self.seq += 1
                fid = f"{self.grant_uid}/1/{self.seq}"
                line = self.lines[fid] = _Line(fid, req.session, self.seq, self.endpoint)
            return grant_pb2.CloneResponse(
                fiber_id=line.fiber_id,
                endpoint=line.endpoint,
                fence=grant_pb2.Fence(grant_uid=self.grant_uid, epoch=1, seq=line.seq),
                kind=kind,
                routing_key=self.routing_key,
                server_key_sha256=self.server_key_sha256,
            )

    def _running(self, fiber_id: str, context: grpc.ServicerContext) -> _Line:
        line = self.lines.get(fiber_id)
        if line is None or line.parked:
            context.abort(grpc.StatusCode.NOT_FOUND, f"fiber {fiber_id} unknown")
        return line

    def park(self, req: grant_pb2.ParkRequest, context: grpc.ServicerContext) -> empty_pb2.Empty:
        with self.lock:
            line = self._running(req.fiber_id, context)
            if line.session:
                line.parked = True
            else:
                del self.lines[req.fiber_id]
        return empty_pb2.Empty()

    def release(self, req: grant_pb2.ReleaseRequest, context: grpc.ServicerContext) -> empty_pb2.Empty:
        with self.lock:
            self._running(req.fiber_id, context)
            del self.lines[req.fiber_id]
        return empty_pb2.Empty()

    def watch(self, _req: empty_pb2.Empty, context: grpc.ServicerContext):
        while context.is_active():
            with self.lock:
                st = grant_pb2.Status(
                    grant_uid=self.grant_uid,
                    running=sum(not ln.parked for ln in self.lines.values()),
                    parked=sum(ln.parked for ln in self.lines.values()),
                    latest=grant_pb2.Fence(grant_uid=self.grant_uid, epoch=1, seq=self.seq),
                )
            yield st
            time.sleep(self.status_interval)

    def handler(self) -> grpc.GenericRpcHandler:
        unary, stream = grpc.unary_unary_rpc_method_handler, grpc.unary_stream_rpc_method_handler
        empty = empty_pb2.Empty.SerializeToString
        return grpc.method_handlers_generic_handler(SERVICE, {
            "Clone": unary(self.clone, request_deserializer=grant_pb2.CloneRequest.FromString, response_serializer=grant_pb2.CloneResponse.SerializeToString),
            "Park": unary(self.park, request_deserializer=grant_pb2.ParkRequest.FromString, response_serializer=empty),
            "Release": unary(self.release, request_deserializer=grant_pb2.ReleaseRequest.FromString, response_serializer=empty),
            "Watch": stream(self.watch, request_deserializer=empty_pb2.Empty.FromString, response_serializer=grant_pb2.Status.SerializeToString),
        })

    def serve(self, target: str = "127.0.0.1:0", creds: grpc.ServerCredentials | None = None) -> tuple[grpc.Server, str]:
        """Starts the home on target, "unix:/path" or host:0, and returns the server and the address to dial."""
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
        server.add_generic_rpc_handlers((self.handler(),))
        port = server.add_secure_port(target, creds) if creds else server.add_insecure_port(target)
        server.start()
        host = target.rsplit(":", 1)[0]
        return server, target if target.startswith("unix:") else f"{host}:{port}"


@dataclass(frozen=True)
class Pair:
    """A certificate and its key, in memory and as PEM files."""

    cert: x509.Certificate
    key: ec.EllipticCurvePrivateKey

    @property
    def cert_pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    @property
    def key_pem(self) -> bytes:
        return self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    @property
    def der(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.DER)

    @property
    def spki(self) -> bytes:
        return self.cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    @property
    def pin(self) -> str:
        return _der.pin(self.spki)

    def write(self, dir: str | os.PathLike[str], name: str) -> tuple[str, str]:
        """The PEM files name.crt and name.key in dir, and their paths."""
        cert, key = Path(dir) / f"{name}.crt", Path(dir) / f"{name}.key"
        cert.write_bytes(self.cert_pem)
        key.write_bytes(self.key_pem)
        return str(cert), str(key)


def issue(name: str, parent: Pair | None = None, *, ca: bool = False, server: bool = False) -> Pair:
    """A P-256 certificate named name, self-signed or issued by parent, valid for an hour around now."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(parent.cert.subject if parent else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if server:
        names = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
        b = b.add_extension(x509.SubjectAlternativeName(names), critical=False)
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    elif not ca:
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    return Pair(b.sign(parent.key if parent else key, hashes.SHA256()), key)


def server_credentials(ca: Pair, server: Pair) -> grpc.ServerCredentials:
    """Mutual TLS for a home, every caller under ca."""
    return grpc.ssl_server_credentials([(server.key_pem, server.cert_pem)], root_certificates=ca.cert_pem, require_client_auth=True)


class DirectFiber:
    """A fiber on a unix or tcp endpoint that answers "ping" with "pong" and anything else with itself."""

    def __init__(self, endpoint: str) -> None:
        self.endpoint = endpoint
        if endpoint.startswith("unix://"):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.bind(endpoint[len("unix://"):])
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind(("127.0.0.1", 0))
            self.endpoint = "tcp://127.0.0.1:%d" % self.sock.getsockname()[1]
        self.sock.listen()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            with c:
                line = c.recv(4096)
                c.sendall(b"pong\n" if line.strip() == b"ping" else line)

    def close(self) -> None:
        self.sock.close()


class HandoffFiber:
    """A fiber behind a TLS listener, as the home's router presents it.

    It holds identity's key, accepts only caller's certificate and answers
    a line with the server name it was dialed by and the line.
    """

    def __init__(self, identity: Pair, caller: Pair) -> None:
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        cert, key = identity.write(_tmpdir(), "fiber")
        self.ctx.load_cert_chain(cert, key)
        self.ctx.verify_mode = ssl.CERT_REQUIRED
        self.ctx.load_verify_locations(cadata=caller.cert_pem.decode())
        self.names: dict[int, str] = {}
        self.ctx.sni_callback = lambda sock, name, _ctx: self.names.__setitem__(id(sock), name or "")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.endpoint = "tcp://127.0.0.1:%d" % self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                raw, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._answer, args=(raw,), daemon=True).start()

    def _answer(self, raw: socket.socket) -> None:
        try:
            with self.ctx.wrap_socket(raw, server_side=True) as tls:
                line = tls.recv(4096)
                tls.sendall(f"{self.names.pop(id(tls), '')} ".encode() + line)
        except (ssl.SSLError, OSError):
            raw.close()

    def close(self) -> None:
        self.sock.close()


def _tmpdir() -> str:
    return tempfile.mkdtemp(prefix="fiberd-client-")
