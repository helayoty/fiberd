"""What a Clone returns, and how a caller reaches it."""

from __future__ import annotations

import enum
import os
import socket
import ssl
from dataclasses import dataclass
from typing import Literal, Union
from urllib.parse import urlsplit

from fiberd.client import _der
from fiberd.client._errors import KeyMismatch, NotHandoff

# The TLS server name a handoff fiber is routed by is its routing key under this suffix.
HANDOFF_SUFFIX = ".fiberd"


class Kind(enum.IntEnum):
    """How a Clone was served."""

    CREATE = 0
    ATTACH = 1
    RESUME = 2


@dataclass(frozen=True)
class Fence:
    """One run of a fiber, grant/epoch/seq."""

    grant_uid: str
    epoch: int
    seq: int

    def __str__(self) -> str:
        return f"{self.grant_uid}/{self.epoch}/{self.seq}"


def parse_endpoint(endpoint: str) -> Union[tuple[Literal["unix"], str], tuple[Literal["tcp"], tuple[str, int]]]:
    """("unix", path) or ("tcp", (host, port)) for an endpoint as fiberd spells it. The address's type tells the two apart."""
    u = urlsplit(endpoint)
    if u.scheme == "unix" and u.path:
        return "unix", u.path
    if u.scheme == "tcp" and u.hostname and u.port is not None:
        return "tcp", (u.hostname, u.port)
    raise ValueError(f"endpoint {endpoint!r} is not unix:///path or tcp://host:port")


@dataclass(frozen=True)
class Fiber:
    """A fiber a Clone handed back. id is its fence as a string, which Park and Release take."""

    id: str
    endpoint: str
    fence: Fence
    kind: Kind
    # session is the name the caller asked for, empty for an anonymous fiber.
    session: str
    # home is the target it was cloned from, where its Park and Release go.
    home: str
    # routing_key, server_key_sha256 and server_cert are set only under a HANDOFF grant. Reach such a fiber with dial_handoff.
    # server_cert is the fiber's certificate as DER, and server_key_sha256 the pin of its key.
    routing_key: str = ""
    server_key_sha256: str = ""
    server_cert: bytes = b""

    @property
    def handoff(self) -> bool:
        return bool(self.routing_key)

    def dial(self, *, timeout: float | None = None) -> socket.socket:
        """A connected stream socket to a direct fiber's unix or tcp endpoint."""
        if self.handoff:
            raise ValueError(f"fiber {self.id} is reached through dial_handoff, not dial")
        _, addr = parse_endpoint(self.endpoint)
        if isinstance(addr, str):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                s.settimeout(timeout)
                s.connect(addr)
            except BaseException:
                s.close()
                raise
            return s
        return socket.create_connection(addr, timeout=timeout)

    def dial_handoff(self, cert: str | os.PathLike[str], key: str | os.PathLike[str], *, timeout: float | None = None) -> ssl.SSLSocket:
        """A TLS connection to a handoff fiber through its home's router.

        cert and key are the PEM files of the certificate the grant is
        bound to, the same one used on the control API, and the fiber
        refuses any other. The fiber must present server_cert, the one
        trust anchor of the handshake, which fails on any other
        (ssl.SSLCertVerificationError). Its key must then hash to
        server_key_sha256 (KeyMismatch otherwise), checked before a byte
        is sent.
        """
        if not self.handoff:
            raise NotHandoff(f"fiber {self.id} was not cloned under a HANDOFF grant, dial its endpoint")
        if not self.server_cert:
            raise ValueError(f"fiber {self.id} carries no certificate to pin, which a HANDOFF clone returns as server_cert")
        _, addr = parse_endpoint(self.endpoint)
        if isinstance(addr, str):
            raise NotHandoff(f"endpoint {self.endpoint!r} is not tcp://")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        # The fiber's certificate is the one anchor, so the handshake admits
        # it alone. Its name (*.fiberd) is a route, not an identity, and
        # OpenSSL would not match a one-label wildcard anyway.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
        ctx.load_verify_locations(cadata=self.server_cert)
        ctx.load_cert_chain(os.fspath(cert), os.fspath(key))
        raw = socket.create_connection(addr, timeout=timeout)
        try:
            tls = ctx.wrap_socket(raw, server_hostname=self.routing_key + HANDOFF_SUFFIX)
        except BaseException:
            raw.close()
            raise
        try:
            peer = tls.getpeercert(binary_form=True)
            if not peer:
                raise KeyMismatch(f"fiber {self.id} presented no certificate")
            try:
                got = _der.pin(_der.spki(peer))
            except _der.DERError as e:
                raise KeyMismatch(f"fiber {self.id} presented a certificate that does not parse: {e}") from e
            if got != self.server_key_sha256:
                raise KeyMismatch(f"fiber {self.id} holds another key than its pin")
        except BaseException:
            tls.close()
            raise
        return tls
