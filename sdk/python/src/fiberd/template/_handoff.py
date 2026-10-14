"""A handoff fiber's TLS, over the identity fiberd sent down its channel.

ssl.SSLContext.load_cert_chain takes paths, so the key and certificate are
written to a sealed memfd and loaded through /proc/self/fd. The key is
never a file on disk. The caller's certificate, the one the clone arrived
under, is the context's only trust anchor, with VERIFY_X509_PARTIAL_CHAIN
so OpenSSL takes a leaf as one. Any other certificate fails the
handshake, with or without the home's CA behind it. The thumbprint of the
peer (RFC 8705 x5t#S256) is checked again after the handshake, against
the caller the grant is bound to.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import os
import socket
import ssl
from typing import Optional

from fiberd.template._errors import TemplateError

# The seals a sealed identity carries, the four every Linux since 3.17
# has. Looked up by name so the module imports off Linux, where the
# client half of the package is used and nothing is sealed.
SEALS = sum(getattr(fcntl, name, 0) for name in ("F_SEAL_SEAL", "F_SEAL_SHRINK", "F_SEAL_GROW", "F_SEAL_WRITE"))

# How long a caller may take over its handshake before it is dropped, as refzygote allows.
HANDSHAKE_TIMEOUT = 5.0


def thumbprint(der: bytes) -> str:
    """x5t#S256 of a certificate, the base64url SHA-256 of its DER without padding."""
    return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode("ascii")


def pinned(peer_der: bytes | None, caller: str) -> bool:
    """Whether the peer presented the one certificate the grant is bound to."""
    if not peer_der or not caller:
        return False
    return thumbprint(peer_der) == caller


def seal_identity(key_pem: str, cert_pem: str, name: str = "fiberd-identity") -> int:
    """A sealed memfd holding the key and the certificate, as one PEM file ssl can load. Its descriptor is returned."""
    if not hasattr(os, "memfd_create"):
        raise TemplateError("a handoff fiber seals its identity in a memfd, which needs Linux")
    fd = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        data = (key_pem + ("" if key_pem.endswith("\n") else "\n") + cert_pem).encode("ascii")
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, SEALS)
    except BaseException:
        os.close(fd)
        raise
    return fd


def identity_path(fd: int) -> str:
    """Where ssl reads the sealed identity from. A path into the process's own descriptors, not the file system."""
    return f"/proc/self/fd/{fd}"


class HandshakeObject(ssl.SSLObject):
    """The SSL object of an asyncio handshake over a handoff connection.

    When the handshake fails, OpenSSL queues its alert in the outgoing
    BIO, and asyncio discards that with the connection, so the caller
    would see a bare close. The alert is taken here, as it is raised,
    for the fiber to send itself (see send_alert).
    """

    outgoing: Optional[ssl.MemoryBIO] = None

    def do_handshake(self) -> None:
        try:
            super().do_handshake()
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            raise
        except ssl.SSLError:
            ctx = self.context
            if isinstance(ctx, ServerContext) and self.outgoing is not None:
                ctx.alert = self.outgoing.read()
            raise


class ServerContext(ssl.SSLContext):
    """The context of a handoff fiber. Its asyncio handshakes keep their alert (HandshakeObject), one at a time per fiber."""

    sslobject_class = HandshakeObject
    alert: bytes = b""

    def wrap_bio(self, incoming: ssl.MemoryBIO, outgoing: ssl.MemoryBIO, server_side: bool = False,
                 server_hostname: Optional[str] = None, session: Optional[ssl.SSLSession] = None) -> ssl.SSLObject:
        obj = super().wrap_bio(incoming, outgoing, server_side, server_hostname, session)
        if isinstance(obj, HandshakeObject):
            obj.outgoing = outgoing
        return obj


def send_alert(ctx: ServerContext, sock: socket.socket) -> None:
    """Sends the alert the last asyncio handshake kept on sock, a duplicate of the connection asyncio closed, and closes it.

    A caller that stalled the handshake left none, and nothing is sent.
    """
    alert, ctx.alert = ctx.alert, b""
    try:
        if alert:
            sock.send(alert)
    except OSError:
        pass
    finally:
        sock.close()


def server_context(identity_fd: int, caller: str, caller_pem: str) -> ServerContext:
    """The TLS 1.3 server context of a handoff fiber.

    caller_pem, the certificate of the caller the grant is bound to, is
    the one trust anchor, so only that certificate completes a handshake.
    It must be the certificate caller is the thumbprint of. Resumption is
    off, so every connection presents it.
    """
    if not caller_pem:
        raise TemplateError("the home sent no caller certificate with the handoff identity, so this fiber cannot pin its caller")
    try:
        caller_der = ssl.PEM_cert_to_DER_cert(caller_pem)
    except ValueError as e:
        raise TemplateError(f"the caller certificate the home sent with the handoff identity does not parse ({e})") from e
    if thumbprint(caller_der) != caller:
        raise TemplateError("the caller certificate the home sent with the handoff identity is not the caller the grant is bound to")
    ctx = ServerContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    ctx.options |= ssl.OP_NO_TICKET
    ctx.num_tickets = 0
    try:
        ctx.load_verify_locations(cadata=caller_pem)
    except (ssl.SSLError, ValueError) as e:
        raise TemplateError(f"the caller certificate the home sent with the handoff identity does not load ({e})") from e
    try:
        ctx.load_cert_chain(identity_path(identity_fd))
    except (ssl.SSLError, OSError) as e:
        raise TemplateError(f"the grant's handoff key and certificate do not load ({e})") from e
    return ctx
