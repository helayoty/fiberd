"""A handoff fiber's TLS, over the identity fiberd sent down its channel.

ssl.SSLContext.load_cert_chain takes paths, so the key and certificate are
written to a sealed memfd and loaded through /proc/self/fd. The key is
never a file on disk. The caller is pinned after the handshake by the
thumbprint of its certificate (RFC 8705 x5t#S256), which the chain check
against the home's CA bundle comes before, since the stdlib cannot accept
an arbitrary chain the way refzygote does.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import os
import ssl

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
    return bool(peer_der) and bool(caller) and thumbprint(peer_der) == caller


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


def server_context(identity_fd: int, ca_pem: str) -> ssl.SSLContext:
    """The TLS 1.3 server context of a handoff fiber. The caller must chain to ca_pem, and resumption is off, so every connection presents it."""
    if not ca_pem:
        raise TemplateError(
            "the home sent no CA bundle with the handoff identity, so this fiber cannot verify its caller. "
            "A handoff fiber checks the caller's certificate against the home's -client-ca, which a home started "
            "with -insecure-plaintext does not have"
        )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.options |= ssl.OP_NO_TICKET
    ctx.num_tickets = 0
    try:
        ctx.load_verify_locations(cadata=ca_pem)
    except (ssl.SSLError, ValueError) as e:
        raise TemplateError(f"the CA bundle the home sent with the handoff identity does not parse ({e})") from e
    try:
        ctx.load_cert_chain(identity_path(identity_fd))
    except (ssl.SSLError, OSError) as e:
        raise TemplateError(f"the grant's handoff key and certificate do not load ({e})") from e
    return ctx
