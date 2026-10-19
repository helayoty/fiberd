"""A handoff fiber's TLS: the sealed identity, the caller pinned in the handshake, accept(), serve() and the async twins, with no process started.

The certificates come from cryptography, as the client's tests do, so
the module is skipped where it is missing. The TLS clients run in
threads over socket pairs, which is what fiberd's channel delivers.
"""

from __future__ import annotations

import asyncio
import datetime
import errno
import fcntl
import os
import signal
import socket
import ssl
import threading
import time

import pytest

import fiberd.template as ft
from fiberd._testtable import table
from fiberd.template import _handoff

x509 = pytest.importorskip("cryptography.x509")
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

linux_only = pytest.mark.skipif(not hasattr(os, "memfd_create"), reason="a sealed memfd needs Linux")


# ---- certificates --------------------------------------------------------


class Pair:
    """A certificate and its key, as PEM strings and as the DER the thumbprint is of."""

    def __init__(self, cert, key):
        self.cert, self.key = cert, key

    @property
    def cert_pem(self) -> str:
        return self.cert.public_bytes(serialization.Encoding.PEM).decode()

    @property
    def key_pem(self) -> str:
        return self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()

    @property
    def thumbprint(self) -> str:
        return _handoff.thumbprint(self.cert.public_bytes(serialization.Encoding.DER))

    def write(self, dir, name):
        cert, key = dir / f"{name}.crt", dir / f"{name}.key"
        cert.write_text(self.cert_pem)
        key.write_text(self.key_pem)
        return str(cert), str(key)


def issue(name, parent=None, *, ca=False):
    """A P-256 certificate, self-signed or issued by parent, valid for an hour around now."""
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
    if not ca:
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    return Pair(b.sign(parent.key if parent else key, hashes.SHA256()), key)


def grant_identity():
    """The grant's identity as pkg/handoff derives it, an Ed25519 self-signed certificate for *.fiberd."""
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fiberd handoff")])
    b = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(9999, 12, 31, 23, 59, 59, tzinfo=datetime.timezone.utc))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("*.fiberd")]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    )
    return Pair(b.sign(key, None), key)


class World:
    """A home's CA, the grant's bound caller, another caller under the CA, a stranger outside it and the grant's identity."""

    def __init__(self):
        self.ca = issue("ca", ca=True)
        self.caller = issue("caller", self.ca)
        self.other = issue("other", self.ca)
        self.stranger = issue("stranger", issue("stranger ca", ca=True))
        self.server = grant_identity()

    def identity(self, caller_pem=None) -> ft.Identity:
        """The identity fiberd sends, bound to the caller, with its certificate unless caller_pem replaces it."""
        return ft.Identity(self.server.key_pem, self.server.cert_pem, self.caller.thumbprint, self.caller.cert_pem if caller_pem is None else caller_pem)


@pytest.fixture(scope="module")
def world():
    return World()


# ---- the pure parts ------------------------------------------------------


THUMBPRINTS = [
    # the DER, its x5t#S256
    ("empty", b"", "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"),
    ("abc", b"abc", "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"),
]


@table(THUMBPRINTS)
def test_thumbprint_is_base64url_sha256_without_padding(name, f0, f1):
    assert _handoff.thumbprint(f0) == f1
    assert "=" not in f1 and "+" not in f1 and "/" not in f1


PINS = [
    # the peer's DER, the caller pinned, the verdict
    ("the bound caller", b"abc", "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0", True),
    ("another certificate", b"abd", "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0", False),
    ("no certificate", None, "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0", False),
    ("an empty pin accepts nobody", b"", "", False),
]


@table(PINS)
def test_pinned(name, f0, f1, f2):
    assert _handoff.pinned(f0, f1) is f2


def test_identity_repr_hides_the_key(world):
    ident = world.identity()
    assert repr(ident) == f"Identity(caller={world.caller.thumbprint!r})"
    assert "PRIVATE" not in repr(ident)


@linux_only
def test_seal_identity_is_sealed_and_not_a_file_on_disk(world):
    fd = _handoff.seal_identity(world.server.key_pem, world.server.cert_pem)
    try:
        with open(_handoff.identity_path(fd), encoding="ascii") as fh:
            assert fh.read() == world.server.key_pem + world.server.cert_pem
        assert fcntl.fcntl(fd, fcntl.F_GET_SEALS) & _handoff.SEALS == _handoff.SEALS
        with pytest.raises(OSError):
            os.write(fd, b"x")
        assert os.readlink(f"/proc/self/fd/{fd}").startswith("/memfd:"), "the key lives in memory, not in the file system"
        assert fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
    finally:
        os.close(fd)


CONTEXT_REFUSALS = [
    # the caller certificate, the identity PEM, the message wanted
    ("no caller certificate", "", "good", "no caller certificate"),
    ("a caller certificate that is not PEM", "not pem", "good", "does not parse"),
    ("a caller certificate that is not the bound caller's", "other", "good", "not the caller the grant is bound to"),
    ("an identity that does not load", "good", "garbage", "do not load"),
]


@linux_only
@table(CONTEXT_REFUSALS)
def test_server_context_refusals(world, name, f0, f1, f2):
    caller_pem = {"good": world.caller.cert_pem, "other": world.other.cert_pem}.get(f0, f0)
    fd = _handoff.seal_identity(world.server.key_pem, world.server.cert_pem) if f1 == "good" else _handoff.seal_identity("garbage", "garbage")
    try:
        with pytest.raises(ft.TemplateError, match=f2) as e:
            _handoff.server_context(fd, world.caller.thumbprint, caller_pem)
        assert "PRIVATE KEY" not in str(e.value) and world.server.key_pem.splitlines()[1] not in str(e.value)
    finally:
        os.close(fd)


@linux_only
def test_server_context_trusts_the_caller_certificate_alone(world):
    fd = _handoff.seal_identity(world.server.key_pem, world.server.cert_pem)
    try:
        ctx = _handoff.server_context(fd, world.caller.thumbprint, world.caller.cert_pem)
    finally:
        os.close(fd)
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.minimum_version == ssl.TLSVersion.TLSv1_3
    assert ctx.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN, "a leaf is the trust anchor only with partial chains allowed"
    stats = ctx.cert_store_stats()
    assert (stats["x509"], stats["x509_ca"]) == (1, 0), "the bound caller's leaf is the one certificate in the store, no CA"


# ---- accept() and serve() over socket pairs ------------------------------


class HandoffExt:
    """The C binding of a handoff fiber: accept() hands out the server ends queued, then the channel's close. waits is what each incarnation_wait answers."""

    ABI_VERSION = 10

    def __init__(self, waits=()):
        self.calls = []
        self.queue = []
        self.waits = list(waits)

    def quiesce(self):
        self.calls.append(("quiesce",))

    def incarnation_wait(self):
        self.calls.append(("wait",))
        return self.waits.pop(0)

    def fiber_ready(self):
        self.calls.append(("ready",))

    def accept(self):
        if not self.queue:
            raise ConnectionResetError(104, "fiberd closed the channel")
        return self.queue.pop(0)


def client(pair, tmp_path, fd, line=b"ping\n", served=True):
    """A TLS client over fd presenting pair (or nothing), which sends line and reads the reply. What happened, as a tuple.

    In TLS 1.3 the client's handshake ends with its Finished, before the
    fiber has looked at the certificate, so a caller that expects to be
    refused reads first. The fiber's verdict is then an alert from its
    failed handshake, or a bare close after one that succeeded.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if pair is not None:
        ctx.load_cert_chain(*pair.write(tmp_path, f"c{fd}"))
    raw = socket.socket(fileno=fd)
    raw.settimeout(5)
    try:
        tls = ctx.wrap_socket(raw, server_hostname="routing.fiberd")
    except (OSError, ValueError) as e:
        raw.close()
        return ("handshake refused", type(e).__name__)
    try:
        if served:
            tls.sendall(line)
        reply = tls.recv(64)
    except ssl.SSLError as e:
        return ("alert", e.reason)
    except OSError as e:
        return ("closed", type(e).__name__)
    finally:
        tls.close()
    return ("reply", reply) if reply else ("closed", "EOF")


def handoff_fiber(world, ext, monkeypatch, channel, identity=None):
    monkeypatch.setattr(ft, "_ext", lambda: ext)
    f = ft.Fiber("g/1/1", "handoff", b"", "", {"FIBERD_CHANNEL_FD": str(channel.fileno())}, identity=world.identity() if identity is None else identity)
    assert f.kind == "handoff"
    return f


def start_clients(world, tmp_path, ext, which, served=None):
    """One socket pair per caller in which, the server ends queued for accept() and the clients started. The threads and their results.

    served says per caller whether it expects a reply. The others read
    first, for the fiber's verdict.
    """
    results = [None] * len(which)
    threads = []
    for i, pair in enumerate(which):
        a, b = socket.socketpair()
        ext.queue.append(a.detach())
        fd = b.detach()
        ok = served[i] if served is not None else True
        th = threading.Thread(target=lambda i=i, pair=pair, fd=fd, ok=ok: results.__setitem__(i, client(pair, tmp_path, fd, served=ok)), daemon=True)
        th.start()
        threads.append(th)
    return threads, results


def join(threads):
    for th in threads:
        th.join(10)
        assert not th.is_alive(), "a client never finished"


CALLERS = [
    # the callers in order, and which of them are served. Every refusal
    # is the fiber's handshake failing, which the caller sees as an alert
    # and never as a close after a handshake that succeeded, so only the
    # served callers reach the thumbprint check.
    ("the bound caller", ["caller"], [True]),
    ("another certificate under the CA fails the handshake", ["other", "caller"], [False, True]),
    ("a certificate outside the CA fails the handshake", ["stranger", "caller"], [False, True]),
    ("no certificate fails the handshake", [None, "caller"], [False, True]),
]


def refused(result):
    """Whether the result is the fiber's handshake alert, not a reply and not a bare close after a handshake."""
    return result[0] in ("handshake refused", "alert")


def spy_pinned(monkeypatch):
    """The peers the post-handshake thumbprint check sees, which a caller refused in the handshake never reaches."""
    seen = []
    real = _handoff.pinned

    def pinned(peer_der, caller):
        seen.append(peer_der)
        return real(peer_der, caller)

    monkeypatch.setattr(_handoff, "pinned", pinned)
    return seen


@linux_only
@table(CALLERS)
def test_accept_serves_the_bound_caller_only(world, tmp_path, monkeypatch, name, f0, f1):
    ext = HandoffExt()
    ch, host_end = socket.socketpair()
    f = handoff_fiber(world, ext, monkeypatch, ch)
    checked = spy_pinned(monkeypatch)
    threads, results = start_clients(world, tmp_path, ext, [getattr(world, w) if w else None for w in f0], served=f1)
    # fiberd's end: one message per connection, then the close at release.
    host_end.sendall(b"\0" * len(f0))
    host_end.close()
    served = []
    for _ in range(sum(f1)):
        conn = f.accept()
        assert isinstance(conn, ssl.SSLSocket)
        assert _handoff.thumbprint(conn.getpeercert(binary_form=True)) == world.caller.thumbprint
        served.append(conn.recv(64))
        conn.sendall(b"pong\n")
        conn.close()
    with pytest.raises(ConnectionResetError):
        f.accept()
    join(threads)
    assert served == [b"ping\n"] * sum(f1)
    assert [r == ("reply", b"pong\n") for r in results] == f1
    assert all(refused(r) for r, ok in zip(results, f1, strict=True) if not ok), f"a refused caller sees the fiber's alert, not {results}"
    assert len(checked) == sum(f1), "a refused caller failed the handshake itself and never reached the thumbprint check"
    assert ext.calls == [], "accept() does not report ready, the author does"


class BlockingExt(HandoffExt):
    """The binding as fz_accept behaves: it blocks on the channel until a message or its close, through any interruption."""

    def __init__(self, channel):
        super().__init__()
        self.channel = channel

    def accept(self):
        self.calls.append(("accept",))
        if not self.channel.recv(1):
            raise ConnectionResetError(104, "fiberd closed the channel")
        return self.queue.pop(0)


# The time accept() has to notice the stop, and when the channel closes
# behind it, so code that notices nothing fails the bound instead of
# hanging the suite.
STOP_BOUND = 1.5
STOP_RELEASE = 3.0

STOPS = [
    # how the fiber is asked to stop, 0.1s into accept()
    ("stopping set", lambda f: f.stopping.set()),
    ("SIGTERM under the handler serve() installs", lambda f: signal.pthread_kill(threading.main_thread().ident, signal.SIGTERM)),
]


@linux_only
@table(STOPS)
def test_accept_returns_when_the_fiber_is_asked_to_stop(world, monkeypatch, name, f0):
    """accept() with no connection in sight ends, as it does at release, once the fiber is asked to stop."""
    ch, host_end = socket.socketpair()
    ext = BlockingExt(ch)
    f = handoff_fiber(world, ext, monkeypatch, ch)
    previous = signal.signal(signal.SIGTERM, lambda *_: f.stopping.set())
    stop = threading.Timer(0.1, f0, [f])
    release = threading.Timer(STOP_RELEASE, host_end.close)
    try:
        stop.start()
        release.start()
        started = time.monotonic()
        with pytest.raises(ConnectionResetError):
            f.accept()
        took = time.monotonic() - started
    finally:
        signal.signal(signal.SIGTERM, previous)
        stop.cancel()
        release.cancel()
        stop.join()
        host_end.close()
    assert took < STOP_BOUND, f"accept() took {took:.2f}s to notice the stop"
    assert f.stopping.is_set()
    assert ext.calls == [], "fz_accept is called only once the channel is readable"


def target(fd):
    """What a descriptor points at, or "" for one gone again, such as the listing's own."""
    try:
        return os.readlink(f"/proc/self/fd/{fd}")
    except OSError:
        return ""


@linux_only
def test_tls_context_is_built_once_and_the_key_stays_in_a_memfd(world, monkeypatch):
    ext = HandoffExt()
    ch, _ = socket.socketpair()
    f = handoff_fiber(world, ext, monkeypatch, ch)
    def sealed():
        return [fd for fd in os.listdir("/proc/self/fd") if target(fd).startswith("/memfd:fiberd-identity")]

    before = len(sealed())
    ctx = f._tls_context()
    assert f._tls_context() is ctx
    assert len(sealed()) == before + 1, "the identity is one sealed memfd, kept for the fiber's lifetime"
    assert fcntl.fcntl(f._identity_fd, fcntl.F_GET_SEALS) & _handoff.SEALS == _handoff.SEALS
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.minimum_version == ssl.TLSVersion.TLSv1_3


CONTEXT_FIBERS = [
    # the fiber's endpoint, its identity, the refusal
    ("a unix fiber has nothing to accept", "/tmp/ep.sock", "ident", "only a handoff fiber"),
    ("a handoff fiber without an identity", "handoff", None, "holds no identity"),
    ("an identity without the caller's certificate", "handoff", "no caller cert", "no caller certificate"),
    ("an identity with another caller's certificate", "handoff", "other caller", "not the caller the grant is bound to"),
]


@table(CONTEXT_FIBERS)
def test_accept_refusals(world, monkeypatch, name, f0, f1, f2):
    monkeypatch.setattr(ft, "_ext", lambda: HandoffExt())
    identities = {
        "ident": world.identity(),
        None: None,
        "no caller cert": world.identity(caller_pem=""),
        "other caller": world.identity(caller_pem=world.other.cert_pem),
    }
    identity = identities[f1]
    f = ft.Fiber("g/1/1", f0, b"", "", {"FIBERD_CHANNEL_FD": "4"}, identity=identity)
    with pytest.raises(ft.TemplateError, match=f2):
        f.accept()
    assert f._identity_fd == -1, "a refused identity is never sealed, so no memfd is left open"


@linux_only
def test_serve_handoff_reports_ready_and_ends_with_the_channel(world, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ext = HandoffExt()
    ch, host_end = socket.socketpair()
    f = handoff_fiber(world, ext, monkeypatch, ch)
    f._incarnate("fork", 1, os.urandom(32))
    threads, results = start_clients(world, tmp_path, ext, [world.other, world.caller], served=[False, True])
    # fiberd's end: one message per connection, then the close at release.
    host_end.sendall(b"\0\0")
    host_end.close()
    served = []

    def handler(conn):
        served.append((conn.recv(64), f.fence, f.incarnation.kind))
        conn.sendall(b"pong\n")

    f.serve(handler, poll=0.05)
    join(threads)
    assert ext.calls == [("ready",)]
    assert served == [(b"ping\n", "g/1/1", "fork")], "only the bound caller reached the handler"
    assert refused(results[0]) and results[1] == ("reply", b"pong\n")


class RoundExt(HandoffExt):
    """The binding when a park's round arrives ahead of its signal: the first accept ends with EINTR, as fz_accept does then."""

    def __init__(self, waits=()):
        super().__init__(waits)
        self.rounds = 1

    def accept(self):
        if self.rounds:
            self.rounds -= 1
            self.calls.append(("round",))
            raise InterruptedError(errno.EINTR, "a park's round")
        return super().accept()


@linux_only
def test_serve_handoff_sees_a_park_round_ahead_of_its_signal(world, tmp_path, monkeypatch):
    """An accept that ends with EINTR is not the end of the loop. It looks at parking again, finds the park, and answers it."""
    monkeypatch.chdir(tmp_path)
    ext = RoundExt(waits=[("resume", "g/1/2", "handoff", b"", bytearray(32), "", 2)])
    ch, host_end = socket.socketpair()
    f = handoff_fiber(world, ext, monkeypatch, ch)
    f._incarnate("fork", 1, os.urandom(32))
    threads, results = start_clients(world, tmp_path, ext, [world.caller])
    # fiberd's end: the round, the resume's record after the park, the
    # connection, then the close at release.
    host_end.sendall(b"\0\0\0")
    host_end.close()
    served = []

    def handler(conn):
        served.append((conn.recv(64), f.fence, f.incarnation.kind))
        conn.sendall(b"pong\n")

    # The park flag is set as the handler would set it at the signal,
    # once the round's EINTR has sent the loop back to look.
    original = ext.accept

    def accept_then_flag():
        try:
            return original()
        except InterruptedError:
            f.parking.set()
            raise

    ext.accept = accept_then_flag
    f.serve(handler, poll=0.05)
    join(threads)
    assert ext.calls == [("ready",), ("round",), ("quiesce",), ("wait",), ("ready",)], "the round's EINTR, then the park answered, then the connection"
    assert served == [(b"ping\n", "g/1/2", "resume")]
    assert results == [("reply", b"pong\n")]


@linux_only
def test_serve_handoff_answers_a_park_between_connections(world, tmp_path, monkeypatch):
    """A park on a handoff fiber: the connection in hand ends, fiberd is told, and the next connection comes to the resumed incarnation."""
    monkeypatch.chdir(tmp_path)
    ext = HandoffExt(waits=[("resume", "g/1/2", "handoff", b"", bytearray(32), "", 2)])
    ch, host_end = socket.socketpair()
    f = handoff_fiber(world, ext, monkeypatch, ch)
    f._incarnate("fork", 1, os.urandom(32))
    threads, results = start_clients(world, tmp_path, ext, [world.caller, world.caller])
    # fiberd's end: the first connection, the resume's record after the
    # park, the second connection, then the close at release.
    host_end.sendall(b"\0\0\0")
    host_end.close()
    served = []

    def handler(conn):
        served.append((conn.recv(64), f.fence, f.incarnation.kind))
        conn.sendall(b"pong\n")
        if len(served) == 1:
            f.parking.set()

    f.serve(handler, poll=0.05)
    join(threads)
    assert ext.calls == [("ready",), ("quiesce",), ("wait",), ("ready",)], "the park was answered once the first connection was served, and the resume acked"
    assert served == [(b"ping\n", "g/1/1", "fork"), (b"ping\n", "g/1/2", "resume")]
    assert results == [("reply", b"pong\n")] * 2


# ---- the async twins -----------------------------------------------------


def test_run_awaits_an_async_on_fiber():
    async def on_fiber(f):
        await asyncio.sleep(0)
        return 3

    async def failing(f):
        raise RuntimeError("no")

    f = ft.Fiber("g/1/1", "/tmp/ep.sock", b"", "", {})
    assert ft._run(on_fiber, f) == 3
    assert ft._run(failing, f) == 1


@pytest.fixture
def sock_dir():
    import shutil
    import tempfile

    d = tempfile.mkdtemp(prefix="fz", dir="/tmp")
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_serve_async_unix_reports_ready_and_unlinks(sock_dir, monkeypatch):
    ext = HandoffExt()
    monkeypatch.setattr(ft, "_ext", lambda: ext)
    ep = os.path.join(sock_dir, "ep.sock")
    f = ft.Fiber("g/1/1", ep, b"", "", {})
    f._incarnate("fork", 1, os.urandom(32))
    served = []

    async def handler(reader, writer):
        served.append((await reader.readline(), f.fence, f.incarnation.kind))
        writer.write(b"pong\n")
        await writer.drain()

    async def on_fiber(fiber):
        async def talk():
            reader, writer = await asyncio.open_unix_connection(ep)
            writer.write(b"ping\n")
            reply = await reader.readline()
            writer.close()
            fiber.stopping.set()
            return reply

        serving = asyncio.ensure_future(fiber.serve_async(handler, poll=0.05))
        await asyncio.sleep(0.05)
        reply = await talk()
        await serving
        return 0 if reply == b"pong\n" else 5

    assert ft._run(on_fiber, f) == 0
    assert ext.calls == [("ready",)]
    assert served == [(b"ping\n", "g/1/1", "fork")]
    assert not os.path.exists(ep)


def test_serve_async_unix_parks_on_usr1_and_serves_again(sock_dir, monkeypatch):
    """The async loop's park: the server and its connections close, fiberd is told, and the resumed fiber listens and reports again."""
    ext = HandoffExt(waits=[("resume", "g/1/2", "", b"", bytearray(32), "", 2)])
    ch, host_end = socket.socketpair()
    host_end.sendall(b"\0")  # fiberd's answer, there once the fiber asks
    monkeypatch.setattr(ft, "_ext", lambda: ext)
    ep = os.path.join(sock_dir, "ep.sock")
    f = ft.Fiber("g/1/1", ep, b"", "", {"FIBERD_CHANNEL_FD": str(ch.fileno())})
    f._incarnate("fork", 1, os.urandom(32))
    served = []

    async def handler(reader, writer):
        served.append((await reader.readline(), f.fence, f.incarnation.kind))
        writer.write(b"pong\n")
        await writer.drain()

    async def on_fiber(fiber):
        async def talk():
            reader, writer = await asyncio.open_unix_connection(ep)
            writer.write(b"ping\n")
            reply = await reader.readline()
            writer.close()
            return reply

        serving = asyncio.ensure_future(fiber.serve_async(handler, poll=0.05))
        await asyncio.sleep(0.05)
        first = await talk()
        signal.raise_signal(signal.SIGUSR1)
        while ext.calls.count(("ready",)) < 2:
            await asyncio.sleep(0.02)
        second = await talk()
        fiber.stopping.set()
        await serving
        return 0 if (first, second) == (b"pong\n", b"pong\n") else 5

    try:
        assert ft._run(on_fiber, f) == 0
    finally:
        host_end.close()
        ch.close()
    assert ext.calls == [("ready",), ("quiesce",), ("wait",), ("ready",)]
    assert served == [(b"ping\n", "g/1/1", "fork"), (b"ping\n", "g/1/2", "resume")]
    assert not os.path.exists(ep)


@linux_only
def test_connections_yields_the_bound_caller_only(world, tmp_path, monkeypatch):
    ext = HandoffExt()
    ch, host_end = socket.socketpair()
    f = handoff_fiber(world, ext, monkeypatch, ch)
    checked = spy_pinned(monkeypatch)
    threads, results = start_clients(world, tmp_path, ext, [world.stranger, world.other, world.caller], served=[False, False, True])
    host_end.sendall(b"\0\0\0")
    host_end.close()
    served = []

    async def on_fiber(fiber):
        fiber.ready()
        async for reader, writer in fiber.connections(poll=0.05):
            served.append(await reader.readline())
            writer.write(b"pong\n")
            await writer.drain()
            writer.close()
        return 0

    assert ft._run(on_fiber, f) == 0
    join(threads)
    assert served == [b"ping\n"]
    assert refused(results[0]) and refused(results[1]) and results[2] == ("reply", b"pong\n"), f"refused callers see the alert under asyncio too: {results}"
    assert len(checked) == 1, "the stranger and the other caller failed the handshake itself, before the thumbprint check"
    assert ext.calls == [("ready",)]


@linux_only
def test_serve_async_handoff_runs_a_task_per_connection(world, tmp_path, monkeypatch):
    ext = HandoffExt()
    ch, host_end = socket.socketpair()
    f = handoff_fiber(world, ext, monkeypatch, ch)
    threads, results = start_clients(world, tmp_path, ext, [world.caller, world.caller])
    host_end.sendall(b"\0\0")
    host_end.close()

    async def handler(reader, writer):
        line = await reader.readline()
        writer.write(b"pong\n" if line == b"ping\n" else b"?\n")
        await writer.drain()

    async def on_fiber(fiber):
        await fiber.serve_async(handler, poll=0.05)
        # The loop ended with the channel. Let the handler tasks finish.
        await asyncio.sleep(0.2)
        return 0

    assert ft._run(on_fiber, f) == 0
    join(threads)
    assert results == [("reply", b"pong\n")] * 2
    assert ext.calls == [("ready",)]
