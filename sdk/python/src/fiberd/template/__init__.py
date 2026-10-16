"""fiberd.template: the Python template SDK, over libfiberzygote (sdk/c/template).

A template warms up once and forks a fiber for every Clone. Call init()
first, do the warm-up, then serve(on_fiber). on_fiber runs in the child
with a Fiber, serves on its endpoint and returns the exit code.

    import fiberd.template as ft

    ft.init()                      # first line, before any thread
    model = load_model()           # the warm-up, paid once

    def on_fiber(f: ft.Fiber) -> int:
        task = json.loads(f.payload)
        f.serve(lambda conn: handle(conn, model, task))
        return 0

    ft.serve(on_fiber)

On gVisor nothing forks. serve() notices the sandbox, checkpoints the
warm template and runs on_fiber in every sandbox restored from that
image, so the same template serves on proc, runc and gVisor.

The rules serve() enforces, and why, are in docs/design/sdk.md.
"""

from __future__ import annotations

import asyncio
import errno
import functools
import gc
import os
import random
import select
import signal
import socket
import ssl
import sys
import threading
import traceback
from typing import Any, AsyncIterator, Awaitable, Callable, Optional

from fiberd.template import _fence, _gvisor, _handoff, _rules
from fiberd.template._errors import TemplateError
from fiberd.template._fence import Fence

__all__ = [
    "Fence",
    "Fiber",
    "Identity",
    "Incarnation",
    "TemplateError",
    "init",
    "on_incarnation",
    "register_random",
    "serve",
]

PROC_SELF = "/proc/self"

_inited = False
_hooks: list[Callable[[Incarnation], None]] = []
_randoms: list[random.Random] = []


# The platform a template refuses off, read once. The unit tests set it to
# run the Linux paths over fakes on any host.
_PLATFORM = sys.platform


def _require_linux() -> None:
    """A template runs on Linux only. Off it the refusal is an ImportError that says so, before any /proc is read."""
    if _PLATFORM != "linux":
        raise ImportError(f"fiberd.template runs a template on Linux only, and this is {_PLATFORM}. fiberd.client works here")


def _ext():
    """The C binding, imported when first needed so the pure parts work without it."""
    _require_linux()
    try:
        from fiberd import _zygote
    except ImportError as e:
        raise TemplateError(f"fiberd.template runs a template on Linux with the fiberd._zygote extension built, which this install lacks ({e})") from e
    return _zygote


class Incarnation:
    """One run of a copy of the template. kind is fork, resume or restore.

    generation is fiberd's count of the lineage. A fork or a restore of
    the template is 1, a resume is the parked generation plus one, on
    whichever home resumes it. A template that counts its own
    incarnations can tell a missed one from the number.

    seed is the 32 bytes of entropy the host sent on the incarnation
    record, which the generators were reseeded from. It is zeroed once
    the on_incarnation hooks have run, and never shown by repr.
    """

    __slots__ = ("kind", "generation", "fence", "seed")

    def __init__(self, kind: str, generation: int, fence: str, seed: bytearray) -> None:
        self.kind = kind
        self.generation = generation
        self.fence = fence
        self.seed = seed

    def __repr__(self) -> str:
        return f"Incarnation(kind={self.kind!r}, generation={self.generation}, fence={self.fence!r})"


class Identity:
    """A handoff fiber's TLS identity, the grant's key and certificate, and the one caller it accepts.

    caller is the thumbprint (x5t#S256) of the one client certificate the
    fiber serves, and caller_pem is that certificate, the one the clone
    arrived under. The key is never a file on disk and never shown by
    repr.
    """

    __slots__ = ("key_pem", "cert_pem", "caller", "caller_pem")

    def __init__(self, key_pem: str, cert_pem: str, caller: str, caller_pem: str) -> None:
        self.key_pem = key_pem
        self.cert_pem = cert_pem
        self.caller = caller
        self.caller_pem = caller_pem

    def __repr__(self) -> str:
        return f"Identity(caller={self.caller!r})"


def on_incarnation(fn: Callable[[Incarnation], None]) -> Callable[[Incarnation], None]:
    """Registers fn to run in every new incarnation, after the reseed and before anything serves."""
    _hooks.append(fn)
    return fn


def register_random(rng: random.Random) -> random.Random:
    """Registers a random.Random the template owns, so every incarnation reseeds it too."""
    _randoms.append(rng)
    return rng


def init() -> None:
    """The first call of a template, before any thread and before the warm-up.

    It re-execs the interpreter once with address-space randomisation off
    and takes the mount namespace fiberd asked for, both of which need one
    thread. The second incarnation returns at once.
    """
    global _inited
    if _inited:
        return
    _require_linux()
    _rules.check_main_thread(threading.current_thread() is threading.main_thread())
    _rules.check_threads_at_init(PROC_SELF)
    # A gVisor fiber is a restored sandbox, not a fork over the zygote's
    # pages, so there is no layout to pin and the library is not told.
    if not _gvisor.detect(PROC_SELF):
        _ext().init(list(sys.orig_argv))
    _inited = True


def serve(on_fiber: Callable[[Fiber], int], *, threads: str = "refuse", control_fd: int = _rules.CONTROL_FD) -> int:
    """Checks the rules, then hands the process to libfiberzygote, which forks a fiber per Clone.

    on_fiber runs in each child with its Fiber and returns the exit code.
    threads="warn" turns the one-thread refusal into a warning, for an
    author who stops their pools around clones. Returns when fiberd closes
    the channel.

    On gVisor it runs on_fiber in every sandbox restored from the
    template's checkpoint instead, and returns when one fails.
    """
    if threads not in ("refuse", "warn"):
        raise ValueError('threads is "refuse" or "warn"')
    _require_linux()
    _rules.check_gil(sys._is_gil_enabled())
    _rules.check_main_thread(threading.current_thread() is threading.main_thread())
    _rules.check_init(_inited)
    if _gvisor.detect(PROC_SELF, control_fd):
        # A restored sandbox carries every thread and descriptor with it,
        # so the fork rules below do not apply.
        return _serve_gvisor(on_fiber)
    _rules.check_threads(PROC_SELF, own_tid=threading.get_native_id(), mode=threads)
    _rules.check_descriptors(PROC_SELF, control_fd=control_fd)
    _flush()
    # Everything alive now is the warm state. Frozen, a collection in the
    # fiber leaves it alone, so warm pages are not copied for nothing.
    gc.collect()
    gc.freeze()
    return _ext().serve(functools.partial(_born, on_fiber), control_fd)


def _born(on_fiber: Callable[[Fiber], int], fence: str, endpoint: str, payload: bytes, session: str, env: dict[str, str],
          generation: int, kind: str, seed: bytearray, identity: Optional[tuple[str, str, str, str]]) -> int:
    """The first Python in a fiber, after the C trampoline restored the interpreter.

    Everything but env is the incarnation record the library read off the
    fiber's channel. The seed is the host's 32 bytes, and identity is a
    handoff fiber's TLS identity, None on any other fiber.
    """
    try:
        _rebuild_environ(env)
        f = Fiber(fence, endpoint, payload, session, env, identity=Identity(*identity) if identity is not None else None)
        if f.kind == "handoff" and f.identity is None:
            raise TemplateError("fiberd named a handoff fiber but its record holds no identity")
        f._incarnate(kind, generation, seed)
    except BaseException:
        traceback.print_exc()
        _flush()
        return 1
    return _run(on_fiber, f)


def _run(on_fiber: Callable[[Fiber], Any], f: Fiber) -> int:
    """on_fiber's return, or what it raised, as the fiber's exit code. An async on_fiber runs under a loop born here, in the fiber."""
    try:
        rc = on_fiber(f)
        if asyncio.iscoroutine(rc):
            rc = asyncio.run(rc)
        return _exit_code(rc)
    except SystemExit as e:
        return _exit_code(e.code)
    except BaseException:
        traceback.print_exc()
        return 1
    finally:
        _flush()


def _serve_gvisor(on_fiber: Callable[[Fiber], int]) -> int:
    """The gVisor loop, refzygote's gvisor_main. Returns when an incarnation fails, with its exit code.

    The warm-up is done, so the ready marker tells the backend to take
    the template image from outside while this process blocks in its
    checkpoint read. That read is where every sandbox restored from the
    image resumes, and nothing else tells a restored copy from the
    original. A restored copy takes its identity on fiberd's channel, a
    pooled one waits there until it is handed out, and a resumed park
    comes back the same way with kind "resume". Every copy holds the
    same random state until it reseeds from the seed the identity brings,
    so that happens before on_fiber runs.
    """
    serving: list[Optional[Fiber]] = [None]

    # The template is the sandbox's init, and pid 1 ignores a signal it
    # has no handler for. SIGUSR1 is the backend asking the fiber to
    # close its endpoint for a park.
    def stop(*_: object) -> None:
        if serving[0] is not None:
            serving[0].stopping.set()

    signal.signal(signal.SIGUSR1, stop)
    signal.signal(signal.SIGTERM, stop)
    _flush()
    _gvisor.mark_ready(_gvisor.READY_MARKER)
    print("fiberd.template: warm, waiting for the template checkpoint", file=sys.stderr)
    _flush()
    while True:
        if _gvisor.wait_checkpoint() != "restore":
            # The original, or a fiber checkpointed in place. Nothing to
            # serve. The backend ends it, or the template stands by.
            continue
        kind, fence, endpoint, payload, seed, session, generation = _ext().gvisor_identity()
        try:
            env = _gvisor.fiber_environ(dict(os.environ), fence, endpoint, session)
            _rebuild_environ(env)
            f = Fiber(fence, endpoint, payload, session, env, backend="gvisor")
            f._incarnate(_gvisor.incarnation_kind(kind), generation, seed)
        except BaseException:
            traceback.print_exc()
            _flush()
            return 1
        serving[0] = f
        rc = _run(on_fiber, f)
        serving[0] = None
        if rc != 0:
            return rc


def _rebuild_environ(env: dict[str, str]) -> None:
    """os.environ is the zygote's copy; the C environ is the fiber's scrubbed one."""
    os.environ.clear()
    os.environ.update(env)


def _exit_code(rc: object) -> int:
    if rc is None:
        return 0
    if isinstance(rc, int):
        return rc & 0xFF
    print(rc, file=sys.stderr)
    return 1


def _flush() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except (OSError, ValueError, AttributeError):
            pass


class Fiber:
    """What a fiber knows about itself, handed to on_fiber in the child.

    backend is "fork" for a forked fiber (proc, runc) and "gvisor" for a
    restored sandbox, for the rare author who must tell them apart.
    """

    def __init__(self, fence: str, endpoint: str, payload: bytes, session: str, env: dict[str, str], *, backend: str = "fork",
                 identity: Optional[Identity] = None) -> None:
        self.backend = backend
        self.fence = fence
        self.fence_parts = _fence.parse_fence(fence)
        self.endpoint = endpoint
        self.kind = _fence.endpoint_kind(endpoint)
        self.payload = payload
        self.session = session
        self.env = dict(env)
        self.incarnation: Optional[Incarnation] = None
        self.stopping = threading.Event()
        self.identity = identity
        self._birth = self.fence_parts
        self._ready = False
        # The fiber's channel to fiberd, which the SDK waits on for a
        # handoff fiber's connections and never hands out.
        self._channel_fd = int(env.get("FIBERD_CHANNEL_FD", "-1"))
        # The identity sealed in a memfd, held for the fiber's lifetime, and the context over it.
        self._identity_fd = -1
        self._tls: Optional[_handoff.ServerContext] = None

    def listen(self) -> socket.socket:
        """A bound, listening socket for a unix or tcp endpoint, as fiberd spelled it."""
        if self.kind == "tcp":
            v6, port = _fence.tcp_bind(self.endpoint)
            s = socket.socket(socket.AF_INET6 if v6 else socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("::" if v6 else "0.0.0.0", port))
        elif self.kind == "unix":
            path = _fence.unix_path(self.endpoint)
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.bind(path)
        else:
            raise TemplateError("a handoff fiber does not listen. fiberd accepts for it, and it serves accept() or serve()")
        s.listen(16)
        return s

    def ready(self) -> None:
        """Tells fiberd the endpoint accepts connections. Once, after listen(). stderr is /dev/null after it."""
        if self._ready:
            return
        if self.backend == "gvisor":
            _ext().gvisor_ack()
        else:
            _ext().fiber_ready()
        self._ready = True

    def serve(self, handler: Callable[[socket.socket], None], *, listener: Optional[socket.socket] = None, poll: float = 0.5) -> None:
        """The accept loop. Listens, reports ready, hands each connection to handler and closes it after.

        The channel is polled before each connection, so a fiber resumed
        from a park is reseeded before it serves. A listener from listen()
        may be passed in when the fiber did work between binding and ready.
        Returns when the fiber is asked to stop (SIGTERM, or stopping set,
        which on gVisor the park's SIGUSR1 does), with the endpoint closed
        and unlinked.

        A handoff fiber listens on nothing. Each connection fiberd passes
        down the channel reaches handler as an ssl.SSLSocket, TLS already
        terminated under the grant's identity with the caller's certificate
        pinned, as accept() returns it, and the loop ends when fiberd
        closes the channel at release.
        """
        if self.kind == "handoff":
            self._serve_handoff(handler, poll)
            return
        srv = listener if listener is not None else self.listen()
        try:
            srv.settimeout(poll)
            previous = signal.signal(signal.SIGTERM, lambda *_: self.stopping.set())
            self.ready()
            while not self.stopping.is_set():
                try:
                    conn, _ = srv.accept()
                except (TimeoutError, InterruptedError):
                    continue
                self.poll_incarnation()
                try:
                    handler(conn)
                finally:
                    conn.close()
            signal.signal(signal.SIGTERM, previous)
        finally:
            srv.close()
            if self.kind == "unix":
                try:
                    os.unlink(_fence.unix_path(self.endpoint))
                except OSError:
                    pass

    def _serve_handoff(self, handler: Callable[[socket.socket], None], poll: float) -> None:
        """serve() for a handoff fiber. Waits on the channel, so stopping is noticed between connections as the other loop does."""
        ctx = self._tls_context()
        previous = signal.signal(signal.SIGTERM, lambda *_: self.stopping.set())
        self.ready()
        try:
            while True:
                try:
                    fd = self._next_handoff(poll)
                except ConnectionResetError:
                    return
                self.poll_incarnation()
                conn = self._terminate(ctx, fd)
                if conn is None:
                    continue
                try:
                    handler(conn)
                finally:
                    conn.close()
        finally:
            signal.signal(signal.SIGTERM, previous)

    def _next_handoff(self, poll: float) -> int:
        """The next descriptor off the handoff channel.

        The library's accept retries through signals, so a Python handler
        that sets stopping would not be seen until a connection came. The
        wait is done here instead, in poll slices with stopping checked
        between them, and the library is called once the channel is
        readable. Raises ConnectionResetError when fiberd closed the
        channel, and the same when the fiber is asked to stop.
        """
        while not self.stopping.is_set():
            readable, _, _ = select.select([self._channel_fd], [], [], poll)
            if readable:
                return _ext().accept()
        raise ConnectionResetError(errno.ECONNRESET, "the fiber was asked to stop")

    def accept(self, *, handshake_timeout: float = _handoff.HANDSHAKE_TIMEOUT, poll: float = 0.5) -> ssl.SSLSocket:
        """The next handed-off connection, as an ssl.SSLSocket with TLS terminated under the grant's identity.

        Only the certificate the grant is bound to completes the handshake.
        Any other connection fails it, and the next is waited for.
        Blocks. Raises ConnectionResetError once fiberd closes the channel,
        which it does at release, and once the fiber is asked to stop
        (stopping set, which a SIGTERM handler such as serve()'s does),
        noticed within poll seconds.
        """
        ctx = self._tls_context()
        while True:
            conn = self._terminate(ctx, self._next_handoff(poll), handshake_timeout)
            if conn is not None:
                return conn

    def _tls_context(self) -> _handoff.ServerContext:
        """The server context, built once from the identity sealed in a memfd for the fiber's lifetime."""
        if self._tls is not None:
            return self._tls
        if self.kind != "handoff":
            raise TemplateError(f"only a handoff fiber accepts handed-off connections, and this one serves {self.endpoint!r}")
        if self.identity is None:
            raise TemplateError("this handoff fiber holds no identity")
        # Checked before the key is sealed, so a refused identity leaves no memfd behind.
        _handoff.check_caller(self.identity.caller, self.identity.caller_pem)
        self._identity_fd = _handoff.seal_identity(self.identity.key_pem, self.identity.cert_pem)
        self._tls = _handoff.server_context(self._identity_fd, self.identity.caller, self.identity.caller_pem)
        return self._tls

    def _terminate(self, ctx: ssl.SSLContext, fd: int, handshake_timeout: float = _handoff.HANDSHAKE_TIMEOUT) -> Optional[ssl.SSLSocket]:
        """TLS over one handed-off descriptor, or None, with it closed, when the handshake fails or the caller is not the grant's.

        The handshake admits the bound caller's certificate alone. The
        thumbprint check after it is the second look.
        """
        assert self.identity is not None
        raw = socket.socket(fileno=fd)
        raw.settimeout(handshake_timeout)
        try:
            conn = ctx.wrap_socket(raw, server_side=True)
        except (OSError, ValueError):
            raw.close()
            return None
        if not _handoff.pinned(conn.getpeercert(binary_form=True), self.identity.caller):
            conn.close()
            return None
        conn.settimeout(None)
        return conn

    async def serve_async(self, handler: Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]], *,
                          listener: Optional[socket.socket] = None, poll: float = 0.5) -> None:
        """serve() for an async on_fiber. handler(reader, writer) runs as a task per connection and the writer is closed after it.

        A unix or tcp endpoint is served by asyncio.start_unix_server or
        start_server over listen(). A handoff fiber is served from
        connections(). The loop ends as serve()'s does.
        """
        loop = asyncio.get_running_loop()

        async def one(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                await handler(reader, writer)
            finally:
                writer.close()

        loop.add_signal_handler(signal.SIGTERM, self.stopping.set)
        try:
            if self.kind == "handoff":
                self._tls_context()
                self.ready()
                tasks: set[asyncio.Task[None]] = set()
                async for reader, writer in self.connections(poll=poll):
                    task = loop.create_task(one(reader, writer))
                    tasks.add(task)
                    task.add_done_callback(tasks.discard)
                return
            srv = listener if listener is not None else self.listen()

            async def checked(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
                self.poll_incarnation()
                await one(reader, writer)

            if self.kind == "unix":
                server = await asyncio.start_unix_server(checked, sock=srv)
            else:
                server = await asyncio.start_server(checked, sock=srv)
            try:
                self.ready()
                while not self.stopping.is_set():
                    await asyncio.sleep(poll)
            finally:
                server.close()
                if self.kind == "unix":
                    try:
                        os.unlink(_fence.unix_path(self.endpoint))
                    except OSError:
                        pass
        finally:
            loop.remove_signal_handler(signal.SIGTERM)

    async def connections(self, *, poll: float = 0.5,
                          handshake_timeout: float = _handoff.HANDSHAKE_TIMEOUT) -> AsyncIterator[tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
        """accept() for an async on_fiber. Yields (reader, writer) per handed-off connection, TLS terminated in the loop with the caller pinned.

        The loop waits on the handoff channel, so other tasks run between
        connections. Call ready() first, as before accept(). Ends when
        fiberd closes the channel or the fiber is asked to stop.
        """
        ctx = self._tls_context()
        loop = asyncio.get_running_loop()
        while not self.stopping.is_set():
            arrived = loop.create_future()
            loop.add_reader(self._channel_fd, lambda fut=arrived: fut.done() or fut.set_result(None))
            try:
                await asyncio.wait({arrived}, timeout=poll)
            finally:
                loop.remove_reader(self._channel_fd)
            if not arrived.done():
                continue
            try:
                fd = _ext().accept()
            except ConnectionResetError:
                return
            self.poll_incarnation()
            conn = await self._terminate_async(ctx, fd, handshake_timeout)
            if conn is not None:
                yield conn

    async def _terminate_async(self, ctx: _handoff.ServerContext, fd: int,
                               handshake_timeout: float) -> Optional[tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
        """_terminate under the running loop. The handshake runs in the loop, and the thumbprint is checked again before the pair is handed out.

        asyncio closes a connection whose handshake failed without the
        alert OpenSSL queued, so the caller would see a bare close. The
        alert goes out on a duplicate of the descriptor instead, as it
        does from the blocking handshake.
        """
        assert self.identity is not None
        loop = asyncio.get_running_loop()
        raw = socket.socket(fileno=fd)
        keep = socket.socket(fileno=os.dup(fd))
        reader = asyncio.StreamReader(loop=loop)
        protocol = asyncio.StreamReaderProtocol(reader, loop=loop)
        try:
            transport, _ = await loop.connect_accepted_socket(lambda: protocol, raw, ssl=ctx, ssl_handshake_timeout=handshake_timeout)
        except (OSError, ValueError, asyncio.TimeoutError):
            _handoff.send_alert(ctx, keep)
            raw.close()
            return None
        keep.close()
        ssl_object = transport.get_extra_info("ssl_object")
        peer = ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
        if not _handoff.pinned(peer, self.identity.caller):
            transport.close()
            return None
        return reader, asyncio.StreamWriter(transport, protocol, reader, loop)

    def poll_incarnation(self) -> bool:
        """Takes a resume's record off the channel, when one has arrived. True for a resume, which reseeds and runs the hooks.

        Called by serve() before each connection. An author running their
        own loop over listen() calls it the same way. It never blocks. The
        record names the new fence, the session the resuming clone gave
        and fiberd's generation, and brings a fresh seed. A gVisor fiber
        has no channel to poll, since a resumed sandbox takes a whole
        identity.
        """
        if self.backend == "gvisor":
            return False
        rec = _ext().incarnation_poll()
        if rec is None:
            return False
        kind, fence, _endpoint, _payload, seed, session, generation = rec
        self.fence = fence
        self.fence_parts = _fence.parse_fence(fence)
        self.session = session
        self._incarnate(kind, generation, seed)
        return True

    def _incarnate(self, kind: str, generation: int, seed: bytes | bytearray) -> None:
        """Reseeds every generator and runs the hooks, once per copy of the template. generation is fiberd's count.

        A bytearray is kept as it is, so the one copy the library's
        binding made is the one zeroed after the hooks.
        """
        inc = Incarnation(kind, generation, self.fence, seed if isinstance(seed, bytearray) else bytearray(seed))
        self.incarnation = inc
        # Each generator gets the seed with fresh kernel entropy of its own,
        # so no two draw the same sequence. OpenSSL's DRBG is reseeded on
        # every kind, since its fork check sees a fork and not a restore.
        random.seed(bytes(inc.seed) + os.urandom(16))
        for rng in _randoms:
            rng.seed(bytes(inc.seed) + os.urandom(16))
        ssl.RAND_add(bytes(inc.seed) + os.urandom(16), float(len(inc.seed)))
        try:
            for hook in _hooks:
                hook(inc)
        finally:
            inc.seed[:] = bytes(len(inc.seed))
