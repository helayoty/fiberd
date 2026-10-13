"""fiberd.template: the Python template SDK, over libfiberzygote (sdk/c).

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

The rules serve() enforces, and why, are in docs/design/sdk.md.
"""

from __future__ import annotations

import functools
import gc
import os
import random
import signal
import socket
import ssl
import sys
import threading
import traceback
from typing import Callable, Optional

from fiberd.template import _fence, _rules
from fiberd.template._errors import TemplateError
from fiberd.template._fence import Fence

__all__ = [
    "Fence",
    "Fiber",
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
_generation = 0


def _ext():
    """The C binding, imported when first needed so the pure parts work without it."""
    try:
        from fiberd import _zygote
    except ImportError as e:
        raise TemplateError(f"fiberd.template runs a template on Linux with the fiberd._zygote extension built, which this install lacks ({e})") from e
    return _zygote


class Incarnation:
    """One run of a copy of the template. kind is fork, resume or restore.

    seed is the entropy this incarnation was reseeded from, zeroed once the
    on_incarnation hooks have run, and never shown by repr.
    """

    __slots__ = ("kind", "generation", "fence", "seed")

    def __init__(self, kind: str, generation: int, fence: str, seed: bytearray) -> None:
        self.kind = kind
        self.generation = generation
        self.fence = fence
        self.seed = seed

    def __repr__(self) -> str:
        return f"Incarnation(kind={self.kind!r}, generation={self.generation}, fence={self.fence!r})"


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
    _rules.check_main_thread(threading.current_thread() is threading.main_thread())
    _rules.check_threads_at_init(PROC_SELF)
    _ext().init(list(sys.orig_argv))
    _inited = True


def serve(on_fiber: Callable[[Fiber], int], *, threads: str = "refuse", control_fd: int = _rules.CONTROL_FD) -> int:
    """Checks the rules, then hands the process to libfiberzygote, which forks a fiber per Clone.

    on_fiber runs in each child with its Fiber and returns the exit code.
    threads="warn" turns the one-thread refusal into a warning, for an
    author who stops their pools around clones. Returns when fiberd closes
    the channel.
    """
    if threads not in ("refuse", "warn"):
        raise ValueError('threads is "refuse" or "warn"')
    _rules.check_gil(getattr(sys, "_is_gil_enabled", lambda: True)())
    _rules.check_main_thread(threading.current_thread() is threading.main_thread())
    _rules.check_init(_inited)
    _rules.check_threads(PROC_SELF, own_tid=threading.get_native_id(), mode=threads)
    _rules.check_descriptors(PROC_SELF, control_fd=control_fd)
    _flush()
    # Everything alive now is the warm state. Frozen, a collection in the
    # fiber leaves it alone, so warm pages are not copied for nothing.
    gc.collect()
    gc.freeze()
    return _ext().serve(functools.partial(_born, on_fiber), control_fd)


def _born(on_fiber: Callable[[Fiber], int], fence: str, endpoint: str, payload: bytes, session: str, env: dict[str, str]) -> int:
    """The first Python in a fiber, after the C trampoline restored the interpreter."""
    try:
        _rebuild_environ(env)
        f = Fiber(fence, endpoint, payload, session, env)
        f._incarnate("fork", os.urandom(32))
        return _exit_code(on_fiber(f))
    except SystemExit as e:
        return _exit_code(e.code)
    except BaseException:
        traceback.print_exc()
        return 1
    finally:
        _flush()


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
    """What a fiber knows about itself, handed to on_fiber in the child."""

    def __init__(self, fence: str, endpoint: str, payload: bytes, session: str, env: dict[str, str]) -> None:
        self.fence = fence
        self.fence_parts = _fence.parse_fence(fence)
        self.endpoint = endpoint
        self.kind = _fence.endpoint_kind(endpoint, "FIBERD_HANDOFF_FD" in env)
        self.payload = payload
        self.session = session
        self.env = dict(env)
        self.incarnation: Optional[Incarnation] = None
        self.stopping = threading.Event()
        self.identity = None
        self._birth = self.fence_parts
        self._ready = False

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
            raise TemplateError("a handoff fiber does not listen, it serves accept(), which a later stage adds")
        s.listen(16)
        return s

    def ready(self) -> None:
        """Tells fiberd the endpoint accepts connections. Once, after listen(). stderr is /dev/null after it."""
        if not self._ready:
            _ext().fiber_ready()
            self._ready = True

    def serve(self, handler: Callable[[socket.socket], None], *, listener: Optional[socket.socket] = None, poll: float = 0.5) -> None:
        """The accept loop. Listens, reports ready, hands each connection to handler and closes it after.

        The fence file is checked before each connection, so a fiber resumed
        from a park is reseeded before it serves. A listener from listen()
        may be passed in when the fiber did work between binding and ready.
        Returns when the fiber is asked to stop (SIGTERM, or stopping set).
        """
        if self.kind == "handoff":
            raise TemplateError("a handoff fiber serves accept(), which a later stage adds")
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
                self.check_fence()
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

    def accept(self) -> socket.socket:
        raise TemplateError("handoff fibers come in a later stage of the SDK")

    def check_fence(self) -> bool:
        """Reads the fence file fiberd publishes beside the endpoint. A new fence is a resume, and reseeds.

        Called by serve() before each connection. An author running their
        own loop over listen() calls it the same way.
        """
        now = _fence.live_fence(_fence.fence_file(self.endpoint, self.kind, self._birth), self.fence)
        if now == self.fence:
            return False
        self.fence = now
        self.fence_parts = _fence.parse_fence(now)
        self._incarnate("resume", os.urandom(32))
        return True

    def _incarnate(self, kind: str, seed: bytes) -> None:
        """Reseeds every generator and runs the hooks, once per copy of the template."""
        global _generation
        _generation += 1
        inc = Incarnation(kind, _generation, self.fence, bytearray(seed))
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
