"""init, serve, the fiber's birth, the incarnations and the accept loop, with no process started."""

from __future__ import annotations

import errno
import os
import pathlib
import random
import shutil
import signal
import socket
import tempfile
import threading
import time

import pytest

import fiberd.template as ft
from fiberd._testtable import table
from fiberd.template import _rules


class FakeExt:
    """The C binding as a recorder. waits is what each incarnation_wait answers: a record, None for a park that failed, or an exception to raise."""

    ABI_VERSION = 11

    def __init__(self, waits=()):
        self.calls = []
        self.waits = list(waits)

    def quiesce(self):
        self.calls.append(("quiesce",))

    def incarnation_wait(self):
        self.calls.append(("wait",))
        rec = self.waits.pop(0)
        if isinstance(rec, BaseException):
            raise rec
        return rec

    def init(self, argv):
        self.calls.append(("init", list(argv)))

    def serve(self, cb, ctl_fd):
        self.calls.append(("serve", ctl_fd))
        self.cb = cb
        return 0

    def fiber_ready(self):
        self.calls.append(("ready",))


# IDENTITY is a handoff fiber's TLS identity as the record carries it.
IDENTITY = ("-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----\n", "cert", "x5t", "caller cert")
SEED = bytes(range(32))


def one_thread_proc(tmp_path):
    d = tmp_path / "task" / "10"
    d.mkdir(parents=True)
    (d / "comm").write_text("python3\n")
    (tmp_path / "fd").mkdir()
    return str(tmp_path)


def test_init_passes_orig_argv_and_runs_once(tmp_path, monkeypatch):
    ext = FakeExt()
    monkeypatch.setattr(ft, "_ext", lambda: ext)
    monkeypatch.setattr(ft, "PROC_SELF", one_thread_proc(tmp_path))
    monkeypatch.setattr(ft.sys, "orig_argv", ["python3", "-m", "agent"])
    ft.init()
    ft.init()
    assert ext.calls == [("init", ["python3", "-m", "agent"])]
    assert ft._inited


OFF_LINUX = [
    # the platform, the call
    ("init on macOS", "darwin", "init"),
    ("serve on macOS", "darwin", "serve"),
    ("init on Windows", "win32", "init"),
]


@table(OFF_LINUX)
def test_off_linux_is_an_import_error_naming_linux(tmp_path, monkeypatch, name, f0, f1):
    """The design's promise, which the macOS CI job runs for real. fiberd.client stays importable there."""
    monkeypatch.setattr(ft, "_PLATFORM", f0)
    monkeypatch.setattr(ft, "PROC_SELF", str(tmp_path / "no-proc"))
    with pytest.raises(ImportError, match="Linux only"):
        ft.init() if f1 == "init" else ft.serve(lambda f: 0)


SERVE_REFUSALS = [
    # inited, threads mode, the error type, its text
    ("init skipped", False, "refuse", ft.TemplateError, "init\\(\\) did not run"),
    ("a threads mode that is neither", True, "maybe", ValueError, 'threads is "refuse" or "warn"'),
]


@table(SERVE_REFUSALS)
def test_serve_refusals(tmp_path, monkeypatch, name, f0, f1, f2, f3):
    monkeypatch.setattr(ft, "_inited", f0)
    monkeypatch.setattr(ft, "PROC_SELF", one_thread_proc(tmp_path))
    with pytest.raises(f2, match=f3):
        ft.serve(lambda f: 0, threads=f1)


def test_serve_checks_then_hands_over(tmp_path, monkeypatch):
    ext = FakeExt()
    monkeypatch.setattr(ft, "_ext", lambda: ext)
    monkeypatch.setattr(ft, "_inited", True)
    monkeypatch.setattr(ft, "PROC_SELF", one_thread_proc(tmp_path))
    monkeypatch.setattr(_rules, "threads", lambda proc: [_rules.Thread(ft.threading.get_native_id(), "python3")])
    assert ft.serve(lambda f: 0) == 0
    assert ext.calls == [("serve", 3)]


BORN = [
    # what on_fiber returns or raises, the exit code
    ("None is 0", lambda f: None, 0),
    ("an int", lambda f: 3, 3),
    ("an int is one byte", lambda f: 300, 44),
    ("SystemExit", lambda f: (_ for _ in ()).throw(SystemExit(2)), 2),
    ("an exception is 1", lambda f: 1 / 0, 1),
    ("a string is 1", lambda f: "no", 1),
]


@table(BORN)
def test_born_exit_code(monkeypatch, name, f0, f1):
    monkeypatch.setattr(ft, "_rebuild_environ", lambda env: None)
    assert ft._born(f0, "g/1/1", "/tmp/ep.sock", b"", "", {}, 1, "fork", bytearray(SEED), None) == f1


def test_born_hands_the_fiber_its_record(monkeypatch):
    seen = {}
    monkeypatch.setattr(ft, "_rebuild_environ", lambda env: seen.setdefault("env", env))

    def on_fiber(f):
        seen["fiber"] = f
        return 0

    env = {"FIBERD_FENCE": "g/2/5", "FIBERD_ENDPOINT": "/run/g/2-5.sock", "FIBERD_SESSION": "conv 42", "FIBERD_CHANNEL_FD": "4"}
    assert ft._born(on_fiber, "g/2/5", "/run/g/2-5.sock", b'{"task":1}', "conv 42", env, 1, "fork", bytearray(SEED), None) == 0
    f = seen["fiber"]
    assert seen["env"] == env
    assert (f.fence, f.fence_parts, f.endpoint, f.kind, f._channel_fd) == ("g/2/5", ft.Fence("g", 2, 5), "/run/g/2-5.sock", "unix", 4)
    assert (f.payload, f.session, f.env) == (b'{"task":1}', "conv 42", env)
    assert f.incarnation.kind == "fork" and f.incarnation.generation == 1
    assert not f.stopping.is_set() and f.identity is None


def test_born_installs_the_park_handler_before_on_fiber(monkeypatch):
    """A park's SIGUSR1 can land the moment the fiber reports ready, before serve(), and must set parking rather than end the fiber."""
    ext = FakeExt()
    monkeypatch.setattr(ft, "_ext", lambda: ext)
    previous = signal.signal(signal.SIGUSR1, signal.SIG_DFL)
    seen = []

    def on_fiber(f):
        handler = signal.getsignal(signal.SIGUSR1)
        seen.append(handler)
        if callable(handler):
            handler(signal.SIGUSR1, None)
        seen.append(f.parking.is_set())
        return 0

    try:
        assert ft._born(on_fiber, "g/1/1", "/run/g/1-1.sock", b"", "", {}, 1, "fork", bytearray(32), None) == 0
    finally:
        signal.signal(signal.SIGUSR1, previous)
    assert callable(seen[0]) and seen[0] is not signal.SIG_DFL, "the handler is in place before on_fiber runs"
    assert seen[1] is True, "the handler sets parking"


def test_born_reseeds_from_the_record_and_zeroes_the_seed(monkeypatch):
    """The fork incarnation's seed is the record's, the one the library handed over, not a draw of the SDK's own."""
    monkeypatch.setattr(ft, "_rebuild_environ", lambda env: None)
    monkeypatch.setattr(ft, "_hooks", [])
    seen = []
    ft.on_incarnation(lambda inc: seen.append((inc.kind, inc.generation, inc.fence, bytes(inc.seed))))
    seed = bytearray(SEED)
    fibers = []
    assert ft._born(lambda f: fibers.append(f) or 0, "g/1/1", "/tmp/ep.sock", b"", "", {}, 1, "fork", seed, None) == 0
    assert seen == [("fork", 1, "g/1/1", SEED)], "the hook sees the record's seed"
    inc = fibers[0].incarnation
    assert inc.seed is seed and bytes(seed) == bytes(32), "the binding's bytearray is the one zeroed after the hooks"
    assert "seed" not in repr(inc) and SEED.hex()[:8] not in repr(inc)


BORN_IDENTITY = [
    # the endpoint, the identity on the record, the identity wanted
    ("a unix fiber has none", "/run/g/2-5.sock", None, None),
    ("a handoff fiber takes the record's", "handoff", IDENTITY, ("x5t", "caller cert")),
]


@table(BORN_IDENTITY)
def test_born_takes_the_handoff_identity_off_the_record(monkeypatch, name, f0, f1, f2):
    monkeypatch.setattr(ft, "_rebuild_environ", lambda env: None)
    seen = {}

    def on_fiber(f):
        seen["fiber"] = f
        return 0

    assert ft._born(on_fiber, "g/2/5", f0, b"", "", {"FIBERD_CHANNEL_FD": "4"}, 1, "fork", bytearray(SEED), f1) == 0
    f = seen["fiber"]
    if f2 is None:
        assert f.identity is None and f.kind == "unix"
        return
    assert f.kind == "handoff" and f._channel_fd == 4
    assert (f.identity.caller, f.identity.caller_pem) == f2
    assert f.identity.key_pem.startswith("-----BEGIN PRIVATE KEY-----") and "PRIVATE" not in repr(f.identity)


def test_born_refuses_a_handoff_fiber_without_an_identity(monkeypatch, capsys):
    monkeypatch.setattr(ft, "_rebuild_environ", lambda env: None)
    assert ft._born(lambda f: 0, "g/1/1", "handoff", b"", "", {"FIBERD_CHANNEL_FD": "4"}, 1, "fork", bytearray(SEED), None) == 1
    assert "holds no identity" in capsys.readouterr().err


def test_incarnation_reseeds_and_runs_hooks_in_order():
    rng = ft.register_random(random.Random(1))
    seen = []
    ft.on_incarnation(lambda inc: seen.append(("a", inc.kind, inc.generation, bytes(inc.seed))))
    ft.on_incarnation(lambda inc: seen.append(("b", inc.kind, inc.generation, bytes(inc.seed))))
    random.seed(1)
    before = (random.getrandbits(32), rng.getrandbits(32))
    f = ft.Fiber("g/1/1", "/tmp/ep.sock", b"", "", {})
    f._incarnate("fork", 4, b"\x07" * 32)
    assert [s[:3] for s in seen] == [("a", "fork", 4), ("b", "fork", 4)], "the generation is the one given, not a count of this process"
    assert all(s[3] == b"\x07" * 32 for s in seen), "the hooks see the seed"
    assert bytes(f.incarnation.seed) == bytes(32), "zeroed once the hooks ran"
    assert "seed" not in repr(f.incarnation) and "07" not in repr(f.incarnation)
    random.seed(1)
    rng.seed(1)
    assert (random.getrandbits(32), rng.getrandbits(32)) == before, "the generators were reseeded from the kernel, not left alone"


def resume_record(fence="g/1/2", generation=5, session="", kind="resume"):
    """A resume's record as the binding hands it over: (kind, fence, endpoint, payload, seed, session, generation)."""
    return (kind, fence, "/run/g/1-1.sock", b"", bytearray(SEED), session, generation)


def channel(monkeypatch):
    """A fiber's channel as a pair, fiberd's end returned beside the env that names the fiber's."""
    fiber_end, host_end = socket.socketpair()
    return host_end, {"FIBERD_CHANNEL_FD": str(fiber_end.fileno())}, fiber_end


PARK = [
    # what fiberd answers, whether park() reports a resume, the fence and the generation after, the hooks run
    ("a resume's record", [resume_record()], True, "g/1/2", 5, [("resume", "g/1/2")]),
    ("the park failed, the fiber serves on as it was", [None], False, "g/1/1", 4, []),
    ("a signal's interruption, then the record", [InterruptedError(errno.EINTR, "interrupted"), resume_record()], True, "g/1/2", 5, [("resume", "g/1/2")]),
    ("a record the library refused", [OSError(errno.EPROTO, "malformed record")], None, "g/1/1", 4, []),
]


@table(PARK)
def test_park(monkeypatch, name, f0, f1, f2, f3, f4):
    """park() tells fiberd the fiber serves nothing, waits for its answer, and reseeds under a resume's record."""
    ext = FakeExt(waits=f0)
    monkeypatch.setattr(ft, "_ext", lambda: ext)
    seen = []
    monkeypatch.setattr(ft, "_hooks", [seen.append])
    host_end, env, fiber_end = channel(monkeypatch)
    f = ft.Fiber("g/1/1", "/run/g/1-1.sock", b"", "", env)
    f._incarnate("fork", 4, os.urandom(32))
    f._ready = True
    f.parking.set()
    host_end.sendall(b"\0")  # the answer is there to read
    try:
        if f1 is None:
            with pytest.raises(OSError, match="malformed record"):
                f.park(poll=0.05)
        else:
            assert f.park(poll=0.05) is f1
            assert f._ready is False, "ready() reports again, which after a resume acks"
    finally:
        host_end.close()
        fiber_end.close()
    assert not f.parking.is_set()
    assert ext.calls == [("quiesce",)] + [("wait",)] * len(f0), "told fiberd first, then waited once per answer"
    assert f.fence == f2 and f.fence_parts == ft._fence.parse_fence(f2)
    assert f.incarnation.generation == f3, "the generation is the record's, fiberd's count, not a count of this process"
    assert [(inc.kind, inc.fence) for inc in seen[1:]] == f4, "the hooks ran once per resume"
    assert all(bytes(inc.seed) == bytes(32) for inc in seen), "every seed is zeroed once the hooks ran"


# The time park() has to notice the stop, so code that notices nothing
# fails the bound instead of hanging the suite.
STOP_BOUND = 1.5

STOPS = [
    # how the fiber is asked to stop, 0.1s into the wait
    ("stopping set", lambda f: f.stopping.set()),
    ("SIGTERM under the handler serve() installs", lambda f: signal.pthread_kill(threading.main_thread().ident, signal.SIGTERM)),
]


@table(STOPS)
def test_park_returns_when_the_fiber_is_asked_to_stop(monkeypatch, name, f0):
    """The wait for fiberd's answer runs in slices with stopping checked, so a stop is seen with no answer in sight and the binding's wait is never entered."""
    ext = FakeExt(waits=[resume_record()])
    monkeypatch.setattr(ft, "_ext", lambda: ext)
    host_end, env, fiber_end = channel(monkeypatch)
    f = ft.Fiber("g/1/1", "/run/g/1-1.sock", b"", "", env)
    f._incarnate("fork", 1, os.urandom(32))
    previous = signal.signal(signal.SIGTERM, lambda *_: f.stopping.set())
    stop = threading.Timer(0.1, f0, [f])
    try:
        stop.start()
        started = time.monotonic()
        with pytest.raises(ConnectionResetError):
            f.park(poll=0.05)
        took = time.monotonic() - started
    finally:
        signal.signal(signal.SIGTERM, previous)
        stop.cancel()
        stop.join()
        host_end.close()
        fiber_end.close()
    assert took < STOP_BOUND, f"park() took {took:.2f}s to notice the stop"
    assert ext.calls == [("quiesce",)], "incarnation_wait is called only once the channel is readable"


def test_park_takes_the_session_off_the_record(monkeypatch):
    ext = FakeExt(waits=[resume_record(session="conv 43")])
    monkeypatch.setattr(ft, "_ext", lambda: ext)
    host_end, env, fiber_end = channel(monkeypatch)
    f = ft.Fiber("g/1/1", "/run/g/1-1.sock", b"", "conv 42", env)
    f._incarnate("fork", 1, os.urandom(32))
    host_end.sendall(b"\0")
    try:
        assert f.park(poll=0.05) is True and f.session == "conv 43"
    finally:
        host_end.close()
        fiber_end.close()


def test_park_is_refused_on_gvisor(monkeypatch):
    ext = FakeExt(waits=[resume_record()])
    monkeypatch.setattr(ft, "_ext", lambda: ext)
    f = ft.Fiber("g/1/1", "/host/1-1.sock", b"", "", {}, backend="gvisor")
    f._incarnate("clone", 1, os.urandom(32))
    with pytest.raises(ft.TemplateError, match="returning from serve"):
        f.park()
    assert ext.calls == [], "a sandbox parks by closing its endpoint, and a resumed one takes a whole identity"


@pytest.fixture
def sock_dir():
    """A short directory for unix sockets, since tmp_path on macOS overruns sun_path (104 bytes there)."""
    d = tempfile.mkdtemp(prefix="fz", dir="/tmp")
    try:
        yield pathlib.Path(d)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_listen_unix(sock_dir):
    ep = str(sock_dir / "ep.sock")
    f = ft.Fiber("g/1/1", "unix://" + ep, b"", "", {})
    with f.listen() as s:
        assert s.family == socket.AF_UNIX and os.path.exists(ep)


def test_listen_handoff_refused():
    f = ft.Fiber("g/1/1", "handoff", b"", "", {"FIBERD_CHANNEL_FD": "4"})
    assert f.kind == "handoff"
    with pytest.raises(ft.TemplateError, match="handoff fiber does not listen"):
        f.listen()


def test_serve_loop_reports_ready_and_hands_connections_over(sock_dir, monkeypatch):
    ext = FakeExt()
    monkeypatch.setattr(ft, "_ext", lambda: ext)
    ep = str(sock_dir / "ep.sock")
    f = ft.Fiber("g/1/1", ep, b"", "", {})
    f._incarnate("fork", 1, os.urandom(32))
    srv = f.listen()
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(ep)
    client.sendall(b"hi\n")
    served = []

    def handler(conn):
        served.append((conn.recv(16), f.fence, f.incarnation.kind, f.incarnation.generation))
        f.stopping.set()

    previous = (signal.getsignal(signal.SIGUSR1), signal.getsignal(signal.SIGTERM))
    f.serve(handler, listener=srv, poll=0.05)
    client.close()
    assert ext.calls == [("ready",)]
    assert served == [(b"hi\n", "g/1/1", "fork", 1)]
    assert not os.path.exists(ep), "the endpoint is unlinked on the way out"
    assert (signal.getsignal(signal.SIGUSR1), signal.getsignal(signal.SIGTERM)) == previous, "serve() restores the handlers it installed"


def test_serve_loop_parks_on_usr1_and_serves_again(sock_dir, monkeypatch):
    """The park's SIGUSR1, seen between connections: the listener goes, fiberd is told, and the resumed fiber listens and reports again."""
    ext = FakeExt(waits=[resume_record("g/1/2", 2)])
    monkeypatch.setattr(ft, "_ext", lambda: ext)
    host_end, env, fiber_end = channel(monkeypatch)
    host_end.sendall(b"\0")  # fiberd's answer, there once the fiber asks
    ep = str(sock_dir / "ep.sock")
    f = ft.Fiber("g/1/1", ep, b"", "", env)
    f._incarnate("fork", 1, os.urandom(32))
    served = []
    gone_while_parked = []

    cut = []

    def talk(line):
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        c.connect(ep)
        c.sendall(line)
        c.recv(1)
        if line == b"hi\n":
            cut.append(c.recv(1))  # the fiber's end of it, cut at the signal
        c.close()

    def second_client():
        # Once the fiber reports ready again, after its park.
        deadline = time.monotonic() + 5
        while ext.calls.count(("ready",)) < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        talk(b"again\n")

    def handler(conn):
        line = conn.recv(16)
        served.append((line, f.fence, f.incarnation.kind, f.incarnation.generation))
        conn.sendall(b"k")
        if line == b"hi\n":
            signal.raise_signal(signal.SIGUSR1)
            gone_while_parked.append(ext.calls.count(("quiesce",)))
            # The signal shut the connection in hand down, so a handler
            # blocked here would have returned at once.
            cut.append(conn.recv(1))
        else:
            f.stopping.set()

    srv = f.listen()  # before the first client, which connects at once
    first = threading.Thread(target=talk, args=(b"hi\n",))
    second = threading.Thread(target=second_client)
    first.start()
    second.start()
    try:
        f.serve(handler, listener=srv, poll=0.05)
    finally:
        first.join()
        second.join()
        host_end.close()
        fiber_end.close()
    assert ext.calls == [("ready",), ("quiesce",), ("wait",), ("ready",)], "ready at birth, then the park's word, the wait and the ack"
    assert served == [(b"hi\n", "g/1/1", "fork", 1), (b"again\n", "g/1/2", "resume", 2)], "the second connection reached the resumed incarnation"
    assert gone_while_parked == [0], "the park waited for the connection being served to end"
    assert cut == [b"", b""], "the signal cut the connection in hand, seen from both ends"
    assert not os.path.exists(ep)


# ---- gVisor --------------------------------------------------------------


class FakeGvisorExt(FakeExt):
    """The C binding of a sandbox: identities handed out in order, acks recorded."""

    def __init__(self, identities):
        super().__init__()
        self.identities = list(identities)

    def gvisor_identity(self):
        self.calls.append(("identity",))
        return self.identities.pop(0)

    def gvisor_ack(self):
        self.calls.append(("ack",))


def gvisor_here(monkeypatch, tmp_path, answers):
    """A fake sandbox: detect says gVisor, each checkpoint read answers from answers on a descriptor of no file, the ready marker lands in tmp_path."""
    monkeypatch.setattr(ft._gvisor, "detect", lambda *a, **k: True)
    monkeypatch.setattr(ft._gvisor, "open_checkpoint", lambda path=None: -1)
    monkeypatch.setattr(ft._gvisor, "read_checkpoint", lambda fd: answers.pop(0))
    monkeypatch.setattr(ft._gvisor, "READY_MARKER", str(tmp_path / "warm.ready"))
    monkeypatch.setattr(ft, "_rebuild_environ", lambda env: None)


def descriptors_on(path):
    """How many of this process's descriptors are open on path, which Linux's /proc tells."""
    fds = "/proc/self/fd"
    n = 0
    for name in os.listdir(fds):
        try:
            if os.readlink(os.path.join(fds, name)) == path:
                n += 1
        except OSError:
            continue
    return n


REGISTERED = [
    # what lets the backend take the next checkpoint, when the loop must already hold the file open
    ("the ready marker lets it take the template image", "mark"),
    ("an incarnation serving lets it take a park", "fiber"),
]


@pytest.mark.skipif(not os.path.isdir("/proc/self/fd"), reason="the witness is /proc/self/fd")
@table(REGISTERED)
def test_serve_on_gvisor_opens_the_checkpoint_file_before_it_lets_the_backend_checkpoint(tmp_path, monkeypatch, name, f0):
    """The checkpoint file is open before the marker and before each incarnation, since a read answers only for checkpoints taken after its open."""
    checkpoint = tmp_path / "checkpoint"
    checkpoint.write_text("restore\n")
    monkeypatch.setattr(ft._gvisor, "CHECKPOINT", str(checkpoint))
    monkeypatch.setattr(ft._gvisor, "READY_MARKER", str(tmp_path / "warm.ready"))
    monkeypatch.setattr(ft._gvisor, "detect", lambda *a, **k: True)
    monkeypatch.setattr(ft, "_rebuild_environ", lambda env: None)
    ext = FakeGvisorExt([("clone", "g/1/1", "/host/1-1.sock", b"", os.urandom(32), "", 1)])
    monkeypatch.setattr(ft, "_ext", lambda: ext)
    monkeypatch.setattr(ft, "_inited", True)
    monkeypatch.setattr(ft, "PROC_SELF", one_thread_proc(tmp_path))
    held = {}
    real_mark = ft._gvisor.mark_ready

    def mark(marker):
        held["mark"] = descriptors_on(str(checkpoint))
        real_mark(marker)

    monkeypatch.setattr(ft._gvisor, "mark_ready", mark)

    def on_fiber(f):
        held["fiber"] = descriptors_on(str(checkpoint))
        return 7

    assert ft.serve(on_fiber) == 7
    assert held[f0] == 1, f"the checkpoint file must be open when {name}"


def test_init_on_gvisor_skips_the_library(tmp_path, monkeypatch):
    ext = FakeExt()
    monkeypatch.setattr(ft, "_ext", lambda: ext)
    monkeypatch.setattr(ft, "PROC_SELF", one_thread_proc(tmp_path))
    monkeypatch.setattr(ft._gvisor, "detect", lambda *a, **k: True)
    ft.init()
    assert ext.calls == [] and ft._inited


def test_serve_on_gvisor_runs_every_restore(tmp_path, monkeypatch):
    """The loop: mark ready, wait, skip the original's "resume", take the identity on each "restore", reseed and run on_fiber."""
    seed1, seed2 = os.urandom(32), os.urandom(32)
    ext = FakeGvisorExt([
        ("clone", "g/1/1", "/host/1-1.sock", b'{"task":1}', seed1, "conv 42", 1),
        ("resume", "g/1/2", "/host/1-2.sock", b"", seed2, "", 3),
    ])
    monkeypatch.setattr(ft, "_ext", lambda: ext)
    monkeypatch.setattr(ft, "_inited", True)
    monkeypatch.setattr(ft, "PROC_SELF", one_thread_proc(tmp_path))
    gvisor_here(monkeypatch, tmp_path, ["resume", "restore", "restore"])
    seen = []
    ft.on_incarnation(lambda inc: seen.append((inc.kind, inc.generation, inc.fence, bytes(inc.seed))))
    fibers = []

    def on_fiber(f):
        fibers.append(f)
        f.ready()
        f.ready()
        return 0 if len(fibers) < 2 else 7

    assert ft.serve(on_fiber) == 7
    assert (tmp_path / "warm.ready").exists(), "the backend takes the template image once the marker is there"
    assert ext.calls == [("identity",), ("ack",), ("identity",), ("ack",)], "one identity and one ack per restore, and no fork hooks"
    assert seen == [("restore", 1, "g/1/1", seed1), ("resume", 3, "g/1/2", seed2)], "seed, generation and kind reach the hooks from the record"
    a, b = fibers
    assert (a.backend, a.fence, a.endpoint, a.kind, a.payload, a.session) == ("gvisor", "g/1/1", "/host/1-1.sock", "unix", b'{"task":1}', "conv 42")
    assert a.env["FIBERD_FENCE"] == "g/1/1" and a.env["FIBERD_SESSION"] == "conv 42"
    assert (b.backend, b.fence, b.session, b.incarnation.kind) == ("gvisor", "g/1/2", "", "resume")
    assert "FIBERD_SESSION" not in b.env
    with pytest.raises(ft.TemplateError):
        a.park()
    assert a.incarnation.generation == 1, "a sandbox has no channel to answer a park on"


def test_serve_on_gvisor_ends_with_a_failed_incarnation(tmp_path, monkeypatch):
    ext = FakeGvisorExt([("clone", "g/1/1", "/host/1-1.sock", b"", os.urandom(32), "", 1)])
    monkeypatch.setattr(ft, "_ext", lambda: ext)
    monkeypatch.setattr(ft, "_inited", True)
    monkeypatch.setattr(ft, "PROC_SELF", one_thread_proc(tmp_path))
    gvisor_here(monkeypatch, tmp_path, ["restore"])
    assert ft.serve(lambda f: 1 / 0) == 1


def test_usr1_stops_the_serving_fiber_on_gvisor(tmp_path, sock_dir, monkeypatch):
    """The park's SIGUSR1 sets stopping on the fiber serving now, and serve() unlinks its endpoint on the way out."""
    ep = str(sock_dir / "1-1.sock")
    ext = FakeGvisorExt([("clone", "g/1/1", ep, b"", os.urandom(32), "", 1)])
    monkeypatch.setattr(ft, "_ext", lambda: ext)
    monkeypatch.setattr(ft, "_inited", True)
    monkeypatch.setattr(ft, "PROC_SELF", one_thread_proc(tmp_path))
    gvisor_here(monkeypatch, tmp_path, ["restore"])
    previous = (ft.signal.getsignal(ft.signal.SIGUSR1), ft.signal.getsignal(ft.signal.SIGTERM))

    def on_fiber(f):
        srv = f.listen()
        ft.signal.raise_signal(ft.signal.SIGUSR1)
        f.serve(lambda conn: None, listener=srv, poll=0.05)
        return 3

    try:
        assert ft.serve(on_fiber) == 3
    finally:
        ft.signal.signal(ft.signal.SIGUSR1, previous[0])
        ft.signal.signal(ft.signal.SIGTERM, previous[1])
    assert not os.path.exists(ep)
    assert ("ack",) in ext.calls


def test_serve_on_gvisor_serves_the_footprint_probe(tmp_path, monkeypatch):
    """The backend measures a restored sandbox under the fence "probe", which is not grant/epoch/seq and is served all the same."""
    ext = FakeGvisorExt([("clone", "probe", "/host/probe.sock", b"", os.urandom(32), "", 1)])
    monkeypatch.setattr(ft, "_ext", lambda: ext)
    monkeypatch.setattr(ft, "_inited", True)
    monkeypatch.setattr(ft, "PROC_SELF", one_thread_proc(tmp_path))
    gvisor_here(monkeypatch, tmp_path, ["restore"])
    seen = []

    def on_fiber(f):
        seen.append((f.fence, f.fence_parts))
        f.ready()
        return 5

    assert ft.serve(on_fiber) == 5
    assert seen == [("probe", ft.Fence("probe", 0, 0))] and ext.calls[-1] == ("ack",)
