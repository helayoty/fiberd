"""init, serve, the fiber's birth, the incarnations and the accept loop, with no process started."""

from __future__ import annotations

import os
import random
import socket

import pytest

import fiberd.template as ft
from fiberd._testtable import table
from fiberd.template import _rules


class FakeExt:
    """The C binding as a recorder."""

    ABI_VERSION = 2

    def __init__(self):
        self.calls = []

    def init(self, argv):
        self.calls.append(("init", list(argv)))

    def serve(self, cb, ctl_fd):
        self.calls.append(("serve", ctl_fd))
        self.cb = cb
        return 0

    def fiber_ready(self):
        self.calls.append(("ready",))


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
    assert ft._born(f0, "g/1/1", "/tmp/ep.sock", b"", "", {}) == f1


def test_born_hands_the_fiber_its_record(monkeypatch):
    seen = {}
    monkeypatch.setattr(ft, "_rebuild_environ", lambda env: seen.setdefault("env", env))

    def on_fiber(f):
        seen["fiber"] = f
        return 0

    env = {"FIBERD_FENCE": "g/2/5", "FIBERD_ENDPOINT": "/run/g/2-5.sock", "FIBERD_SESSION": "conv 42"}
    assert ft._born(on_fiber, "g/2/5", "/run/g/2-5.sock", b'{"task":1}', "conv 42", env) == 0
    f = seen["fiber"]
    assert seen["env"] == env
    assert (f.fence, f.fence_parts, f.endpoint, f.kind) == ("g/2/5", ft.Fence("g", 2, 5), "/run/g/2-5.sock", "unix")
    assert (f.payload, f.session, f.env) == (b'{"task":1}', "conv 42", env)
    assert f.incarnation.kind == "fork" and f.incarnation.generation == 1
    assert not f.stopping.is_set() and f.identity is None


def test_incarnation_reseeds_and_runs_hooks_in_order():
    rng = ft.register_random(random.Random(1))
    seen = []
    ft.on_incarnation(lambda inc: seen.append(("a", inc.kind, inc.generation, bytes(inc.seed))))
    ft.on_incarnation(lambda inc: seen.append(("b", inc.kind, inc.generation, bytes(inc.seed))))
    random.seed(1)
    before = (random.getrandbits(32), rng.getrandbits(32))
    f = ft.Fiber("g/1/1", "/tmp/ep.sock", b"", "", {})
    f._incarnate("fork", b"\x07" * 32)
    assert [s[:3] for s in seen] == [("a", "fork", 1), ("b", "fork", 1)]
    assert all(s[3] == b"\x07" * 32 for s in seen), "the hooks see the seed"
    assert bytes(f.incarnation.seed) == bytes(32), "zeroed once the hooks ran"
    assert "seed" not in repr(f.incarnation) and "07" not in repr(f.incarnation)
    random.seed(1)
    rng.seed(1)
    assert (random.getrandbits(32), rng.getrandbits(32)) == before, "the generators were reseeded from the kernel, not left alone"


FENCE_FILE = [
    # the file's content, whether a resume is seen, the fence after
    ("the birth fence", "g/1/1\n", False, "g/1/1"),
    ("no file yet", None, False, "g/1/1"),
    ("a new fence is a resume", "g/1/2\n", True, "g/1/2"),
]


@table(FENCE_FILE)
def test_check_fence(tmp_path, name, f0, f1, f2):
    ep = str(tmp_path / "ep.sock")
    if f0 is not None:
        (tmp_path / "ep.sock.fence").write_text(f0)
    f = ft.Fiber("g/1/1", ep, b"", "", {})
    f._incarnate("fork", os.urandom(32))
    assert f.check_fence() == f1
    assert f.fence == f2 and f.fence_parts == ft._fence.parse_fence(f2)
    assert f.incarnation.kind == ("resume" if f1 else "fork")
    assert f.incarnation.generation == (2 if f1 else 1)
    assert f.check_fence() is False, "seen once"


def test_listen_unix(tmp_path):
    ep = str(tmp_path / "ep.sock")
    f = ft.Fiber("g/1/1", "unix://" + ep, b"", "", {})
    with f.listen() as s:
        assert s.family == socket.AF_UNIX and os.path.exists(ep)


def test_listen_handoff_refused():
    f = ft.Fiber("g/1/1", "/tmp/ep.sock", b"", "", {"FIBERD_HANDOFF_FD": "4"})
    assert f.kind == "handoff"
    with pytest.raises(ft.TemplateError, match="handoff fiber does not listen"):
        f.listen()


def test_serve_loop_reports_ready_checks_the_fence_and_hands_connections_over(tmp_path, monkeypatch):
    ext = FakeExt()
    monkeypatch.setattr(ft, "_ext", lambda: ext)
    ep = str(tmp_path / "ep.sock")
    f = ft.Fiber("g/1/1", ep, b"", "", {})
    f._incarnate("fork", os.urandom(32))
    srv = f.listen()
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(ep)
    client.sendall(b"hi\n")
    (tmp_path / "ep.sock.fence").write_text("g/1/2\n")
    served = []

    def handler(conn):
        served.append((conn.recv(16), f.fence, f.incarnation.kind))
        f.stopping.set()

    f.serve(handler, listener=srv, poll=0.05)
    client.close()
    assert ext.calls == [("ready",)]
    assert served == [(b"hi\n", "g/1/2", "resume")], "the fence file was read before the connection was served"
    assert not os.path.exists(ep), "the endpoint is unlinked on the way out"
