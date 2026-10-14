"""The reference template's line protocol, over a fake fiber and the warm heap."""

from __future__ import annotations

import socket
import sys
import types

import pytest

import fiberd.template as ft
from fiberd._testtable import table
from fiberd.template import _cli, ref


def state(tmp_path, payload=b'{"task":1}', session="conv 42"):
    f = ft.Fiber("g/1/1", str(tmp_path / "ep.sock"), payload, session, {})
    return ref.State(ref.Warm(1), f)


ANSWERS = [
    ("ping", "ping", "pong"),
    ("incr counts", "incr", "1"),
    ("fence", "fence", "g/1/1"),
    ("session", "session", "conv 42"),
    ("payload in hex", "payload", b'{"task":1}'.hex()),
    ("dirty touches the heap", "dirty 8192", "ok 8192"),
    ("dirty is capped at the heap", "dirty 99999999", f"ok {1 << 20}"),
    ("getenv of a missing name", "getenv FIBERD_NOPE", "-"),
    ("status of a missing key", "status NoSuchKey", "-"),
    ("read of a missing file", "read /nonexistent/x", "-"),
    ("wopen of a missing file", "wopen /nonexistent/x", "ENOENT"),
    ("stat of a missing path", "stat /nonexistent", "ENOENT"),
    ("no engine", "reserve 1024", "err no engine"),
    ("devfree without an engine", "devfree", "err no engine"),
    ("unknown", "frobnicate", "err unknown command"),
]


@table(ANSWERS)
def test_answer(tmp_path, name, f0, f1):
    assert ref.answer(state(tmp_path), f0) == f1


def test_counter_is_per_state(tmp_path):
    st = state(tmp_path)
    assert [ref.answer(st, c) for c in ("incr", "incr", "get")] == ["1", "2", "2"]
    assert ref.answer(state(tmp_path), "get") == "0"


PAYLOAD_ANSWERS = [
    ("none", b"", "", "-"),
    ("short", b"ab", "", "6162"),
    ("longer than the reply line", b"x" * 128, "", "-"),
    ("anonymous", b"", "", "-"),
]


@table(PAYLOAD_ANSWERS)
def test_payload_and_session(tmp_path, name, f0, f1, f2):
    st = state(tmp_path, payload=f0, session=f1)
    assert ref.answer(st, "payload") == f2
    assert ref.answer(st, "session") == "-"


def test_random_and_getrandom_draw(tmp_path):
    st = state(tmp_path)
    a, b = ref.answer(st, "random"), ref.answer(st, "random")
    assert a.isdigit() and b.isdigit()
    assert len(ref.answer(st, "getrandom")) == 16


def test_file_probes(tmp_path):
    (tmp_path / "f").write_text("first\nsecond\n")
    (tmp_path / "d").mkdir()
    st = state(tmp_path)
    assert ref.answer(st, f"read {tmp_path / 'f'}") == "first"
    assert ref.answer(st, f"wopen {tmp_path / 'f'}") == "ok"
    assert ref.answer(st, f"stat {tmp_path / 'f'}") == "file"
    assert ref.answer(st, f"stat {tmp_path / 'd'}") == "dir"
    assert ref.answer(st, f"mkdir {tmp_path / 'new'}") == "ok"
    assert not (tmp_path / "new").exists(), "the directory is removed again"
    assert ref.answer(st, f"rdonly {tmp_path}") == "rw"
    assert ref.answer(st, f"mkdir {tmp_path / 'nope' / 'x'}") == "ENOENT"


def test_getenv_sees_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("FIBERD_FENCE", "g/1/1")
    assert ref.answer(state(tmp_path), "getenv FIBERD_FENCE") == "g/1/1"


PAYLOADS = [
    ("empty", b"", {}),
    ("json", b'{"dirty_bytes": 4096}', {"dirty_bytes": 4096}),
    ("not json", b"\xff", {}),
    ("json that is no object", b"[1]", {}),
]


@table(PAYLOADS)
def test_payload_dict(name, f0, f1):
    assert ref.payload_dict(f0) == f1


def test_handle_answers_each_line(tmp_path):
    a, b = socket.socketpair()
    b.sendall(b"ping\nincr\r\nget\n")
    b.shutdown(socket.SHUT_WR)
    ref.handle(a, state(tmp_path))
    assert b.recv(64) == b"pong\n1\n1\n"
    a.close()
    b.close()


def test_errname():
    assert ref.errname(13) == "EACCES"
    assert ref.errname(9999) == "errno 9999"


RESOLVE = [
    ("module and name", "agentmod:run", "run"),
    ("the default name", "agentmod", "on_fiber"),
    ("no such name", "agentmod:nope", None),
    ("no module", ":on_fiber", None),
]


@table(RESOLVE)
def test_cli_resolve(monkeypatch, name, f0, f1):
    mod = types.ModuleType("agentmod")
    mod.run = lambda f: 0
    mod.on_fiber = lambda f: 1
    monkeypatch.setitem(sys.modules, "agentmod", mod)
    if f1 is None:
        with pytest.raises(ft.TemplateError):
            _cli.resolve(f0)
    else:
        assert _cli.resolve(f0) is getattr(mod, f1)


def test_counter_lives_in_the_warm_state(tmp_path):
    """A park and resume keeps the counter on every backend, so it is the warm state's, not the connection's."""
    warm = ref.Warm(1)
    a = ref.State(warm, ft.Fiber("g/1/1", str(tmp_path / "a.sock"), b"", "", {}))
    b = ref.State(warm, ft.Fiber("g/1/2", str(tmp_path / "b.sock"), b"", "", {}))
    assert [ref.answer(a, "incr"), ref.answer(b, "incr"), ref.answer(b, "get")] == ["1", "2", "2"]


DIRTY = [
    # the backend, the heap pages touched, the fresh bytes kept
    ("a fork writes into the warm heap", "fork", 2, 0),
    ("a restored sandbox allocates, since its heap is already its own", "gvisor", 0, 8192),
]


@table(DIRTY)
def test_dirty_by_backend(tmp_path, name, f0, f1, f2):
    warm = ref.Warm(1)
    st = ref.State(warm, ft.Fiber("g/1/1", str(tmp_path / "ep.sock"), b"", "", {}, backend=f0))
    assert ref.answer(st, "dirty 8192") == "ok 8192"
    assert sum(1 for i in range(0, 8192, 4096) if warm.heap[i] != (i >> 12) & 0xFF) == f1
    assert sum(len(b) for b in warm.grown) == f2


class FakeFiber:
    """A Fiber whose listen, ready and serve are recorded, for on_fiber's ordering."""

    def __init__(self, payload, backend):
        self.payload = payload
        self.backend = backend
        self.calls = []

    def listen(self):
        self.calls.append("listen")
        return "srv"

    def ready(self):
        self.calls.append("ready")

    def serve(self, handler, listener=None):
        self.calls.append(("serve", listener))


ON_FIBER = [
    # the payload, the backend, the calls wanted, the fd 3 writes wanted
    ("plain", b"", "fork", ["listen", "ready", ("serve", "srv")], []),
    ("exit after ready", b'{"exit_after_ready": 1}', "fork", ["listen", "ready"], []),
    ("ready misuse writes the pipe on a fork", b'{"ready_misuse": 1}', "fork", ["listen", "ready", ("serve", "srv")], [(3, b"x")]),
    ("ready misuse is nothing on gVisor, which has no pipe", b'{"ready_misuse": 1}', "gvisor", ["listen", "ready", ("serve", "srv")], []),
]


@table(ON_FIBER)
def test_on_fiber_order(monkeypatch, name, f0, f1, f2, f3):
    writes = []
    monkeypatch.setattr(ref.os, "write", lambda fd, data: writes.append((fd, data)))
    f = FakeFiber(f0, f1)
    assert ref.on_fiber(ref.Warm(1), f) == 0
    assert f.calls == f2 and writes == f3


def test_reopen_stdio_dups_the_log_over_stdout_and_stderr(tmp_path, monkeypatch):
    dups = []
    monkeypatch.setattr(ref.os, "dup2", lambda a, b: dups.append(b))
    ref.reopen_stdio(str(tmp_path / "zygote.log"))
    assert dups == [0, 1, 2] and (tmp_path / "zygote.log").exists()


def test_main_takes_log_as_a_launcher_passes_it(monkeypatch):
    """runc appends --log /host/zygote.log to the template command, so the template must take it."""
    monkeypatch.setattr(ft, "init", lambda: None)
    monkeypatch.setattr(ft, "serve", lambda on_fiber: 0)
    seen = []
    monkeypatch.setattr(ref, "reopen_stdio", lambda path: seen.append(path))
    assert ref.main(["--heap-mb", "1", "--log", "/host/zygote.log"]) == 0
    assert seen == ["/host/zygote.log"]
