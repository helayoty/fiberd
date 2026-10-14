"""The rule checks over a fake /proc tree."""

from __future__ import annotations

import os

import pytest

from fiberd._testtable import table
from fiberd.template import _rules
from fiberd.template._errors import TemplateError


def fake_proc(root, threads: dict[int, str], fds: dict[int, str]):
    """A /proc/self with the given task comms and fd targets."""
    for tid, comm in threads.items():
        d = root / "task" / str(tid)
        d.mkdir(parents=True)
        (d / "comm").write_text(comm + "\n")
    (root / "fd").mkdir()
    for fd, target in fds.items():
        os.symlink(target, root / "fd" / str(fd))
    return str(root)


THREADS = [
    ("one thread", {10: "python3"}, [_rules.Thread(10, "python3")]),
    ("sorted by tid", {30: "rayon", 10: "python3", 20: "OpenBLAS"},
     [_rules.Thread(10, "python3"), _rules.Thread(20, "OpenBLAS"), _rules.Thread(30, "rayon")]),
]


@table(THREADS)
def test_threads(tmp_path, name, f0, f1):
    assert _rules.threads(fake_proc(tmp_path, f0, {})) == f1


KINDS = [
    ("socket", "socket:[12345]", "a socket"),
    ("pipe", "pipe:[777]", "a pipe"),
    ("epoll", "anon_inode:[eventpoll]", "an epoll instance"),
    ("eventfd", "anon_inode:[eventfd]", "an eventfd"),
    ("timerfd", "anon_inode:[timerfd]", "a timerfd"),
    ("signalfd", "anon_inode:[signalfd]", "a signalfd"),
    ("inotify is not refused", "anon_inode:inotify", None),
    ("a memfd survives its descriptor", "/memfd:model (deleted)", None),
    ("a regular file", "/var/log/app.log", None),
    ("a device", "/dev/null", None),
]


@table(KINDS)
def test_descriptor_kind(name, f0, f1):
    assert _rules.descriptor_kind(f0) == f1


CHECK_THREADS = [
    # threads, own tid, mode, the refusal's text, whether a warning comes instead
    ("alone", {10: "python3"}, 10, "refuse", None, False),
    ("a C thread refused by comm", {10: "python3", 11: "OpenBLAS"}, 10, "refuse", "OpenBLAS (tid 11)", False),
    ("two threads, both named", {10: "python3", 11: "rayon", 12: "python3"}, 10, "refuse", "rayon (tid 11), python3 (tid 12)", False),
    ("warn is the escape hatch", {10: "python3", 11: "torch"}, 10, "warn", None, True),
]


@table(CHECK_THREADS)
def test_check_threads(tmp_path, name, f0, f1, f2, f3, f4):
    proc = fake_proc(tmp_path, f0, {})
    if f3:
        with pytest.raises(TemplateError, match="serve\\(\\) needs one thread") as e:
            _rules.check_threads(proc, own_tid=f1, mode=f2)
        assert f3 in str(e.value)
        assert 'threads="warn"' in str(e.value)
    elif f4:
        with pytest.warns(RuntimeWarning, match="needs one thread"):
            _rules.check_threads(proc, own_tid=f1, mode=f2)
    else:
        _rules.check_threads(proc, own_tid=f1, mode=f2)


CHECK_FDS = [
    # fds, the refusal's text, whether a warning comes instead
    ("stdio and the control socket alone", {0: "/dev/null", 1: "/tmp/zygote.log", 2: "/tmp/zygote.log", 3: "socket:[1]"}, None, False),
    ("a socket", {3: "socket:[1]", 5: "socket:[99]"}, "fd 5 is a socket (socket:[99])", False),
    ("a pipe and an epoll, both named", {4: "pipe:[2]", 6: "anon_inode:[eventpoll]"}, "fd 4 is a pipe (pipe:[2]); fd 6 is an epoll instance", False),
    ("an eventfd", {7: "anon_inode:[eventfd]"}, "an eventfd", False),
    ("a memory map's descriptor is fine", {8: "/memfd:weights (deleted)"}, None, False),
    ("a regular file is a warning", {9: "/var/log/app.log"}, None, True),
    ("a device is not", {9: "/dev/urandom"}, None, False),
]


@table(CHECK_FDS)
def test_check_descriptors(tmp_path, name, f0, f1, f2):
    proc = fake_proc(tmp_path, {10: "python3"}, f0)
    if f1:
        with pytest.raises(TemplateError, match="serve\\(\\) needs no open socket") as e:
            _rules.check_descriptors(proc)
        assert f1 in str(e.value)
    elif f2:
        with pytest.warns(RuntimeWarning, match="regular files open at serve"):
            _rules.check_descriptors(proc)
    else:
        _rules.check_descriptors(proc)


SIMPLE = [
    ("main thread", _rules.check_main_thread, True, None),
    ("not the main thread", _rules.check_main_thread, False, "main thread"),
    ("gil on", _rules.check_gil, True, None),
    ("free-threaded build", _rules.check_gil, False, "needs the GIL"),
    ("init ran", _rules.check_init, True, None),
    ("init skipped", _rules.check_init, False, "init\\(\\) did not run"),
]


@table(SIMPLE)
def test_simple_checks(name, f0, f1, f2):
    if f2 is None:
        f0(f1)
    else:
        with pytest.raises(TemplateError, match=f2):
            f0(f1)


AT_INIT = [
    ("alone", {10: "python3"}, None),
    ("a thread before init", {10: "python3", 11: "grpc_global_tim"},
     "init\\(\\) runs before any thread, and this process already has 2: python3 \\(tid 10\\), grpc_global_tim \\(tid 11\\)"),
]


@table(AT_INIT)
def test_check_threads_at_init(tmp_path, name, f0, f1):
    proc = fake_proc(tmp_path, f0, {})
    if f1 is None:
        _rules.check_threads_at_init(proc)
    else:
        with pytest.raises(TemplateError, match=f1):
            _rules.check_threads_at_init(proc)
