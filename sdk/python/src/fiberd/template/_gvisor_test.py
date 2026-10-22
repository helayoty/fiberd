"""The gVisor detection, the checkpoint read and the identity's environment, on fake files."""

from __future__ import annotations

import os

import pytest

from fiberd._testtable import table
from fiberd.template import _gvisor


def fake_proc(tmp_path, fd3):
    """A proc tree whose fd 3 is a socket, a file or absent, as fd3 says."""
    (tmp_path / "fd").mkdir(parents=True)
    if fd3 == "socket":
        os.symlink("socket:[12345]", tmp_path / "fd" / "3")
    elif fd3 == "file":
        os.symlink("/host/zygote.log", tmp_path / "fd" / "3")
    return str(tmp_path)


DETECT = [
    # fd 3, whether the checkpoint file exists, gVisor or not
    ("a control socket on a host with the file", "socket", True, False),
    ("a control socket and no file", "socket", False, False),
    ("no descriptor and the file", None, True, True),
    ("no descriptor and no file", None, False, False),
    ("a log at fd 3 and the file", "file", True, True),
]


@table(DETECT)
def test_detect(tmp_path, name, f0, f1, f2):
    checkpoint = tmp_path / "checkpoint"
    if f1:
        checkpoint.write_text("")
    assert _gvisor.detect(fake_proc(tmp_path / "proc", f0), 3, str(checkpoint)) is f2


CHECKPOINT = [
    # what the read answers, what the caller sees
    ("a restored sandbox", b"restore", "restore"),
    ("the original, with a newline", b"resume\n", "resume"),
    ("a failed checkpoint", b"error", "error"),
    ("nothing", b"", "error"),
]


@table(CHECKPOINT)
def test_read_checkpoint(tmp_path, name, f0, f1):
    """The answer lands after the open, as a checkpoint's does, and the read closes the descriptor."""
    path = tmp_path / "checkpoint"
    path.write_bytes(b"")
    fd = _gvisor.open_checkpoint(str(path))
    path.write_bytes(f0)
    assert _gvisor.read_checkpoint(fd) == f1
    with pytest.raises(OSError):
        os.fstat(fd)


def test_open_checkpoint_without_the_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        _gvisor.open_checkpoint(str(tmp_path / "missing"))


def test_mark_ready(tmp_path):
    _gvisor.mark_ready(str(tmp_path / "warm.ready"))
    assert (tmp_path / "warm.ready").exists()


KINDS = [
    ("a clone of the image is a restore", "clone", "restore"),
    ("a park comes back as a resume", "resume", "resume"),
    ("anything else is a restore", "", "restore"),
]


@table(KINDS)
def test_incarnation_kind(name, f0, f1):
    assert _gvisor.incarnation_kind(f0) == f1


ENVIRON = [
    # the spec environment, the session, the environment the fiber sees
    ("a named session over the warm environment", {"PATH": "/bin", "FIBERD_FENCE": "none"}, "conv 42",
     {"PATH": "/bin", "FIBERD_FENCE": "g/1/1", "FIBERD_ENDPOINT": "/host/f.sock", "FIBERD_SESSION": "conv 42"}),
    ("an anonymous fiber unsets a previous session", {"FIBERD_SESSION": "old"}, "",
     {"FIBERD_FENCE": "g/1/1", "FIBERD_ENDPOINT": "/host/f.sock"}),
]


@table(ENVIRON)
def test_fiber_environ(name, f0, f1, f2):
    assert _gvisor.fiber_environ(f0, "g/1/1", "/host/f.sock", f1) == f2
