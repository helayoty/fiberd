"""A unit test starts no process and forks nothing.

Every test runs with os.fork, the spawn and exec calls, subprocess.Popen
and the C binding replaced by raisers, so a test that reaches for one
fails at once. The integration harness under tests/integration/python is
where a real fiberd and a real template run. This file is not shipped
(see setup.py).
"""

from __future__ import annotations

import os
import subprocess

import pytest

import fiberd.template as ft


def _refuse(*_args, **_kwargs):
    raise AssertionError("a unit test starts no process; see tests/integration/python for the harness")


class _NoExt:
    """The C binding's shape, every call refused."""

    ABI_VERSION = 10

    def __getattr__(self, name):
        return _refuse


@pytest.fixture(autouse=True)
def _no_processes(monkeypatch):
    for name in ("fork", "forkpty", "posix_spawn", "posix_spawnp", "execv", "execve", "execvp", "execvpe",
                 "spawnv", "spawnve", "spawnvp", "spawnvpe", "system"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, _refuse)
    monkeypatch.setattr(subprocess, "Popen", _refuse)
    monkeypatch.setattr(ft, "_ext", lambda: _NoExt())
    monkeypatch.setattr(ft, "_PLATFORM", "linux")
    monkeypatch.setattr(ft, "_inited", False)
    monkeypatch.setattr(ft, "_hooks", [])
    monkeypatch.setattr(ft, "_randoms", [])
