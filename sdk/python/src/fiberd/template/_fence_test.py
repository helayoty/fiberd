"""The fence parser, the endpoint forms and the fence file."""

from __future__ import annotations

import pytest

from fiberd._testtable import table
from fiberd.template import _fence
from fiberd.template._errors import TemplateError

PARSE = [
    ("plain", "grant/3/7", _fence.Fence("grant", 3, 7)),
    ("a grant uid with a slash keeps it", "tenant/grant/3/7", _fence.Fence("tenant/grant", 3, 7)),
    ("two fields", "grant/3", None),
    ("an epoch that is no number", "grant/x/7", None),
    ("an empty grant", "/3/7", None),
]


@table(PARSE)
def test_parse_fence(name, f0, f1):
    if f1 is None:
        with pytest.raises(TemplateError, match="is not grant/epoch/seq"):
            _fence.parse_fence(f0)
    else:
        got = _fence.parse_fence(f0)
        assert got == f1
        assert str(got) == f0


KINDS = [
    ("a unix path", "/run/fiberd/g/1-1.sock", False, "unix"),
    ("a unix url", "unix:///run/fiberd/g/1-1.sock", False, "unix"),
    ("tcp", "tcp://10.0.0.1:9000", False, "tcp"),
    ("a handoff channel in the environment wins", "/run/fiberd/g/1-1.sock", True, "handoff"),
]


@table(KINDS)
def test_endpoint_kind(name, f0, f1, f2):
    assert _fence.endpoint_kind(f0, f1) == f2


TCP = [
    ("ipv4", "tcp://10.0.0.1:9000", (False, 9000)),
    ("ipv6 bracketed", "tcp://[fd00::1]:9000", (True, 9000)),
    ("no port", "tcp://10.0.0.1", None),
    ("a port that is no number", "tcp://10.0.0.1:x", None),
]


@table(TCP)
def test_tcp_bind(name, f0, f1):
    if f1 is None:
        with pytest.raises(TemplateError, match="is not tcp://host:port"):
            _fence.tcp_bind(f0)
    else:
        assert _fence.tcp_bind(f0) == f1


FILES = [
    ("beside a unix endpoint", "/run/fiberd/g/1-1.sock", "unix", "/run/fiberd/g/1-1.sock.fence"),
    ("beside a unix url", "unix:///run/fiberd/g/1-1.sock", "unix", "/run/fiberd/g/1-1.sock.fence"),
    ("a tcp fiber reads its birth fence's file in its cwd", "tcp://10.0.0.1:9000", "tcp", "1-1.fence"),
    ("so does a handoff fiber", "/run/fiberd/g/1-1.sock", "handoff", "1-1.fence"),
]


@table(FILES)
def test_fence_file(name, f0, f1, f2):
    assert _fence.fence_file(f0, f1, _fence.Fence("g", 1, 1)) == f2


LIVE = [
    ("a published fence wins", "g/1/2\n", "g/1/2"),
    ("an empty file is the birth fence", "", "g/1/1"),
    ("a missing file is the birth fence", None, "g/1/1"),
]


@table(LIVE)
def test_live_fence(tmp_path, name, f0, f1):
    path = tmp_path / "ep.sock.fence"
    if f0 is not None:
        path.write_text(f0)
    assert _fence.live_fence(str(path), "g/1/1") == f1
