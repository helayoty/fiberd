"""The fence parser and the endpoint forms."""

from __future__ import annotations

import pytest

from fiberd._testtable import table
from fiberd.template import _fence
from fiberd.template._errors import TemplateError

PARSE = [
    # the fence, its parts, whether str() gives the fence back
    ("plain", "grant/3/7", _fence.Fence("grant", 3, 7), True),
    ("a grant uid with a slash keeps it", "tenant/grant/3/7", _fence.Fence("tenant/grant", 3, 7), True),
    ("the gVisor footprint probe's fence is served, not refused", "probe", _fence.Fence("probe", 0, 0), False),
    ("two fields", "grant/3", _fence.Fence("grant/3", 0, 0), False),
    ("an epoch that is no number", "grant/x/7", _fence.Fence("grant/x/7", 0, 0), False),
    ("an empty grant", "/3/7", _fence.Fence("/3/7", 0, 0), False),
]


@table(PARSE)
def test_parse_fence(name, f0, f1, f2):
    got = _fence.parse_fence(f0)
    assert got == f1
    assert (str(got) == f0) is f2


KINDS = [
    ("a unix path", "/run/fiberd/g/1-1.sock", "unix"),
    ("a unix url", "unix:///run/fiberd/g/1-1.sock", "unix"),
    ("tcp", "tcp://10.0.0.1:9000", "tcp"),
    ("the handoff endpoint", "handoff", "handoff"),
]


@table(KINDS)
def test_endpoint_kind(name, f0, f1):
    assert _fence.endpoint_kind(f0) == f1


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
