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


NOT_HOSTPORT = "is not tcp://host:port"
NO_LITERAL = "names no IP literal to bind"

TCP = [
    # the endpoint, what tcp_bind returns, or the refusal it raises
    ("ipv4", "tcp://10.0.0.1:9000", (False, "10.0.0.1", 9000), None),
    ("ipv6 bracketed", "tcp://[fd00::1]:9000", (True, "fd00::1", 9000), None),
    ("no port", "tcp://10.0.0.1", None, NOT_HOSTPORT),
    ("a port that is no number", "tcp://10.0.0.1:x", None, NOT_HOSTPORT),
    ("a hostname, which fiberd never writes", "tcp://fiber.example:9000", None, NO_LITERAL),
    ("an ipv4 literal in brackets", "tcp://[10.0.0.1]:9000", None, NO_LITERAL),
    ("an ipv6 literal without brackets, which fiberd's endpoint package refuses too", "tcp://fd00::1:9000", None, NO_LITERAL),
    ("an empty host", "tcp://:9000", None, NO_LITERAL),
    ("empty brackets", "tcp://[]:9000", None, NO_LITERAL),
]


@table(TCP)
def test_tcp_bind(name, f0, f1, f2):
    if f2 is not None:
        with pytest.raises(TemplateError, match=f2):
            _fence.tcp_bind(f0)
    else:
        assert _fence.tcp_bind(f0) == f1
