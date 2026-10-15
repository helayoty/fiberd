"""The endpoint parser, and a fiber dialed directly and through the handoff router."""

from __future__ import annotations

import dataclasses
import ssl
import tempfile

import pytest

from fiberd._testtable import table
from fiberd.client import Fence, Fiber, KeyMismatch, Kind, NotHandoff
from fiberd.client import _testhome as th
from fiberd.client._fiber import parse_endpoint

ENDPOINTS = [
    # the endpoint, what it parses to or the error wanted
    ("a unix url", "unix:///var/lib/fiberd/run/g/1-1.sock", ("unix", "/var/lib/fiberd/run/g/1-1.sock")),
    ("ipv4", "tcp://10.0.0.7:30012", ("tcp", ("10.0.0.7", 30012))),
    ("ipv6 bracketed", "tcp://[fd00::7]:30012", ("tcp", ("fd00::7", 30012))),
    ("a host name", "tcp://home:7443", ("tcp", ("home", 7443))),
    ("tcp without a port", "tcp://10.0.0.7", ValueError),
    ("a bare path", "/run/fiberd/g.sock", ValueError),
    ("another scheme", "http://home:80", ValueError),
    ("empty", "", ValueError),
]


@table(ENDPOINTS)
def test_parse_endpoint(name, f0, f1):
    if f1 is ValueError:
        with pytest.raises(ValueError, match="is not unix:///path or tcp://host:port"):
            parse_endpoint(f0)
    else:
        assert parse_endpoint(f0) == f1


def _fiber(endpoint: str, **kw) -> Fiber:
    return Fiber(id="g1/1/1", endpoint=endpoint, fence=Fence("g1", 1, 1), kind=Kind.CREATE, session="", home="home:7443", **kw)


DIAL = [
    # the endpoint kind, what the fiber answers to "ping"
    ("a unix endpoint", "unix", b"pong\n"),
    ("a tcp endpoint", "tcp", b"pong\n"),
]


@table(DIAL)
def test_dial(name, f0, f1):
    endpoint = "unix://" + tempfile.mkdtemp(prefix="fiberd-client-") + "/f.sock" if f0 == "unix" else "tcp://"
    fib = th.DirectFiber(endpoint)
    try:
        with _fiber(fib.endpoint).dial(timeout=5) as s:
            s.sendall(b"ping\n")
            assert s.recv(16) == f1
    finally:
        fib.close()


def test_dial_refuses_a_handoff_fiber():
    with pytest.raises(ValueError, match="dial_handoff, not dial"):
        _fiber("tcp://127.0.0.1:1", routing_key="k", server_key_sha256="x", server_cert=b"c").dial()


@pytest.fixture(scope="module")
def handoff():
    """A handoff fiber holding one identity, accepting one caller, and the certificates around it."""
    # A fiber's certificate is for server use, as pkg/handoff issues it, and the client's verification checks that purpose.
    identity, other = th.issue("fiber", server=True), th.issue("other-fiber", server=True)
    caller, stranger = th.issue("caller"), th.issue("stranger")
    fib = th.HandoffFiber(identity, caller)
    d = tempfile.mkdtemp(prefix="fiberd-client-")
    routed = _fiber(fib.endpoint, routing_key="k", server_key_sha256=identity.pin, server_cert=identity.der)
    yield dict(routed=routed, other=other, caller=caller.write(d, "caller"), stranger=stranger.write(d, "stranger"))
    fib.close()


HANDOFF = [
    # how the fiber is changed (OTHER is the other fiber's value), who dials, the reply wanted, the error wanted
    ("routed by key, caller accepted, certificate and key pinned", {}, "caller", b"k.fiberd hi\n", None),
    ("a direct fiber has no route", dict(routing_key=""), "caller", None, NotHandoff),
    ("a handoff endpoint must be tcp", dict(endpoint="unix:///tmp/x.sock"), "caller", None, NotHandoff),
    ("a fiber without a certificate to pin is refused before dialing", dict(server_cert=b""), "caller", None, ValueError),
    ("a fiber presenting another certificate fails the handshake", dict(server_cert="OTHER"), "caller", None, ssl.SSLCertVerificationError),
    ("a fiber whose pin names another key is refused before a byte is sent", dict(server_key_sha256="OTHER"), "caller", None, KeyMismatch),
    ("the fiber refuses another caller", {}, "stranger", None, OSError),
]


@table(HANDOFF)
def test_dial_handoff(handoff, name, f0, f1, f2, f3):
    other = {"server_key_sha256": handoff["other"].pin, "server_cert": handoff["other"].der}
    f = dataclasses.replace(handoff["routed"], **{k: other[k] if v == "OTHER" else v for k, v in f0.items()})
    cert, key = handoff[f1]
    if f3 is not None:
        with pytest.raises(f3):
            with f.dial_handoff(cert, key, timeout=5) as s:
                s.sendall(b"hi\n")
                assert s.recv(64) == b""
        return
    with f.dial_handoff(cert, key, timeout=5) as s:
        s.sendall(b"hi\n")
        assert s.recv(64) == f2
