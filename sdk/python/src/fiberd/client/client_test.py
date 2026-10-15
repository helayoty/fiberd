"""The sync Client against a home in this process, every call, every miss, the TLS paths and what never leaks."""

from __future__ import annotations

import importlib
import logging
import sys
import tempfile
import time

import grpc
import pytest

import fiberd.client
from fiberd._testtable import table
from fiberd.client import Client, Deferred, Fence, Kind, NotFound, Shed, TierGap
from fiberd.client import _testhome as th

TOKEN = "eyJhbGciOiJFUzI1NiJ9.secret-grant-token.signature"


@pytest.fixture
def home():
    """A plaintext home on loopback, stopped after the test."""
    h = th.Home()
    server, addr = h.serve()
    h.addr = addr
    yield h
    server.stop(None)


@pytest.fixture
def client(home):
    with Client.dial(home.addr) as c:
        yield c


# A session runs its whole life in order, as the Go client's test has it.
LIFE = [
    # the step, the kind wanted, the fence seq wanted, whether it is the first clone's fiber, the error wanted
    ("the first clone of a session creates under fence 1", "clone", Kind.CREATE, 1, False, None),
    ("a second clone attaches to the same fiber", "clone", Kind.ATTACH, 1, True, None),
    ("the fiber parks", "park", None, None, False, None),
    ("the parked session resumes under fence 2", "clone", Kind.RESUME, 2, False, None),
    ("the resumed fiber releases", "release", None, None, False, None),
    ("releasing it twice is NotFound", "release", None, None, False, NotFound),
]


def test_clone_attach_park_resume(client):
    first = last = None
    for name, step, kind, seq, same, err in LIFE:
        if err is not None:
            with pytest.raises(err, match=last.id):
                client.release(last)
            continue
        if step == "park":
            client.park(first, sync=True)
            continue
        if step == "release":
            client.release(last, discard=True)
            continue
        f = client.clone(TOKEN, "S", deadline=1)
        assert (f.kind, f.fence.seq, f.session, f.home) == (kind, seq, "S", client.target), name
        assert f.id == str(f.fence) and f.endpoint and not f.handoff, name
        if same:
            assert f.id == first.id, name
        first = first or f
        last = f


MISSES = [
    # the home's state, the exception wanted, what it must say and carry
    ("a full grant with the issuer reachable is Deferred from the issuer", dict(fiber_max=0), Deferred,
     "deferred: grant g1 is at fibers.max", dict(issuer=th.ISSUER, preferred_home="")),
    ("deferred names where the session lives", dict(fiber_max=0, preferred_home="home-b"), Deferred,
     "deferred: grant g1 is at fibers.max (session lives on home-b)", dict(preferred_home="home-b")),
    ("a full grant with the issuer unreachable is Shed with its retry", dict(fiber_max=0, issuer_reachable=False, retry_after=3), Shed,
     "shed: grant g1 is at fibers.max, retry after 3s", dict(retry_after=3.0, issuer=th.ISSUER)),
    ("min_tier above the home is TierGap, not a miss", dict(tier_gap="grant needs FIBER_SNAPSHOT, home offers FIBER_CHECKPOINT"), TierGap,
     "tier gap: grant needs FIBER_SNAPSHOT, home offers FIBER_CHECKPOINT", {}),
    ("another caller's grant is the raw Unauthenticated", dict(bound_to=b"someone else"), grpc.RpcError, "", {}),
]


@table(MISSES)
def test_misses_are_typed(home, client, name, f0, f1, f2, f3):
    for k, v in f0.items():
        setattr(home, k, v)
    with pytest.raises(f1) as e:
        client.clone(TOKEN)
    if f2:
        assert str(e.value) == f2
    for k, v in f3.items():
        assert getattr(e.value, k) == v
    if f1 is grpc.RpcError:
        assert e.value.code() == grpc.StatusCode.UNAUTHENTICATED


WIRE = [
    # the clone's arguments, what the request must carry
    ("a token as a string", dict(token=TOKEN), dict(grant_jwt=TOKEN, session="", payload=b"", deadline=False)),
    ("a token from a callable, for a caller that refreshes it", dict(token=lambda: TOKEN + "2"), dict(grant_jwt=TOKEN + "2")),
    ("session, payload and a deadline in the future", dict(token=TOKEN, session="conv 42", payload=b'{"task":1}', deadline=0.5),
     dict(session="conv 42", payload=b'{"task":1}', deadline=True)),
    ("no deadline leaves the field unset for fiberd's default", dict(token=TOKEN, deadline=0), dict(deadline=False)),
]


@table(WIRE)
def test_clone_request(home, client, name, f0, f1):
    before = time.time()
    client.clone(**f0)
    req = home.last_clone
    for k, v in f1.items():
        if k == "deadline":
            assert req.HasField("deadline") is v, name
            if v:
                assert before + f0["deadline"] <= req.deadline.ToNanoseconds() / 1e9 <= time.time() + f0["deadline"]
        else:
            assert getattr(req, k) == v, name


def test_handoff_fields(home, client):
    home.routing_key, home.server_key_sha256, home.server_cert = "k", "PIN", b"CERT"
    f = client.clone(TOKEN)
    assert (f.routing_key, f.server_key_sha256, f.server_cert, f.handoff) == ("k", "PIN", b"CERT", True)


@pytest.fixture(scope="module")
def tls_home():
    """A mutual-TLS home whose one grant is bound to the owner's certificate, with the PEM files on disk."""
    d = tempfile.mkdtemp(prefix="fiberd-client-")
    ca, other_ca = th.issue("ca", ca=True), th.issue("other-ca", ca=True)
    owner, other = th.issue("owner", ca), th.issue("other", ca)
    h = th.Home(bound_to=owner.cert_pem)
    server, addr = h.serve("localhost:0", th.server_credentials(ca, th.issue("fiberd", ca, server=True)))
    yield dict(addr=addr, owner=owner.write(d, "owner"), other=other.write(d, "other"), ca=ca.write(d, "ca")[0], other_ca=other_ca.write(d, "other-ca")[0])
    server.stop(None)


DIAL = [
    # how the client dials, the gRPC code the clone ends with
    ("the bound caller clones over mutual TLS", lambda t: Client.dial_tls(t["addr"], *t["owner"], t["ca"]), grpc.StatusCode.OK),
    ("another caller over mutual TLS is Unauthenticated", lambda t: Client.dial_tls(t["addr"], *t["other"], t["ca"]), grpc.StatusCode.UNAUTHENTICATED),
    ("a home under another CA is Unavailable", lambda t: Client.dial_tls(t["addr"], *t["owner"], t["other_ca"]), grpc.StatusCode.UNAVAILABLE),
    ("plaintext to a TLS home fails the call", lambda t: Client.dial(t["addr"]), grpc.StatusCode.UNAVAILABLE),
]


@table(DIAL)
def test_dial_tls(tls_home, name, f0, f1):
    with f0(tls_home) as c:
        assert c.tls is (f0 is not DIAL[3][1])
        if f1 == grpc.StatusCode.OK:
            assert c.clone(TOKEN, timeout=10).fence.grant_uid == "g1"
            return
        with pytest.raises(grpc.RpcError) as e:
            c.clone(TOKEN, timeout=10)
        assert e.value.code() == f1


def test_dial_tls_reads_the_files_once(tls_home, tmp_path):
    """The key is read when the client is made and not held by it."""
    cert, key = tls_home["owner"]
    copy = tmp_path / "key.pem"
    copy.write_bytes(open(key, "rb").read())
    with Client.dial_tls(tls_home["addr"], cert, copy, tls_home["ca"]) as c:
        copy.write_bytes(b"gone")
        assert c.clone(TOKEN, timeout=10).kind == Kind.CREATE
        assert "gone" not in repr(c) and str(copy) not in repr(c)


WATCH = [
    # how the watch ends, the error wanted
    ("the caller stopping iteration is a clean end", "break", None),
    ("the home stopping is an error", "stop", grpc.RpcError),
    ("a closed client cannot watch", "closed", ValueError),
]


@table(WATCH)
def test_watch_ends(name, f0, f1):
    h = th.Home()
    server, addr = h.serve()
    c = Client.dial(addr)
    c.clone(TOKEN)
    if f0 == "closed":
        c.close()
        with pytest.raises(ValueError):
            next(iter(c.watch()))
        server.stop(None)
        return
    seen = []
    with pytest.raises(f1) if f1 else _nothing():
        for st in c.watch(timeout=10):
            seen.append(st)
            if f0 == "break":
                break
            server.stop(None)
    assert seen and seen[0].grant_uid == "g1" and seen[0].running == 1 and seen[0].latest == Fence("g1", 1, 1)
    c.close()
    server.stop(None)


class _nothing:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def test_watch_streams_status(home, client):
    client.clone(TOKEN)
    client.clone(TOKEN)
    for st in client.watch(timeout=10):
        if st.running == 2:
            return
    pytest.fail("no status with running=2")


def _raised(c, h, **state) -> str:
    """Every text a clone that fails under the home's state leaves behind."""
    for k, v in state.items():
        setattr(h, k, v)
    try:
        c.clone(TOKEN)
    except Exception as e:
        return repr(e) + str(e) + repr(e.__traceback__)
    return ""


REDACT = [
    # what happens, giving the texts that must not carry the token
    ("a repr", lambda c, h: repr(c)),
    ("a clone that misses", lambda c, h: _raised(c, h, fiber_max=0)),
    ("a clone that is refused", lambda c, h: _raised(c, h, bound_to=b"x")),
    ("a fiber", lambda c, h: repr(c.clone(TOKEN, "S", payload=TOKEN.encode()))),
]


@table(REDACT)
def test_token_never_shows(home, client, caplog, name, f0):
    caplog.set_level(logging.DEBUG, logger="fiberd.client")
    text = f0(client, home)
    assert "secret-grant-token" not in text, name
    assert "secret-grant-token" not in caplog.text, name
    assert caplog.text or name == "a repr"


def test_no_environment_fallback(monkeypatch, home):
    """Nothing in the client reads the environment for a token or a key."""
    monkeypatch.setenv("FIBERD_GRANT", TOKEN)
    monkeypatch.setenv("FIBERD_ADDR", home.addr)
    with Client.dial(home.addr) as c:
        with pytest.raises(grpc.RpcError) as e:
            c.clone("")
        assert e.value.code() == grpc.StatusCode.UNAUTHENTICATED


TEXT = [
    ("shed says why and when to retry", Shed(retry_after=2, reason="grant g is at pids.max"), "shed: grant g is at pids.max, retry after 2s"),
    ("deferred says why", Deferred(reason="grant full"), "deferred: grant full"),
    ("deferred names where the session lives", Deferred(reason="too large", preferred_home="home-b"), "deferred: too large (session lives on home-b)"),
    ("a tier gap says why", TierGap("needs CHECKPOINT"), "tier gap: needs CHECKPOINT"),
    ("a fence is grant, epoch and seq", Fence("g1", 3, 7), "g1/3/7"),
]


@table(TEXT)
def test_text(name, f0, f1):
    assert str(f0) == f1


def test_import_names_the_extra(monkeypatch):
    """Without grpcio the import fails with the extra to install, not an unrelated error."""
    monkeypatch.setitem(sys.modules, "grpc", None)
    with pytest.raises(ImportError, match=r"pip install 'fiberd\[client\]'"):
        importlib.reload(fiberd.client)
    monkeypatch.undo()
    importlib.reload(fiberd.client)
