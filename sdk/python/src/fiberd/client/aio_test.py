"""The grpc.aio twin against the same home in this process."""

from __future__ import annotations

import asyncio
import tempfile

import grpc
import pytest

from fiberd._testtable import table
from fiberd.client import Deferred, Kind, NotFound, Shed, TierGap
from fiberd.client import _testhome as th
from fiberd.client.aio import Client

TOKEN = "eyJhbGciOiJFUzI1NiJ9.secret-grant-token.signature"


@pytest.fixture
def home():
    h = th.Home()
    server, addr = h.serve()
    h.addr = addr
    yield h
    server.stop(None)


def test_clone_attach_park_resume(home):
    async def life():
        async with Client.dial(home.addr) as c:
            assert repr(c) == f"aio.Client(target={home.addr!r}, tls=False)"
            first = await c.clone(TOKEN, "S", deadline=1, payload=b"x")
            again = await c.clone(TOKEN, "S")
            await c.park(first)
            resumed = await c.clone(TOKEN, "S")
            await c.release(resumed, discard=True)
            with pytest.raises(NotFound):
                await c.release(resumed.id)
            return first, again, resumed

    first, again, resumed = asyncio.run(life())
    assert (first.kind, first.fence.seq, first.session) == (Kind.CREATE, 1, "S")
    assert (again.kind, again.id) == (Kind.ATTACH, first.id)
    assert (resumed.kind, resumed.fence.seq) == (Kind.RESUME, 2)
    assert home.last_clone.session == "S" and home.last_clone.payload == b""


MISSES = [
    # the home's state, the exception wanted, what it carries
    ("a full grant with the issuer reachable is Deferred", dict(fiber_max=0, preferred_home="home-b"), Deferred, dict(preferred_home="home-b")),
    ("a full grant with the issuer unreachable is Shed", dict(fiber_max=0, issuer_reachable=False, retry_after=2), Shed, dict(retry_after=2.0)),
    ("min_tier above the home is TierGap", dict(tier_gap="needs FIBER_SNAPSHOT"), TierGap, dict(reason="needs FIBER_SNAPSHOT")),
    ("another caller's grant is the raw AioRpcError", dict(bound_to=b"x"), grpc.aio.AioRpcError, {}),
]


@table(MISSES)
def test_misses_are_typed(home, name, f0, f1, f2):
    for k, v in f0.items():
        setattr(home, k, v)

    async def clone():
        async with Client.dial(home.addr) as c:
            await c.clone(TOKEN)

    with pytest.raises(f1) as e:
        asyncio.run(clone())
    for k, v in f2.items():
        assert getattr(e.value, k) == v
    assert "secret-grant-token" not in str(e.value) + repr(e.value)


def test_dial_tls():
    d = tempfile.mkdtemp(prefix="fiberd-client-")
    ca = th.issue("ca", ca=True)
    owner = th.issue("owner", ca)
    h = th.Home(bound_to=owner.cert_pem)
    server, addr = h.serve("localhost:0", th.server_credentials(ca, th.issue("fiberd", ca, server=True)))
    cert, key = owner.write(d, "owner")
    cafile, _ = ca.write(d, "ca")

    async def clone():
        async with Client.dial_tls(addr, cert, key, cafile) as c:
            assert c.tls
            return await c.clone(TOKEN, timeout=10)

    try:
        assert asyncio.run(clone()).fence.grant_uid == "g1"
    finally:
        server.stop(None)


WATCH = [
    # how the watch ends, the error wanted
    ("the caller stopping iteration is a clean end", "break", None),
    ("the home stopping is an error", "stop", grpc.aio.AioRpcError),
]


@table(WATCH)
def test_watch_ends(name, f0, f1):
    h = th.Home()
    server, addr = h.serve()

    async def watch():
        seen = []
        async with Client.dial(addr) as c:
            await c.clone(TOKEN)
            await c.clone(TOKEN)
            async for st in c.watch(timeout=10):
                seen.append(st)
                if st.running == 2 and f0 == "break":
                    break
                if st.running == 2:
                    server.stop(None)
        return seen

    try:
        if f1 is None:
            seen = asyncio.run(watch())
        else:
            with pytest.raises(f1):
                asyncio.run(watch())
            return
        assert seen[-1].grant_uid == "g1" and seen[-1].running == 2
    finally:
        server.stop(None)
