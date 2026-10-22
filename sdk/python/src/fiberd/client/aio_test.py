"""The grpc.aio twin against the same home in this process."""

from __future__ import annotations

import asyncio
import hashlib
import io
import os
import tempfile

import grpc
import pytest

from fiberd._testtable import table
from fiberd.client import Deferred, FileInfo, Kind, NotFound, NoWorkspace, QuotaExceeded, Shed, TierGap
from fiberd.client import _testhome as th
from fiberd.client.aio import Client

MiB = 1 << 20

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


def _on_fiber(home, body):
    """Runs body(client, fiber) against the home, on a fiber cloned for it."""

    async def run():
        async with Client.dial(home.addr) as c:
            return await body(c, await c.clone(TOKEN))

    return asyncio.run(run())


async def _pieces(*items):
    for item in items:
        yield item


UPLOAD = [
    # the file's size, the source made from the data, the size passed given the data, the data chunks fiberd must see
    ("empty bytes are the header alone, its size set to zero", 0, lambda d: d, None, []),
    ("1 MiB and a byte of bytes", MiB + 1, lambda d: d, None, [MiB, 1]),
    ("a BytesIO, read in the loop's thread", MiB + 1, io.BytesIO, None, [MiB, 1]),
    ("an async iterable keeps its small pieces and skips empty ones", 4, lambda d: _pieces(d[:2], b"", d[2:]), len, [2, 2]),
    ("an async iterable's piece over 1 MiB is split", MiB + 1, lambda d: _pieces(d), len, [MiB, 1]),
    ("an empty async iterable is an empty file", 0, lambda d: _pieces(), len, []),
]


@table(UPLOAD)
def test_upload(home, name, f0, f1, f2, f3):
    data = os.urandom(f0)

    async def up(c, f):
        return f, await c.upload(f, "in.bin", f1(data), size=f2(data) if f2 else None, mode=0o600)

    f, info = _on_fiber(home, up)
    rec = home.uploads[-1]
    assert rec.chunks == f3, name
    assert rec.header.HasField("size") and rec.header.size == f0, name
    assert info == FileInfo("in.bin", f0, 0o600, False, hashlib.sha256(data).digest()), name
    assert home.workspaces[f.id]["in.bin"] == (data, 0o600), name


BROKEN = [
    # the source, the size declared, what the error says
    ("an async iterable a byte short", lambda: _pieces(b"ab"), 3, "ended 1 bytes short"),
    ("an async iterable that ends at once", lambda: _pieces(), 2, "ended 2 bytes short"),
    ("an async iterable a byte long", lambda: _pieces(b"ab", b"cd"), 3, "holds more than its size, 3 bytes"),
    ("an async iterable for an empty file that is not empty", lambda: _pieces(b"x"), 0, "holds more than its size, 0 bytes"),
    ("an async iterable needs size", lambda: _pieces(b"ab"), None, "needs size"),
    ("bytes with another size", lambda: b"abc", 4, "size is 4 and the data is 3 bytes"),
]


@table(BROKEN)
def test_upload_source_breaks_its_size(home, name, f0, f1, f2):
    """The source fails locally with ValueError, not a cancellation, and fiberd never sees a finished upload."""

    async def up(c, f):
        with pytest.raises(ValueError, match=f2):
            await c.upload(f, "x.bin", f0(), size=f1)
        return f

    f = _on_fiber(home, up)
    for u in home.uploads:
        assert u.ended.wait(10) and not u.done, name
        assert u.header is None or u.header.size == 0 or sum(u.chunks) < u.header.size, name
    assert "x.bin" not in home.workspaces.get(f.id, {}), name


def test_upload_then_download(home):
    data = os.urandom(2 * MiB + 7)

    async def round_trip(c, f):
        await c.upload(f, "round/trip.bin", _pieces(data[:5], data[5:]), size=len(data))
        return b"".join([chunk async for chunk in await c.download(f, "round/trip.bin")])

    assert _on_fiber(home, round_trip) == data


DOWNLOAD = [
    # the file's size, the home's chunk size, the offset, the chunk sizes wanted
    ("an empty file is its info alone", 0, MiB, 0, []),
    ("a file over many chunks reassembles", 25, 10, 0, [10, 10, 5]),
    ("an offset skips the start, and info still names the whole file", 25, 10, 7, [10, 8]),
]


@table(DOWNLOAD)
def test_download(home, name, f0, f1, f2, f3):
    data = os.urandom(f0)
    home.download_chunk = f1

    async def down(c, f):
        home.put(f.id, "out/r.bin", data, 0o640)
        d = await c.download(f, "out/r.bin", offset=f2)
        async with d:
            return d.info, [chunk async for chunk in d]

    info, chunks = _on_fiber(home, down)
    assert info == FileInfo("out/r.bin", f0, 0o640), name
    assert [len(c) for c in chunks] == f3, name
    assert b"".join(chunks) == data[f2:], name


FILE_CALLS = {
    "upload": lambda c, fid: c.upload(fid, "a.txt", b"hello"),
    "download": lambda c, fid: c.download(fid, "a.txt"),
    "download a missing file": lambda c, fid: c.download(fid, "missing.txt"),
    "list_files": lambda c, fid: c.list_files(fid),
}

FILE_ERRORS = [
    # the call, the home's state, whether the fiber is unknown, the exception wanted
    ("an upload to an unknown fiber is NotFound", "upload", {}, True, NotFound),
    ("a download from an unknown fiber is NotFound from download itself", "download", {}, True, NotFound),
    ("listing an unknown fiber is NotFound", "list_files", {}, True, NotFound),
    ("an upload with no disk budget is NoWorkspace", "upload", dict(disk_budget=0), False, NoWorkspace),
    ("a download with no disk budget is NoWorkspace", "download", dict(disk_budget=0), False, NoWorkspace),
    ("listing with no disk budget is NoWorkspace", "list_files", dict(disk_budget=0), False, NoWorkspace),
    ("an upload over the budget is QuotaExceeded", "upload", dict(disk_budget=4), False, QuotaExceeded),
    ("a missing file is NotFound from download itself", "download a missing file", {}, False, NotFound),
]


@table(FILE_ERRORS)
def test_file_errors(home, name, f0, f1, f2, f3):
    for k, v in f1.items():
        setattr(home, k, v)

    async def call(c, f):
        home.put(f.id, "a.txt", b"hello")
        with pytest.raises(f3) as e:
            await FILE_CALLS[f0](c, "g1/1/99" if f2 else f.id)
        return e.value

    err = _on_fiber(home, call)
    assert "secret-grant-token" not in str(err) + repr(err), name


MID_STREAM = [
    # the status the home ends the stream with after the first chunk, the exception wanted
    ("a fiber gone mid-stream is NotFound", (grpc.StatusCode.NOT_FOUND, "fiber went away"), NotFound),
    ("anything else is the raw AioRpcError", (grpc.StatusCode.ABORTED, "park cancelled the transfer"), grpc.aio.AioRpcError),
]


@table(MID_STREAM)
def test_download_fails_mid_stream(home, name, f0, f1):
    data = os.urandom(30)
    home.download_chunk = 10
    home.download_fail, home.download_fail_after = f0, 1

    async def down(c, f):
        home.put(f.id, "big", data)
        d = await c.download(f, "big")
        first = await anext(d)
        with pytest.raises(f1) as e:
            await anext(d)
        return first, e.value

    first, err = _on_fiber(home, down)
    assert first == data[:10], name
    assert f0[1] in (err.details() if f1 is grpc.aio.AioRpcError else str(err)), name


LIST = [
    # the directory listed, the entries wanted
    ("the workspace itself, files and directories", "", [FileInfo("a.txt", 2, 0o600), FileInfo("d", 0, 0o755, True)]),
    ("a directory, not recursive", "d", [FileInfo("d/b.bin", 3, 0o644)]),
]


@table(LIST)
def test_list_files(home, name, f0, f1):
    async def ls(c, f):
        home.put(f.id, "a.txt", b"hi", 0o600)
        home.put(f.id, "d/b.bin", b"xyz")
        return await c.list_files(f, f0)

    assert _on_fiber(home, ls) == f1, name
