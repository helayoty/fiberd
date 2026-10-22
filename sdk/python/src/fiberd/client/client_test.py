"""The sync Client against a home in this process, every call, every miss, the TLS paths and what never leaks."""

from __future__ import annotations

import hashlib
import importlib
import io
import logging
import os
import sys
import tempfile
import threading
import time

import grpc
import pytest

import fiberd.client
from fiberd._testtable import table
from fiberd.client import Client, Deferred, Fence, FileInfo, Kind, NotFound, NoWorkspace, QuotaExceeded, Shed, TierGap
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


MiB = 1 << 20


class _Stream:
    """A binary stream with read alone, no fileno and no seek, as a pipe reads."""

    def __init__(self, data: bytes) -> None:
        self._b = io.BytesIO(data)

    def read(self, n: int = -1) -> bytes:
        return self._b.read(n)


def _file(dir, data: bytes, skip: int = 0):
    """A regular file holding data, open for reading at skip."""
    path = dir / "source.bin"
    path.write_bytes(data)
    f = open(path, "rb")
    f.seek(skip)
    return f


def _no_file_landed(home, fiber_id: str, path: str) -> None:
    """Every upload the home saw has ended without a file, and the workspace holds none at path."""
    for u in home.uploads:
        assert u.ended.wait(10) and not u.done
        assert u.header is None or sum(u.chunks) < u.header.size or u.header.size == 0
    assert path not in home.workspaces.get(fiber_id, {})


UPLOAD = [
    # the file's size, the data chunks fiberd must see
    ("an empty file is the header alone, its size set to zero", 0, []),
    ("one byte is one chunk", 1, [1]),
    ("exactly 1 MiB is one full chunk", MiB, [MiB]),
    ("1 MiB and a byte is a full chunk and one byte", MiB + 1, [MiB, 1]),
]


@table(UPLOAD)
def test_upload_chunks(home, client, name, f0, f1):
    f = client.clone(TOKEN)
    data = os.urandom(f0)
    digest = hashlib.sha256(data).digest()
    info = client.upload(f, "d/data.bin", data, mode=0o600, sha256=digest)
    rec = home.uploads[-1]
    assert rec.chunks == f1, name
    assert rec.header.HasField("size") and rec.header.size == f0, name
    assert (rec.header.fiber_id, rec.header.path, rec.header.mode, rec.header.sha256) == (f.id, "d/data.bin", 0o600, digest), name
    assert info == FileInfo("d/data.bin", f0, 0o600, False, digest), name
    assert home.workspaces[f.id]["d/data.bin"] == (data, 0o600), name


def test_upload_defaults(home, client):
    """No mode is zero on the wire, which fiberd reads as 0644, and no sha256 is empty."""
    f = client.clone(TOKEN)
    info = client.upload(f.id, "a.txt", b"hello")
    h = home.uploads[-1].header
    assert (h.mode, h.sha256, h.size) == (0, b"", 5)
    assert (info.path, info.size, info.mode, info.directory) == ("a.txt", 5, 0o644, False)


SOURCES = [
    # the source made from the data in a directory, the size passed given the data, the error wanted
    ("a regular file, sized by fstat", lambda d, tmp: _file(tmp, d), None, None),
    ("a regular file is read from where it stands", lambda d, tmp: _file(tmp, b"skip" + d, skip=4), None, None),
    ("a BytesIO has no fileno and is sized by seeking", lambda d, tmp: io.BytesIO(d), None, None),
    ("a stream with neither and its size", lambda d, tmp: _Stream(d), len, None),
    ("a stream with neither needs size", lambda d, tmp: _Stream(d), None, ValueError),
    ("bytes with another size", lambda d, tmp: d, lambda d: len(d) + 1, ValueError),
    ("a negative size", lambda d, tmp: _Stream(d), lambda d: -1, ValueError),
]


@table(SOURCES)
def test_upload_sources(home, client, tmp_path, name, f0, f1, f2):
    f = client.clone(TOKEN)
    data = os.urandom(MiB + 3)
    src = f0(data, tmp_path)
    try:
        size = f1(data) if f1 else None
        if f2 is not None:
            with pytest.raises(f2):
                client.upload(f, "in.bin", src, size=size)
            assert home.uploads == [], name
            return
        info = client.upload(f, "in.bin", src, size=size)
    finally:
        getattr(src, "close", lambda: None)()
    assert info.size == len(data), name
    assert home.uploads[-1].chunks == [MiB, 3], name
    assert home.workspaces[f.id]["in.bin"][0] == data, name


BROKEN = [
    # the source, the size declared, what the error says
    ("a stream a byte short", lambda: _Stream(b"x" * 9), 10, "ended 1 bytes short"),
    ("a stream short after a full chunk", lambda: _Stream(b"x" * MiB), MiB + 5, "ended 5 bytes short"),
    ("a stream that ends at once", lambda: _Stream(b""), 3, "ended 3 bytes short"),
    ("a stream a byte long", lambda: _Stream(b"x" * 11), 10, "holds more than its size, 10 bytes"),
    ("a stream long after a full chunk", lambda: _Stream(b"x" * (MiB + 1)), MiB, "holds more than its size"),
    ("an empty file that is not empty", lambda: _Stream(b"x"), 0, "holds more than its size, 0 bytes"),
]


@table(BROKEN)
def test_upload_source_breaks_its_size(home, client, name, f0, f1, f2):
    """The source fails locally with ValueError, and fiberd never sees a finished upload."""
    f = client.clone(TOKEN)
    with pytest.raises(ValueError, match=f2):
        client.upload(f, "x.bin", f0(), size=f1)
    _no_file_landed(home, f.id, "x.bin")


def test_upload_source_read_error(home, client):
    """A source whose read fails raises that error, and no file lands."""

    class Failing(_Stream):
        def read(self, n: int = -1) -> bytes:
            raise OSError("disk went away")

    f = client.clone(TOKEN)
    with pytest.raises(OSError, match="disk went away"):
        client.upload(f, "x.bin", Failing(b""), size=4)
    _no_file_landed(home, f.id, "x.bin")


DOWNLOAD = [
    # the file's size, the home's chunk size, the offset, the chunk sizes wanted
    ("an empty file is its info alone", 0, MiB, 0, []),
    ("a small file is one chunk", 5, MiB, 0, [5]),
    ("a file over many chunks reassembles", 25, 10, 0, [10, 10, 5]),
    ("1 MiB and a byte in full chunks", MiB + 1, MiB, 0, [MiB, 1]),
    ("an offset skips the start, and info still names the whole file", 25, 10, 7, [10, 8]),
    ("an offset at the end is no data", 25, 10, 25, []),
]


@table(DOWNLOAD)
def test_download(home, client, name, f0, f1, f2, f3):
    f = client.clone(TOKEN)
    data = os.urandom(f0)
    home.put(f.id, "out/r.bin", data, 0o640)
    home.download_chunk = f1
    with client.download(f, "out/r.bin", offset=f2) as d:
        assert d.info == FileInfo("out/r.bin", f0, 0o640), name
        chunks = list(d)
    assert [len(c) for c in chunks] == f3, name
    assert b"".join(chunks) == data[f2:], name
    assert b"".join(client.download(f.id, "out/r.bin", offset=f2)) == data[f2:], name


def test_upload_then_download(home, client):
    f = client.clone(TOKEN)
    data = os.urandom(2 * MiB + 7)
    client.upload(f, "round/trip.bin", io.BytesIO(data))
    assert b"".join(client.download(f, "round/trip.bin")) == data


FILE_CALLS = {
    "upload": lambda c, fid: c.upload(fid, "a.txt", b"hello"),
    "download": lambda c, fid: c.download(fid, "a.txt"),
    "download a missing file": lambda c, fid: c.download(fid, "missing.txt"),
    "list_files": lambda c, fid: c.list_files(fid),
}

FILE_ERRORS = [
    # the call, the home's state, whether the fiber is unknown, the exception wanted, what it says
    ("an upload to an unknown fiber is NotFound", "upload", {}, True, NotFound, "not found: fiber g1/1/99 unknown"),
    ("a download from an unknown fiber is NotFound", "download", {}, True, NotFound, "not found: fiber g1/1/99 unknown"),
    ("listing an unknown fiber is NotFound", "list_files", {}, True, NotFound, "not found: fiber g1/1/99 unknown"),
    ("an upload with no disk budget is NoWorkspace, not a tier gap", "upload", dict(disk_budget=0), False, NoWorkspace, "no workspace: grant has no workspace"),
    ("a download with no disk budget is NoWorkspace", "download", dict(disk_budget=0), False, NoWorkspace, "no workspace: grant has no workspace"),
    ("listing with no disk budget is NoWorkspace", "list_files", dict(disk_budget=0), False, NoWorkspace, "no workspace: grant has no workspace"),
    ("an upload over the budget is QuotaExceeded, not Shed", "upload", dict(disk_budget=4), False, QuotaExceeded,
     "quota exceeded: the file is larger than the grant's disk budget: 5 bytes"),
    ("a missing file is NotFound from download itself", "download a missing file", {}, False, NotFound, "not found: file missing.txt does not exist"),
    ("a failure before the first chunk raises from download itself", "download", dict(download_fail=(grpc.StatusCode.NOT_FOUND, "gone"), download_fail_after=0),
     False, NotFound, "not found: gone"),
]


@table(FILE_ERRORS)
def test_file_errors(home, client, name, f0, f1, f2, f3, f4):
    f = client.clone(TOKEN)
    home.put(f.id, "a.txt", b"hello")
    for k, v in f1.items():
        setattr(home, k, v)
    with pytest.raises(f3) as e:
        FILE_CALLS[f0](client, "g1/1/99" if f2 else f.id)
    assert str(e.value).startswith(f4), name


MID_STREAM = [
    # the status the home ends the stream with after the first chunk, the exception wanted
    ("a fiber gone mid-stream is NotFound", (grpc.StatusCode.NOT_FOUND, "fiber went away"), NotFound),
    ("anything else is the raw grpc.RpcError", (grpc.StatusCode.ABORTED, "park cancelled the transfer"), grpc.RpcError),
]


@table(MID_STREAM)
def test_download_fails_mid_stream(home, client, name, f0, f1):
    f = client.clone(TOKEN)
    data = os.urandom(30)
    home.put(f.id, "big", data)
    home.download_chunk = 10
    home.download_fail, home.download_fail_after = f0, 1
    d = client.download(f, "big")
    assert next(d) == data[:10], name
    with pytest.raises(f1) as e:
        next(d)
    if f1 is grpc.RpcError:
        assert e.value.code() == f0[0], name
    else:
        assert f0[1] in str(e.value), name


def test_download_cancel(home, client):
    """Leaving a download's with block early cancels it. The home holds the second chunk back until then."""
    f = client.clone(TOKEN)
    home.put(f.id, "big", os.urandom(30))
    home.download_chunk = 10
    home.download_gate = threading.Event()
    try:
        with client.download(f, "big") as d:
            assert len(next(d)) == 10
        with pytest.raises(grpc.RpcError) as e:
            next(d)
        assert e.value.code() == grpc.StatusCode.CANCELLED
    finally:
        home.download_gate.set()


LIST = [
    # the directory listed, the entries wanted or the exception wanted
    ("the workspace itself, files and directories", "", [FileInfo("a.txt", 2, 0o600), FileInfo("d", 0, 0o755, True)]),
    ("a directory, not recursive", "d", [FileInfo("d/b.bin", 3, 0o644), FileInfo("d/e", 0, 0o755, True)]),
    ("a directory deeper down", "d/e", [FileInfo("d/e/c", 0, 0o644)]),
    ("a directory that is not there is NotFound", "nope", NotFound),
]


@table(LIST)
def test_list_files(home, client, name, f0, f1):
    f = client.clone(TOKEN)
    home.put(f.id, "a.txt", b"hi", 0o600)
    home.put(f.id, "d/b.bin", b"xyz")
    home.put(f.id, "d/e/c", b"")
    if isinstance(f1, type):
        with pytest.raises(f1):
            client.list_files(f, f0)
        return
    assert client.list_files(f, f0) == f1, name


def test_list_files_empty(home, client):
    assert client.list_files(client.clone(TOKEN)) == []


TEXT = [
    ("shed says why and when to retry", Shed(retry_after=2, reason="grant g is at pids.max"), "shed: grant g is at pids.max, retry after 2s"),
    ("deferred says why", Deferred(reason="grant full"), "deferred: grant full"),
    ("deferred names where the session lives", Deferred(reason="too large", preferred_home="home-b"), "deferred: too large (session lives on home-b)"),
    ("a tier gap says why", TierGap("needs CHECKPOINT"), "tier gap: needs CHECKPOINT"),
    ("no workspace says why", NoWorkspace("fiber g/1/1"), "no workspace: fiber g/1/1"),
    ("a quota says why", QuotaExceeded("over the disk budget"), "quota exceeded: over the disk budget"),
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
