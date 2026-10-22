"""The conversions between the wrapper's records and the wire messages, shared by the sync and aio clients."""

from __future__ import annotations

import os
import stat
import time
from collections.abc import AsyncIterator, Awaitable, Iterator
from dataclasses import dataclass
from typing import BinaryIO, Callable, Union

from fiberd.client._api import grant_pb2
from fiberd.client._fiber import Fence, Fiber, Kind

# A grant token is given as the JWT or as a callable that returns the current one, so a caller can refresh it.
Token = Union[str, Callable[[], str]]

# The most data one Upload or Download message carries, pkg/rpc's MaxChunk. gRPC's own limit is 4 MiB.
CHUNK = 1 << 20

# read(n) returns at most n bytes of an upload's source, and empty bytes at its end.
Reader = Callable[[int], bytes]
AsyncReader = Callable[[int], Awaitable[bytes]]


@dataclass(frozen=True)
class Status:
    """One grant's line of the Watch stream."""

    grant_uid: str
    running: int
    parked: int
    pooled: int
    w_used_bytes: int
    latest: Fence


@dataclass(frozen=True)
class FileInfo:
    """One entry of a fiber's workspace. path is relative to its /workspace, and sha256 is set in an upload's reply only."""

    path: str
    size: int
    mode: int
    directory: bool = False
    sha256: bytes = b""


def clone_request(token: Token, session: str | None, deadline: float | None, payload: bytes | None) -> grant_pb2.CloneRequest:
    req = grant_pb2.CloneRequest(grant_jwt=token() if callable(token) else token, session=session or "", payload=payload or b"")
    if deadline is not None and deadline > 0:
        req.deadline.FromNanoseconds(time.time_ns() + int(deadline * 1e9))
    return req


def fence_from(f: grant_pb2.Fence) -> Fence:
    return Fence(f.grant_uid, f.epoch, f.seq)


def fiber_from(r: grant_pb2.CloneResponse, session: str | None, home: str) -> Fiber:
    return Fiber(
        id=r.fiber_id,
        endpoint=r.endpoint,
        fence=fence_from(r.fence),
        kind=Kind(r.kind),
        session=session or "",
        home=home,
        routing_key=r.routing_key,
        server_key_sha256=r.server_key_sha256,
        server_cert=r.server_cert,
    )


def status_from(s: grant_pb2.Status) -> Status:
    return Status(grant_uid=s.grant_uid, running=s.running, parked=s.parked, pooled=s.pooled, w_used_bytes=s.w_used_bytes, latest=fence_from(s.latest))


def fiber_id(f: Fiber | str) -> str:
    return f.id if isinstance(f, Fiber) else f


def file_info_from(f: grant_pb2.FileInfo) -> FileInfo:
    return FileInfo(path=f.path, size=f.size, mode=f.mode, directory=f.directory, sha256=f.sha256)


def upload_header(fiber: Fiber | str, path: str, size: int, mode: int, sha256: bytes | None) -> grant_pb2.UploadHeader:
    h = grant_pb2.UploadHeader(fiber_id=fiber_id(fiber), path=path, mode=mode, sha256=sha256 or b"")
    # size has presence and fiberd refuses a header without it. Zero is an empty file, so it is set even then.
    h.size = size
    return h


def stream_size(f: BinaryIO) -> int:
    """What is left of a binary file from its position, by fstat for a regular file or else by seeking to its end."""
    try:
        st: os.stat_result | None = os.fstat(f.fileno())
    except (AttributeError, OSError, ValueError):
        # io.UnsupportedOperation is both an OSError and a ValueError.
        st = None
    if st is not None and stat.S_ISREG(st.st_mode):
        return max(0, st.st_size - f.tell())
    seekable = getattr(f, "seekable", None)
    if callable(seekable) and seekable():
        here = f.tell()
        end = f.seek(0, os.SEEK_END)
        f.seek(here)
        return max(0, end - here)
    raise ValueError("upload: the source is a stream that tells no size, so pass size")


def upload_source(data: bytes | bytearray | memoryview | BinaryIO, size: int | None) -> tuple[Reader, int]:
    """A reader over an upload's source, bytes or a binary file, and the size to declare."""
    if size is not None and size < 0:
        raise ValueError(f"upload: size is {size}")
    if isinstance(data, (bytes, bytearray, memoryview)):
        view = memoryview(data).cast("B")
        if size is not None and size != len(view):
            raise ValueError(f"upload: size is {size} and the data is {len(view)} bytes")
        at = 0

        def read(n: int) -> bytes:
            nonlocal at
            chunk = bytes(view[at:at + n])
            at += len(chunk)
            return chunk

        return read, len(view)
    if size is None:
        size = stream_size(data)
    return data.read, size


class Upload:
    """The messages of one Upload, the header and then the source in chunks of at most CHUNK bytes.

    The source must hold exactly the header's size. One that ends early or
    holds more fails with ValueError, raised from the request iterator so
    gRPC cancels the call. The message that completes the size is held back
    until the source is checked for more, so fiberd never sees a finished
    upload of the wrong file. error keeps what failed, for the caller to
    raise in place of the cancelled call's error.
    """

    def __init__(self, header: grant_pb2.UploadHeader) -> None:
        self.header = header
        self.error: Exception | None = None

    def _check(self, chunk: bytes, left: int) -> None:
        if not chunk:
            raise ValueError(f"upload of {self.header.path}: the source ended {left} bytes short of its size, {self.header.size} bytes")
        if len(chunk) > left:
            self._long()

    def _long(self) -> None:
        raise ValueError(f"upload of {self.header.path}: the source holds more than its size, {self.header.size} bytes")

    def requests(self, read: Reader) -> Iterator[grant_pb2.UploadRequest]:
        try:
            pending = grant_pb2.UploadRequest(header=self.header)
            left = self.header.size
            while left:
                chunk = read(min(CHUNK, left))
                self._check(chunk, left)
                left -= len(chunk)
                yield pending
                pending = grant_pb2.UploadRequest(data=bytes(chunk))
            if read(1):
                self._long()
        except Exception as e:
            self.error = e
            raise
        yield pending

    async def arequests(self, read: AsyncReader) -> AsyncIterator[grant_pb2.UploadRequest]:
        try:
            pending = grant_pb2.UploadRequest(header=self.header)
            left = self.header.size
            while left:
                chunk = await read(min(CHUNK, left))
                self._check(chunk, left)
                left -= len(chunk)
                yield pending
                pending = grant_pb2.UploadRequest(data=bytes(chunk))
            if await read(1):
                self._long()
        except Exception as e:
            self.error = e
            raise
        yield pending
