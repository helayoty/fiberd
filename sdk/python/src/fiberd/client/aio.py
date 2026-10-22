"""fiberd.client over grpc.aio. The same Client with the calls as coroutines, and watch and download as async iterators."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterable, AsyncIterator
from typing import Any, BinaryIO

import grpc
import grpc.aio
from google.protobuf import empty_pb2

from fiberd.client import PathLike, _calls, log, tls_credentials
from fiberd.client._api import grant_pb2
from fiberd.client._calls import FileInfo, Status, Token
from fiberd.client._errors import Error, classify
from fiberd.client._fiber import Fiber
from fiberd.client._stubs import Stubs

__all__ = ["Client", "Download"]


class Download:
    """One file coming down from a fiber's workspace, an async iterator of its bytes.

    info is what the first message carried. cancel(), or the end of an
    async with block, stops it early. A failure while reading raises the
    same typed errors as the call.
    """

    def __init__(self, call: Any, info: FileInfo, first: bytes) -> None:
        self._call = call
        self._first = first
        self.info = info

    def __repr__(self) -> str:
        return f"aio.Download(info={self.info!r})"

    def __aiter__(self) -> Download:
        return self

    async def __anext__(self) -> bytes:
        if self._first:
            data, self._first = self._first, b""
            return data
        while True:
            try:
                chunk = await self._call.read()
            except grpc.RpcError as e:
                raise classify(e) from None
            if chunk is grpc.aio.EOF:
                raise StopAsyncIteration
            if chunk.data:
                return chunk.data

    async def __aenter__(self) -> Download:
        return self

    async def __aexit__(self, *_: object) -> None:
        self.cancel()

    def cancel(self) -> None:
        """Stops the transfer. A call already done is left as it is."""
        self._call.cancel()


class _AsyncSource:
    """read(n) over an async iterable of bytes, in pieces of at most n bytes whatever size the iterable yields."""

    def __init__(self, it: AsyncIterable[bytes]) -> None:
        self._it = aiter(it)
        self._buf = memoryview(b"")

    async def read(self, n: int) -> bytes:
        while not self._buf:
            try:
                item = await anext(self._it)
            except StopAsyncIteration:
                return b""
            self._buf = memoryview(item).cast("B")
        chunk, self._buf = bytes(self._buf[:n]), self._buf[n:]
        return chunk


class Client:
    """Talks to one home over a grpc.aio channel. Made with dial or dial_tls, or over a channel of one's own."""

    def __init__(self, channel: grpc.aio.Channel, target: str, *, tls: bool = False) -> None:
        self._channel = channel
        self._stubs = Stubs(channel)
        self.target = target
        self.tls = tls

    @classmethod
    def dial(cls, target: str) -> Client:
        """Connects in plaintext. It works only against a home started with -insecure-plaintext, use dial_tls otherwise."""
        return cls(grpc.aio.insecure_channel(target), target)

    @classmethod
    def dial_tls(cls, target: str, cert: PathLike, key: PathLike, ca: PathLike) -> Client:
        """Connects over mutual TLS with the caller's certificate. Grants bound to it work only on this connection."""
        return cls(grpc.aio.secure_channel(target, tls_credentials(cert, key, ca)), target, tls=True)

    def __repr__(self) -> str:
        return f"aio.Client(target={self.target!r}, tls={self.tls})"

    async def __aenter__(self) -> Client:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self._channel.close()

    async def clone(
        self,
        token: Token,
        session: str | None = None,
        *,
        payload: bytes | None = None,
        deadline: float | None = None,
        timeout: float | None = None,
    ) -> Fiber:
        """Resolves session (None for an anonymous fiber) under the grant, within deadline seconds of runtime work.

        Raises Shed, Deferred or TierGap, or the grpc.aio.AioRpcError for anything else.
        """
        try:
            r = await self._stubs.clone(_calls.clone_request(token, session, deadline, payload), timeout=timeout)
        except grpc.RpcError as e:
            log.debug("clone on %s missed: %s", self.target, e.details())
            raise classify(e) from None
        f = _calls.fiber_from(r, session, self.target)
        log.debug("clone on %s: %s %s", self.target, f.kind.name, f.id)
        return f

    async def park(self, fiber: Fiber | str, *, sync: bool = True, timeout: float | None = None) -> None:
        """Checkpoints the fiber. With sync the reply waits for the delta to be durable. Raises NotFound for a fiber the home does not know."""
        try:
            await self._stubs.park(grant_pb2.ParkRequest(fiber_id=_calls.fiber_id(fiber), sync=sync), timeout=timeout)
        except grpc.RpcError as e:
            raise classify(e) from None

    async def release(self, fiber: Fiber | str, *, discard: bool = False, timeout: float | None = None) -> None:
        """Ends the fiber. With discard its session's parked delta goes too. Raises NotFound for a fiber the home does not know."""
        try:
            await self._stubs.release(grant_pb2.ReleaseRequest(fiber_id=_calls.fiber_id(fiber), discard=discard), timeout=timeout)
        except grpc.RpcError as e:
            raise classify(e) from None

    async def watch(self, *, timeout: float | None = None) -> AsyncIterator[Status]:
        """Yields the home's per-grant status until the caller stops iterating or the stream breaks."""
        call = self._stubs.watch(empty_pb2.Empty(), timeout=timeout)
        try:
            async for st in call:
                yield _calls.status_from(st)
        except grpc.RpcError as e:
            raise classify(e) from None
        finally:
            call.cancel()

    async def upload(
        self,
        fiber: Fiber | str,
        path: str,
        data: bytes | BinaryIO | AsyncIterable[bytes],
        *,
        size: int | None = None,
        mode: int = 0,
        sha256: bytes | None = None,
        timeout: float | None = None,
    ) -> FileInfo:
        """Writes data to path in the fiber's workspace, relative to its /workspace, and returns what landed.

        data is bytes, a binary file read from where it stands (in this
        thread, as the sync client does), or an async iterable of bytes,
        which needs size. A source that ends early or holds more than size
        bytes raises ValueError, and fiberd keeps no file. Raises NotFound,
        NoWorkspace or QuotaExceeded, or the grpc.aio.AioRpcError for
        anything else.
        """
        if isinstance(data, AsyncIterable):
            if size is None or size < 0:
                raise ValueError("upload: an async iterable source needs size")
            up = _calls.Upload(_calls.upload_header(fiber, path, size, mode, sha256))
            requests: Any = up.arequests(_AsyncSource(data).read)
        else:
            read, size = _calls.upload_source(data, size)
            up = _calls.Upload(_calls.upload_header(fiber, path, size, mode, sha256))
            requests = up.requests(read)
        try:
            r = await self._stubs.upload(requests, timeout=timeout)
        except (grpc.RpcError, asyncio.CancelledError) as e:
            # A source that broke its size made grpc.aio cancel the call, which it reports as a
            # cancellation. A cancellation of this task itself is passed on as it is.
            task = asyncio.current_task()
            if up.error is not None and not (task is not None and task.cancelling()):
                raise up.error from None
            if isinstance(e, grpc.RpcError):
                raise classify(e) from None
            raise
        return _calls.file_info_from(r)

    async def download(self, fiber: Fiber | str, path: str, *, offset: int = 0, timeout: float | None = None) -> Download:
        """Starts reading path from the fiber's workspace at offset, and returns once its info arrived.

        Raises NotFound for an unknown fiber or a missing file, NoWorkspace,
        or the grpc.aio.AioRpcError for anything else, from here rather than
        from the first read.
        """
        call = self._stubs.download(grant_pb2.DownloadRequest(fiber_id=_calls.fiber_id(fiber), path=path, offset=offset), timeout=timeout)
        try:
            first = await call.read()
        except grpc.RpcError as e:
            raise classify(e) from None
        if first is grpc.aio.EOF:
            call.cancel()
            raise Error(f"download of {path}: the stream ended before the file's info")
        return Download(call, _calls.file_info_from(first.info), first.data)

    async def list_files(self, fiber: Fiber | str, dir: str = "", *, timeout: float | None = None) -> list[FileInfo]:
        """The entries of dir in the fiber's workspace, not recursive. Empty dir is the workspace itself."""
        try:
            r = await self._stubs.list_files(grant_pb2.ListFilesRequest(fiber_id=_calls.fiber_id(fiber), dir=dir), timeout=timeout)
        except grpc.RpcError as e:
            raise classify(e) from None
        return [_calls.file_info_from(f) for f in r.files]
