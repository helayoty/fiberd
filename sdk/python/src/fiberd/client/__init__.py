"""fiberd.client: the grant protocol from the caller's side.

A caller (an activator, a shim, a controller) holds a signed grant and
asks a home for fibers under it. Clone returns a Fiber to dial, or raises
one of the two misses: on Deferred the caller takes its ordinary path (or
routes to preferred_home), on Shed it waits retry_after and tries again.

    from fiberd.client import Client, Shed, Deferred

    with Client.dial_tls("home:7443", cert="me.pem", key="me-key.pem", ca="ca.pem") as c:
        try:
            f = c.clone(jwt, session="conv-42", payload=b'{"task":1}')
        except Shed as e:
            time.sleep(e.retry_after)
        except Deferred as e:
            route_to(e.preferred_home)
        sock = f.dial()
        c.park(f)
        c.release(f, discard=True)

A fiber whose grant has a disk budget has a workspace, its /workspace.
upload, download and list_files move files in and out of it.

fiberd.client.aio.Client is the same over grpc.aio. The token is never
stored, logged or shown by a repr, and nothing here reads the environment.
"""

from __future__ import annotations

try:
    import grpc
except ImportError as e:
    raise ImportError("fiberd.client needs grpcio and protobuf, which the client extra installs: pip install 'fiberd[client]'") from e

import logging
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any, BinaryIO

from google.protobuf import empty_pb2

from fiberd.client import _calls
from fiberd.client._api import grant_pb2
from fiberd.client._calls import FileInfo, Status, Token
from fiberd.client._errors import Deferred, Error, KeyMismatch, NotFound, NotHandoff, NoWorkspace, QuotaExceeded, Shed, TierGap, classify
from fiberd.client._fiber import HANDOFF_SUFFIX, Fence, Fiber, Kind
from fiberd.client._stubs import Stubs

__all__ = [
    "HANDOFF_SUFFIX",
    "Client",
    "Deferred",
    "Download",
    "Error",
    "Fence",
    "Fiber",
    "FileInfo",
    "KeyMismatch",
    "Kind",
    "NotFound",
    "NotHandoff",
    "NoWorkspace",
    "QuotaExceeded",
    "Shed",
    "Status",
    "TierGap",
    "Token",
    "tls_credentials",
]

log = logging.getLogger("fiberd.client")

PathLike = str | os.PathLike[str]


def tls_credentials(cert: PathLike, key: PathLike, ca: PathLike) -> grpc.ChannelCredentials:
    """Mutual TLS from PEM files, the caller's certificate and key and the home's CA. The key bytes are not kept."""
    return grpc.ssl_channel_credentials(
        root_certificates=Path(ca).read_bytes(), private_key=Path(key).read_bytes(), certificate_chain=Path(cert).read_bytes()
    )


class Download:
    """One file coming down from a fiber's workspace, an iterator of its bytes.

    info is what the first message carried. b"".join(download) reads the
    whole file. cancel(), or the end of a with block, stops it early. A
    failure while reading raises the same typed errors as the call.
    """

    def __init__(self, call: Any, info: FileInfo, first: bytes) -> None:
        # call is the grpc stream, a grpc.Call that iterates FileChunks.
        self._call = call
        self._first = first
        self.info = info

    def __repr__(self) -> str:
        return f"Download(info={self.info!r})"

    def __iter__(self) -> Download:
        return self

    def __next__(self) -> bytes:
        if self._first:
            data, self._first = self._first, b""
            return data
        while True:
            try:
                chunk = next(self._call)
            except grpc.RpcError as e:
                raise classify(e) from None
            if chunk.data:
                return chunk.data

    def __enter__(self) -> Download:
        return self

    def __exit__(self, *_: object) -> None:
        self.cancel()

    def cancel(self) -> None:
        """Stops the transfer. A call already done is left as it is."""
        self._call.cancel()


class Client:
    """Talks to one home over a channel. Made with dial or dial_tls, or over a channel of one's own."""

    def __init__(self, channel: grpc.Channel, target: str, *, tls: bool = False) -> None:
        self._channel = channel
        self._stubs = Stubs(channel)
        self.target = target
        self.tls = tls

    @classmethod
    def dial(cls, target: str) -> Client:
        """Connects in plaintext. It works only against a home started with -insecure-plaintext, use dial_tls otherwise."""
        return cls(grpc.insecure_channel(target), target)

    @classmethod
    def dial_tls(cls, target: str, cert: PathLike, key: PathLike, ca: PathLike) -> Client:
        """Connects over mutual TLS with the caller's certificate. Grants bound to it work only on this connection."""
        return cls(grpc.secure_channel(target, tls_credentials(cert, key, ca)), target, tls=True)

    def __repr__(self) -> str:
        return f"Client(target={self.target!r}, tls={self.tls})"

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._channel.close()

    def clone(
        self,
        token: Token,
        session: str | None = None,
        *,
        payload: bytes | None = None,
        deadline: float | None = None,
        timeout: float | None = None,
    ) -> Fiber:
        """Resolves session (None for an anonymous fiber) under the grant, within deadline seconds of runtime work.

        Raises Shed, Deferred or TierGap, or the grpc.RpcError for anything else.
        """
        try:
            r = self._stubs.clone(_calls.clone_request(token, session, deadline, payload), timeout=timeout)
        except grpc.RpcError as e:
            log.debug("clone on %s missed: %s", self.target, e.details())
            raise classify(e) from None
        f = _calls.fiber_from(r, session, self.target)
        log.debug("clone on %s: %s %s", self.target, f.kind.name, f.id)
        return f

    def park(self, fiber: Fiber | str, *, sync: bool = True, timeout: float | None = None) -> None:
        """Checkpoints the fiber. With sync the reply waits for the delta to be durable. Raises NotFound for a fiber the home does not know."""
        try:
            self._stubs.park(grant_pb2.ParkRequest(fiber_id=_calls.fiber_id(fiber), sync=sync), timeout=timeout)
        except grpc.RpcError as e:
            raise classify(e) from None

    def release(self, fiber: Fiber | str, *, discard: bool = False, timeout: float | None = None) -> None:
        """Ends the fiber. With discard its session's parked delta goes too. Raises NotFound for a fiber the home does not know."""
        try:
            self._stubs.release(grant_pb2.ReleaseRequest(fiber_id=_calls.fiber_id(fiber), discard=discard), timeout=timeout)
        except grpc.RpcError as e:
            raise classify(e) from None

    def watch(self, *, timeout: float | None = None) -> Iterator[Status]:
        """Yields the home's per-grant status until the caller stops iterating or the stream breaks."""
        call = self._stubs.watch(empty_pb2.Empty(), timeout=timeout)
        try:
            for st in call:
                yield _calls.status_from(st)
        except grpc.RpcError as e:
            raise classify(e) from None
        finally:
            call.cancel()

    def upload(
        self,
        fiber: Fiber | str,
        path: str,
        data: bytes | BinaryIO,
        *,
        size: int | None = None,
        mode: int = 0,
        sha256: bytes | None = None,
        timeout: float | None = None,
    ) -> FileInfo:
        """Writes data to path in the fiber's workspace, relative to its /workspace, and returns what landed.

        data is bytes or a binary file read from where it stands. A file's
        size comes from fstat or a seek to its end, and a stream with
        neither needs size. A source that ends early or holds more than
        size bytes raises ValueError, and fiberd keeps no file. mode zero
        is 0644. sha256, when given, is checked before the file appears.
        Raises NotFound, NoWorkspace or QuotaExceeded, or the grpc.RpcError
        for anything else.
        """
        read, size = _calls.upload_source(data, size)
        up = _calls.Upload(_calls.upload_header(fiber, path, size, mode, sha256))
        try:
            r = self._stubs.upload(up.requests(read), timeout=timeout)
        except grpc.RpcError as e:
            # A source that broke its size cancelled the call from the request iterator.
            if up.error is not None:
                raise up.error from None
            raise classify(e) from None
        return _calls.file_info_from(r)

    def download(self, fiber: Fiber | str, path: str, *, offset: int = 0, timeout: float | None = None) -> Download:
        """Starts reading path from the fiber's workspace at offset, and returns once its info arrived.

        Raises NotFound for an unknown fiber or a missing file, NoWorkspace,
        or the grpc.RpcError for anything else, from here rather than from
        the first read.
        """
        call = self._stubs.download(grant_pb2.DownloadRequest(fiber_id=_calls.fiber_id(fiber), path=path, offset=offset), timeout=timeout)
        try:
            first = next(call)
        except grpc.RpcError as e:
            raise classify(e) from None
        except StopIteration:
            call.cancel()
            raise Error(f"download of {path}: the stream ended before the file's info") from None
        return Download(call, _calls.file_info_from(first.info), first.data)

    def list_files(self, fiber: Fiber | str, dir: str = "", *, timeout: float | None = None) -> list[FileInfo]:
        """The entries of dir in the fiber's workspace, not recursive. Empty dir is the workspace itself."""
        try:
            r = self._stubs.list_files(grant_pb2.ListFilesRequest(fiber_id=_calls.fiber_id(fiber), dir=dir), timeout=timeout)
        except grpc.RpcError as e:
            raise classify(e) from None
        return [_calls.file_info_from(f) for f in r.files]
