"""fiberd.client over grpc.aio. The same Client with the calls as coroutines and watch as an async iterator."""

from __future__ import annotations

from collections.abc import AsyncIterator

import grpc
import grpc.aio
from google.protobuf import empty_pb2

from fiberd.client import PathLike, _calls, log, tls_credentials
from fiberd.client._api import grant_pb2
from fiberd.client._calls import Status, Token
from fiberd.client._errors import classify
from fiberd.client._fiber import Fiber
from fiberd.client._stubs import Stubs

__all__ = ["Client"]


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
