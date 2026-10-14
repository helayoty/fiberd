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

from google.protobuf import empty_pb2

from fiberd.client import _calls
from fiberd.client._api import grant_pb2
from fiberd.client._calls import Status, Token
from fiberd.client._errors import Deferred, Error, KeyMismatch, NotFound, NotHandoff, Shed, TierGap, classify
from fiberd.client._fiber import HANDOFF_SUFFIX, Fence, Fiber, Kind
from fiberd.client._stubs import Stubs

__all__ = [
    "HANDOFF_SUFFIX",
    "Client",
    "Deferred",
    "Error",
    "Fence",
    "Fiber",
    "KeyMismatch",
    "Kind",
    "NotFound",
    "NotHandoff",
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
