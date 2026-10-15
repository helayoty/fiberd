"""The conversions between the wrapper's records and the wire messages, shared by the sync and aio clients."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Union

from fiberd.client._api import grant_pb2
from fiberd.client._fiber import Fence, Fiber, Kind

# A grant token is given as the JWT or as a callable that returns the current one, so a caller can refresh it.
Token = Union[str, Callable[[], str]]


@dataclass(frozen=True)
class Status:
    """One grant's line of the Watch stream."""

    grant_uid: str
    running: int
    parked: int
    pooled: int
    w_used_bytes: int
    latest: Fence


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
