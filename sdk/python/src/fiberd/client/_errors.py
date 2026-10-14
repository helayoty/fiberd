"""The typed outcomes a caller branches on, and the classifier that reads them off a failed call.

A miss travels as a google.rpc.Status in the grpc-status-details-bin
trailer with the Miss as one of its Any details. The trailer is read with
a small protobuf wire walker rather than grpcio-status, so the client
needs only grpcio and protobuf.
"""

from __future__ import annotations

from collections.abc import Iterator

import grpc
from google.protobuf.message import DecodeError

from fiberd.client._api import grant_pb2

DETAILS_KEY = "grpc-status-details-bin"
MISS_TYPE = "/fiberd.grant.v1.Miss"


class Error(Exception):
    """The base of every exception fiberd.client raises itself. A gRPC failure it does not classify is raised as is."""


class Shed(Error):
    """The miss that says to retry here later.

    The control plane is unreachable, or the home is under pressure
    (memory, tasks, the clone rate limit). The caller waits retry_after
    seconds and tries again. It does not fall back, because the fallback
    path needs the same control plane or adds load where there is already
    too much. reason is the home's own.
    """

    def __init__(self, retry_after: float, issuer: str = "", reason: str = "") -> None:
        super().__init__(f"shed: {reason}, retry after {retry_after:g}s")
        self.retry_after = retry_after
        self.issuer = issuer
        self.reason = reason


class Deferred(Error):
    """The miss with the control plane healthy.

    The home cannot serve this clone (no capacity, expired grant, session
    too large to move) and the caller takes its ordinary path.
    preferred_home, when set, is where the session's parked state lives.
    """

    def __init__(self, issuer: str = "", preferred_home: str = "", reason: str = "") -> None:
        where = f" (session lives on {preferred_home})" if preferred_home else ""
        super().__init__(f"deferred: {reason}{where}")
        self.issuer = issuer
        self.preferred_home = preferred_home
        self.reason = reason


class TierGap(Error):
    """The grant or the parked session needs a tier this home does not offer. Not a miss, the grant was placed on the wrong home."""

    def __init__(self, reason: str = "") -> None:
        super().__init__(f"tier gap: {reason}")
        self.reason = reason


class NotFound(Error):
    """A Park or Release of a fiber the home does not know, a prior epoch's fence or one already gone."""

    def __init__(self, reason: str = "") -> None:
        super().__init__(f"not found: {reason}")
        self.reason = reason


class NotHandoff(Error):
    """The fiber was not cloned under a HANDOFF grant, so it has no routing key. Dial its endpoint directly."""


class KeyMismatch(Error):
    """The handoff fiber's TLS key is not the one the home pinned in server_key_sha256."""


def _varint(b: bytes, at: int) -> tuple[int, int]:
    """The varint at `at` and the offset after it."""
    n = shift = 0
    while True:
        if at >= len(b) or shift > 63:
            raise ValueError("truncated varint")
        c = b[at]
        n |= (c & 0x7F) << shift
        at += 1
        if not c & 0x80:
            return n, at
        shift += 7


def fields(b: bytes) -> Iterator[tuple[int, bytes | int]]:
    """The (number, value) of each field of a protobuf message, bytes for length-delimited ones and int for varints."""
    at = 0
    while at < len(b):
        tag, at = _varint(b, at)
        number, wire = tag >> 3, tag & 7
        if wire == 0:
            value, at = _varint(b, at)
            yield number, value
        elif wire == 2:
            size, at = _varint(b, at)
            if at + size > len(b):
                raise ValueError("truncated field")
            yield number, b[at:at + size]
            at += size
        elif wire in (1, 5):
            at += 8 if wire == 1 else 4
        else:
            raise ValueError(f"wire type {wire}")


def miss_from_status(raw: bytes) -> grant_pb2.Miss | None:
    """The Miss among a serialized google.rpc.Status's details, or None."""
    for number, value in fields(raw):
        if number != 3 or not isinstance(value, bytes):
            continue
        type_url, payload = b"", b""
        for n, v in fields(value):
            if n == 1 and isinstance(v, bytes):
                type_url = v
            elif n == 2 and isinstance(v, bytes):
                payload = v
        if type_url.endswith(MISS_TYPE.encode()):
            return grant_pb2.Miss.FromString(payload)
    return None


def miss_from_call(call: object) -> grant_pb2.Miss | None:
    """The Miss detail of a failed call (a grpc.Call or a grpc.aio.AioRpcError), when it carries one."""
    metadata = call.trailing_metadata() if callable(getattr(call, "trailing_metadata", None)) else None
    for key, value in metadata or ():
        if key == DETAILS_KEY and isinstance(value, bytes):
            try:
                return miss_from_status(value)
            except (ValueError, DecodeError):
                return None
    return None


def classify(err: grpc.RpcError) -> Exception:
    """The typed exception for a failed call, or err itself for anything the protocol leaves untyped."""
    # A sync failure is a grpc.Call and an aio one an AioRpcError, and both answer code() and details().
    if not callable(getattr(err, "code", None)) or not callable(getattr(err, "details", None)):
        return err
    reason = err.details() or ""
    miss = miss_from_call(err)
    if miss is not None:
        if miss.code == grant_pb2.SHED:
            return Shed(retry_after=float(miss.retry_after_s), issuer=miss.issuer, reason=reason)
        if miss.code == grant_pb2.DEFERRED_FALLBACK:
            return Deferred(issuer=miss.issuer, preferred_home=miss.preferred_home, reason=reason)
    code = err.code()
    if code == grpc.StatusCode.FAILED_PRECONDITION:
        return TierGap(reason)
    if code == grpc.StatusCode.NOT_FOUND:
        return NotFound(reason)
    return err
