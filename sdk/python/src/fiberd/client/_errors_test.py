"""The wire walker that finds the Miss and the NoWorkspace detail in a status trailer, and the classifier over it."""

from __future__ import annotations

import grpc
import pytest

from fiberd._testtable import table
from fiberd.client import Deferred, NotFound, NoWorkspace, QuotaExceeded, Shed, TierGap
from fiberd.client import _testhome as th
from fiberd.client._api import grant_pb2
from fiberd.client._errors import classify, fields, miss_from_call, miss_from_status, no_workspace_in_status

SHED = grant_pb2.Miss(code=grant_pb2.SHED, retry_after_s=2, issuer="i")
DEFER = grant_pb2.Miss(code=grant_pb2.DEFERRED_FALLBACK, issuer="i", preferred_home="home-b")


def _any(type_url: str, payload: bytes) -> bytes:
    return th.ld(1, type_url.encode()) + th.ld(2, payload)


RETRY_INFO = _any("type.googleapis.com/google.rpc.RetryInfo", b"\x0a\x00")
FIXED = b"\x09" + b"\x00" * 8 + b"\x15" + b"\x00" * 4


STATUS = [
    # the serialized google.rpc.Status, the Miss wanted or the error wanted
    ("a shed", th.rich_status(8, "full", SHED), SHED),
    ("a deferral", th.rich_status(14, "full", DEFER), DEFER),
    ("no details", th.vi(1, 14) + th.ld(2, b"full"), None),
    ("another detail first", th.vi(1, 14) + th.ld(3, RETRY_INFO) + th.ld(3, _any("x/fiberd.grant.v1.Miss", SHED.SerializeToString())), SHED),
    ("only another detail", th.vi(1, 14) + th.ld(3, RETRY_INFO), None),
    ("fixed-width fields are skipped", FIXED + th.ld(3, _any("a/fiberd.grant.v1.Miss", DEFER.SerializeToString())), DEFER),
    ("empty", b"", None),
    ("a truncated varint", b"\x08\x80", ValueError),
    ("a truncated field", b"\x1a\x05\x00", ValueError),
    ("a group wire type", b"\x0b", ValueError),
]


@table(STATUS)
def test_miss_from_status(name, f0, f1):
    if f1 is ValueError:
        with pytest.raises(ValueError):
            miss_from_status(f0)
    else:
        assert miss_from_status(f0) == f1


NO_WS = th.no_workspace_status(9, "fiber g/1/1")
NO_WS_WITH_VALUE = th.vi(1, 9) + th.ld(3, _any("type.googleapis.com/fiberd.grant.v1.NoWorkspace", b""))

WORKSPACE = [
    # the serialized google.rpc.Status, whether it carries the NoWorkspace detail
    ("the detail as Go sends it, a type URL alone", NO_WS, True),
    ("the detail with an empty value", NO_WS_WITH_VALUE, True),
    ("the detail after another one", th.vi(1, 9) + th.ld(3, RETRY_INFO) + th.ld(3, _any("x/fiberd.grant.v1.NoWorkspace", b"")), True),
    ("a Miss is not it", th.rich_status(8, "full", SHED), False),
    ("a type that only starts the same", th.vi(1, 9) + th.ld(3, _any("x/fiberd.grant.v1.NoWorkspaceX", b"")), False),
    ("a name without the URL's slash", th.vi(1, 9) + th.ld(3, _any("fiberd.grant.v1.NoWorkspace", b"")), False),
    ("no details", th.vi(1, 9), False),
    ("empty", b"", False),
]


@table(WORKSPACE)
def test_no_workspace_in_status(name, f0, f1):
    assert no_workspace_in_status(f0) is f1


def test_fields_round_trip():
    raw = th.vi(1, 300) + th.ld(2, b"hi") + th.vi(7, 0)
    assert list(fields(raw)) == [(1, 300), (2, b"hi"), (7, 0)]


class _Call:
    """What classify reads off a failed call."""

    def __init__(self, code, details, trailer=None):
        self._code, self._details, self._trailer = code, details, trailer

    def code(self):
        return self._code

    def details(self):
        return self._details

    def trailing_metadata(self):
        return None if self._trailer is None else (("x", "y"), ("grpc-status-details-bin", self._trailer))


CALLS = [
    # the call, the exception type wanted, its text
    ("a shed trailer", _Call(grpc.StatusCode.RESOURCE_EXHAUSTED, "full", th.rich_status(8, "full", SHED)), Shed, "shed: full, retry after 2s"),
    ("a deferral trailer", _Call(grpc.StatusCode.UNAVAILABLE, "full", th.rich_status(14, "full", DEFER)), Deferred, "deferred: full (session lives on home-b)"),
    ("a failed precondition without a miss", _Call(grpc.StatusCode.FAILED_PRECONDITION, "needs FIBER_SNAPSHOT"), TierGap, "tier gap: needs FIBER_SNAPSHOT"),
    ("a failed precondition with the NoWorkspace detail", _Call(grpc.StatusCode.FAILED_PRECONDITION, "fiber g/1/1", NO_WS), NoWorkspace,
     "no workspace: fiber g/1/1"),
    ("the NoWorkspace detail with an empty value", _Call(grpc.StatusCode.FAILED_PRECONDITION, "fiber g/1/1", NO_WS_WITH_VALUE), NoWorkspace,
     "no workspace: fiber g/1/1"),
    ("a failed precondition with another detail is still a tier gap", _Call(grpc.StatusCode.FAILED_PRECONDITION, "x", th.vi(1, 9) + th.ld(3, RETRY_INFO)),
     TierGap, "tier gap: x"),
    ("a failed precondition whose trailer does not parse is a tier gap", _Call(grpc.StatusCode.FAILED_PRECONDITION, "x", b"\x1a\x05"), TierGap, "tier gap: x"),
    ("a detail cut short inside its Any is a tier gap, not a crash",
     _Call(grpc.StatusCode.FAILED_PRECONDITION, "x", th.vi(1, 9) + b"\x1a\x05\x0a\x10abc"), TierGap, "tier gap: x"),
    ("the NoWorkspace detail on another code changes nothing", _Call(grpc.StatusCode.NOT_FOUND, "gone", NO_WS), NotFound, "not found: gone"),
    ("resource exhausted without a miss is a quota", _Call(grpc.StatusCode.RESOURCE_EXHAUSTED, "file too large"), QuotaExceeded,
     "quota exceeded: file too large"),
    ("resource exhausted with another detail and no miss is a quota", _Call(grpc.StatusCode.RESOURCE_EXHAUSTED, "x", th.vi(1, 8) + th.ld(3, RETRY_INFO)),
     QuotaExceeded, "quota exceeded: x"),
    ("resource exhausted with a shed miss is still a shed", _Call(grpc.StatusCode.RESOURCE_EXHAUSTED, "busy", th.rich_status(8, "busy", SHED)), Shed,
     "shed: busy, retry after 2s"),
    ("a shed miss ahead of a detail that does not parse is still a shed",
     _Call(grpc.StatusCode.RESOURCE_EXHAUSTED, "busy", th.rich_status(8, "busy", SHED) + b"\x1a\x05"), Shed, "shed: busy, retry after 2s"),
    ("a shed miss whose payload does not parse is not read as a quota",
     _Call(grpc.StatusCode.RESOURCE_EXHAUSTED, "x", th.vi(1, 8) + th.ld(3, _any("a/fiberd.grant.v1.Miss", b"\x08"))), _Call, None),
    ("not found", _Call(grpc.StatusCode.NOT_FOUND, "fiber g/1/1 unknown"), NotFound, "not found: fiber g/1/1 unknown"),
    ("unauthenticated stays what it was", _Call(grpc.StatusCode.UNAUTHENTICATED, "no"), _Call, None),
    ("a resource-exhausted trailer that does not parse stays what it was, not a quota",
     _Call(grpc.StatusCode.RESOURCE_EXHAUSTED, "x", b"\x1a\x05"), _Call, None),
    ("something that is no call stays what it was", RuntimeError("x"), RuntimeError, "x"),
]


@table(CALLS)
def test_classify(name, f0, f1, f2):
    got = classify(f0)
    assert isinstance(got, f1)
    if f2 is not None:
        assert str(got) == f2
    if f1 is _Call:
        assert got is f0 and miss_from_call(f0) is None
