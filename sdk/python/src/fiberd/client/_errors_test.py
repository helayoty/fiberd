"""The wire walker that finds the Miss in a status trailer, and the classifier over it."""

from __future__ import annotations

import grpc
import pytest

from fiberd._testtable import table
from fiberd.client import Deferred, NotFound, Shed, TierGap
from fiberd.client import _testhome as th
from fiberd.client._api import grant_pb2
from fiberd.client._errors import classify, fields, miss_from_call, miss_from_status

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
    ("not found", _Call(grpc.StatusCode.NOT_FOUND, "fiber g/1/1 unknown"), NotFound, "not found: fiber g/1/1 unknown"),
    ("unauthenticated stays what it was", _Call(grpc.StatusCode.UNAUTHENTICATED, "no"), _Call, None),
    ("a trailer that does not parse is ignored", _Call(grpc.StatusCode.RESOURCE_EXHAUSTED, "x", b"\x1a\x05"), _Call, None),
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
