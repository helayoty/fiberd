"""The four methods of the Fibers service over a channel, sync or grpc.aio.

Written by hand rather than generated, since the generated grant_pb2_grpc
would import the messages by their proto path and need a rewrite step.
Both channel kinds build the callables the same way and differ only in
how a call is awaited, so one constructor serves the two clients.
"""

from __future__ import annotations

from typing import Any

from google.protobuf import empty_pb2

from fiberd.client._api import grant_pb2

SERVICE = "fiberd.grant.v1.Fibers"


class Stubs:
    """The service's multicallables over one channel."""

    def __init__(self, channel: Any) -> None:
        self.clone = channel.unary_unary(
            f"/{SERVICE}/Clone",
            request_serializer=grant_pb2.CloneRequest.SerializeToString,
            response_deserializer=grant_pb2.CloneResponse.FromString,
        )
        self.park = channel.unary_unary(
            f"/{SERVICE}/Park",
            request_serializer=grant_pb2.ParkRequest.SerializeToString,
            response_deserializer=empty_pb2.Empty.FromString,
        )
        self.release = channel.unary_unary(
            f"/{SERVICE}/Release",
            request_serializer=grant_pb2.ReleaseRequest.SerializeToString,
            response_deserializer=empty_pb2.Empty.FromString,
        )
        self.watch = channel.unary_stream(
            f"/{SERVICE}/Watch",
            request_serializer=empty_pb2.Empty.SerializeToString,
            response_deserializer=grant_pb2.Status.FromString,
        )
