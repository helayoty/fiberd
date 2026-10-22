"""The fence and the endpoint, as fiberd spells them."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from fiberd.template._errors import TemplateError


@dataclass(frozen=True)
class Fence:
    """A fiber's identity, grant/epoch/seq."""

    grant_uid: str
    epoch: int
    seq: int

    def __str__(self) -> str:
        return f"{self.grant_uid}/{self.epoch}/{self.seq}"


def parse_fence(s: str) -> Fence:
    """The parts of a fence fiberd handed over, or Fence(s, 0, 0) for one that is not grant/epoch/seq.

    The gVisor backend's footprint probe restores the template under the
    fence "probe", and the template serves it like any other, so an odd
    fence is not refused.
    """
    parts = s.rsplit("/", 2)
    if len(parts) != 3 or not parts[0] or not parts[1].isdigit() or not parts[2].isdigit():
        return Fence(s, 0, 0)
    return Fence(parts[0], int(parts[1]), int(parts[2]))


def endpoint_kind(endpoint: str) -> str:
    """unix, tcp or handoff, as fiberd spells the endpoint. A handoff fiber's endpoint is the word "handoff", since it binds nothing."""
    if endpoint == "handoff":
        return "handoff"
    if endpoint.startswith("tcp://"):
        return "tcp"
    return "unix"


def unix_path(endpoint: str) -> str:
    return endpoint[len("unix://"):] if endpoint.startswith("unix://") else endpoint


def tcp_bind(endpoint: str) -> tuple[bool, str, int]:
    """Whether a tcp endpoint names an IPv6 host, the host without brackets, and its port.

    The listener binds that host, the one address fiberd advertises and
    relays on, never a wildcard. fiberd writes an IP literal, an IPv6 one
    in brackets, so anything else is refused.
    """
    hostport = endpoint[len("tcp://"):]
    host, sep, port = hostport.rpartition(":")
    if not sep or not port.isdigit():
        raise TemplateError(f"endpoint {endpoint!r} is not tcp://host:port")
    v6 = host.startswith("[") and host.endswith("]")
    if v6:
        host = host[1:-1]
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is None or ip.version != (6 if v6 else 4):
        raise TemplateError(f"endpoint {endpoint!r} names no IP literal to bind, want tcp://a.b.c.d:port or tcp://[v6]:port")
    return v6, host, int(port)
