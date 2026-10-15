"""The fence, the endpoint and the fence file fiberd publishes beside it."""

from __future__ import annotations

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


def tcp_bind(endpoint: str) -> tuple[bool, int]:
    """Whether a tcp endpoint names an IPv6 host, and its port. The listener binds that family's wildcard."""
    hostport = endpoint[len("tcp://"):]
    host, sep, port = hostport.rpartition(":")
    if not sep or not port.isdigit():
        raise TemplateError(f"endpoint {endpoint!r} is not tcp://host:port")
    return host.startswith("["), int(port)


def fence_file(endpoint: str, kind: str, birth: Fence) -> str:
    """Where fiberd publishes a resumed fiber's fence, as refzygote looks for it.

    Beside a unix endpoint, as <path>.fence. A fiber that binds tcp itself or
    serves handed-off connections has no socket, and finds the file in its
    working directory, its grant's run directory, under its birth fence's
    name, <epoch>-<seq>.fence.
    """
    if kind == "unix":
        return unix_path(endpoint) + ".fence"
    return f"{birth.epoch}-{birth.seq}.fence"


def live_fence(path: str, fallback: str) -> str:
    """The fence in the file's first line, or fallback when there is none."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            line = f.readline().strip()
    except OSError:
        return fallback
    return line or fallback
