"""The reference Python template, the twin of sdk/c/template/refzygote.c.

It warms a heap of --heap-mb MiB once, and every fiber serves the line
protocol refzygote speaks on its endpoint, so the conformance suite and
the integration tests drive both the same way.

    ping            -> pong
    dirty <bytes>   -> ok <n>     (writes into the warm heap, which the fiber pays for as W)
    incr            -> <n>        (a counter, state a park and resume must keep)
    get             -> <n>
    fence           -> the fence this incarnation serves under
    pid             -> the fiber's pid
    random          -> a draw from the random module, reseeded in every incarnation
    getrandom       -> 8 bytes from the kernel, hex
    rss             -> resident bytes
    getenv <NAME>   -> the value, or "-" (proves the scrub)
    session         -> the session the caller named, or "-"
    payload         -> the birth payload in hex (up to 127 bytes), or "-"
    status <Key>    -> that field of /proc/self/status, or "-"
    read <path>     -> the file's first line, or "-"
    wopen <path>    -> "ok" when the path opens for writing, else the errno's name
    stat <path>     -> dir, file, sock or other, else the errno's name
    rdonly <path>   -> ro or rw for the mount holding path
    mkdir <path>    -> "ok" when the directory could be made (and is removed), else the errno's name

The probes that need fork or mount(2) (unshare, mount, remount, connect)
and the device engine (reserve, devfree) stay with refzygote, which
answers "err no engine" here. The payload is JSON. "dirty_bytes" is
written right after ready, "ready_delay_ms" delays the ready report,
"ready_misuse" misuses the readiness pipe and "exit_after_ready" ends
the fiber at once, for the runtime's own tests. --log reopens stdio on a
file, as a launcher that runs the template as a container's init asks.

    python3 -m fiberd.template.ref --heap-mb 32

On gVisor the same template serves as a restored sandbox. There the warm
heap is already the fiber's own, so "dirty" grows W by allocating fresh
memory instead, as refzygote does.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import random
import socket
import stat
import sys
import time
from typing import Any

import fiberd.template as ft

_ERRNAMES = frozenset({"EROFS", "EACCES", "EPERM", "ENOENT", "ENOSPC", "ECONNREFUSED", "ENETUNREACH", "EHOSTUNREACH", "ETIMEDOUT", "EINVAL"})


class Warm:
    """What the zygote holds for every fiber, the heap it warmed.

    The counter lives here rather than on the fiber so a park and resume
    keeps it on every backend. A fork starts from the zygote's zero, a
    restored sandbox from the image's.
    """

    def __init__(self, heap_mb: int) -> None:
        self.heap = bytearray(heap_mb << 20)
        for i in range(0, len(self.heap), 4096):
            self.heap[i] = (i >> 12) & 0xFF
        self.counter = 0
        self.grown: list[bytearray] = []

    def dirty(self, n: int) -> int:
        """Touches n bytes of the heap, a page at a time, as refzygote does."""
        n = min(n, len(self.heap))
        for i in range(0, n, 4096):
            self.heap[i] ^= 1
        return n

    def grow(self, n: int) -> int:
        """Allocates and touches n fresh bytes, kept, for a copy whose heap is already its own."""
        block = bytearray(n)
        for i in range(0, n, 4096):
            block[i] = 1
        self.grown.append(block)
        return n


class State:
    """One fiber's state over the warm heap."""

    def __init__(self, warm: Warm, f: ft.Fiber) -> None:
        self.warm = warm
        self.f = f

    def dirty(self, n: int) -> int:
        if self.f.backend == "gvisor":
            return self.warm.grow(n)
        return self.warm.dirty(n)


def errname(e: int) -> str:
    name = errno.errorcode.get(e, "")
    return name if name in _ERRNAMES else f"errno {e}"


def answer(st: State, line: str) -> str:
    """One reply for one request line, without the newline."""
    cmd, _, arg = line.partition(" ")
    f = st.f
    if cmd == "ping":
        return "pong"
    if cmd == "dirty":
        return f"ok {st.dirty(int(arg or 0))}"
    if cmd == "incr":
        st.warm.counter += 1
        return str(st.warm.counter)
    if cmd == "get":
        return str(st.warm.counter)
    if cmd == "fence":
        return f.fence
    if cmd == "pid":
        return str(os.getpid())
    if cmd == "random":
        return str(random.getrandbits(31))
    if cmd == "getrandom":
        return os.urandom(8).hex()
    if cmd == "rss":
        return str(_rss())
    if cmd == "getenv":
        return os.environ.get(arg, "-")
    if cmd == "session":
        return f.session or "-"
    if cmd == "payload":
        return f.payload.hex() if 0 < len(f.payload) <= 127 else "-"
    if cmd == "status":
        return _status(arg)
    if cmd == "read":
        return _first_line(arg)
    if cmd == "wopen":
        return _wopen(arg)
    if cmd == "stat":
        return _stat(arg)
    if cmd == "rdonly":
        return _rdonly(arg)
    if cmd == "mkdir":
        return _mkdir(arg)
    if cmd in ("reserve", "devfree"):
        return "err no engine"
    return "err unknown command"


def _rss() -> int:
    try:
        with open("/proc/self/statm", encoding="ascii") as fh:
            return int(fh.read().split()[1]) * 4096
    except (OSError, ValueError, IndexError):
        return 0


def _status(key: str) -> str:
    try:
        with open("/proc/self/status", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                k, sep, v = line.partition(":")
                if sep and k == key:
                    return v.strip()
    except OSError:
        pass
    return "-"


def _first_line(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.readline().rstrip("\r\n") or "-"
    except OSError:
        return "-"


def _wopen(path: str) -> str:
    try:
        os.close(os.open(path, os.O_WRONLY | os.O_CLOEXEC | os.O_NOCTTY))
    except OSError as e:
        return errname(e.errno)
    return "ok"


def _stat(path: str) -> str:
    try:
        mode = os.stat(path).st_mode
    except OSError as e:
        return errname(e.errno)
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISSOCK(mode):
        return "sock"
    return "other"


def _rdonly(path: str) -> str:
    try:
        flags = os.statvfs(path).f_flag
    except OSError as e:
        return errname(e.errno)
    return "ro" if flags & os.ST_RDONLY else "rw"


def _mkdir(path: str) -> str:
    try:
        os.mkdir(path, 0o755)
    except OSError as e:
        return errname(e.errno)
    os.rmdir(path)
    return "ok"


def handle(conn: socket.socket, st: State) -> None:
    """Serves one connection, a line per request, until the peer closes."""
    buf = b""
    while True:
        chunk = conn.recv(512)
        if not chunk:
            return
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            reply = answer(st, line.decode("utf-8", "replace").rstrip("\r"))
            conn.sendall(reply.encode("utf-8") + b"\n")


def payload_dict(payload: bytes) -> dict[str, Any]:
    try:
        d = json.loads(payload) if payload else {}
    except ValueError:
        return {}
    return d if isinstance(d, dict) else {}


def on_fiber(warm: Warm, f: ft.Fiber) -> int:
    opts = payload_dict(f.payload)
    st = State(warm, f)
    # The runtime's tests ask for a late or misused ready report here.
    # On gVisor readiness is the endpoint accepting connections, so the
    # delay comes before the bind, and there is no readiness pipe to
    # misuse.
    if opts.get("ready_delay_ms") and f.backend == "gvisor":
        time.sleep(int(opts["ready_delay_ms"]) / 1000)
    # A handoff fiber listens on nothing. fiberd passes it connections,
    # which serve() terminates TLS on with the grant's identity.
    srv = f.listen() if f.kind != "handoff" else None
    if opts.get("ready_delay_ms") and f.backend != "gvisor":
        time.sleep(int(opts["ready_delay_ms"]) / 1000)
    misuse = int(opts.get("ready_misuse", 0)) if f.backend != "gvisor" else 0
    if misuse == 1:
        os.write(3, b"x")
    elif misuse == 2:
        os.close(3)
    f.ready()
    if opts.get("exit_after_ready"):
        return 0
    if opts.get("dirty_bytes"):
        st.dirty(int(opts["dirty_bytes"]))
    f.serve(lambda conn: handle(conn, st), listener=srv)
    return 0


def reopen_stdio(path: str) -> None:
    """stdin from /dev/null and stdout and stderr appended to path, as refzygote's --log does.

    Done from inside the process, since a template that is a container's
    init inherits descriptors from outside its mount namespace, which
    criu cannot map when it checkpoints the zygote's pages.
    """
    for stream in (sys.stdout, sys.stderr):
        stream.flush()
    log = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC, 0o644)
    null = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
    os.dup2(null, 0)
    os.dup2(log, 1)
    os.dup2(log, 2)
    os.close(log)
    os.close(null)


def main(argv: list[str] | None = None) -> int:
    ft.init()
    p = argparse.ArgumentParser(prog="fiberd.template.ref", description="the reference Python template")
    p.add_argument("--heap-mb", type=int, default=64, help="MiB to warm once in the zygote (default 64)")
    p.add_argument("--log", metavar="PATH", help="append stdout and stderr to PATH (a launcher's zygote log)")
    args = p.parse_args(argv)
    if args.log:
        reopen_stdio(args.log)
    warm = Warm(args.heap_mb)
    return ft.serve(lambda f: on_fiber(warm, f))


if __name__ == "__main__":
    sys.exit(main())
