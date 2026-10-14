"""The rules serve() enforces before the first fork.

Each check reads a /proc tree given as a path, so the unit tests hand in a
fake one and start nothing. A refusal is a TemplateError whose message
names the rule and the fix.
"""

from __future__ import annotations

import os
import warnings
from dataclasses import dataclass

from fiberd.template._errors import TemplateError

# The control socket fiberd hands the zygote, the one descriptor a zygote
# may hold beyond its stdio.
CONTROL_FD = 3


@dataclass(frozen=True)
class Thread:
    tid: int
    comm: str


@dataclass(frozen=True)
class Descriptor:
    fd: int
    target: str


def threads(proc: str = "/proc/self") -> list[Thread]:
    """Every thread of the process, with its comm, from proc's task directory."""
    out = []
    for name in os.listdir(os.path.join(proc, "task")):
        if not name.isdigit():
            continue
        try:
            with open(os.path.join(proc, "task", name, "comm"), encoding="utf-8", errors="replace") as f:
                comm = f.read().strip()
        except OSError:
            comm = "?"
        out.append(Thread(int(name), comm))
    return sorted(out, key=lambda t: t.tid)


def descriptors(proc: str = "/proc/self") -> list[Descriptor]:
    """Every open descriptor with what it points at, from proc's fd directory."""
    out = []
    for name in os.listdir(os.path.join(proc, "fd")):
        if not name.isdigit():
            continue
        try:
            target = os.readlink(os.path.join(proc, "fd", name))
        except OSError:
            continue
        out.append(Descriptor(int(name), target))
    return sorted(out, key=lambda d: d.fd)


def descriptor_kind(target: str) -> str | None:
    """What a descriptor is when it is one the scrub would leave dangling, else None."""
    if target.startswith("socket:"):
        return "a socket"
    if target.startswith("pipe:"):
        return "a pipe"
    for marker, kind in (("eventpoll", "an epoll instance"), ("eventfd", "an eventfd"),
                         ("timerfd", "a timerfd"), ("signalfd", "a signalfd")):
        if target.startswith("anon_inode:") and marker in target:
            return kind
    return None


def check_main_thread(is_main: bool) -> None:
    if not is_main:
        raise TemplateError("init() and serve() run on the main thread, which the signal handling and the fork hooks assume")


def check_gil(gil_enabled: bool) -> None:
    if not gil_enabled:
        raise TemplateError("fiberd.template needs the GIL, and this is a free-threaded build. Run the template on a standard CPython")


def check_init(inited: bool) -> None:
    if not inited:
        raise TemplateError("init() did not run in this process. Call fiberd.template.init() first, before any thread and before the warm-up")


def check_threads_at_init(proc: str = "/proc/self") -> None:
    found = threads(proc)
    if len(found) > 1:
        raise TemplateError(
            f"init() runs before any thread, and this process already has {len(found)}: {_names(found)}. "
            "init() re-execs to turn address-space randomisation off and takes a mount namespace, which need one thread"
        )


def check_threads(proc: str, *, own_tid: int, mode: str) -> None:
    """One thread. mode is "refuse" or "warn", the escape hatch for an author who stops their pools around clones."""
    others = [t for t in threads(proc) if t.tid != own_tid]
    if not others:
        return
    msg = (
        f"serve() needs one thread, and this process has {len(others)} more: {_names(others)}. "
        "A fiber is a copy of the serving thread alone, and a lock another thread holds at the clone stays held "
        "in the copy forever. Stop pools before serve() (OPENBLAS_NUM_THREADS=1, TOKENIZERS_PARALLELISM=false, "
        "torch.set_num_threads(1)) and make clients in on_fiber. serve(threads=\"warn\") overrides this, unsupported"
    )
    if mode == "warn":
        warnings.warn(msg, RuntimeWarning, stacklevel=3)
        return
    raise TemplateError(msg)


def check_descriptors(proc: str, *, control_fd: int = CONTROL_FD) -> None:
    """No live socket, pipe, epoll, eventfd, timerfd or signalfd beyond stdio and the control socket."""
    refused = []
    files = []
    for d in descriptors(proc):
        if d.fd in (0, 1, 2, control_fd):
            continue
        kind = descriptor_kind(d.target)
        if kind:
            refused.append(f"fd {d.fd} is {kind} ({d.target})")
        elif d.target.startswith("/") and not d.target.startswith(("/dev/", "/memfd:")):
            files.append(f"fd {d.fd} is {d.target}")
    if refused:
        raise TemplateError(
            f"serve() needs no open socket, pipe, epoll, eventfd, timerfd or signalfd, and this process holds "
            f"{len(refused)}: {'; '.join(refused)}. The scrub closes every inherited descriptor in the fiber, so a "
            "Python object over one would be a dangling wrapper. Close clients, pools and loops before serve() "
            "and make them in on_fiber, where they are one fiber's own"
        )
    if files:
        warnings.warn(
            f"regular files open at serve() are closed in every fiber while their Python objects think they are "
            f"open: {'; '.join(files)}. A fiber opens its own log in on_fiber",
            RuntimeWarning, stacklevel=3,
        )


def _names(found: list[Thread]) -> str:
    return ", ".join(f"{t.comm} (tid {t.tid})" for t in found)
