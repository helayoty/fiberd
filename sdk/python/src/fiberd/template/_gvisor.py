"""The gVisor side of serve(), the twin of refzygote's gvisor_main.

Nothing forks on gVisor. The template is a sandbox's init, it checkpoints
itself once warm, and every fiber is a sandbox restored from that image.
A restore is told apart from the original by the Sentry's checkpoint
file, whose blocking read answers "restore" in a restored copy, and the
copy then takes its identity on fiberd's channel (fz_gvisor_identity).
The pieces that read a path are given it, so the unit tests hand in a
fake tree and start nothing.
"""

from __future__ import annotations

import os

from fiberd.template._rules import CONTROL_FD

CHECKPOINT = "/proc/gvisor/checkpoint"
# Touched once the warm-up is done. The backend takes the template image
# when it appears.
READY_MARKER = "/host/warm.ready"


def detect(proc: str = "/proc/self", control_fd: int = CONTROL_FD, checkpoint: str = CHECKPOINT) -> bool:
    """Whether this process is a gVisor sandbox's init rather than a zygote on a control socket.

    On proc and runc fiberd hands the zygote a unix socket as control_fd.
    A sandbox's init has no such descriptor and sees the Sentry's
    checkpoint file instead. Both must hold, so a template run by hand on
    a host that happens to have a /proc/gvisor is still refused later as
    one without a control socket.
    """
    try:
        target = os.readlink(os.path.join(proc, "fd", str(control_fd)))
    except OSError:
        target = ""
    return not target.startswith("socket:") and os.path.exists(checkpoint)


def mark_ready(marker: str = READY_MARKER) -> None:
    """Tells the backend the warm-up is done, so it may take the template image."""
    with open(marker, "w"):
        pass


def wait_checkpoint(path: str = CHECKPOINT) -> str:
    """Blocks until the next checkpoint of this sandbox completes.

    Opening registers interest in the next checkpoint, the read answers
    once it is done, and the file must be reopened to wait again. The
    answer is "restore" in a sandbox restored from the image, "resume" in
    the original (or a fiber checkpointed with sync) and "error" when the
    checkpoint failed. A signal interrupts the read, and the handler runs
    before it is retried.
    """
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        answer = os.read(fd, 32)
    finally:
        os.close(fd)
    return answer.decode("ascii", "replace").strip() or "error"


def incarnation_kind(kind: str) -> str:
    """The incarnation kind for what the incarnation record says: a clone of the image is a restore."""
    return "resume" if kind == "resume" else "restore"


def fiber_environ(base: dict[str, str], fence: str, endpoint: str, session: str) -> dict[str, str]:
    """The fiber's environment, the sandbox's spec environment with the identity over it.

    The scrub names a forked fiber's fence, endpoint and session the same
    way, so an author reads one environment on every backend. The session
    is unset for an anonymous fiber, as there.
    """
    env = {k: v for k, v in base.items() if k != "FIBERD_SESSION"}
    env["FIBERD_FENCE"] = fence
    env["FIBERD_ENDPOINT"] = endpoint
    if session:
        env["FIBERD_SESSION"] = session
    return env
