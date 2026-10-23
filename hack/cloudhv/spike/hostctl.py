#!/usr/bin/env python3
"""The host side of the Cloud Hypervisor spikes. Standard library only.

The spike scripts call it with "python3 -I". It starts VMMs, talks to their
API socket (HTTP over a unix socket) and to the guest over hybrid vsock, and
times each step in this process, so no shell or curl start-up is counted.

  hostctl.py boot     --ch BIN --run DIR --kernel K --initramfs I [--mem-file F] [--leaf CG]
  hostctl.py restore  --ch BIN --run DIR --source SNAP [--mode copy|ondemand|copyonwrite] [--private-zones] [--leaf CG]
  hostctl.py api      SOCK METHOD ENDPOINT [JSON]
  hostctl.py call     VSOCK PORT LINE
  hostctl.py shutdown --run DIR
  hostctl.py listen   PATH [--expect-cgroup CG] [--hold-ctl FIFO] [--count N]
  hostctl.py smaps    PID
  hostctl.py stats    (numbers on stdin)
"""

import argparse
import json
import os
import select
import shutil
import signal
import socket
import statistics
import struct
import subprocess
import sys
import time

SO_PEERPIDFD = 77  # Linux 6.5 and later. Not in the socket module yet.
GUEST_PORT = 1024


def now_ms():
    return time.monotonic_ns() / 1e6


def die(msg):
    print(f"hostctl: {msg}", file=sys.stderr)
    sys.exit(1)


# HTTP over the VMM's API socket. Cloud Hypervisor's server answers one
# request per exchange, so the reply is read by its Content-Length.
def http(sock_path, method, endpoint, body=None, timeout=10.0):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(sock_path)
        data = body.encode() if body else b""
        head = f"{method} /api/v1/{endpoint} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n"
        if body:
            head += "Content-Type: application/json\r\n"
        head += f"Content-Length: {len(data)}\r\n\r\n"
        s.sendall(head.encode() + data)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        head_raw, _, rest = buf.partition(b"\r\n\r\n")
        lines = head_raw.decode(errors="replace").split("\r\n")
        status = int(lines[0].split()[1]) if lines and len(lines[0].split()) > 1 else 0
        length = 0
        for line in lines[1:]:
            k, _, v = line.partition(":")
            if k.strip().lower() == "content-length":
                length = int(v.strip())
        while len(rest) < length:
            chunk = s.recv(65536)
            if not chunk:
                break
            rest += chunk
        return status, rest.decode(errors="replace")
    finally:
        s.close()


def api_ok(sock_path, method, endpoint, body=None):
    status, text = http(sock_path, method, endpoint, body)
    if status >= 300 or status == 0:
        die(f"{method} {endpoint}: HTTP {status} {text.strip()}")
    return text


def wait_api(sock_path, deadline_s=10.0):
    end = time.monotonic() + deadline_s
    while time.monotonic() < end:
        try:
            status, _ = http(sock_path, "GET", "vmm.ping", timeout=1.0)
            if status == 200:
                return
        except OSError:
            pass
        time.sleep(0.002)
    die(f"API socket {sock_path} not up after {deadline_s}s")


def vm_state(sock_path):
    status, text = http(sock_path, "GET", "vm.info")
    if status != 200:
        return f"http-{status}"
    return json.loads(text).get("state", "?")


# One request over hybrid vsock. The host writes "CONNECT <port>", the VMM
# answers "OK <host port>", then the guest's listener has the connection.
def read_line(s):
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = s.recv(1)
        if not chunk:
            break
        buf += chunk
    return buf.decode(errors="replace").rstrip("\n")


def vsock_call(vsock_path, port, line, timeout=3.0):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(vsock_path)
        s.sendall(f"CONNECT {port}\n".encode())
        ok = read_line(s)
        if not ok.startswith("OK "):
            raise OSError(f"handshake answered {ok!r}")
        s.sendall(f"{line}\n".encode())
        return read_line(s)
    finally:
        s.close()


def wait_reply(vsock_path, line, want, deadline_s):
    end = time.monotonic() + deadline_s
    last = "nothing"
    while time.monotonic() < end:
        try:
            got = vsock_call(vsock_path, GUEST_PORT, line, timeout=1.0)
            if got == want:
                return
            last = repr(got)
        except OSError as e:
            last = str(e)
        time.sleep(0.001)
    die(f"no {want!r} from the guest after {deadline_s}s (last: {last})")


def start_vmm(ch, run, extra, leaf):
    os.makedirs(run, exist_ok=True)
    api = os.path.join(run, "api.sock")
    for name in ("api.sock", "vsock.sock"):
        try:
            os.unlink(os.path.join(run, name))
        except FileNotFoundError:
            pass

    def join_leaf():
        with open(os.path.join(leaf, "cgroup.procs"), "w") as f:
            f.write(str(os.getpid()))

    out = open(os.path.join(run, "ch.out"), "ab")
    cmd = [ch, "--api-socket", f"path={api}", "--log-file", os.path.join(run, "ch.log"), "-v"] + extra
    p = subprocess.Popen(cmd, cwd=run, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                         start_new_session=True, preexec_fn=join_leaf if leaf else None)
    with open(os.path.join(run, "pid"), "w") as f:
        f.write(f"{p.pid}\n")
    return p.pid, api


def cmd_boot(a):
    t0 = now_ms()
    pid, api = start_vmm(a.ch, a.run, [], a.leaf)
    wait_api(api)
    mem = a.mem_mb << 20
    if a.mem_file:
        if not os.path.exists(a.mem_file):
            with open(a.mem_file, "wb") as f:
                f.truncate(mem)
        memory = {"size": 0, "zones": [{"id": "mem0", "size": mem, "file": a.mem_file, "shared": True}]}
    else:
        memory = {"size": mem}
    cfg = {
        "cpus": {"boot_vcpus": 1, "max_vcpus": 1},
        "memory": memory,
        "payload": {"kernel": a.kernel, "initramfs": a.initramfs, "cmdline": a.cmdline},
        "vsock": {"cid": 3, "socket": os.path.join(a.run, "vsock.sock")},
        "serial": {"mode": "File", "file": os.path.join(a.run, "serial.log")},
        "console": {"mode": "Off"},
        "rng": {"src": "/dev/urandom"},
    }
    api_ok(api, "PUT", "vm.create", json.dumps(cfg))
    api_ok(api, "PUT", "vm.boot")
    wait_reply(os.path.join(a.run, "vsock.sock"), "ping", "pong", a.deadline)
    print(f"pid={pid} boot_ms={now_ms() - t0:.1f}")


# A restore gets its own copy of the snapshot's config, with its own vsock
# socket and serial file, so many restores of one snapshot can run at once.
# memory-ranges is linked, not copied.
def prepare(source, dest, run, a):
    if os.path.isdir(dest):
        shutil.rmtree(dest)
    os.makedirs(dest)
    for name in os.listdir(source):
        src = os.path.join(source, name)
        if name == "memory-ranges":
            os.symlink(os.path.abspath(src), os.path.join(dest, name))
        elif os.path.isfile(src):
            shutil.copy2(src, os.path.join(dest, name))
    path = os.path.join(dest, "config.json")
    with open(path) as f:
        cfg = json.load(f)
    cfg["vsock"]["socket"] = os.path.join(run, "vsock.sock")
    cfg["serial"] = {**cfg.get("serial", {}), "mode": "File", "file": os.path.join(run, "serial.log")}
    if a.private_zones:
        for z in (cfg.get("memory", {}).get("zones") or []):
            z["shared"] = False
    if a.kernel:
        cfg["payload"]["kernel"] = a.kernel
    if a.initramfs:
        cfg["payload"]["initramfs"] = a.initramfs
    with open(path, "w") as f:
        json.dump(cfg, f)


def cmd_restore(a):
    snap = os.path.join(a.run, "snap")
    os.makedirs(a.run, exist_ok=True)
    prepare(a.source, snap, a.run, a)
    t0 = now_ms()
    pid, api = start_vmm(a.ch, a.run, ["--restore", f"source_url=file://{snap},memory_restore_mode={a.mode}"], a.leaf)
    wait_api(api)
    end = time.monotonic() + a.deadline
    state = "?"
    while time.monotonic() < end:
        state = vm_state(api)
        if state == "Paused":
            break
        time.sleep(0.001)
    if state != "Paused":
        die(f"restore did not reach Paused (state {state}), see {a.run}/ch.log")
    t_restored = now_ms()
    api_ok(api, "PUT", "vm.resume")
    t_resumed = now_ms()
    wait_reply(os.path.join(a.run, "vsock.sock"), f"incarnate {a.incarnate}", f"served {a.incarnate}", a.deadline)
    t_served = now_ms()
    print(f"pid={pid} restored_ms={t_restored - t0:.1f} resumed_ms={t_resumed - t0:.1f} served_ms={t_served - t0:.1f}")


def cmd_api(a):
    print(api_ok(a.sock, a.method, a.endpoint, a.body).strip())


def cmd_call(a):
    try:
        print(vsock_call(a.vsock, a.port, a.line, timeout=a.timeout))
    except OSError as e:
        die(f"call {a.line!r}: {e}")


def cmd_shutdown(a):
    try:
        with open(os.path.join(a.run, "pid")) as f:
            pid = int(f.read().strip())
    except (OSError, ValueError):
        return
    try:
        http(os.path.join(a.run, "api.sock"), "PUT", "vmm.shutdown", timeout=2.0)
    except OSError:
        pass
    end = time.monotonic() + 5.0
    while time.monotonic() < end:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.02)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def peer(c):
    pid, uid, gid = struct.unpack("3i", c.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    try:
        fd = struct.unpack("i", c.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD, 4))[0]
        pidfd_pid = "?"
        with open(f"/proc/self/fdinfo/{fd}") as f:
            for line in f:
                if line.startswith("Pid:"):
                    pidfd_pid = line.split()[1]
        os.close(fd)
    except OSError as e:
        pidfd_pid = f"unavailable(errno {e.errno})"
    try:
        with open(f"/proc/{pid}/cgroup") as f:
            cg = f.read().strip()
        with open(f"/proc/{pid}/comm") as f:
            comm = f.read().strip()
    except OSError as e:
        cg, comm = f"unreadable({e.errno})", "?"
    return pid, uid, pidfd_pid, comm, cg


def stamp(t0, *words):
    print(f"t={now_ms() - t0:9.1f}ms", *words, flush=True)


def hold(c, ctl, t0):
    c.setblocking(False)
    fds = [c] + ([ctl] if ctl is not None else [])
    while True:
        r, _, _ = select.select(fds, [], [])
        if c in r:
            try:
                data = c.recv(4096)
            except OSError as e:
                stamp(t0, "conn error", e.errno, e.strerror)
                return True
            if not data:
                stamp(t0, "conn eof")
                return True
            stamp(t0, "conn recv", repr(data.decode(errors="replace")))
        if ctl is not None and ctl in r:
            for cmd in os.read(ctl, 4096).decode().splitlines():
                if cmd.startswith("mark "):
                    stamp(t0, "mark", cmd[5:])
                elif cmd.startswith("send "):
                    try:
                        c.sendall((cmd[5:] + "\n").encode())
                        stamp(t0, "conn send ok", repr(cmd[5:]))
                    except OSError as e:
                        stamp(t0, "conn send err", e.errno, e.strerror)
                elif cmd == "close":
                    c.close()
                    stamp(t0, "conn closed by host")
                    return True
                elif cmd == "quit":
                    stamp(t0, "quit")
                    return False


def cmd_listen(a):
    try:
        os.unlink(a.path)
    except FileNotFoundError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(a.path)
    srv.listen(8)
    ctl = os.open(a.hold_ctl, os.O_RDWR) if a.hold_ctl else None  # RDWR, so the FIFO never reads EOF
    t0 = now_ms()
    stamp(t0, "listening", a.path)
    failed = False
    n = 0
    while a.count == 0 or n < a.count:
        if ctl is not None:
            r, _, _ = select.select([srv, ctl], [], [])
            if ctl in r and srv not in r:
                quit_now = False
                for cmd in os.read(ctl, 4096).decode().splitlines():
                    if cmd.startswith("mark "):
                        stamp(t0, "mark", cmd[5:])
                    elif cmd.startswith("send "):
                        stamp(t0, "send skipped, no open connection", repr(cmd[5:]))
                    elif cmd == "quit":
                        quit_now = True
                if quit_now:
                    stamp(t0, "quit")
                    break
                continue
        c, _ = srv.accept()
        n += 1
        pid, uid, pidfd_pid, comm, cg = peer(c)
        stamp(t0, f"accept peer_pid={pid} uid={uid} pidfd_pid={pidfd_pid} comm={comm} cgroup={cg}")
        if a.expect_cgroup:
            got = cg.split("::", 1)[1] if "::" in cg else cg
            if got == a.expect_cgroup:
                stamp(t0, f"PASS peer cgroup {got}")
            else:
                stamp(t0, f"FAIL peer cgroup {got}, want {a.expect_cgroup}")
                failed = True
        if ctl is not None:
            if not hold(c, ctl, t0):
                break
            continue
        c.settimeout(5.0)
        try:
            stamp(t0, "recv", repr(read_line(c)))
            c.sendall(b"ok\n")
        except OSError as e:
            stamp(t0, "conn error", e)
        c.close()
    sys.exit(1 if failed else 0)


def cmd_smaps(a):
    vals = {}
    with open(f"/proc/{a.pid}/smaps_rollup") as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 2 and parts[0].endswith(":"):
                vals[parts[0][:-1]] = parts[1]
    keys = ["Rss", "Pss", "Private_Dirty", "Private_Clean", "Shared_Clean", "Shared_Dirty", "Anonymous"]
    print(" ".join(f"{k.lower()}_kb={vals.get(k, '?')}" for k in keys))


def cmd_stats(_a):
    xs = [float(x) for x in sys.stdin.read().split()]
    if not xs:
        print("n=0")
        return
    print(f"n={len(xs)} min={min(xs):.1f} median={statistics.median(xs):.1f} max={max(xs):.1f}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("boot")
    b.add_argument("--ch", required=True)
    b.add_argument("--run", required=True)
    b.add_argument("--kernel", required=True)
    b.add_argument("--initramfs", required=True)
    b.add_argument("--cmdline", default="console=ttyS0 panic=-1 quiet")
    b.add_argument("--mem-mb", type=int, default=128)
    b.add_argument("--mem-file", help="back guest RAM with this file, mapped shared")
    b.add_argument("--leaf", help="cgroup v2 directory the VMM starts in")
    b.add_argument("--deadline", type=float, default=30.0)
    b.set_defaults(fn=cmd_boot)

    r = sub.add_parser("restore")
    r.add_argument("--ch", required=True)
    r.add_argument("--run", required=True)
    r.add_argument("--source", required=True, help="the snapshot directory")
    r.add_argument("--mode", choices=["copy", "ondemand", "copyonwrite"], default="copy")
    r.add_argument("--private-zones", action="store_true", help="map file-backed zones private (copy-on-write)")
    r.add_argument("--kernel")
    r.add_argument("--initramfs")
    r.add_argument("--leaf")
    r.add_argument("--incarnate", default="1")
    r.add_argument("--deadline", type=float, default=30.0)
    r.set_defaults(fn=cmd_restore)

    x = sub.add_parser("api")
    x.add_argument("sock")
    x.add_argument("method")
    x.add_argument("endpoint")
    x.add_argument("body", nargs="?")
    x.set_defaults(fn=cmd_api)

    c = sub.add_parser("call")
    c.add_argument("vsock")
    c.add_argument("port", type=int)
    c.add_argument("line")
    c.add_argument("--timeout", type=float, default=5.0)
    c.set_defaults(fn=cmd_call)

    s = sub.add_parser("shutdown")
    s.add_argument("--run", required=True)
    s.set_defaults(fn=cmd_shutdown)

    li = sub.add_parser("listen")
    li.add_argument("path")
    li.add_argument("--expect-cgroup")
    li.add_argument("--hold-ctl", help="a FIFO of 'send <text>', 'mark <text>', 'close' and 'quit' lines")
    li.add_argument("--count", type=int, default=0)
    li.set_defaults(fn=cmd_listen)

    m = sub.add_parser("smaps")
    m.add_argument("pid", type=int)
    m.set_defaults(fn=cmd_smaps)

    st = sub.add_parser("stats")
    st.set_defaults(fn=cmd_stats)

    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
