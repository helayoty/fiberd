#!/usr/bin/env bash
# Probe gVisor inside the dev container for what the gvisor backend needs:
# runsc runs a sandbox here (systrap, no KVM), checkpoint/restore works, a
# bind-mounted host directory can carry unix sockets (--host-uds), and the
# workload can trigger its own checkpoint through /proc/gvisor/checkpoint
# and read the restore-time environment from /proc/gvisor/spec_environ.
#
#   make linux-gvisor-check
#
# Lessons this script encodes: the rootfs must be a real directory (with
# root.path "/" runsc places bind mounts under the host's real "/"); a
# root overlay makes bind mounts read-only, so --overlay2=none; the
# self-checkpoint directory is opened when the sandbox is created and must
# exist; restore validates that process args match the checkpoint.
set -u
fail=0
ok()   { printf 'ok    %s\n' "$*"; }
warn() { printf 'WARN  %s\n' "$*"; }
bad()  { printf 'FAIL  %s\n' "$*"; fail=1; }
# The restore probes run this host's /bin/sh inside the sandbox, so the
# host's userland must be restorable: on aarch64 that means no pointer
# authentication (see hack/dev/Dockerfile for why the image is bookworm).

command -v runsc >/dev/null || { bad "runsc not installed"; exit 1; }
ok "runsc $(runsc --version | head -1)"

W=$(mktemp -d /var/lib/gvisor-probe.XXXXXX)
ROOT=$W/root       # runsc --root: its state directory
HOSTDIR=$W/host    # bind-mounted into every sandbox at /host
ROOTFS=$W/rootfs   # a minimal rootfs: sh + a few tools + their libraries
mkdir -p "$ROOT" "$HOSTDIR" "$ROOTFS"/{bin,proc,dev,host,tmp}
for t in sh sleep echo cat tr grep; do cp "$(command -v $t)" "$ROOTFS/bin/"; done
for f in $(ldd /bin/sh /usr/bin/tr /usr/bin/grep | awk '/=>/ {print $3} /ld-linux|ld-musl/ {print $1}' | sort -u); do mkdir -p "$ROOTFS$(dirname "$f")"; cp "$f" "$ROOTFS$f"; done
# A tiny unix-socket server/client for the endpoint probe.
cat >"$W/uds.c" <<'EOF'
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
int main(int argc, char **argv) {
  struct sockaddr_un a = {.sun_family = AF_UNIX};
  strncpy(a.sun_path, argv[2], sizeof a.sun_path - 1);
  int s = socket(AF_UNIX, SOCK_STREAM, 0);
  if (argv[1][0] == 's') {
    unlink(argv[2]);
    if (bind(s, (struct sockaddr *)&a, sizeof a) || listen(s, 1)) { perror("bind"); return 1; }
    FILE *r = fopen(argv[3], "w"); fclose(r);
    int c = accept(s, 0, 0); write(c, "pong\n", 5); close(c); return 0;
  }
  if (connect(s, (struct sockaddr *)&a, sizeof a)) { perror("connect"); return 1; }
  char b[16]; int n = read(s, b, sizeof b); write(1, b, n > 0 ? n : 0); return 0;
}
EOF
gcc -static -O2 -o "$ROOTFS/bin/uds" "$W/uds.c" 2>/dev/null || cp "$(gcc -O2 -o "$W/uds" "$W/uds.c" && echo "$W/uds")" "$ROOTFS/bin/uds"

RUNSC="runsc --root=$ROOT --platform=systrap --network=none --ignore-cgroups --host-uds=all --overlay2=none --debug-log=$W/ --log-format=text"

bundle() { # name script [self-checkpoint dir]
  local b=$W/$1; mkdir -p "$b"
  local ann='{}'
  if [ -n "${3:-}" ]; then
    mkdir -p "$3"
    ann="{\"dev.gvisor.internal.checkpoint.path\": \"$3\", \"dev.gvisor.internal.checkpoint.enable\": \"true\", \"dev.gvisor.internal.checkpoint.resume\": \"true\"}"
  fi
  cat >"$b/config.json" <<EOF
{
  "ociVersion": "1.0.2",
  "process": {"terminal": false, "user": {"uid": 0, "gid": 0}, "cwd": "/",
    "args": ["/bin/sh", "-c", $(printf '%s' "$2" | jq -Rs .)],
    "env": ["PATH=/bin", "FIBERD_FENCE=${FENCE:-none}", "FIBERD_ENDPOINT=${ENDPOINT:-none}"]},
  "root": {"path": "$ROOTFS", "readonly": false},
  "hostname": "probe",
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc"},
    {"destination": "/dev", "type": "tmpfs", "source": "tmpfs"},
    {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs"},
    {"destination": "/host", "type": "bind", "source": "$HOSTDIR", "options": ["rbind", "rw"]}
  ],
  "annotations": $ann,
  "linux": {"namespaces": [{"type": "pid"}, {"type": "mount"}, {"type": "ipc"}, {"type": "uts"}]}
}
EOF
  echo "$b"
}

# 1. A sandbox runs at all and its writes to /host reach us.
B=$(bundle hello 'echo hello-from-gvisor > /host/hello; cat /proc/version > /host/kernel')
t0=$(date +%s%N)
if $RUNSC run --bundle "$B" hello >"$W/hello.out" 2>&1 && [ "$(cat "$HOSTDIR/hello" 2>/dev/null)" = hello-from-gvisor ]; then
  ok "sandbox runs in $(( ($(date +%s%N) - t0) / 1000000 )) ms; guest kernel: $(cut -d' ' -f1-3 "$HOSTDIR/kernel")"
else
  bad "sandbox did not run or /host not writable: $(tail -3 "$W/hello.out" | tr '\n' ' ')"; exit 1
fi

# 2. A counter survives checkpoint + restore into a new sandbox.
B=$(bundle count 'n=0; while :; do n=$((n+1)); echo $n > /host/count; sleep 0.2; done')
$RUNSC run --detach --bundle "$B" count >"$W/count.out" 2>&1 || { bad "detached run: $(cat "$W/count.out")"; exit 1; }
sleep 1.5
before=$(cat "$HOSTDIR/count")
t0=$(date +%s%N)
if $RUNSC checkpoint --image-path="$W/ckpt" count >"$W/ckpt.out" 2>&1; then
  ok "checkpoint of a running sandbox in $(( ($(date +%s%N) - t0) / 1000000 )) ms (count was $before, images $(du -sh "$W/ckpt" | cut -f1))"
else
  bad "checkpoint failed: $(tail -3 "$W/ckpt.out" | tr '\n' ' ')"
fi
$RUNSC delete -force count >/dev/null 2>&1 || true
t0=$(date +%s%N)
if $RUNSC restore --detach --image-path="$W/ckpt" --bundle "$B" count2 >"$W/restore.out" 2>&1; then
  rt=$(( ($(date +%s%N) - t0) / 1000000 ))
  sleep 1
  after=$(cat "$HOSTDIR/count")
  if [ "$after" -gt "$before" ] 2>/dev/null; then ok "restore in $rt ms continues the counter ($before -> $after)"; else bad "restored sandbox did not continue ($before -> $after)"; fi
else
  bad "restore failed: $(tail -3 "$W/restore.out" | tr '\n' ' ')"
fi
$RUNSC delete -force count2 >/dev/null 2>&1 || true

# 3. A unix socket on the bind-mounted host dir, served from the sandbox,
#    reachable from here: what a fiber endpoint needs.
B=$(bundle uds '/bin/uds s /host/ep.sock /host/uds-ready')
$RUNSC run --detach --bundle "$B" uds >"$W/uds.out" 2>&1 || bad "uds sandbox: $(cat "$W/uds.out")"
for _ in $(seq 1 50); do [ -e "$HOSTDIR/uds-ready" ] && break; sleep 0.1; done
reply=$("$ROOTFS/bin/uds" c "$HOSTDIR/ep.sock" 2>&1)
[ "$reply" = pong ] && ok "host reaches a unix socket the sandbox created on the bind mount (--host-uds)" || bad "unix socket through the bind mount: '$reply'"
$RUNSC delete -force uds >/dev/null 2>&1 || true

# 3b. The same, across a checkpoint: a serving socket survives park/resume?
B=$(bundle uds2 'while :; do /bin/uds s /host/ep2.sock /host/uds2-ready; done')
$RUNSC run --detach --bundle "$B" uds2 >"$W/uds2.out" 2>&1 || bad "uds2 sandbox: $(cat "$W/uds2.out")"
for _ in $(seq 1 50); do [ -e "$HOSTDIR/uds2-ready" ] && break; sleep 0.1; done
if $RUNSC checkpoint --image-path="$W/ckpt2" uds2 >"$W/ckpt2.out" 2>&1; then
  $RUNSC delete -force uds2 >/dev/null 2>&1 || true
  if $RUNSC restore --detach --image-path="$W/ckpt2" --bundle "$B" uds3 >"$W/restore2.out" 2>&1; then
    sleep 0.5
    reply=$("$ROOTFS/bin/uds" c "$HOSTDIR/ep2.sock" 2>&1)
    [ "$reply" = pong ] && ok "a listening host unix socket survives checkpoint/restore" || warn "listening socket after restore: '$reply' (fibers must re-bind after resume)"
    $RUNSC delete -force uds3 >/dev/null 2>&1 || true
  else
    warn "restore with a listening host unix socket failed: $(tail -2 "$W/restore2.out" | tr '\n' ' ') (fibers must close endpoints before park)"
  fi
else
  warn "checkpoint with a listening host unix socket failed: $(tail -2 "$W/ckpt2.out" | tr '\n' ' ') (fibers must close endpoints before park)"
  $RUNSC delete -force uds2 >/dev/null 2>&1 || true
fi

# 4. Application-driven checkpoint: the workload writes /proc/gvisor/checkpoint
#    after warming up, keeps running (resume annotation), and the images land.
SCRIPT='echo warm > /host/selfck-state; echo 1 > /proc/gvisor/checkpoint; cat /proc/gvisor/spec_environ | tr "\0" "\n" > /host/selfck-env; echo after-checkpoint > /host/selfck-after; sleep 30'
B=$(bundle selfck "$SCRIPT" "$HOSTDIR/self-ckpt")
$RUNSC run --detach --bundle "$B" selfck >"$W/selfck.out" 2>&1 || bad "selfck sandbox: $(cat "$W/selfck.out")"
for _ in $(seq 1 100); do [ -e "$HOSTDIR/selfck-after" ] && break; sleep 0.1; done
if [ -e "$HOSTDIR/selfck-after" ] && [ -s "$HOSTDIR/self-ckpt/checkpoint.img" ]; then
  ok "workload-triggered checkpoint via /proc/gvisor/checkpoint, sandbox kept running ($(du -sh "$HOSTDIR/self-ckpt" | cut -f1) of images)"
else
  bad "workload-triggered checkpoint: after=$([ -e "$HOSTDIR/selfck-after" ] && echo yes || echo no) images=$(ls "$HOSTDIR/self-ckpt" 2>/dev/null | wc -l)"
fi
$RUNSC delete -force selfck >/dev/null 2>&1 || true

# 5. The backend's own mechanism: the workload drops a marker, opens
#    /proc/gvisor/checkpoint and blocks reading it; the checkpoint is taken
#    from outside with --leave-running; the read answers "resume" in the
#    original and "restore" in a sandbox restored from the image with a
#    different env, which the restored copy then reads from spec_environ.
# After "restore" the spec environment can still read as the checkpoint's
# for a moment (seen on GitHub's x86 runners); the workload polls for the
# new fence the way the backend's workload does.
SCRIPT2='touch /host/ext-ready; exec 3</proc/gvisor/checkpoint; r=$(cat <&3); echo "$r" > /host/ext-$$-$r; if [ "$r" = restore ]; then i=0; while [ $i -lt 300 ]; do if tr "\0" "\n" < /proc/gvisor/spec_environ | grep -q "^FIBERD_FENCE=g/7/3"; then break; fi; sleep 0.01; i=$((i+1)); done; tr "\0" "\n" < /proc/gvisor/spec_environ > /host/ext-env; fi; sleep 30'
B=$(bundle ext "$SCRIPT2")
rm -f "$HOSTDIR"/ext-*
$RUNSC run --detach --bundle "$B" ext >"$W/ext.out" 2>&1 || bad "ext sandbox: $(cat "$W/ext.out")"
for _ in $(seq 1 50); do [ -e "$HOSTDIR/ext-ready" ] && break; sleep 0.1; done
sleep 0.2
if $RUNSC checkpoint --leave-running --direct --image-path="$W/ext-ckpt" ext >"$W/extck.out" 2>&1; then
  sleep 0.5
  ls "$HOSTDIR"/ext-*-resume >/dev/null 2>&1 && ok "external --leave-running checkpoint: the original's read answered 'resume'" || warn "the original's read did not answer 'resume' after --leave-running ($(ls "$HOSTDIR" | tr '\n' ' '))"
  FENCE=g/7/3 ENDPOINT=/host/g-7-3.sock B=$(bundle ext2 "$SCRIPT2")
  if $RUNSC restore --detach --direct --image-path="$W/ext-ckpt" --bundle "$B" ext2 >"$W/ext2.out" 2>&1; then
    for _ in $(seq 1 50); do [ -s "$HOSTDIR/ext-env" ] && break; sleep 0.1; done
    env_seen=$(grep '^FIBERD_FENCE=' "$HOSTDIR/ext-env" 2>/dev/null || true)
    [ "$env_seen" = "FIBERD_FENCE=g/7/3" ] && ok "restored sandbox's read answered 'restore' and spec_environ carries the restore-time env ($env_seen)" || bad "restored sandbox: env '$env_seen'; spec_environ read as: $(tr '\n' ' ' <"$HOSTDIR/ext-env" 2>/dev/null | cut -c1-160)"
    $RUNSC delete -force ext2 >/dev/null 2>&1 || true
  else
    bad "restore from the external checkpoint: $(tail -3 "$W/ext2.out" | tr '\n' ' ')"
  fi
else
  bad "external checkpoint --leave-running --direct: $(tail -3 "$W/extck.out" | tr '\n' ' ')"
fi
$RUNSC delete -force ext >/dev/null 2>&1 || true

if [ "$fail" = 0 ]; then rm -rf "$W"; else echo "state kept in $W"; fi
exit $fail
