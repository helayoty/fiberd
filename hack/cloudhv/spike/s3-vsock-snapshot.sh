#!/usr/bin/env bash
# S3. What happens to an open guest-to-host vsock connection across
# vm.snapshot and a restore?
#
#   sudo bash hack/cloudhv/spike/s3-vsock-snapshot.sh
#
# The guest opens one connection to host port 5000 and keeps it. A listener
# on <vsock socket>_5000 holds the host end and logs every event with a
# time stamp. Both ends send and receive before the snapshot. Then:
#   control   the paused VM resumes in place, and both ends try again
#   end       the original VMM ends (as a park does)
#   restored  a new VMM restores the snapshot on the same vsock socket path,
#             and both ends try the old connection again
#   new       the restored guest dials a fresh connection
# It reports what each side saw. The design never depends on the answer.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
prereqs
need_cmd mkfifo

OUT=$SPIKE_DIR/s3
run=$OUT/vm
fifo=$OUT/ctl
trap cleanup EXIT
rm -rf "$OUT"
mkdir -p "$run" "$OUT/snap"
mkfifo "$fifo"
log=$OUT/transcript.txt
: >"$log"

hc listen "$run/vsock.sock_5000" --hold-ctl "$fifo" >"$OUT/listen.log" 2>&1 &
lpid=$!
for _ in $(seq 1 100); do [ -S "$run/vsock.sock_5000" ] && break; sleep 0.05; done
[ -S "$run/vsock.sock_5000" ] || fail "the listener did not start, see $OUT/listen.log"

ctl() { printf '%s\n' "$*" >"$fifo"; }
guest() { hc call "$run/vsock.sock" 1024 "$*" 2>&1 || true; }
say() { printf '%s\n' "$*" | tee -a "$log"; }
# exchange <label>. The guest sends, the host sends, the guest reads.
exchange() {
  ctl "mark $1"
  say "$1: guest send -> $(guest send "guest-$1")"
  ctl "send host-$1"
  sleep 0.3
  say "$1: guest recv -> $(guest recv)"
}

hc boot --ch "$CH" --run "$run" --kernel "$KERNEL" --initramfs "$INITRAMFS" \
  --cmdline "$SPIKE_CMDLINE" --mem-mb "$SPIKE_MEM_MB" >"$OUT/boot.txt" || fail "boot failed, see $run/ch.log"
say "boot: guest dial -> $(guest dial)"
exchange before

ctl "mark snapshot"
hc api "$run/api.sock" PUT vm.pause >/dev/null
hc api "$run/api.sock" PUT vm.snapshot "{\"destination_url\":\"file://$OUT/snap\"}" >/dev/null
say "snapshot: taken while paused"

hc api "$run/api.sock" PUT vm.resume >/dev/null
exchange control

ctl "mark end"
hc shutdown --run "$run"
rm -f "$run/pid"
sleep 0.5
say "end: the original VMM is gone (the listener log shows what the host end saw)"

ctl "mark restore"
hc restore --ch "$CH" --run "$run" --source "$OUT/snap" >"$OUT/restore.txt" || fail "restore failed, see $run/ch.log"
say "restore: $(cat "$OUT/restore.txt")"
exchange restored
say "restored: guest send again -> $(guest send guest-restored-2)"
sleep 0.3
say "restored: guest recv again -> $(guest recv)"

ctl "mark new"
say "new: guest dial -> $(guest dial)"
exchange new

ctl quit
wait "$lpid" || true

echo
echo "S3 on $(hostname), cloud-hypervisor $CH_VERSION"
echo "--- what the guest saw"
cat "$log"
echo "--- what the host end saw (listener on <vsock>_5000)"
cat "$OUT/listen.log"
