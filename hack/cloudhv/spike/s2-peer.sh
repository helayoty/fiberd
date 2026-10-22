#!/usr/bin/env bash
# S2. Does the engine's peer check name the VMM's leaf?
#
#   sudo bash hack/cloudhv/spike/s2-peer.sh
#
# A guest connects to host CID 2 port 5000. The VMM turns that into a
# connect to the host unix socket <vsock socket>_5000, where a listener
# prints its peer's pid (SO_PEERCRED, and SO_PEERPIDFD where the kernel has
# it) and that pid's /proc/<pid>/cgroup. Two cases, each in its own leaf.
#   boot      a booted VMM started inside leaf s2-boot
#   restored  a VMM restored from that guest's snapshot inside leaf s2-restored
# PASS when the peer's cgroup is the VMM's leaf. Exits 1 on any FAIL.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
prereqs

OUT=$SPIKE_DIR/s2
trap cleanup EXIT
rm -rf "$OUT"
mkdir -p "$OUT/boot" "$OUT/restored" "$OUT/snap"
rel() { printf '%s\n' "${1#/sys/fs/cgroup}"; }
verdict=0

# check <case> <run dir> <leaf>. The guest dials, the listener judges.
check() {
  local name=$1 run=$2 lf=$3 lpid reply
  hc listen "$run/vsock.sock_5000" --expect-cgroup "$(rel "$lf")" --count 1 >"$OUT/listen-$name.log" 2>&1 &
  lpid=$!
  for _ in $(seq 1 100); do [ -S "$run/vsock.sock_5000" ] && break; sleep 0.05; done
  reply=$(hc call "$run/vsock.sock" 1024 dial) || reply="call failed"
  echo "$name: guest says $reply"
  # No connection came, so the listener would wait forever.
  if [ "$reply" != dialed ]; then kill "$lpid" 2>/dev/null || true; fi
  echo "$name: VMM pid $(cat "$run/pid"), its cgroup $(cat "/proc/$(cat "$run/pid")/cgroup")"
  if wait "$lpid"; then ok "S2 $name: peer is in $(rel "$lf")"; else echo "FAIL  S2 $name"; verdict=1; fi
  sed 's/^/      /' "$OUT/listen-$name.log"
}

boot_leaf=$(leaf s2-boot)
hc boot --ch "$CH" --run "$OUT/boot" --kernel "$KERNEL" --initramfs "$INITRAMFS" \
  --cmdline "$SPIKE_CMDLINE" --mem-mb "$SPIKE_MEM_MB" --leaf "$boot_leaf" >"$OUT/boot.txt" ||
  fail "boot failed, see $OUT/boot/ch.log"
check boot "$OUT/boot" "$boot_leaf"

hc api "$OUT/boot/api.sock" PUT vm.pause >/dev/null
hc api "$OUT/boot/api.sock" PUT vm.snapshot "{\"destination_url\":\"file://$OUT/snap\"}" >/dev/null
hc shutdown --run "$OUT/boot"
rm -f "$OUT/boot/pid"

restored_leaf=$(leaf s2-restored)
hc restore --ch "$CH" --run "$OUT/restored" --source "$OUT/snap" --leaf "$restored_leaf" >"$OUT/restore.txt" ||
  fail "restore failed, see $OUT/restored/ch.log"
check restored "$OUT/restored" "$restored_leaf"

echo
echo "S2 on $(hostname), kernel $(uname -r), cloud-hypervisor $CH_VERSION: $([ "$verdict" = 0 ] && echo PASS || echo FAIL)"
exit "$verdict"
