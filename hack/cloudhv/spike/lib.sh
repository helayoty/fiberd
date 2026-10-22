# Shared by the spike scripts. Sourced, never run.
# shellcheck shell=bash
SPIKE_SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=env.sh
. "$SPIKE_SRC/env.sh"

CH=$SPIKE_DIR/bin/cloud-hypervisor
KERNEL=$SPIKE_DIR/guest/vmlinux
INITRAMFS=$SPIKE_DIR/guest/initramfs.cpio.gz

fail() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }
ok() { printf 'ok    %s\n' "$*"; }
hc() { python3 -I "$SPIKE_SRC/hostctl.py" "$@"; }

need_root() { [ "$(id -u)" = 0 ] || fail "needs root for cgroups and /dev/kvm (sudo bash $0)"; }
need_cmd() { local c; for c in "$@"; do command -v "$c" >/dev/null 2>&1 || fail "missing command: $c"; done; }
need_kvm() {
  [ -c /dev/kvm ] || fail "no /dev/kvm: this host cannot run KVM guests"
  { : <>/dev/kvm; } 2>/dev/null || fail "/dev/kvm is not readable and writable here"
}
need_cgroup2() {
  [ "$(stat -f -c %T /sys/fs/cgroup 2>/dev/null)" = cgroup2fs ] || fail "/sys/fs/cgroup is not cgroup v2"
  case $SPIKE_CGROUP in /sys/fs/cgroup/*) ;; *) fail "SPIKE_CGROUP must be under /sys/fs/cgroup" ;; esac
}
need_setup() {
  [ -x "$CH" ] && [ -f "$KERNEL" ] && [ -f "$INITRAMFS" ] || fail "run setup.sh first (SPIKE_DIR=$SPIKE_DIR)"
}
# Every spike checks the same things first, and fails by name.
prereqs() {
  [ "$(uname -m)" = x86_64 ] || fail "x86_64 only (the pins are the x86_64 assets)"
  need_root
  need_cmd python3 tar sha256sum stat
  need_kvm
  need_cgroup2
  need_setup
}

# leaf <name> creates a cgroup v2 leaf under SPIKE_CGROUP and prints its path.
leaf() {
  mkdir -p "$SPIKE_CGROUP/$1" || fail "cannot create cgroup $SPIKE_CGROUP/$1"
  printf '%s\n' "$SPIKE_CGROUP/$1"
}

# cleanup ends every VMM under OUT, every background job, and the leaves.
cleanup() {
  local p
  if [ -n "${OUT:-}" ] && [ -d "$OUT" ]; then
    while IFS= read -r p; do hc shutdown --run "$(dirname "$p")" || true; done < <(find "$OUT" -name pid -type f 2>/dev/null)
  fi
  for p in $(jobs -p); do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  if [ -d "$SPIKE_CGROUP" ]; then
    find "$SPIKE_CGROUP" -mindepth 1 -depth -type d -exec rmdir {} \; 2>/dev/null || true
    rmdir "$SPIKE_CGROUP" 2>/dev/null || true
  fi
}

# warm_snapshot <dir> [file] boots a guest, dirties SPIKE_WARM_MB in it,
# pauses it, snapshots it into <dir>/snap and ends the VMM. With "file", the
# guest RAM is the file <dir>/guest.mem mapped shared, which the snapshot
# skips, so a restore can map that file private (copy-on-write).
warm_snapshot() {
  local dir=$1 file=${2:-}
  local args=(boot --ch "$CH" --run "$dir/vm" --kernel "$KERNEL" --initramfs "$INITRAMFS"
    --cmdline "$SPIKE_CMDLINE" --mem-mb "$SPIKE_MEM_MB")
  rm -rf "$dir"
  mkdir -p "$dir/snap"
  if [ -n "$file" ]; then args+=(--mem-file "$dir/guest.mem"); fi
  hc "${args[@]}" >"$dir/boot.txt" || fail "warm boot failed, see $dir/vm/ch.log and $dir/vm/serial.log"
  hc call "$dir/vm/vsock.sock" 1024 "touch $SPIKE_WARM_MB" >/dev/null || fail "warm touch failed"
  hc api "$dir/vm/api.sock" PUT vm.pause >/dev/null || fail "vm.pause failed"
  hc api "$dir/vm/api.sock" PUT vm.snapshot "{\"destination_url\":\"file://$dir/snap\"}" >/dev/null || fail "vm.snapshot failed"
  hc shutdown --run "$dir/vm"
  rm -f "$dir/vm/pid"
  if [ -n "$file" ]; then chmod 0444 "$dir/guest.mem"; fi
  ok "warm snapshot $dir/snap ($(cat "$dir/boot.txt"), $(du -sh --apparent-size "$dir/snap" | cut -f1) apparent, $(du -sh "$dir/snap" | cut -f1) on disk)"
}

# field <name> reads name=value pairs on stdin and prints each value.
field() { sed -n "s/.*\\b$1=\\([^ ]*\\).*/\\1/p"; }
