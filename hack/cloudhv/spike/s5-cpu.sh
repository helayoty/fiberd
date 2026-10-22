#!/usr/bin/env bash
# S5. Which CPU facts does a snapshot depend on?
#
#   sudo bash hack/cloudhv/spike/s5-cpu.sh snapshot s5-<host>.tar.gz    (on host 1)
#   sudo bash hack/cloudhv/spike/s5-cpu.sh restore  s5-<host>.tar.gz    (on host 2)
#
# snapshot boots a guest, snapshots it, and packs the snapshot, the guest
# kernel and initramfs, and this host's CPU facts into a tarball.
# restore unpacks a tarball from another host, prints both hosts' CPU facts
# and the CPU flags only one side has, then restores and resumes the guest
# and asks for its served line. A refused restore is an answer, not an error,
# so it exits 0 once it has one. It exits 1 only when it cannot run.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

usage() { echo "usage: $0 snapshot|restore <tarball>" >&2; exit 2; }
[ $# = 2 ] || usage
cmd=$1
tarball=$(realpath -m "$2")
prereqs
OUT=$SPIKE_DIR/s5
trap cleanup EXIT

# facts <dir> writes this host's facts into <dir>.
facts() {
  mkdir -p "$1"
  lscpu >"$1/lscpu.txt" 2>&1 || echo "lscpu absent" >"$1/lscpu.txt"
  sed -n 's/^flags[[:space:]]*: //p' /proc/cpuinfo | head -1 | tr ' ' '\n' | sed '/^$/d' | sort -u >"$1/flags.txt"
  {
    echo "host $(hostname)"
    echo "kernel $(uname -r)"
    echo "vendor $(sed -n 's/^vendor_id[[:space:]]*: //p' /proc/cpuinfo | head -1)"
    echo "model_name $(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1)"
    echo "family $(sed -n 's/^cpu family[[:space:]]*: //p' /proc/cpuinfo | head -1)"
    echo "model $(sed -n 's/^model[[:space:]]*: //p' /proc/cpuinfo | head -1)"
    echo "stepping $(sed -n 's/^stepping[[:space:]]*: //p' /proc/cpuinfo | head -1)"
    echo "microcode $(sed -n 's/^microcode[[:space:]]*: //p' /proc/cpuinfo | head -1)"
    echo "cpus $(nproc)"
    echo "cloud_hypervisor $("$CH" --version 2>&1 | head -1)"
    echo "cloud_hypervisor_sha256 $(sha256sum "$CH" | cut -d' ' -f1)"
  } >"$1/facts.txt"
}

case $cmd in
  snapshot)
    rm -rf "$OUT"
    mkdir -p "$OUT/pack/snap" "$OUT/pack/guest"
    hc boot --ch "$CH" --run "$OUT/vm" --kernel "$KERNEL" --initramfs "$INITRAMFS" \
      --cmdline "$SPIKE_CMDLINE" --mem-mb "${S5_MEM_MB:-64}" >"$OUT/boot.txt" || fail "boot failed, see $OUT/vm/ch.log"
    hc call "$OUT/vm/vsock.sock" 1024 "touch 8" >/dev/null || fail "touch failed"
    hc api "$OUT/vm/api.sock" PUT vm.pause >/dev/null
    hc api "$OUT/vm/api.sock" PUT vm.snapshot "{\"destination_url\":\"file://$OUT/pack/snap\"}" >/dev/null
    hc shutdown --run "$OUT/vm"
    rm -f "$OUT/vm/pid"
    cp "$KERNEL" "$OUT/pack/guest/vmlinux"
    cp "$INITRAMFS" "$OUT/pack/guest/initramfs.cpio.gz"
    facts "$OUT/pack/facts"
    tar -C "$OUT" -czf "$tarball" pack
    ok "S5 snapshot packed into $tarball ($(du -h "$tarball" | cut -f1))"
    cat "$OUT/pack/facts/facts.txt"
    ;;
  restore)
    [ -f "$tarball" ] || fail "no tarball at $tarball"
    rm -rf "$OUT"
    mkdir -p "$OUT/from"
    tar -C "$OUT/from" -xzf "$tarball"
    facts "$OUT/here"
    from=$OUT/from/pack
    echo "--- snapshot host"
    cat "$from/facts/facts.txt"
    echo "--- restore host"
    cat "$OUT/here/facts.txt"
    echo "--- CPU flags only on the snapshot host"
    comm -23 "$from/facts/flags.txt" "$OUT/here/flags.txt" | tr '\n' ' '
    echo
    echo "--- CPU flags only on the restore host"
    comm -13 "$from/facts/flags.txt" "$OUT/here/flags.txt" | tr '\n' ' '
    echo
    restore=failed resume=skipped served=skipped
    if line=$(hc restore --ch "$CH" --run "$OUT/vm" --source "$from/snap" \
      --kernel "$from/guest/vmlinux" --initramfs "$from/guest/initramfs.cpio.gz" 2>"$OUT/err.txt"); then
      restore=ok resume=ok served=ok
      echo "restore: $line"
      echo "guest after resume: $(hc call "$OUT/vm/vsock.sock" 1024 "touch 4" 2>&1 || true)"
    else
      err=$(tail -1 "$OUT/err.txt")
      case $err in
        *"did not reach Paused"* | *"vm.info"* | *"API socket"*) restore="failed ($err)" ;;
        *vm.resume*) restore=ok resume="failed ($err)" ;;
        *served*) restore=ok resume=ok served="failed ($err)" ;;
        *) restore="failed ($err)" ;;
      esac
      echo "--- the VMM's log, last lines"
      tail -n 30 "$OUT/vm/ch.log" 2>/dev/null || true
      tail -n 10 "$OUT/vm/ch.out" 2>/dev/null || true
    fi
    echo
    echo "S5 RESULT from=$(sed -n 's/^host //p' "$from/facts/facts.txt") to=$(hostname) restore=$restore resume=$resume served=$served"
    ;;
  *) usage ;;
esac
