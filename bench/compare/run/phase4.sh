#!/usr/bin/env bash
# Phase 4: every comparator on one host with /dev/kvm (the KVM host of
# bench/compare/run/kvm-host.sh, or a GitHub runner). The headline
# table comes from here alone. COMPARE_GROUPS picks the classes.
#
#   COMPARE_GROUPS=all|shared-kernel|sandboxed|microvm bench/compare/run/phase4.sh
#
# shared-kernel is phase 1 and the proc and runc rows of phase 2.
# sandboxed is phase 3 and the gVisor row of phase 2. microvm is
# Firecracker (file backend, and UFFD when COMPARE_UFFD_HANDLER names
# Firecracker's example handler) and fiberd Hyperlight. The Firecracker
# adapter runs as root, since it makes network namespaces.
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
cd "$ROOT"
GROUPS_=${COMPARE_GROUPS:-all}
FC_KERNEL=${COMPARE_FC_KERNEL:-$HOME/fc/vmlinux}
want() { [ "$GROUPS_" = all ] || [ "$GROUPS_" = "$1" ]; }

bench/compare/run/phase0.sh
if want shared-kernel; then
  bench/compare/run/phase1.sh
  bench/compare/run/phase2.sh proc runc
fi
if want sandboxed; then
  want shared-kernel || bench/compare/run/phase1.sh deploy
  bench/compare/run/phase3.sh
  bench/compare/run/phase2.sh gvisor
fi
if want microvm; then
  [ -c /dev/kvm ] || { echo "no /dev/kvm: the microvm group needs a KVM host" >&2; exit 1; }
  out=$STATE/phase4; mkdir -p "$out"
  # Firecracker: the static counter, the rootfs, then the adapter as root.
  hack/dev/run.sh true
  docker build --target binaries -o bin/compare-bin -f docker/compare/Dockerfile .
  bench/compare/adapters/firecracker/rootfs.sh bin/compare-bin/counter-static "$out/rootfs.ext4"
  install -m 0755 bin/compare-bin/compare bin/compare-bin/summarize bin/
  fc_flags=(-adapter firecracker -runs "$RUNS" -bursts "$BURSTS" -kernel "$FC_KERNEL" -rootfs "$out/rootfs.ext4"
    -work-dir "$out/fc-work" -netns "$PWD/bench/compare/adapters/firecracker/netns.sh" -resume -density "$DENSITY")
  sudo bin/compare "${fc_flags[@]}" -system firecracker-file -class microvm -snapshot-dir "$out/fc-snapshot" -out "$out/firecracker-file.jsonl"
  if [ -n "${COMPARE_UFFD_HANDLER:-}" ]; then
    sudo bin/compare "${fc_flags[@]}" -system firecracker-uffd -class microvm -snapshot-dir "$out/fc-snapshot" \
      -uffd-handler "$COMPARE_UFFD_HANDLER" -out "$out/firecracker-uffd.jsonl"
  fi
  sudo chown -R "$(id -u):$(id -g)" "$out"
  # fiberd Hyperlight: the real helper, line framing, in the dev container
  # with the hypervisor device. The framing gap is bounded by the proc line
  # row of phase 2 in the same run.
  [ -x bin/hyperlight-helper ] || make hyperlight-helper
  FIBERD_DEV_DOCKER_ARGS="--device /dev/kvm" hack/dev/run.sh env COMPARE_RUNS="$RUNS" COMPARE_BURSTS="$BURSTS" \
    COMPARE_DENSITY="$DENSITY" COMPARE_OUT=/src/bin/compare-state/phase4 bench/compare/run/standalone.sh hyperlight
  want shared-kernel || bench/compare/run/phase2.sh proc
fi
echo "== all results"
(cd bench/compare && "$GO" run ./cmd/summarize "$STATE"/phase*/*.jsonl | tee "$STATE/summary.txt")
