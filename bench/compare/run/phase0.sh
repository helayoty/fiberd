#!/usr/bin/env bash
# Phase 0: what this host is and how loaded it is, recorded before any
# number is taken. Exits 3 when the load still exceeds the core count
# after COMPARE_QUIET_WAIT seconds.
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
mkdir -p "$STATE"
wait_quiet_host
{
  echo "== host"; date -u +%FT%TZ; uname -srm
  echo "== cores $(ncpu), load $(load1)"
  if [ -r /proc/cpuinfo ]; then grep -m1 "model name" /proc/cpuinfo; free -h | head -2; fi
  sysctl -n machdep.cpu.brand_string hw.memsize 2>/dev/null || true
  echo "== git $(git -C "$ROOT" rev-parse --short HEAD) dirty=$(git -C "$ROOT" status --porcelain | wc -l | tr -d ' ')"
  echo "== kvm"; ls -l /dev/kvm 2>/dev/null || echo absent
} | tee "$STATE/host.txt"
