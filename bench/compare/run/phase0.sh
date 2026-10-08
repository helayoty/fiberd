#!/usr/bin/env bash
# Phase 0: what this host is and how loaded it is, recorded before any
# number is taken. Exits 3 when the load exceeds the core count.
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
mkdir -p "$STATE"
{
  echo "== host"; date -u +%FT%TZ; uname -srm
  echo "== cores $(ncpu), load $(load1)"
  if [ -r /proc/cpuinfo ]; then grep -m1 "model name" /proc/cpuinfo; free -h | head -2; fi
  sysctl -n machdep.cpu.brand_string hw.memsize 2>/dev/null || true
  echo "== git $(git -C "$ROOT" rev-parse --short HEAD) dirty=$(git -C "$ROOT" status --porcelain | wc -l | tr -d ' ')"
  echo "== kvm"; ls -l /dev/kvm 2>/dev/null || echo absent
} | tee "$STATE/host.txt"
require_quiet_host
