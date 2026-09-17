#!/usr/bin/env bash
# Probe this host for the Hyperlight backend: a hypervisor device, and the
# helper's own self-test (warm, clone from snapshot, park to disk, resume).
#
#   make linux-hyperlight-check      (passes /dev/kvm into the container)
set -u
cd "$(dirname "$0")/../.."
ok()   { printf 'ok    %s\n' "$*"; }
bad()  { printf 'FAIL  %s\n' "$*"; exit 1; }
if [ -c /dev/kvm ]; then ok "/dev/kvm present"; elif [ -c /dev/mshv ]; then ok "/dev/mshv present"; else bad "no hypervisor device (/dev/kvm or /dev/mshv): Hyperlight cannot run here"; fi
[ -x bin/hyperlight-helper ] || bad "bin/hyperlight-helper missing (make hyperlight-helper)"
[ -f bin/hyperlight-guest ] || bad "bin/hyperlight-guest missing (make hyperlight-helper)"
if out=$(bin/hyperlight-helper --guest bin/hyperlight-guest --heap-mb 32 --check 2>&1); then
  echo "$out" | sed 's/^/      /'; ok "helper self-test"
else
  echo "$out" | sed 's/^/      /'; bad "helper self-test failed"
fi
