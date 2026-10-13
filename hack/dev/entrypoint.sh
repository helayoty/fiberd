#!/usr/bin/env bash
# Prepare a delegated cgroup v2 subtree inside the dev container.
#
# cgroup v2's "no internal processes" rule: a cgroup that has child cgroups
# with controllers enabled may not itself hold processes. Docker puts this
# shell in the namespace root, so move every process into a leaf first,
# then enable the controllers we need on the root and create the fiberd
# subtree that fiberd treats as its delegated root ($FIBERD_CGROUP_ROOT).
set -e
CG=/sys/fs/cgroup
ROOT=${FIBERD_CGROUP_ROOT:-$CG/fiberd}

# enable turns on each controller the kernel offers under dir, retrying
# briefly, and stops with the kernel's error when it does not take.
enable() {
  local dir=$1 c err _
  shift
  if [ ! -f "$dir/cgroup.controllers" ]; then
    echo "fiberd-dev: $dir is not a cgroup" >&2
    exit 1
  fi
  for c in "$@"; do
    grep -qw "$c" "$dir/cgroup.controllers" || continue
    for _ in $(seq 25); do
      err=$({ echo "+$c" >"$dir/cgroup.subtree_control"; } 2>&1) && break
      sleep 0.2
    done
    if ! grep -qw "$c" "$dir/cgroup.subtree_control"; then
      echo "fiberd-dev: cannot enable $c in $dir: ${err:-not listed after the write}" >&2
      exit 1
    fi
  done
}

if [ -w "$CG/cgroup.subtree_control" ]; then
  mkdir -p "$CG/init"
  for _ in $(seq 25); do
    pids=$(cat "$CG/cgroup.procs")
    [ -z "$pids" ] && break
    for p in $pids; do
      # A process that exited meanwhile is gone already, the check below catches the rest.
      echo "$p" >"$CG/init/cgroup.procs" 2>/dev/null || true
    done
  done
  if [ -n "$(cat "$CG/cgroup.procs")" ]; then
    echo "fiberd-dev: processes still in $CG: $(tr '\n' ' ' <"$CG/cgroup.procs")" >&2
    exit 1
  fi
  enable "$CG" memory cpu pids
  mkdir -p "$ROOT"
  enable "$ROOT" memory cpu pids
else
  echo "fiberd-dev: /sys/fs/cgroup is read-only; run with --privileged --cgroupns=private" >&2
fi
exec "$@"
