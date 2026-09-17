#!/usr/bin/env bash
# Prepare a delegated cgroup v2 subtree inside the dev container.
#
# cgroup v2's "no internal processes" rule: a cgroup that has child cgroups
# with controllers enabled may not itself hold processes. Docker puts this
# shell in the namespace root, so move it into a leaf first, then enable
# the controllers we need on the root and create the fiberd subtree that
# the agent treats as its delegated root ($FIBERD_CGROUP_ROOT).
set -e
CG=/sys/fs/cgroup
if [ -w "$CG/cgroup.subtree_control" ]; then
  mkdir -p "$CG/init"
  echo $$ > "$CG/init/cgroup.procs" 2>/dev/null || true
  # Enable what the runtime uses; ignore controllers the kernel lacks.
  for c in memory cpu pids; do
    echo "+$c" > "$CG/cgroup.subtree_control" 2>/dev/null || true
  done
  mkdir -p "${FIBERD_CGROUP_ROOT:-$CG/fiberd}"
  # The subtree root itself must allow children to use the controllers.
  for c in memory cpu pids; do
    echo "+$c" > "${FIBERD_CGROUP_ROOT:-$CG/fiberd}/cgroup.subtree_control" 2>/dev/null || true
  done
else
  echo "fiberd-dev: /sys/fs/cgroup is read-only; run with --privileged --cgroupns=private" >&2
fi
exec "$@"
