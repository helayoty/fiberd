#!/usr/bin/env bash
# slurm-cgroup-setup <root> <controller>...: make <root> a cgroup v2 tree
# slurmd's cgroup/v2 plugin can use without systemd.
#
# The plugin (IgnoreSystemd=yes) builds its hierarchy under
# <root>/system.slice/slurmstepd.scope and needs every named controller
# enabled for system.slice's children. cgroup v2 refuses to enable a
# controller for the children of a cgroup that holds processes, so every
# process in <root> is moved into the <root>/init leaf first. Each write
# is retried briefly and read back, and the script exits 1 naming the
# controller and the error when one stays disabled, so the entrypoint
# stops there instead of starting a slurmd that cannot work.
set -euo pipefail

[ $# -ge 2 ] || { echo "usage: $0 <cgroup root> <controller>..." >&2; exit 2; }
root=$1
shift
[ -f "$root/cgroup.procs" ] || { echo "cgroup-setup: $root is not a cgroup" >&2; exit 1; }

# empty_root moves every process in the root into init and succeeds once
# none is left there. A process forked meanwhile lands beside its parent,
# so a second round settles it.
empty_root() {
  local pid left
  for _ in $(seq 1 50); do
    while read -r pid; do
      echo "$pid" > "$root/init/cgroup.procs" 2>/dev/null || true
    done < "$root/cgroup.procs"
    left=$(tr '\n' ' ' < "$root/cgroup.procs")
    [ -n "$left" ] || return 0
    sleep 0.1
  done
  echo "cgroup-setup: processes still in $root after moving them to init: $left" >&2
  return 1
}

# enable <cgroup> <controller> writes +controller to the cgroup's
# subtree_control until the file lists it. The write fails with EBUSY
# while a process sits in the cgroup, with EINVAL or ENOENT when the
# controller is unknown or not delegated by the parent, and with EIO on
# Docker Desktop's kernel in the first moments of a container, which the
# retries ride out.
enable() {
  local cg=$1 c=$2 err="" have
  for _ in $(seq 1 25); do
    if err=$( { echo "+$c" > "$cg/cgroup.subtree_control"; } 2>&1 ); then
      read -ra have < "$cg/cgroup.subtree_control" || true
      for h in "${have[@]+"${have[@]}"}"; do
        [ "$h" = "$c" ] && return 0
      done
      err="not listed in $cg/cgroup.subtree_control after the write"
    fi
    sleep 0.2
  done
  echo "cgroup-setup: cannot enable $c in $cg: ${err##*: }" >&2
  return 1
}

mkdir -p "$root/init" "$root/system.slice/slurmd"
empty_root
for c in "$@"; do
  enable "$root" "$c"
  enable "$root/system.slice" "$c"
done
