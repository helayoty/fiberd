#!/usr/bin/env bash
# Bring up munge, slurmctld and slurmd on this one node, then wait. The
# container runs privileged with a private cgroup namespace so slurmd's
# cgroup/v2 plugin can carve job-step cgroups and criu can checkpoint.
#
# SLURM_CGROUP=v2 (default) uses proctrack/cgroup + task/cgroup; SLURM_CGROUP=none
# falls back to proctrack/pgid + task/none (no per-step memory ceiling), for
# hosts where slurmd cannot own its cgroup.
set -euo pipefail
NODE=$(hostname -s)
# The node advertises at least 8 CPUs (SlurmdParameters=config_overrides
# lets it): the conformance suite's grants ask for 4 fibers and the storm's
# for 8, and an allocation bounds fibers.max by its CPUs. Cores are not
# pinned (no task/affinity, ConstrainCores=no), so the count is a capacity
# figure, not a cpuset.
CPUS=$(nproc); if [ "$CPUS" -lt "${SLURM_MIN_CPUS:-8}" ]; then CPUS=${SLURM_MIN_CPUS:-8}; fi
MEM=$(( $(awk '/MemTotal/ {print $2}' /proc/meminfo) / 1024 ))
case "${SLURM_CGROUP:-v2}" in
  v2)   PROCTRACK=proctrack/cgroup; TASK=task/cgroup ;;
  none) PROCTRACK=proctrack/pgid;   TASK=task/none ;;
  *) echo "SLURM_CGROUP must be v2 or none" >&2; exit 2 ;;
esac
sed -e "s/@NODE@/$NODE/g" -e "s/@CPUS@/$CPUS/g" -e "s/@MEM@/$MEM/g" \
    -e "s#@PROCTRACK@#$PROCTRACK#g" -e "s#@TASK@#$TASK#g" \
    /etc/slurm/slurm.conf.in > /etc/slurm/slurm.conf

# slurmd's cgroup/v2 plugin (IgnoreSystemd=yes) builds its hierarchy in
# /sys/fs/cgroup/system.slice/slurmstepd.scope and needs cpuset, cpu,
# memory and pids enabled for system.slice's children. Without systemd,
# slurm-cgroup-setup (docker/cgroup-setup.sh) does that by hand. It moves
# every process out of the root into a leaf first, since a cgroup with
# processes may not enable controllers for its children, and it stops
# this script with the controller and the error when one stays disabled.
# slurmd then starts in its own leaf of system.slice.
SLURMD_CG=/sys/fs/cgroup/system.slice/slurmd
if [ "$PROCTRACK" = proctrack/cgroup ]; then
  if ! [ -w /sys/fs/cgroup/cgroup.subtree_control ]; then
    echo "SLURM_CGROUP=v2 needs a writable cgroup root (run with --privileged --cgroupns=private) or SLURM_CGROUP=none" >&2
    exit 1
  fi
  slurm-cgroup-setup /sys/fs/cgroup cpuset cpu memory pids
fi
mkdir -p /var/run/slurm

# munge: a throwaway key for this one-node cluster.
mkdir -p /etc/munge /var/run/munge /var/log/munge /var/lib/munge
[ -s /etc/munge/munge.key ] || dd if=/dev/urandom bs=1 count=1024 of=/etc/munge/munge.key 2>/dev/null
chown -R munge:munge /etc/munge /var/run/munge /var/log/munge /var/lib/munge
chmod 0400 /etc/munge/munge.key
runuser -u munge -- /usr/sbin/munged

/usr/sbin/slurmctld -D >/var/log/slurm/slurmctld.out 2>&1 &
( if [ "$PROCTRACK" = proctrack/cgroup ]; then echo $BASHPID > "$SLURMD_CG/cgroup.procs"; fi
  exec /usr/sbin/slurmd -D >/var/log/slurm/slurmd.out 2>&1 ) &
up=0
for _ in $(seq 1 60); do
  if sinfo -h -o '%T' 2>/dev/null | grep -qE '^(idle|mixed|allocated)$'; then up=1; break; fi
  sleep 1
done
sinfo || true
if [ "$up" != 1 ]; then
  echo "slurm node $NODE did not come up, slurmd said:" >&2
  tail -20 /var/log/slurm/slurmd.out /var/log/slurm/slurmd.log >&2 2>/dev/null || true
  exit 1
fi
echo "slurm up on $NODE ($CPUS CPUs, $MEM MiB, $PROCTRACK, $TASK)"
if [ $# -gt 0 ]; then exec "$@"; fi
exec sleep infinity
