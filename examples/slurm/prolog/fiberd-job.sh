#!/usr/bin/env bash
# The job script of a fiberd allocation: run the agent for as long as the
# allocation lasts, restarting it in place if it exits (an in-place
# restart bumps the epoch; the allocation, its cgroup and the state
# directory stay). Everything after the script name is passed to
# fiberd-slurm; the grant comes from $FIBERD_GRANT or -grant.
#
# When the allocation ends (scancel, time limit) slurmstepd signals this
# script; the agent, which lives in a cgroup of its own beneath the step,
# gets the signal forwarded and stops gracefully, taking its templates and
# fibers with it, so the step drains before Slurm's KillWait and the node
# is not drained for a "Kill task failed".
#
#   sbatch --ntasks=1 --mem=1G --export=ALL,FIBERD_GRANT=... fiberd-job.sh \
#       -verifier jwks -issuer http://localhost:8686 -runtime proc \
#       -template "default=/usr/local/bin/refzygote --heap-mb 32"
set -u
: "${SLURM_JOB_ID:?}"
state="/var/lib/fiberd/job-$SLURM_JOB_ID"
mkdir -p "$state"
agent=""
stopping=0
stop() {
  stopping=1
  [ -n "$agent" ] && kill -TERM "$agent" 2>/dev/null
}
trap stop TERM INT HUP
while [ "$stopping" = 0 ]; do
  fiberd-slurm -state "$state" -run-dir "/run/fiberd/job-$SLURM_JOB_ID/run" "$@" &
  agent=$!
  wait "$agent"
  rc=$?
  agent=""
  [ "$stopping" = 1 ] && break
  echo "fiberd-slurm exited with $rc; restarting in the same allocation" >&2
  sleep 1
done
exit 0
