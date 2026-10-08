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
# While the agent runs, the script polls its /healthz on the admin socket
# every $FIBERD_HEALTH_EVERY seconds (default 10). A 503 means the audit
# spool is poisoned and only a restart clears it, so the script stops the
# agent and the loop restarts it. A socket that does not answer yet is
# left alone. $FIBERD_STATE_ROOT moves the state root (tests use it).
#
#   sbatch --ntasks=1 --mem=1G --export=ALL,FIBERD_GRANT=... fiberd-job.sh \
#       -verifier jwks -issuer http://localhost:8686 -insecure-plaintext -runtime proc \
#       -template "default=/usr/local/bin/refzygote --heap-mb 32"
set -u
: "${SLURM_JOB_ID:?}"
state="${FIBERD_STATE_ROOT:-/var/lib/fiberd}/job-$SLURM_JOB_ID"
every="${FIBERD_HEALTH_EVERY:-10}"
mkdir -p "$state"
agent=""
watcher=""
stopping=0
stop() {
  stopping=1
  [ -n "$agent" ] && kill -TERM "$agent" 2>/dev/null
}
# watch stops agent $1 once its /healthz answers 503.
watch() {
  while sleep "$every"; do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 --unix-socket "$state/private/admin.sock" http://x/healthz)
    if [ "$code" = 503 ]; then
      echo "fiberd-slurm /healthz is 503; restarting it" >&2
      kill -TERM "$1" 2>/dev/null
      return
    fi
  done
}
trap stop TERM INT HUP
while [ "$stopping" = 0 ]; do
  fiberd-slurm -state "$state" -run-dir "/run/fiberd/job-$SLURM_JOB_ID/run" "$@" &
  agent=$!
  watch "$agent" &
  watcher=$!
  wait "$agent"
  rc=$?
  kill "$watcher" 2>/dev/null
  agent=""
  [ "$stopping" = 1 ] && break
  echo "fiberd-slurm exited with $rc; restarting in the same allocation" >&2
  sleep 1
done
exit 0
