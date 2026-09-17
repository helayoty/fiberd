#!/usr/bin/env bash
# The Slurm example's acceptance, end to end in one container:
#
#   1. build fiberd:slurm (slurmctld, slurmd, munge, fiberd-slurm, the
#      issuer, the zygote, criu) and start it privileged;
#   2. run the issuer inside as the cluster's control plane and mint a
#      grant for the node;
#   3. submit fiberd-job.sh: the allocation verifies the grant, starts the
#      agent in the job step's cgroup and serves on the node's address;
#   4. run grant-conform C1-C10 from the host against the published port,
#      every hook reaching into the allocation through docker exec;
#   5. run the 2x overcommit storm inside a second allocation with a 384
#      MiB job memory limit: a park must fire before any OOM kill.
#
#   examples/slurm/conform.sh run          (everything; needs docker and go)
#   examples/slurm/conform.sh up|down      (just the container)
#   examples/slurm/conform.sh restart|lane up|down|audit <event> <fence>|engine-kill <uid>|scope-lost
#                                          (the hooks grant-conform calls)
#
# Runs from the repository root: the image build needs fiberd's tree.
set -euo pipefail
cd "$(dirname "$0")/../.."
DIR=examples/slurm
NAME=${SLURM_CONTAINER:-fiberd-slurm}
IMAGE=${FIBERD_SLURM_IMAGE:-fiberd:slurm}
NODE=slurmnode
PORT=${SLURM_PORT:-18484}
TARGET=127.0.0.1:$PORT
ISSUER_URL=http://$NODE:8686
STATE=${CONFORM_STATE:-bin/conform-state-slurm}
KEY=/var/spool/fiberd/issuer-key.json

dexec() { docker exec "$NAME" "$@"; }
# The conformance job's id and state directory, remembered by `job`.
job_id() { cat "$STATE/job.id"; }
admin() { dexec curl -sf --unix-socket "/var/lib/fiberd/job-$(job_id)/admin.sock" "$@"; }
healthy() { admin http://x/healthz; }

wait_for() { # wait_for <seconds> <description> <cmd...>
  local n=$1 what=$2; shift 2
  for _ in $(seq 1 "$n"); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "timed out waiting for $what" >&2
  return 1
}

up() {
  if ! docker ps --format '{{.Names}}' | grep -qx "$NAME"; then
    hack/dev/run.sh true # the builder stage is the dev image
    docker build -t "$IMAGE" -f "$DIR/docker/Dockerfile" .
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker run -d --name "$NAME" --hostname "$NODE" --privileged --cgroupns=private \
      --tmpfs /run --tmpfs /tmp:exec -p "$PORT:8484" "$IMAGE" >/dev/null
  fi
  wait_for 90 "slurm node idle" sh -c "docker exec $NAME sinfo -h -o %T | grep -qE '^(idle|mixed|allocated)$'"
  dexec sinfo
}

down() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }

# issuer: the cluster's control plane, inside the container.
issuer() {
  mkdir -p "$STATE"
  if ! dexec test -s "$KEY"; then
    dexec grant-issuer keygen -alg EdDSA -out "$KEY" >/dev/null
  fi
  dexec pgrep -f 'grant-issuer serve' >/dev/null || \
    dexec sh -c "nohup grant-issuer serve -key $KEY -addr :8686 -issuer $ISSUER_URL >/var/log/issuer.log 2>&1 &"
  wait_for 20 "issuer" dexec curl -sf "$ISSUER_URL/openid/v1/jwks"
  docker cp "$NAME:$KEY" "$STATE/issuer-key.json"
}

# job: submit the conformance allocation and wait for the agent.
job() {
  local tok
  tok=$(dexec grant-issuer mint -key "$KEY" -issuer "$ISSUER_URL" -aud "$NODE" -template sha256:conform \
        -max 4 -warm 1 -w-budget 32Mi -min-tier FIBER_CHECKPOINT -ttl 2h)
  local id
  # The suite's grants ask for 4 fibers; the allocation must have 4 CPUs.
  id=$(dexec sbatch --parsable --ntasks=1 --cpus-per-task=4 --mem=1G --job-name=fiberd-conform \
        --export=ALL,FIBERD_GRANT="$tok" -o /var/log/fiberd-conform.out /usr/local/bin/fiberd-job.sh \
        -verifier jwks -issuer "$ISSUER_URL" -runtime proc \
        -template "default=/usr/local/bin/refzygote --heap-mb 16 --device-mb 64" \
        -endpoint-family inet4 -admin-unsafe -stale-ttl 20s)
  echo "$id" > "$STATE/job.id"
  wait_for 90 "agent in job $id" healthy
  dexec squeue
}

# Hooks: the target is an allocation, reached through docker exec.
restart() {
  local pid before
  before=$(healthy | tr -d ' \n')
  pid=$(dexec pgrep -f "^fiberd-slurm -state /var/lib/fiberd/job-$(job_id)" | head -1)
  dexec kill -TERM "$pid" # fiberd-job.sh restarts it in the same allocation; the epoch bumps
  wait_for 60 "agent back with a new epoch" sh -c "[ \"\$($0 healthz | tr -d ' \n')\" != \"$before\" ]"
}
healthz() { healthy; }

lane() {
  case "$1" in
    up)   admin -X POST http://x/lane -d '{"healthy":true}' >/dev/null ;;
    down) admin -X POST http://x/lane -d '{"healthy":false}' >/dev/null ;;
    *) echo "lane: up|down" >&2; return 2 ;;
  esac
}

audit() {
  local event=$1 fence=$2 uid epoch seq
  IFS=/ read -r uid epoch seq <<<"$fence"
  dexec grep -q "\"event\":\"$event\".*\"fence\":{\"GrantUID\":\"$uid\",\"Epoch\":$epoch,\"Seq\":$seq}" "/var/lib/fiberd/job-$(job_id)/audit.jsonl"
}

# The fiberd subtree sits under the job step's cgroup; find the grant's
# zygote leaf by name.
engine_kill() {
  dexec sh -c "kill -9 \$(cat \$(find /sys/fs/cgroup -path '*/fiberd/$1/zygote/cgroup.procs' | head -1))"
}

scope_lost() { admin -X POST http://x/scope-lost >/dev/null; }

conform() {
  rm -f bin/grant-conform
  go test -c -o bin/grant-conform ./tests/conform
  bin/grant-conform -test.v -target "$TARGET" -target-tier FIBER_CHECKPOINT -node-id "$NODE" \
    -mint jwt -issuer-key "$STATE/issuer-key.json" -issuer "$ISSUER_URL" \
    -restart-cmd "$0 restart" -cp-health-cmd "$0 lane \$1" -audit-cmd "$0 audit \$1 \$2" \
    -engine-kill-cmd "$0 engine-kill \$1" -scope-cmd "$0 scope-lost" -case-timeout 60s
}

storm() {
  local tok id
  # The conformance allocation is done with; its CPUs go to the storm's.
  if [ -s "$STATE/job.id" ]; then
    dexec scancel "$(job_id)" || true
    # scancel's SIGTERM, then KillWait, then SIGKILL: up to a minute.
    wait_for 120 "conformance job gone" sh -c "! docker exec $NAME squeue -h -j $(job_id) 2>/dev/null | grep -q ."
  fi
  dexec scontrol update nodename="$NODE" state=resume >/dev/null 2>&1 || true
  tok=$(dexec grant-issuer mint -key "$KEY" -issuer "$ISSUER_URL" -aud "$NODE" -template sha256:storm-ready \
        -max 1 -warm 1 -w-budget 16Mi -min-tier FIBER_CHECKPOINT -ttl 2h)
  # The storm's grant asks for 8 fibers; the allocation must have 8 CPUs.
  id=$(dexec sbatch --parsable --ntasks=1 --cpus-per-task=8 --mem=384M --job-name=fiberd-storm \
        --export=ALL,FIBERD_GRANT="$tok" -o /var/log/fiberd-storm.out /usr/local/bin/fiberd-job.sh \
        -verifier jwks -issuer "$ISSUER_URL" -runtime proc -listen :8485 \
        -template "sha256:storm=/usr/local/bin/refzygote --heap-mb 64" -template "default=/usr/local/bin/refzygote --heap-mb 8" \
        -grant-ceiling 167772160 -pressure-interval 200ms -status-interval 100ms -stale-ttl 20s)
  wait_for 90 "agent in storm job $id" dexec curl -sf --unix-socket "/var/lib/fiberd/job-$id/admin.sock" http://x/healthz
  # The job's cgroup carries Slurm's memory limit; its OOM counter is the
  # one the storm must leave untouched.
  dexec sh -c "pid=\$(pgrep -f '^fiberd-slurm -state /var/lib/fiberd/job-$id' | head -1); own=/sys/fs/cgroup\$(grep -m1 '^0::' /proc/\$pid/cgroup | cut -d: -f3); own=\${own%/agent};
    job=\$(echo \$own | sed 's#\(/job_[0-9]*\).*#\1#');
    echo \"job cgroup \$job memory.max=\$(cat \$job/memory.max)\";
    exec storm -target 127.0.0.1:8485 -node-id $NODE -issuer-key $KEY -issuer $ISSUER_URL \
      -cgroup-root \$own/fiberd -container-events \$job/memory.events \
      -fibers 8 -ceiling 167772160 -overcommit 2 -step 2097152 -round 250ms"
  echo "--- storm job:"
  dexec scontrol show job "$id" | grep -E "JobState|ExitCode"
  dexec scancel "$id"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  issuer) issuer ;;
  job) job ;;
  restart) restart ;;
  healthz) healthz ;;
  lane) lane "$2" ;;
  audit) audit "$2" "$3" ;;
  engine-kill) engine_kill "$2" ;;
  scope-lost) scope_lost ;;
  conform) conform ;;
  storm) storm ;;
  run) up; issuer; job; conform; storm ;;
  *) echo "usage: $0 run|up|down|issuer|job|conform|storm|restart|lane up|down|audit <event> <fence>|engine-kill <uid>|scope-lost" >&2; exit 2 ;;
esac
