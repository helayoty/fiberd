#!/usr/bin/env bash
# The 2x overcommit storm (phase 3 acceptance). Run INSIDE the dev
# container with a memory cap:
#
#   FIBERD_DEV_DOCKER_ARGS="--memory=384m --memory-swap=384m" \
#     hack/dev/run.sh hack/test/overcommit.sh
#
# Layout of the numbers: the container may use 384 MiB. The zygote's heap
# is 64 MiB, the agent and issuer take ~40 MiB. The grant's ceiling
# (memory.high) is pinned at 160 MiB and its 8 fibers are driven to
# demand 320 MiB, twice the ceiling. If the ladder works, the grant is
# throttled at 160 MiB, PSI rises, fibers are parked largest-W first, and
# nothing is OOM-killed: 64 + 40 + ~176 stays under 384. If it does not,
# demand reaches 64 + 40 + 320 = 424 MiB and the container's memory.max
# kills something. The storm program checks the container's OOM counter.
set -euo pipefail
cd "$(dirname "$0")/../.."

ADDR=127.0.0.1:18484
ISSUER_ADDR=127.0.0.1:18686
ISSUER_URL="http://$ISSUER_ADDR"
# State (and above all the parked deltas) must be on DISK. The dev
# container mounts /tmp as tmpfs, and a checkpoint image written to tmpfs
# is charged to the container's memory: parking would then consume RAM
# instead of freeing it. /var/lib is the container's disk-backed overlay.
STATE=${STORM_STATE:-/var/lib/fiberd/storm}
NODE=storm-node
CEILING=$((160 << 20))

rm -rf "$STATE"; mkdir -p "$STATE"
# The build happens in an uncapped container first (make overcommit): a
# cold Go build does not fit under the storm's memory cap.
if [ -z "${STORM_PREBUILT:-}" ]; then
  go build -o bin/ ./cmd/fiberd ./cmd/grant-issuer ./hack/storm
  make -s zygote
fi

bin/grant-issuer keygen -alg EdDSA -out "$STATE/issuer-key.json" >/dev/null
bin/grant-issuer serve -key "$STATE/issuer-key.json" -addr "$ISSUER_ADDR" -issuer "$ISSUER_URL" >"$STATE/issuer.log" 2>&1 &
ISSUER_PID=$!
bin/fiberd -state "$STATE" -node-id "$NODE" -verifier jwks -issuer "$ISSUER_URL" -jwks-max-stale 10m \
  -listen "$ADDR" -runtime proc -template "default=$PWD/bin/refzygote --heap-mb 64" -run-dir /tmp/fz-storm \
  -delta-dir "$STATE/deltas" \
  -grant-ceiling "$CEILING" -pressure-interval 200ms -status-interval 100ms -stale-ttl 30s \
  >"$STATE/fiberd.log" 2>&1 &
FIBERD_PID=$!
trap 'kill $FIBERD_PID $ISSUER_PID 2>/dev/null; wait $FIBERD_PID $ISSUER_PID 2>/dev/null || true' EXIT
for _ in $(seq 1 100); do
  curl -sf --unix-socket "$STATE/admin.sock" http://x/healthz >/dev/null 2>&1 && break
  sleep 0.1
done

echo "container memory.max: $(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo unknown); deltas on $(stat -f -c %T "$STATE")"
set +e
bin/storm -target "$ADDR" -node-id "$NODE" -issuer-key "$STATE/issuer-key.json" -issuer "$ISSUER_URL" \
  -fibers 8 -ceiling "$CEILING" -overcommit 2 -step $((2 << 20)) -round 250ms
rc=$?
set -e
echo "--- ladder log:"
grep -E 'pressure:|proc: parked|oom' "$STATE/fiberd.log" | head -30
if ! kill -0 $FIBERD_PID 2>/dev/null; then echo "FAIL: fiberd died"; exit 1; fi
exit $rc
