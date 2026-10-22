#!/usr/bin/env bash
# The 2x overcommit storm (phase 3 acceptance), and its baselines without
# fiberd. Run INSIDE the dev container with a memory cap:
#
#   FIBERD_DEV_DOCKER_ARGS="--memory=384m --memory-swap=384m" \
#     hack/dev/run.sh hack/test/overcommit.sh
#
# Layout of the numbers: the container may use 384 MiB. The zygote's heap
# is 64 MiB, fiberd and issuer take ~40 MiB. The grant's ceiling
# (memory.high) is pinned at 160 MiB and its 8 fibers are driven to
# demand 320 MiB, twice the ceiling. If the ladder works, the grant is
# throttled at 160 MiB, PSI rises, fibers are parked largest-W first, and
# nothing is OOM-killed: 64 + 40 + ~176 stays under 384. If it does not,
# demand reaches 64 + 40 + 320 = 424 MiB and a memory.max kills something.
# The runtime caps its own subtree (zygote and fibers) at 320 MiB with
# memory.high 280 MiB, keeping 64 MiB of the container for fiberd, so
# that kill lands in the subtree, and the container's hierarchical
# memory.events still counts it. The storm program checks that counter.
#
# Three phases run in the same container, one after another.
#
#   fiberd    the storm above. It alone decides the exit status.
#   shared    the same storm without fiberd (storm -plain). One parent
#             touches the 64 MiB heap and forks 8 processes that share
#             it, as fibers share the zygote's. Same growth, nothing
#             parks, no ceiling but the container's.
#   separate  the same, with 8 processes started on their own, each
#             touching a 64 MiB heap of its own.
#
# The baselines only measure. Their OOM kills are expected and never fail
# the run. Each phase ends with one "storm summary:" line.
# STORM_PHASES picks phases ("shared separate" is make
# overcommit-baseline).
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
PHASES=${STORM_PHASES:-fiberd shared separate}
CG_ROOT=${FIBERD_CGROUP_ROOT:-/sys/fs/cgroup/fiberd}

has_phase() { case " $PHASES " in *" $1 "*) return 0 ;; esac; return 1; }

# The build happens in an uncapped container first (make overcommit): a
# cold Go build does not fit under the storm's memory cap.
# fiberd is built with the fiberd_testhooks tag for the cadence flags,
# so the ladder reacts within the storm's window.
if [ -z "${STORM_PREBUILT:-}" ]; then
  go build -o bin/ ./cmd/grant-issuer ./hack/storm
  go build -tags fiberd_testhooks -o bin/fiberd-testhooks ./cmd/fiberd
  make -s zygote storm-grower
fi

FIBERD_PID=""
ISSUER_PID=""
stop_fiberd() {
  [ -n "$FIBERD_PID$ISSUER_PID" ] || return 0
  # shellcheck disable=SC2086  # either may be empty
  kill $FIBERD_PID $ISSUER_PID 2>/dev/null || true
  # shellcheck disable=SC2086
  wait $FIBERD_PID $ISSUER_PID 2>/dev/null || true
  FIBERD_PID=""
  ISSUER_PID=""
}
trap stop_fiberd EXIT

# fiberd_side runs the storm against fiberd and sets FIBERD_RC.
FIBERD_RC=0
fiberd_side() {
  echo "=== storm with fiberd"
  rm -rf "$STATE"; mkdir -p "$STATE"
  bin/grant-issuer keygen -alg EdDSA -out "$STATE/issuer-key.json" >/dev/null
  bin/grant-issuer serve -key "$STATE/issuer-key.json" -addr "$ISSUER_ADDR" -issuer "$ISSUER_URL" >"$STATE/issuer.log" 2>&1 &
  ISSUER_PID=$!
  bin/fiberd-testhooks -state "$STATE" -node-id "$NODE" -verifier jwks -issuer "$ISSUER_URL" -jwks-max-stale 10m -insecure-plaintext \
    -listen "$ADDR" -runtime proc -template "default=$PWD/bin/refzygote --heap-mb 64" \
    -grant-ceiling "$CEILING" -pressure-interval 200ms -status-interval 100ms -stale-ttl 30s \
    >"$STATE/fiberd.log" 2>&1 &
  FIBERD_PID=$!
  for _ in $(seq 1 100); do
    curl -sf --unix-socket "$STATE/private/admin.sock" http://x/healthz >/dev/null 2>&1 && break
    sleep 0.1
  done

  echo "container memory.max: $(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo unknown); deltas on $(stat -f -c %T "$STATE")"
  set +e
  bin/storm -target "$ADDR" -node-id "$NODE" -issuer-key "$STATE/issuer-key.json" -issuer "$ISSUER_URL" -isolation TRUSTED \
    -fibers 8 -ceiling "$CEILING" -overcommit 2 -step $((2 << 20)) -round 250ms
  FIBERD_RC=$?
  set -e
  echo "--- ladder log:"
  grep -E 'pressure:|proc: parked|oom' "$STATE/fiberd.log" | head -30 || true
  if ! kill -0 "$FIBERD_PID" 2>/dev/null; then echo "FAIL: fiberd died"; FIBERD_RC=1; fi
  # Every pressure park must go through. A park that failed had the fiber
  # released instead, which the storm's own verdict cannot see, so it is
  # counted here from fiberd's log and fails the run by itself.
  local parked failed
  parked=$(grep -c 'pressure: parked ' "$STATE/fiberd.log" || true)
  failed=$(grep -c 'pressure: park .* failed' "$STATE/fiberd.log" || true)
  echo "pressure parks: parked=$parked failed=$failed"
  if [ "$failed" -gt 0 ]; then
    echo "FAIL: $failed pressure park(s) failed and released the fiber instead:"
    grep 'pressure: park .* failed' "$STATE/fiberd.log"
    FIBERD_RC=1
  fi
  stop_fiberd
  # Whatever fiberd left in its cgroup subtree goes, and the deltas reach
  # the disk, so a baseline starts from the same empty container.
  for d in "$CG_ROOT"/*/; do
    [ -e "$d/cgroup.kill" ] && { echo 1 >"$d/cgroup.kill"; } 2>/dev/null || true
  done
  sync
}

# plain_side runs the same storm on plain processes, with layout $1, and
# sets BASE_RC only when it could not measure.
BASE_RC=0
plain_side() {
  local layout=$1 rc
  echo "=== storm without fiberd, $layout layout"
  echo "container memory.current before: $(( $(cat /sys/fs/cgroup/memory.current 2>/dev/null || echo 0) >> 20 )) MiB"
  set +e
  bin/storm -plain -layout "$layout" -heap-mb 64 \
    -fibers 8 -ceiling "$CEILING" -overcommit 2 -step $((2 << 20)) -round 250ms
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    echo "the $layout baseline did not measure (storm exit $rc)"
    BASE_RC=$rc
  fi
}

if has_phase fiberd; then fiberd_side; fi
for layout in shared separate; do
  if has_phase "$layout"; then plain_side "$layout"; fi
done
# The fiberd side decides. The baselines decide only a run without it.
if has_phase fiberd; then
  if [ "$FIBERD_RC" -eq 0 ]; then echo "overcommit: PASS on the fiberd side"; else echo "overcommit: FAIL on the fiberd side"; fi
  exit "$FIBERD_RC"
fi
exit "$BASE_RC"
