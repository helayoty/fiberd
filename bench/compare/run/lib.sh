#!/usr/bin/env bash
# Shared by the phase scripts. Sourced, not run.
#
# Every result file carries the host load, and a phase refuses to time
# anything when the 1 minute load exceeds the core count, since a noisy
# host invalidates the run (docs/design/compare.md, phase 0). Each timed
# run first waits for the load a build or deploy left behind to fall.
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
STATE=${COMPARE_STATE:-$ROOT/bin/compare-state}
RUNS=${COMPARE_RUNS:-3}
BURSTS=${COMPARE_BURSTS:-1,10,50}
POOL_N=${COMPARE_POOL_N:-10}
DENSITY=${COMPARE_DENSITY:-20}
CLUSTER=${COMPARE_CLUSTER:-compare}
REG=localhost:${COMPARE_REGISTRY_PORT:-5002}
COUNTER_IMAGE=$REG/counter:latest
NS=compare
CLIENT=compare-client
KC=(kubectl --context "kind-$CLUSTER")
GO=${GO:-go}

ncpu() { nproc 2>/dev/null || sysctl -n hw.ncpu; }
load1() {
  if [ -r /proc/loadavg ]; then cut -d' ' -f1 /proc/loadavg; else sysctl -n vm.loadavg | awk '{print $2}'; fi
}

# require_quiet_host aborts when the load is above the core count.
require_quiet_host() {
  local l n
  l=$(load1); n=$(ncpu)
  echo "host load $l on $n cores"
  if [ "$(awk -v l="$l" -v n="$n" 'BEGIN { print (l > n) ? 1 : 0 }')" = 1 ]; then
    echo "load $l exceeds $n cores: refusing to time anything (COMPARE_FORCE=1 overrides)" >&2
    [ "${COMPARE_FORCE:-0}" = 1 ] || exit 3
  fi
}

# wait_quiet_host waits up to COMPARE_QUIET_WAIT seconds (default 300) for
# the 1 minute load to fall to the core count, then applies
# require_quiet_host.
wait_quiet_host() {
  local deadline=$((SECONDS + ${COMPARE_QUIET_WAIT:-300}))
  while [ "$(awk -v l="$(load1)" -v n="$(ncpu)" 'BEGIN { print (l > n) ? 1 : 0 }')" = 1 ] &&
    [ "$SECONDS" -lt "$deadline" ]; do
    sleep 10
  done
  require_quiet_host
}

# FIBERD_IN_KIND is why the kind phases skip their fiberd rows. Those
# rows need grant Pods, which the controller project
# (Azure/fiberd-k8s-controller) mints, and the kind cluster runs no
# controller. Phase 2 and phase 4 time fiberd outside Kubernetes.
FIBERD_IN_KIND="fiberd in kind needs grant Pods from the controller project (Azure/fiberd-k8s-controller), and kind runs no controller"

# skip_fiberd_kind names the fiberd rows a kind phase skips, and why.
skip_fiberd_kind() { echo "== skipping $*: $FIBERD_IN_KIND" >&2; }

# client_exec runs a command in the client Pod.
client_exec() { "${KC[@]}" -n "$NS" exec "$CLIENT" -- "$@"; }

# control_plane_flags are the counters sampled around every run. The
# scheduler's page is read through the API server's Pod proxy, so the
# client verifies one certificate, the API server's, against the cluster
# CA. The scheduler's own is self-signed.
control_plane_flags() {
  echo "-apiserver-metrics https://kubernetes.default.svc/metrics -scheduler-metrics https://kubernetes.default.svc/api/v1/namespaces/kube-system/pods/https:kube-scheduler-$CLUSTER-control-plane:10259/proxy/metrics -audit-log /host/audit/audit.log"
}

# PHASE_SYSTEMS are the systems this phase ran in the client Pod.
PHASE_SYSTEMS=()

# run_in_client runs one compare invocation in the client Pod, writing
# /out/<system>.jsonl there.
run_in_client() { # run_in_client <system> <class> <args...>
  local system=$1 class=$2; shift 2
  echo "== $system"
  PHASE_SYSTEMS+=("$system")
  wait_quiet_host
  # shellcheck disable=SC2046,SC2016  # the flag strings are lists, $0 and $@ expand in the Pod
  client_exec sh -c 'rm -f "/out/$0.rc"; compare "$@"; rc=$?; echo "$rc" >"/out/$0.rc"; exit "$rc"' "$system" \
    -adapter "${ADAPTER:?}" -system "$system" -class "$class" -runs "$RUNS" -bursts "$BURSTS" \
    -out "/out/$system.jsonl" $(control_plane_flags) "$@"
  # kubectl exec can exit 0 when its stream breaks, as on a containerd
  # restart, while compare still runs. Only the exit file says it ended.
  local rc
  rc=$(client_exec cat "/out/$system.rc" 2>/dev/null) || rc=
  [ "$rc" = 0 ] || { echo "$system: compare did not finish (exit ${rc:-unknown}), the exec stream broke" >&2; return 1; }
}

# collect copies the results of this phase's systems into $STATE/<phase>
# and prints the table. The client's /out keeps every phase's files, so
# only the ones this phase wrote are taken.
collect() { # collect <phase>
  local s
  mkdir -p "$STATE/$1"
  for s in "${PHASE_SYSTEMS[@]}"; do
    "${KC[@]}" -n "$NS" cp "$CLIENT:/out/$s.jsonl" "$STATE/$1/$s.jsonl" >/dev/null
  done
  (cd "$ROOT/bench/compare" && "$GO" run ./cmd/summarize "$STATE/$1"/*.jsonl | tee "$STATE/$1/summary.txt")
}

# wait_ready waits for a Pod to be Ready.
wait_ready() { "${KC[@]}" -n "$NS" wait --for=condition=Ready "pod/$1" --timeout="${2:-300s}"; }
