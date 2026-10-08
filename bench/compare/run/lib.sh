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
ISSUER_URL=http://grant-issuer.fiberd-system.svc:8080
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

# templates are the digests of the counter artifacts phase 1 pushed to
# the compare registry, one per argument set, kept in the state
# directory for the measuring phases (see phase1.sh deploy).
TEMPLATES_ENV=$STATE/templates.env
template_digest() { # template_digest <http|line|gvisor>
  [ -f "$TEMPLATES_ENV" ] || { echo "no $TEMPLATES_ENV: run phase1.sh deploy first" >&2; exit 1; }
  # shellcheck disable=SC1090
  . "$TEMPLATES_ENV"
  local var
  var="DIGEST_$(echo "$1" | tr '[:lower:]' '[:upper:]')"
  [ -n "${!var:-}" ] || { echo "no $var in $TEMPLATES_ENV" >&2; exit 1; }
  echo "${!var}"
}

# client_exec runs a command in the client Pod.
client_exec() { "${KC[@]}" -n "$NS" exec "$CLIENT" -- "$@"; }

# node_ip is the kind node's address, where the scheduler serves metrics.
node_ip() { "${KC[@]}" get node "$CLUSTER-control-plane" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}'; }

# grant_ip is a grant Pod's IP, the home the fiberd adapter dials.
grant_ip() { "${KC[@]}" -n "$NS" get pod "$1-grant" -o jsonpath='{.status.podIP}'; }

# control_plane_flags are the counters sampled around every run.
control_plane_flags() {
  echo "-apiserver-metrics https://kubernetes.default.svc/metrics -scheduler-metrics https://$(node_ip):10259/metrics -audit-log /host/audit/audit.log"
}

# run_in_client runs one compare invocation in the client Pod, writing
# /out/<system>.jsonl there.
run_in_client() { # run_in_client <system> <class> <args...>
  local system=$1 class=$2; shift 2
  echo "== $system"
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

# collect copies the client's results into $STATE/<phase> and prints the
# table.
collect() { # collect <phase>
  mkdir -p "$STATE/$1"
  "${KC[@]}" -n "$NS" cp "$CLIENT:/out" "$STATE/$1" >/dev/null
  (cd "$ROOT/bench/compare" && "$GO" run ./cmd/summarize "$STATE/$1"/*.jsonl | tee "$STATE/$1/summary.txt")
}

# wait_ready waits for a Pod to be Ready.
wait_ready() { "${KC[@]}" -n "$NS" wait --for=condition=Ready "pod/$1" --timeout="${2:-300s}"; }
