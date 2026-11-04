#!/usr/bin/env bash
# Phase 3: the sandboxed class in kind, on the cluster phase 1 deployed.
# Pod under the gvisor RuntimeClass and agent-sandbox under gvisor with
# pools of 1 and N. The fiberd gVisor rows (on demand, and with a pool
# of 2) are skipped until the controller project mints grants in kind
# (FIBERD_IN_KIND in lib.sh).
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
cd "$ROOT"
bench/compare/run/phase0.sh
wait_ready "$CLIENT" 60s
pod_flags="-image $COUNTER_IMAGE -node $CLUSTER-control-plane -namespace $NS -runtime-class gvisor -cgroup-root /host/sys/fs/cgroup -density $DENSITY"
# shellcheck disable=SC2086
ADAPTER=pod run_in_client pod-gvisor sandboxed $pod_flags
# shellcheck disable=SC2086
ADAPTER=agentsandbox run_in_client agentsandbox-gvisor-pool1 sandboxed $pod_flags -replicas 1 -resume
# shellcheck disable=SC2086
ADAPTER=agentsandbox run_in_client "agentsandbox-gvisor-pool$POOL_N" sandboxed $pod_flags -replicas "$POOL_N"
skip_fiberd_kind fiberd-gvisor fiberd-gvisor-pool2
collect phase3
