#!/usr/bin/env bash
# Phase 3: the sandboxed class in kind, on the cluster phase 1 deployed.
# Pod under the gvisor RuntimeClass, agent-sandbox under gvisor with
# pools of 1 and N, and fiberd gVisor through the agent's TCP relay (the
# gvisor grant's fibers are served on the Pod IP, one relay hop each).
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
cd "$ROOT"
bench/compare/run/phase0.sh
for _ in $(seq 1 60); do "${KC[@]}" -n "$NS" get pod compare-gvisor-grant >/dev/null 2>&1 && break; sleep 1; done
wait_ready compare-gvisor-grant 600s
wait_ready "$CLIENT" 60s
pod_flags="-image $COUNTER_IMAGE -node $CLUSTER-control-plane -namespace $NS -runtime-class gvisor -cgroup-root /host/sys/fs/cgroup -density $DENSITY"
# shellcheck disable=SC2086
ADAPTER=pod run_in_client pod-gvisor sandboxed $pod_flags
# shellcheck disable=SC2086
ADAPTER=agentsandbox run_in_client agentsandbox-gvisor-pool1 sandboxed $pod_flags -replicas 1 -resume
# shellcheck disable=SC2086
ADAPTER=agentsandbox run_in_client "agentsandbox-gvisor-pool$POOL_N" sandboxed $pod_flags -replicas "$POOL_N"
ADAPTER=fiberd run_in_client fiberd-gvisor sandboxed -issuer-key /tmp/issuer-key.json -issuer "$ISSUER_URL" -resume \
  -target "$(grant_ip compare-gvisor):8484" -node-id compare-gvisor-grant -isolation UNTRUSTED -want-scheme tcp \
  -template "$(template_digest gvisor)"
collect phase3
