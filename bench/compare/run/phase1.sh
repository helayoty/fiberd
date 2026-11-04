#!/usr/bin/env bash
# Phase 1: the shared-kernel class in kind. Pod warm, Pod cold,
# agent-sandbox under runc with pools of 1 and N, control-plane deltas
# around every run. The client runs in a Pod pinned to the node, since
# Pod IPs are not routable from the Mac. The fiberd rows (proc in both
# framings, and runc) are skipped until the controller project mints
# grants in kind (FIBERD_IN_KIND in lib.sh).
#
#   bench/compare/run/phase1.sh            everything
#   bench/compare/run/phase1.sh deploy     cluster, images and client only
#   bench/compare/run/phase1.sh measure    the runs alone, on a deployed cluster
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
cd "$ROOT"
AGENT_SANDBOX_VERSION=${AGENT_SANDBOX_VERSION:-v1.0.5}
# The release manifest, pinned so a changed file fails.
AGENT_SANDBOX_SHA256=${AGENT_SANDBOX_SHA256:-b150cb058c577c59c42b060ff7f22e31b5311ca80430db98129f1280a0e85970}

deploy() {
  bench/compare/kind/cluster.sh up
  hack/dev/run.sh true   # the build stage of every image is the dev image
  docker build --target counter -t "$COUNTER_IMAGE" -f docker/compare/Dockerfile .
  docker push "$COUNTER_IMAGE"
  docker build --target binaries -o bin/compare-bin -f docker/compare/Dockerfile .
  docker build --target client -t compare-client:local -f docker/compare/Dockerfile .
  kind load docker-image --name "$CLUSTER" compare-client:local
  "${KC[@]}" apply -f bench/compare/kind/manifests/00-compare.yaml
  # agent-sandbox, one manifest, checked against its pin.
  curl -fsSLo "$STATE/agent-sandbox.yaml" "https://github.com/kubernetes-sigs/agent-sandbox/releases/download/$AGENT_SANDBOX_VERSION/sandbox-with-extensions.yaml"
  echo "$AGENT_SANDBOX_SHA256  $STATE/agent-sandbox.yaml" | shasum -a 256 -c - >/dev/null
  "${KC[@]}" apply -f "$STATE/agent-sandbox.yaml"
  "${KC[@]}" -n agent-sandbox-system rollout status deploy --timeout=180s
  wait_ready "$CLIENT" 120s
}

measure() {
  local pod_flags="-image $COUNTER_IMAGE -node $CLUSTER-control-plane -namespace $NS -cgroup-root /host/sys/fs/cgroup -density $DENSITY"
  # shellcheck disable=SC2086
  ADAPTER=pod run_in_client pod-runc-warm shared-kernel $pod_flags
  # shellcheck disable=SC2086
  ADAPTER=pod run_in_client pod-runc-cold shared-kernel $pod_flags -pull Always \
    -cold-cmd "crictl -r unix:///run/containerd/containerd.sock rmi $COUNTER_IMAGE"
  skip_fiberd_kind fiberd-proc fiberd-proc-line fiberd-runc
  # shellcheck disable=SC2086
  ADAPTER=agentsandbox run_in_client agentsandbox-runc-pool1 shared-kernel $pod_flags -replicas 1 -resume
  # shellcheck disable=SC2086
  ADAPTER=agentsandbox run_in_client "agentsandbox-runc-pool$POOL_N" shared-kernel $pod_flags -replicas "$POOL_N"
  collect phase1
}

case "${1:-all}" in
  deploy) bench/compare/run/phase0.sh; deploy ;;
  measure) bench/compare/run/phase0.sh; measure ;;
  all) bench/compare/run/phase0.sh; deploy; measure ;;
  *) echo "usage: $0 [deploy|measure]" >&2; exit 2 ;;
esac
