#!/usr/bin/env bash
# Phase 1: the shared-kernel class in kind. Pod warm, Pod cold, fiberd
# proc (both framings), fiberd runc, agent-sandbox under runc with pools
# of 1 and N, control-plane deltas around every run. The client runs in a
# Pod pinned to the node, since Pod IPs are not routable from the Mac.
# Every fiberd home runs stock fiberd:kind and pulls its template from
# the compare registry (push_templates), so the three framings are three
# artifacts named by digest.
#
#   bench/compare/run/phase1.sh            everything
#   bench/compare/run/phase1.sh deploy     cluster, images, homes, client only
#   bench/compare/run/phase1.sh measure    the runs alone, on a deployed cluster
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
cd "$ROOT"
AGENT_SANDBOX_VERSION=${AGENT_SANDBOX_VERSION:-v1.0.5}
# The release manifest, pinned so a changed file fails.
AGENT_SANDBOX_SHA256=${AGENT_SANDBOX_SHA256:-b150cb058c577c59c42b060ff7f22e31b5311ca80430db98129f1280a0e85970}

# push_templates builds the static counter as a zygote artifact, once per
# argument set, and pushes each to the compare registry. The build runs
# in the dev container, so the artifact records the node's platform
# (linux, this machine's architecture), and the push runs here, where
# the registry is published. The digests land in templates.env for the
# measuring phases and the manifests.
push_templates() {
  # The container sees the checkout as /src, so the state must be under it.
  case "$STATE" in
    "$ROOT"/*) ;;
    *) echo "COMPARE_STATE=$STATE is outside the checkout, which the dev container cannot see" >&2; exit 1 ;;
  esac
  local templates="/src/${STATE#"$ROOT"/}/templates"
  mkdir -p "$STATE/templates"
  hack/dev/run.sh env TEMPLATES="$templates" sh -c 'go build -o bin/ ./cmd/zygotectl && for t in http:"--heap-mb 32" line:"--heap-mb 32 --framing line" gvisor:"--heap-mb 32 --gvisor"; do
      bin/zygotectl build -zygote bin/compare-bin/counter-static -args "${t#*:}" -skip-images -out "$TEMPLATES/${t%%:*}" >/dev/null; done'
  : >"$TEMPLATES_ENV"
  for t in http line gvisor; do
    digest=$(cd "$ROOT" && "$GO" run ./cmd/zygotectl push -dir "$STATE/templates/$t" -ref "$REG/zygotes/counter:$t" -plain-http)
    [ -n "$digest" ] || { echo "zygotectl push printed no digest for $t" >&2; exit 1; }
    echo "DIGEST_$(echo "$t" | tr '[:lower:]' '[:upper:]')=$digest" >>"$TEMPLATES_ENV"
  done
  cat "$TEMPLATES_ENV"
}

# render_grants fills the digests and the registry address into the
# grant manifests, in the state directory.
render_grants() {
  local reg http gvisor
  reg=$(bench/compare/kind/cluster.sh registry-addr)
  http=$(template_digest http)
  gvisor=$(template_digest gvisor)
  mkdir -p "$STATE/manifests"
  sed -e "s|@DIGEST_HTTP@|$http|g" -e "s|@DIGEST_GVISOR@|$gvisor|g" \
    -e "s|@REGISTRY@|$reg|g" bench/compare/kind/manifests/10-grants.yaml >"$STATE/manifests/10-grants.yaml"
}

deploy() {
  bench/compare/kind/cluster.sh up
  hack/dev/run.sh true   # the build stage of every image is the dev image
  docker build --target counter -t "$COUNTER_IMAGE" -f docker/compare/Dockerfile .
  docker push "$COUNTER_IMAGE"
  docker build --target binaries -o bin/compare-bin -f docker/compare/Dockerfile .
  docker build -t fiberd:kind -f docker/kubernetes/Dockerfile --build-arg DEV_IMAGE=fiberd-dev:local .
  docker build --target client -t compare-client:local -f docker/compare/Dockerfile .
  kind load docker-image --name "$CLUSTER" fiberd:kind compare-client:local
  push_templates
  render_grants
  # The Kubernetes example's issuer controller and CRD, then the homes.
  "${KC[@]}" apply -f examples/kubernetes/kind/manifests/00-namespaces.yaml -f examples/kubernetes/kind/manifests/10-crd.yaml
  "${KC[@]}" wait --for=condition=Established crd/capacitygrants.fiberd.io --timeout=60s
  "${KC[@]}" apply -f examples/kubernetes/kind/manifests/20-issuer.yaml -f examples/kubernetes/kind/manifests/30-grant-rbac.yaml
  "${KC[@]}" -n fiberd-system rollout status deploy/grant-issuer --timeout=120s
  "${KC[@]}" apply -f bench/compare/kind/manifests/00-compare.yaml -f bench/compare/kind/manifests/20-grant-rbac.yaml -f "$STATE/manifests/10-grants.yaml"
  # agent-sandbox, one manifest, checked against its pin.
  curl -fsSLo "$STATE/agent-sandbox.yaml" "https://github.com/kubernetes-sigs/agent-sandbox/releases/download/$AGENT_SANDBOX_VERSION/sandbox-with-extensions.yaml"
  echo "$AGENT_SANDBOX_SHA256  $STATE/agent-sandbox.yaml" | shasum -a 256 -c - >/dev/null
  "${KC[@]}" apply -f "$STATE/agent-sandbox.yaml"
  "${KC[@]}" -n agent-sandbox-system rollout status deploy --timeout=180s
  for g in compare-proc compare-runc; do
    for _ in $(seq 1 60); do "${KC[@]}" -n "$NS" get pod "$g-grant" >/dev/null 2>&1 && break; sleep 1; done
    wait_ready "$g-grant"
  done
  wait_ready "$CLIENT" 120s
  "${KC[@]}" -n fiberd-system get secret grant-issuer-key -o jsonpath='{.data.key\.json}' | base64 -d >"$STATE/issuer-key.json"
  "${KC[@]}" -n "$NS" cp --no-preserve "$STATE/issuer-key.json" "$CLIENT:/tmp/issuer-key.json"
}

measure() {
  local pod_flags="-image $COUNTER_IMAGE -node $CLUSTER-control-plane -namespace $NS -cgroup-root /host/sys/fs/cgroup -density $DENSITY"
  # shellcheck disable=SC2086
  ADAPTER=pod run_in_client pod-runc-warm shared-kernel $pod_flags
  # shellcheck disable=SC2086
  ADAPTER=pod run_in_client pod-runc-cold shared-kernel $pod_flags -pull Always \
    -cold-cmd "crictl -r unix:///run/containerd/containerd.sock rmi $COUNTER_IMAGE"
  local http line fflags
  http=$(template_digest http)
  line=$(template_digest line)
  fflags="-issuer-key /tmp/issuer-key.json -issuer $ISSUER_URL -resume -template $http"
  # shellcheck disable=SC2086
  ADAPTER=fiberd run_in_client fiberd-proc shared-kernel $fflags -target "$(grant_ip compare-proc):8484" -node-id compare-proc-grant
  # shellcheck disable=SC2086
  ADAPTER=fiberd run_in_client fiberd-proc-line shared-kernel $fflags -target "$(grant_ip compare-proc):8484" -node-id compare-proc-grant \
    -template "$line" -framing line
  # shellcheck disable=SC2086
  ADAPTER=fiberd run_in_client fiberd-runc shared-kernel $fflags -target "$(grant_ip compare-runc):8484" -node-id compare-runc-grant
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
