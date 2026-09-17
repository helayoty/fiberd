#!/usr/bin/env bash
# The Kata-shaped example end to end in kind, on top of the Kubernetes
# example's cluster (its issuer controller and its `conform` grant Pod are
# the home):
#
#   1. build containerd-shim-fiberd-v1 for the node, copy it there, add
#      the `fiberd` runtime handler to containerd and restart it;
#   2. a RuntimeClass `fiberd`;
#   3. mint a grant for the home (the conform grant Pod) and run a Pod
#      with runtimeClassName: fiberd whose container carries it: the
#      container becomes a fiber; kubectl logs shows which;
#   4. delete the Pod: the fiber is released; run it again with
#      on-stop=park and see the second incarnation resume.
#
#   examples/kata/kind/run.sh run       (from the repo root; needs docker, kind, kubectl, go)
set -euo pipefail
cd "$(dirname "$0")/../../.."
CLUSTER=${KIND_CLUSTER:-fiberd}
NODE=$CLUSTER-control-plane
NS=tenant-a
HOME_POD=conform-grant
KC=(kubectl --context "kind-$CLUSTER")
STATE=${KATA_STATE:-bin/kata-state}
K8S=examples/kubernetes/kind/conform.sh

wait_for() { # wait_for <seconds> <description> <cmd...>
  local n=$1 what=$2; shift 2
  for _ in $(seq 1 "$n"); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "timed out waiting for $what" >&2
  return 1
}

# The home: the Kubernetes example's cluster, controller and conform grant.
home() {
  "$K8S" up
  "$K8S" image
  "$K8S" deploy
}

# The shim onto the node, and containerd's runtime handler.
shim() {
  mkdir -p "$STATE"
  local arch
  arch=$(docker exec "$NODE" uname -m)
  case "$arch" in aarch64) goarch=arm64 ;; x86_64) goarch=amd64 ;; *) echo "node arch $arch" >&2; return 1 ;; esac
  (cd examples/kata && GOOS=linux GOARCH=$goarch CGO_ENABLED=0 go build -o "../../$STATE/containerd-shim-fiberd-v1" ./cmd/containerd-shim-fiberd-v1)
  docker cp "$STATE/containerd-shim-fiberd-v1" "$NODE:/usr/local/bin/containerd-shim-fiberd-v1"
  if ! docker exec "$NODE" grep -q 'runtimes.fiberd\]' /etc/containerd/config.toml; then
    docker exec -i "$NODE" sh -c 'cat >> /etc/containerd/config.toml' < examples/kata/kind/containerd-runtime.toml
    docker exec "$NODE" systemctl restart containerd
    wait_for 60 "containerd back" docker exec "$NODE" ctr version
    wait_for 120 "node Ready" sh -c "${KC[*]} get node $NODE -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}' | grep -q True"
  fi
  "${KC[@]}" apply -f examples/kata/kind/runtimeclass.yaml
}

# The workload's grant, minted once with the controller's key: the
# audience is the home Pod's name (its node id), and the uid is fixed so
# every Pod of the workload carries the same grant and a session parked
# by one Pod is resumed by the next. A renewal keeps the uid too.
mint() {
  if [ ! -s "$STATE/grant.jwt" ]; then
    "${KC[@]}" -n fiberd-system get secret grant-issuer-key -o jsonpath='{.data.key\.json}' | base64 -d >"$STATE/issuer-key.json"
    go run ./cmd/grant-issuer mint -key "$STATE/issuer-key.json" -issuer http://grant-issuer.fiberd-system.svc:8080 \
      -aud "$HOME_POD" -uid kata-demo-grant -template sha256:conform -max 2 -warm 1 -w-budget 32Mi \
      -min-tier FIBER_CHECKPOINT -ttl 2h >"$STATE/grant.jwt"
  fi
  cat "$STATE/grant.jwt"
}

# pod <name> <on-stop>: a Pod whose one container is a fiber.
pod() {
  local name=$1 onstop=$2 tok
  tok=$(mint)
  "${KC[@]}" apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $name
  namespace: $NS
  annotations:
    io.fiberd/grant: "$tok"
    io.fiberd/home: "127.0.0.1:30084"
    io.fiberd/session: "kata-demo"
    io.fiberd/on-stop: "$onstop"
spec:
  runtimeClassName: fiberd
  restartPolicy: Never
  containers:
    - name: app
      image: registry.k8s.io/pause:3.10
EOF
  "${KC[@]}" -n "$NS" wait --for=jsonpath='{.status.phase}'=Running "pod/$name" --timeout=120s
  wait_for 30 "fiber line in the logs" sh -c "${KC[*]} -n $NS logs $name | grep -q '^fiber '"
  "${KC[@]}" -n "$NS" logs "$name"
}

status() { # the home's ledger, through its admin socket
  "${KC[@]}" -n "$NS" exec "$HOME_POD" -c agent -- sh -c 'grep -c "" /var/lib/fiberd/audit.jsonl >/dev/null; tail -3 /var/lib/fiberd/audit.jsonl | cut -c1-160'
}

run() {
  [ -n "${KATA_SKIP_HOME:-}" ] || home
  shim
  rm -f "$STATE/grant.jwt"
  "${KC[@]}" -n "$NS" delete pod kata-1 kata-2 --ignore-not-found --wait=true >/dev/null
  echo "--- a Pod whose container is a fiber (on-stop=park)"
  pod kata-1 park | tee "$STATE/pod1.log"
  grep -q "fiber .* CREATE session=kata-demo" "$STATE/pod1.log" || { echo "FAIL: first Pod's container was not a fresh fiber"; exit 1; }
  "${KC[@]}" -n "$NS" delete pod kata-1 --wait=true >/dev/null
  wait_for 30 "park recorded on the home" sh -c "${KC[*]} -n $NS exec $HOME_POD -c agent -- grep -q '\"event\":\"park\".*\"session\":\"kata-demo\"' /var/lib/fiberd/audit.jsonl"
  echo "ok   deleted: the home parked session kata-demo"
  echo "--- the same session again: the container resumes where it was"
  pod kata-2 release | tee "$STATE/pod2.log"
  grep -q "fiber .* RESUME session=kata-demo" "$STATE/pod2.log" || { echo "FAIL: second Pod's container did not resume the parked session"; exit 1; }
  "${KC[@]}" -n "$NS" delete pod kata-2 --wait=true >/dev/null
  wait_for 30 "release recorded on the home" sh -c "${KC[*]} -n $NS exec $HOME_POD -c agent -- grep -q '\"event\":\"release\".*kata-demo' /var/lib/fiberd/audit.jsonl"
  echo "ok   deleted: the home released session kata-demo"
  echo "PASS kata example: containers of a fiberd RuntimeClass Pod are fibers"
}

case "${1:-}" in
  home) home ;;
  shim) shim ;;
  pod) pod "$2" "${3:-release}" ;;
  run) run ;;
  *) echo "usage: $0 run|home|shim|pod <name> [park|release]" >&2; exit 2 ;;
esac
