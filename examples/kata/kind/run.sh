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
#
# gpu is the GPU PoC's Kata row (docs/proposals/gpu-poc.md, M12), run on
# VM A where kind runs. The home is a fiberd on this host, in the dev
# container on the host network, not in kind. It runs the proc runtime
# with refengine on one MIG instance, and listens on the kind network's
# gateway, which the node reaches. Pod 1 fills the fiber's slice and
# parks it, and Pod 2 resumes the session and checks the slice.
#
#   examples/kata/kind/run.sh gpu       (needs docker, kind, kubectl, and the dev image)
#
#   KATA_GPU_DEVICE  the MIG UUID the engine drives (default: the first
#                    MIG entry of nvidia-smi -L)
#   KATA_GPU_SIM=1   a simulated engine (--sim-mb 64) and no GPU, for any
#                    Linux host with kind
#   KATA_GPU_PORT    the home's gRPC port on the gateway (default 18494)
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
  if command -v go >/dev/null; then
    (cd examples/kata && GOOS=linux GOARCH=$goarch CGO_ENABLED=0 go build -o "../../$STATE/containerd-shim-fiberd-v1" ./cmd/containerd-shim-fiberd-v1)
  else
    # A host with no Go, such as VM A, builds it in the dev container.
    hack/dev/run.sh env GOOS=linux GOARCH="$goarch" CGO_ENABLED=0 \
      go -C examples/kata build -o "../../$STATE/containerd-shim-fiberd-v1" ./cmd/containerd-shim-fiberd-v1
  fi
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
      -aud "$HOME_POD" -uid kata-demo-grant -tenant kata -template sha256:conform -max 2 -warm 1 -w-budget 32Mi \
      -min-tier FIBER_CHECKPOINT -isolation TRUSTED -ttl 2h >"$STATE/grant.jwt"
  fi
  cat "$STATE/grant.jwt"
}

# pod <name> <on-stop>: a Pod whose one container is a fiber.
pod() {
  local name=$1 onstop=$2 tok
  tok=$(mint)
  fiber_pod "$name" "$onstop" "$tok" 127.0.0.1:30084 kata-demo
}

# fiber_pod <name> <on-stop> <grant> <home> <session>: a Pod whose one
# container is a fiber of the session on the home. It prints the Pod's
# logs, the shim's fiber line first.
fiber_pod() {
  local name=$1 onstop=$2 tok=$3 home=$4 session=$5
  "${KC[@]}" apply -f - <<EOF &&
apiVersion: v1
kind: Pod
metadata:
  name: $name
  namespace: $NS
  annotations:
    io.fiberd/grant: "$tok"
    io.fiberd/home: "$home"
    io.fiberd/session: "$session"
    io.fiberd/on-stop: "$onstop"
spec:
  runtimeClassName: fiberd
  restartPolicy: Never
  containers:
    - name: app
      image: registry.k8s.io/pause:3.10
EOF
    "${KC[@]}" -n "$NS" wait --for=jsonpath='{.status.phase}'=Running "pod/$name" --timeout=120s &&
    wait_for 30 "fiber line in the logs" sh -c "${KC[*]} -n $NS logs $name | grep -q '^fiber '" &&
    "${KC[@]}" -n "$NS" logs "$name"
}

status() { # the home's ledger, through its admin socket
  "${KC[@]}" -n "$NS" exec "$HOME_POD" -c fiberd -- sh -c 'grep -c "" /var/lib/fiberd/private/audit.jsonl >/dev/null; tail -3 /var/lib/fiberd/private/audit.jsonl | cut -c1-160'
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
  wait_for 30 "park recorded on the home" sh -c "${KC[*]} -n $NS exec $HOME_POD -c fiberd -- grep -q '\"event\":\"park\".*\"session\":\"kata-demo\"' /var/lib/fiberd/private/audit.jsonl"
  echo "ok   deleted: the home parked session kata-demo"
  echo "--- the same session again: the container resumes where it was"
  pod kata-2 release | tee "$STATE/pod2.log"
  grep -q "fiber .* RESUME session=kata-demo" "$STATE/pod2.log" || { echo "FAIL: second Pod's container did not resume the parked session"; exit 1; }
  "${KC[@]}" -n "$NS" delete pod kata-2 --wait=true >/dev/null
  wait_for 30 "release recorded on the home" sh -c "${KC[*]} -n $NS exec $HOME_POD -c fiberd -- grep -q '\"event\":\"release\".*kata-demo' /var/lib/fiberd/private/audit.jsonl"
  echo "ok   deleted: the home released session kata-demo"
  echo "PASS kata example: containers of a fiberd RuntimeClass Pod are fibers"
}

# ---- The GPU row.

GPU_SESSION=kata-gpu
GPU_NODE=kata-gpu-home
GPU_GRANT=kata-gpu-grant
GPU_PORT=${KATA_GPU_PORT:-18494}
GPU_ISSUER=127.0.0.1:18496
GPU_STATE=/var/lib/fiberd/kata-gpu # in the home's container
GPU_DIR=bin/kata-gpu               # the logs, from the repo root on the host and in the container
GPU_LOG=$GPU_DIR/home/fiberd.log
GPU_AUDIT=$GPU_STATE/home/private/audit.jsonl
GPU_DEV=""
GPU_CLASS=""
GPU_CTR=""
GPU_PID=""
GPU_FAILED=0

gpu_fail() { echo "FAIL: $*"; GPU_FAILED=1; }

# gpu_abort <message> [pod] ends the row on a failure the next steps need.
gpu_abort() {
  echo "FAIL: $1"
  if [ -n "${2:-}" ]; then
    echo "--- pod $2"
    "${KC[@]}" -n "$NS" describe pod "$2" 2>&1 | tail -15 || true
  fi
  if [ -s "$GPU_LOG" ]; then
    echo "--- the last lines of $GPU_LOG"
    tail -20 "$GPU_LOG" || true
  fi
  exit 1
}

gpu_exec() { docker exec "$GPU_CTR" "$@"; }

# gpu_device picks the engine's device and the grant's device class.
gpu_device() {
  if [ "${KATA_GPU_SIM:-0}" = 1 ]; then
    GPU_CLASS=sim
    return 0
  fi
  GPU_DEV=${KATA_GPU_DEVICE:-}
  if [ -z "$GPU_DEV" ]; then
    GPU_DEV=$(nvidia-smi -L 2>/dev/null | sed -n 's/.*(UUID: \(MIG-[^)]*\)).*/\1/p' | sed -n 1p || true)
  fi
  [ -n "$GPU_DEV" ] || gpu_abort "nvidia-smi -L lists no MIG instance. Set KATA_GPU_DEVICE, or KATA_GPU_SIM=1 for a simulated engine"
  GPU_CLASS=gpu
}

# gpu_addr is the home's address as the kind node dials it: the gateway
# of the kind network, which is this host's side of the node's bridge.
gpu_addr() {
  local gw
  gw=$(docker network inspect kind -f '{{range .IPAM.Config}}{{.Gateway}} {{end}}' 2>/dev/null |
    tr ' ' '\n' | grep -m1 '^[0-9][0-9.]*$' || true)
  if [ -z "$gw" ]; then
    gw=$(docker exec "$NODE" ip -4 route show default 2>/dev/null | awk '{print $3; exit}' || true)
  fi
  [ -n "$gw" ] || return 1
  printf '%s:%s' "$gw" "$GPU_PORT"
}

# gpu_home_up starts the home in the dev container, on the host network,
# as hack/gpu/move.sh starts its homes, and waits until it is healthy.
gpu_home_up() {
  local addr=$1 dargs="--network host"
  if docker network inspect fiberd-net >/dev/null 2>&1; then
    gpu_abort "the docker network fiberd-net exists, which hack/dev/run.sh would join beside --network host. Run: docker network rm fiberd-net"
  fi
  [ -z "$GPU_DEV" ] || dargs="$dargs --gpus all -e NVIDIA_DRIVER_CAPABILITIES=compute,utility"
  mkdir -p "$GPU_DIR"
  FIBERD_DEV_NAME=kata-gpu-home FIBERD_DEV_DOCKER_ARGS="$dargs" \
    hack/dev/run.sh bash examples/kata/kind/run.sh gpu-home "$addr" "$GPU_DEV" >"$GPU_DIR/container.log" 2>&1 &
  # hack/dev/run.sh execs docker run under its own pid, which names the
  # container.
  GPU_PID=$!
  GPU_CTR=kata-gpu-home-$GPU_PID
  trap gpu_home_down EXIT
  trap 'exit 130' INT TERM
  echo "--- the home: fiberd in the dev container $GPU_CTR on $addr. Logs in $GPU_DIR"
  for _ in $(seq 1 900); do
    if gpu_exec curl -sf --unix-socket "$GPU_STATE/home/private/admin.sock" http://x/healthz >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$GPU_PID" 2>/dev/null; then
      tail -20 "$GPU_DIR/container.log" || true
      gpu_abort "the home's container ended. Its output is in $GPU_DIR/container.log"
    fi
    sleep 1
  done
  gpu_abort "the home did not become healthy in 15 minutes"
}

gpu_home_down() {
  [ -n "$GPU_CTR" ] || return 0
  docker stop -t 10 "$GPU_CTR" >/dev/null 2>&1 || true
  kill "$GPU_PID" 2>/dev/null || true
  wait "$GPU_PID" 2>/dev/null || true
  GPU_CTR=""
}

# gpu_home_in <listen> [device] runs inside the dev container: the issuer,
# then fiberd on the proc runtime, whose engine drives the device, or a
# simulated pool without one. The issuer's key stays in the container.
gpu_home_in() {
  local listen=${1:?listen} dev=${2:-} engine="/src/bin/refengine --sim-mb 64" devices=()
  [ "$PWD" = /src ] || { echo "gpu-home runs inside the dev container, which $0 gpu starts" >&2; exit 2; }
  if [ -n "$dev" ]; then
    engine="/src/bin/refengine --pool-mb 64"
    devices=(-devices "$dev")
  fi
  rm -rf "$GPU_STATE" "$GPU_DIR/home"
  mkdir -p "$GPU_STATE" "$GPU_DIR/home"
  go build -o bin/ ./cmd/fiberd ./cmd/grant-issuer ./hack/fibctl
  make -s zygote engine
  bin/grant-issuer keygen -alg EdDSA -out "$GPU_STATE/issuer-key.json" >/dev/null
  bin/grant-issuer serve -key "$GPU_STATE/issuer-key.json" -addr "$GPU_ISSUER" -issuer "http://$GPU_ISSUER" \
    >"$GPU_DIR/home/issuer.log" 2>&1 &
  wait_for 30 "the issuer's keys" curl -sf "http://$GPU_ISSUER/openid/v1/jwks"
  echo "fiberd -listen $listen -engine '$engine' ${devices[*]}"
  exec bin/fiberd -state "$GPU_STATE/home" -node-id "$GPU_NODE" -verifier jwks -issuer "http://$GPU_ISSUER" \
    -jwks-max-stale 10m -insecure-plaintext -listen "$listen" -runtime proc \
    -template "default=/src/bin/refzygote --heap-mb 32" -engine "$engine" ${devices[@]+"${devices[@]}"} >"$GPU_LOG" 2>&1
}

# gpu_mint is the row's grant, with a device budget of the engine's
# class, minted in the home's container. The uid is fixed, as mint's is.
gpu_mint() {
  gpu_exec bin/grant-issuer mint -key "$GPU_STATE/issuer-key.json" -issuer "http://$GPU_ISSUER" \
    -aud "$GPU_NODE" -uid "$GPU_GRANT" -tenant kata -template sha256:conform -max 2 -warm 1 -w-budget 32Mi \
    -device-budget 16Mi -device-class "$GPU_CLASS" -min-tier FIBER_CHECKPOINT -isolation TRUSTED -ttl 2h
}

# probe <endpoint> <line...> is the fiber's one-line reply, or fibctl's
# error. fibctl runs in the home's container, where the fiber's unix
# socket is.
probe() { gpu_exec bin/fibctl "$@" 2>&1 || true; }

# endpoint_of <pod log> is the endpoint in the shim's fiber line.
endpoint_of() { sed -n 's/^fiber .* endpoint=\([^ ]*\) .*/\1/p' "$1" | sed -n 1p; }

gpu() {
  local addr tok ep r log=$GPU_DIR/pod1.log log2=$GPU_DIR/pod2.log
  gpu_device
  "$K8S" up
  "${KC[@]}" apply -f examples/kubernetes/kind/manifests/00-namespaces.yaml >/dev/null
  shim
  addr=$(gpu_addr) || gpu_abort "no IPv4 gateway on the kind network"
  gpu_home_up "$addr"
  if [ -n "$GPU_DEV" ]; then
    echo "    its engine: refengine --pool-mb 64 on $GPU_DEV, class gpu"
  else
    echo "    its engine: refengine --sim-mb 64, class sim, no GPU"
  fi
  "${KC[@]}" -n "$NS" delete pod kata-gpu-1 kata-gpu-2 --ignore-not-found --wait=true >/dev/null
  tok=$(gpu_mint) || gpu_abort "the grant could not be minted"

  echo "--- Pod 1, on-stop=park: its container is a fiber of the host home"
  fiber_pod kata-gpu-1 park "$tok" "$addr" "$GPU_SESSION" >"$log" || { cat "$log"; gpu_abort "Pod 1's container did not become a fiber" kata-gpu-1; }
  cat "$log"
  grep -q "^fiber .* CREATE session=$GPU_SESSION " "$log" || gpu_fail "Pod 1's container is not a fresh fiber of session $GPU_SESSION"
  ep=$(endpoint_of "$log")
  [ -n "$ep" ] || gpu_abort "Pod 1's fiber line names no endpoint" kata-gpu-1
  grep -h "device engine of $GPU_GRANT is" "$GPU_LOG" | sed 's/^/    /' || true
  r=$(probe "$ep" gpufill 7 4194304)
  case $r in
    "ok "?*) echo "ok   gpufill 7 4194304 = $r" ;;
    *) gpu_fail "gpufill 7 4194304 answered '$r', want ok and a hash" ;;
  esac
  r=$(probe "$ep" gpuopen /dev/nvidiactl)
  case $r in
    E[A-Z]*) echo "ok   gpuopen /dev/nvidiactl = $r, the fiber has no GPU node" ;;
    *) gpu_fail "gpuopen /dev/nvidiactl answered '$r', want an errno name" ;;
  esac
  "${KC[@]}" -n "$NS" delete pod kata-gpu-1 --wait=true >/dev/null
  wait_for 60 "the parked slice" grep -q "parked device slice of " "$GPU_LOG" ||
    gpu_fail "the home logged no parked device slice"
  wait_for 60 "the park on the home" gpu_exec grep -q "\"event\":\"park\".*\"session\":\"$GPU_SESSION\"" "$GPU_AUDIT" ||
    gpu_abort "the home recorded no park of session $GPU_SESSION"
  grep -h "parked device slice of " "$GPU_LOG" | sed 's/^/    /' || true
  echo "ok   deleted: the home parked session $GPU_SESSION and its slice"

  echo "--- Pod 2, on-stop=release: the same session resumes with its slice"
  fiber_pod kata-gpu-2 release "$tok" "$addr" "$GPU_SESSION" >"$log2" || { cat "$log2"; gpu_abort "Pod 2's container did not become a fiber" kata-gpu-2; }
  cat "$log2"
  grep -q "^fiber .* RESUME session=$GPU_SESSION " "$log2" || gpu_fail "Pod 2's container did not RESUME session $GPU_SESSION"
  ep=$(endpoint_of "$log2")
  if [ -z "$ep" ]; then
    gpu_fail "Pod 2's fiber line names no endpoint"
  else
    r=$(probe "$ep" gpucheck)
    if [ "$r" = ok ]; then echo "ok   gpucheck = ok, the slice came back whole"; else gpu_fail "gpucheck answered '$r', want ok"; fi
  fi
  "${KC[@]}" -n "$NS" delete pod kata-gpu-2 --wait=true >/dev/null
  if wait_for 60 "the release on the home" gpu_exec grep -q "\"event\":\"release\".*$GPU_SESSION" "$GPU_AUDIT"; then
    echo "ok   deleted: the home released session $GPU_SESSION"
  else
    gpu_fail "the home recorded no release of session $GPU_SESSION"
  fi
  [ "$GPU_FAILED" = 0 ] || exit 1
  echo "PASS kata gpu row"
}

case "${1:-}" in
  home) home ;;
  shim) shim ;;
  pod) pod "$2" "${3:-release}" ;;
  run) run ;;
  gpu) gpu ;;
  gpu-home) gpu_home_in "${2:-}" "${3:-}" ;;
  *) echo "usage: $0 run|gpu|home|shim|pod <name> [park|release]" >&2; exit 2 ;;
esac
