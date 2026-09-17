#!/usr/bin/env bash
# The Substrate example end to end in kind: Substrate's own install, a
# WorkerPool of fiberd workers, an actor that is a fiber, driven through
# Substrate's router and control plane:
#
#   1. Substrate's source at the pinned commit (bin/substrate-src, or
#      SUBSTRATE_SRC), its kind cluster (their script: local registry,
#      feature gates for Pod certificates) and its system (ate-api-server,
#      atelet, atenet, rustfs, postgres), built with ko;
#   2. the ateom-fiberd worker image, built from fiberd's dev image and
#      pushed to the cluster's registry;
#   3. a WorkerPool of two fiberd workers, an atespace, an ActorTemplate:
#      Substrate boots the golden actor on a worker and snapshots it;
#   4. an actor: the first request resumes it from the golden snapshot,
#      three POSTs count to three, `kubectl ate suspend` checkpoints it
#      (a park and an export), the next request resumes it on whichever
#      worker is free with the count intact; latencies are printed.
#
#   examples/substrate/kind/run.sh run       (from the repo root; needs docker, kubectl, go, jq)
#   examples/substrate/kind/run.sh src|cluster|system|image|pool|template|actor|down
set -euo pipefail
cd "$(dirname "$0")/../../.."

COMMIT=85ce8ed5313f64aa4d8d5fb616ce450abf1e95e0
SRC=${SUBSTRATE_SRC:-$PWD/bin/substrate-src}
export KIND_CLUSTER_NAME=${KIND_CLUSTER_NAME:-fiberd-substrate}
CTX=kind-$KIND_CLUSTER_NAME
REG=localhost:5001
IMAGE=${ATEOM_FIBERD_IMAGE:-$REG/ateom-fiberd:dev}
ATESPACE=ate-demo-fiberd
POOL=fiberd
TEMPLATE=counter
ACTOR=${ACTOR:-c1}
BUCKET_NAME=ate-snapshots
ROUTER_PORT=${ROUTER_PORT:-18000}
KC=(kubectl --context "$CTX")
STATE=${SUBSTRATE_STATE:-bin/substrate-state}

log() { echo "--- $*"; }

kate() { (cd "$SRC" && go run ./cmd/kubectl-ate --context "$CTX" "$@"); }

wait_for() { # wait_for <seconds> <description> <cmd...>
  local n=$1 what=$2; shift 2
  for _ in $(seq 1 "$n"); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "timed out waiting for $what" >&2
  return 1
}

src() {
  if [ ! -d "$SRC/.git" ]; then
    log "cloning agent-substrate/substrate into $SRC"
    git clone --quiet https://github.com/agent-substrate/substrate "$SRC"
  fi
  (cd "$SRC" && git checkout --quiet "$COMMIT")
}

cluster() {
  log "Substrate's kind cluster $KIND_CLUSTER_NAME (their script; recreates it)"
  (cd "$SRC" && hack/create-kind-cluster.sh)
}

system() {
  # ko builds every Substrate component from source, for the platform
  # their install derives from `go env GOARCH` (it exports
  # KO_DEFAULTPLATFORMS itself, so only GOARCH can steer it). That is the
  # Go toolchain's architecture, not the node's: an amd64 Go under
  # Rosetta on an Apple silicon Mac pushes amd64 images into an aarch64
  # node, where nothing starts. Take the architecture from the node.
  local arch
  arch=$(docker exec "$KIND_CLUSTER_NAME-control-plane" uname -m)
  case "$arch" in aarch64) arch=arm64 ;; x86_64) arch=amd64 ;; esac
  if [ "$(go env GOARCH)" != "$arch" ]; then
    log "note: go is $(go env GOOS)/$(go env GOARCH) but the node is linux/$arch; building for the node"
  fi
  log "Substrate's system for linux/$arch (ko builds every component; several minutes)"
  (cd "$SRC" && GOARCH=$arch hack/install-ate-kind.sh --deploy-ate-system)
}

image() {
  log "the ateom-fiberd worker image"
  hack/dev/run.sh true # the builder stage is the dev image
  docker build -t "$IMAGE" -f examples/substrate/kind/Dockerfile .
  docker push "$IMAGE"
}

version_label() {
  "${KC[@]}" get nodes -o jsonpath='{.items[0].metadata.labels.ate\.dev/substrate-version}'
}

render() { # render <file>
  sed -e "s|\${ATESPACE}|$ATESPACE|g" -e "s|\${POOL}|$POOL|g" -e "s|\${TEMPLATE}|$TEMPLATE|g" \
      -e "s|\${IMAGE}|$IMAGE|g" -e "s|\${SUBSTRATE_VERSION}|$(version_label)|g" -e "s|\${BUCKET_NAME}|$BUCKET_NAME|g" "$1"
}

pool() {
  log "a WorkerPool of fiberd workers"
  render examples/substrate/kind/workerpool.yaml.tmpl | "${KC[@]}" apply -f -
  "${KC[@]}" -n "$ATESPACE" wait --for=create "deployment/$POOL" --timeout=120s
  "${KC[@]}" -n "$ATESPACE" rollout status "deployment/$POOL" --timeout=300s
  "${KC[@]}" -n "$ATESPACE" get pods -o wide
}

template() {
  log "the atespace and the ActorTemplate (Substrate boots and snapshots the golden actor)"
  kate create atespace "$ATESPACE" 2>/dev/null || true
  if ! kate get actor-template "$TEMPLATE" -a "$ATESPACE" >/dev/null 2>&1; then
    render examples/substrate/kind/template.yaml.tmpl | kate create actor-template -f -
  fi
  local t0=$SECONDS
  for _ in $(seq 1 60); do
    local json
    json=$(kate get actor-template "$TEMPLATE" -a "$ATESPACE" -o json 2>/dev/null || true)
    if [ -n "$(jq -r '.status.goldenSnapshotStatus.goldenTag.name // empty' <<<"$json")" ]; then
      echo "golden snapshot ready after $((SECONDS - t0))s"
      return 0
    fi
    local err
    err=$(jq -r '.status.goldenSnapshotStatus.errorMessage // empty' <<<"$json")
    if [ -n "$err" ]; then echo "golden snapshot failed: $err" >&2; return 1; fi
    sleep 5
  done
  echo "timed out waiting for the golden snapshot" >&2
  return 1
}

router() { # port-forward the router once, in the background
  if ! curl -sf -o /dev/null "http://127.0.0.1:$ROUTER_PORT/" -H "ate-target-actor: x/y" 2>/dev/null; then
    "${KC[@]}" -n ate-system port-forward svc/atenet-router "$ROUTER_PORT:80" >/dev/null 2>&1 &
    echo $! >"$STATE/port-forward.pid"
    wait_for 30 "the router port-forward" sh -c "curl -s -o /dev/null http://127.0.0.1:$ROUTER_PORT/ -H 'ate-target-actor: x/y'"
  fi
}

req() { # req <method> [path]: one request to the actor through the router, timed
  local method=$1 path=${2:-/} out
  out=$(curl -s -X "$method" -H "ate-target-actor: $ATESPACE/$ACTOR" -w ' [%{http_code} %{time_total}s]' "http://127.0.0.1:$ROUTER_PORT$path")
  echo "$out"
}

actor() {
  mkdir -p "$STATE"
  log "the actor $ACTOR"
  kate create actor "$ACTOR" -a "$ATESPACE" --template "$TEMPLATE" 2>/dev/null || true
  router
  echo "first request (resume from the golden snapshot onto a free worker):"
  req GET /count
  echo "three increments:"
  req POST /incr; req POST /incr; req POST /incr
  kate get actors -a "$ATESPACE"
  echo "suspend (checkpoint: park + export, the snapshot goes to the object store):"
  local t0 t1
  t0=$(date +%s.%N); kate suspend actor "$ACTOR" -a "$ATESPACE"; t1=$(date +%s.%N)
  echo "suspended in $(echo "$t1 - $t0" | bc)s"
  kate get actors -a "$ATESPACE"
  echo "next request (resume from the actor's own snapshot, count intact):"
  local got
  got=$(req GET /count)
  echo "$got"
  case "$got" in 3\ *) echo "PASS substrate example: an actor that is a fiber counted to 3, was suspended through Substrate and resumed with 3" ;;
    *) echo "FAIL: expected the count 3 after the resume" >&2; return 1 ;; esac
  kate get actors -a "$ATESPACE"
  kate get workers -a "$ATESPACE" 2>/dev/null || true
}

down() {
  [ -f "$STATE/port-forward.pid" ] && kill "$(cat "$STATE/port-forward.pid")" 2>/dev/null || true
  (cd "$SRC" && hack/kind.sh delete cluster --name "$KIND_CLUSTER_NAME") || true
}

case "${1:-}" in
  src) src ;;
  cluster) src; cluster ;;
  system) src; system ;;
  image) image ;;
  pool) pool ;;
  template) template ;;
  actor) actor ;;
  down) down ;;
  run) src; cluster; system; image; pool; template; actor ;;
  *) echo "usage: $0 run|src|cluster|system|image|pool|template|actor|down" >&2; exit 2 ;;
esac
