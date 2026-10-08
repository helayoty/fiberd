#!/usr/bin/env bash
# The Substrate example end to end in kind: Substrate's own install, a
# WorkerPool of fiberd workers, an actor that is a fiber, driven through
# Substrate's router and control plane:
#
#   1. Substrate's source at the pinned commit (bin/substrate-src, or
#      SUBSTRATE_SRC), its kind cluster (their script: local registry,
#      feature gates for Pod certificates) and its system (ate-api-server,
#      atelet, atenet, rustfs, postgres), built with ko;
#   2. the ateom-fiberd worker image (the herder, runsc and a gVisor
#      rootfs), built from fiberd's dev image and pushed to the cluster's
#      registry;
#   3. a WorkerPool of two fiberd workers that mount their shared delta
#      keys from a Secret generated once, an atespace, and an ActorTemplate
#      whose golden actor Substrate boots on a worker and snapshots;
#   4. an actor: the first request resumes it from the golden snapshot,
#      three POSTs count to three, `kubectl ate suspend` checkpoints it
#      (a park and an export), the next request resumes it on whichever
#      worker is free with the count intact; latencies are printed. Every
#      actor is its own gVisor sandbox, so the pool's class is true.
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
KEYS=fiberd-delta-keys
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
  # ko builds every Substrate component from source. Their install sets
  # KO_DEFAULTPLATFORMS to linux/$(go env GOARCH), which overrides any
  # .ko.yaml, and ko refuses a GOARCH next to it. So the Go toolchain's
  # architecture must match the node's. An amd64 Go under Rosetta on an
  # Apple silicon Mac would push amd64 images into an aarch64 node, where
  # nothing starts, so stop early instead.
  local arch goarch
  arch=$(docker exec "$KIND_CLUSTER_NAME-control-plane" uname -m)
  case "$arch" in aarch64) arch=arm64 ;; x86_64) arch=amd64 ;; esac
  goarch=$(env -u GOARCH go env GOARCH)
  if [ "$goarch" != "$arch" ]; then
    echo "go is $(go env GOOS)/$goarch but the kind node is linux/$arch." >&2
    echo "Put a native $arch Go first in PATH and run again." >&2
    return 1
  fi
  log "Substrate's system for linux/$arch (ko builds every component; several minutes)"
  (cd "$SRC" && env -u GOARCH -u GOOS hack/install-ate-kind.sh --deploy-ate-system)
}

image() {
  log "the ateom-fiberd worker image"
  hack/dev/run.sh true # the builder stage is the dev image
  docker build -t "$IMAGE" -f docker/substrate/Dockerfile .
  docker push "$IMAGE"
}

version_label() {
  "${KC[@]}" get nodes -o jsonpath='{.items[0].metadata.labels.ate\.dev/substrate-version}'
}

render() { # render <file>
  sed -e "s|\${ATESPACE}|$ATESPACE|g" -e "s|\${POOL}|$POOL|g" -e "s|\${TEMPLATE}|$TEMPLATE|g" \
      -e "s|\${IMAGE}|$IMAGE|g" -e "s|\${SUBSTRATE_VERSION}|$(version_label)|g" -e "s|\${BUCKET_NAME}|$BUCKET_NAME|g" "$1"
}

# keys creates the Secret with the delta signing and seal keys every
# worker shares, so a snapshot taken on one worker restores on another.
# They are generated once, on the first run, and never written into the
# image or kept on the host.
keys() {
  if "${KC[@]}" -n "$ATESPACE" get secret "$KEYS" >/dev/null 2>&1; then
    log "the delta keys (Secret $KEYS exists)"
    return 0
  fi
  log "the delta keys every worker shares (Secret $KEYS, generated once)"
  (
    d=$(mktemp -d)
    trap 'rm -rf "$d"' EXIT
    go run ./cmd/grant-issuer keygen -alg EdDSA -out "$d/delta-key.json" >/dev/null
    go run ./cmd/grant-issuer keygen -alg A256GCM -out "$d/delta-seal-key.json" >/dev/null
    "${KC[@]}" -n "$ATESPACE" create secret generic "$KEYS" \
      --from-file="$d/delta-key.json" --from-file="$d/delta-seal-key.json"
  )
}

# mount_keys adds the Secret to the pool's Deployment at /etc/fiberd, where
# the image's ATEOM_FIBERD_DELTA_KEY and ATEOM_FIBERD_DELTA_SEAL_KEY point.
# The WorkerPool has no field for volumes, so this is a server-side apply
# under its own field manager. Substrate's controller applies only the
# fields it owns, so it keeps these.
mount_keys() {
  "${KC[@]}" -n "$ATESPACE" apply --server-side --field-manager=fiberd-example -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: $POOL
spec:
  template:
    spec:
      containers:
      - name: ateom
        volumeMounts:
        - name: delta-keys
          mountPath: /etc/fiberd
          readOnly: true
      volumes:
      - name: delta-keys
        secret:
          secretName: $KEYS
          defaultMode: 0400
EOF
}

pool() {
  log "a WorkerPool of fiberd workers"
  render examples/substrate/kind/workerpool.yaml.tmpl | "${KC[@]}" apply -f -
  keys
  "${KC[@]}" -n "$ATESPACE" wait --for=create "deployment/$POOL" --timeout=120s
  mount_keys
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
  # The workload ends its body with a newline. Drop it, so each request
  # prints one line, such as "3 [200 0.5s]".
  echo "${out//$'\n'/}"
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
  echo "suspend (checkpoint: the sandbox is parked and exported, the snapshot goes to the object store):"
  local t0 t1
  t0=$(date +%s.%N); kate suspend actor "$ACTOR" -a "$ATESPACE"; t1=$(date +%s.%N)
  echo "suspended in $(echo "$t1 - $t0" | bc)s"
  kate get actors -a "$ATESPACE"
  echo "next request (resume from the actor's own snapshot, count intact):"
  local got
  got=$(req GET /count)
  echo "$got"
  case "$got" in "3 [200 "*) echo "PASS substrate example: an actor that is a fiber counted to 3, was suspended through Substrate and resumed with 3" ;;
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
