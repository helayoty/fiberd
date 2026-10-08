#!/usr/bin/env bash
# The Kubernetes home's acceptance, end to end in kind:
#
#   1. build fiberd:kind (agent, controller, zygote, criu) and load it;
#   2. apply the CRD, the issuer controller and a CapacityGrant;
#   3. wait until the controller minted the grant, the agent admitted it,
#      warmed the template and set the readiness gate (the Pod is Ready);
#   4. run grant-conform C1-C10 from the host against the Pod's NodePort,
#      with every hook reaching into the Pod through kubectl exec;
#   5. run the 2x overcommit storm inside a second grant Pod under a
#      384 MiB limit: a park must fire before any OOM kill;
#   6. run sessioncheck from a client Pod against an UNTRUSTED gVisor
#      grant: a Clone from another Pod reaches the fiber over the Pod IP
#      (the agent relays the port to the sandbox's unix socket), and a
#      park and resume keep its state.
#
#   examples/kubernetes/kind/conform.sh run       (everything; needs docker, kind, kubectl, go)
#   examples/kubernetes/kind/conform.sh gvisor    (step 6 alone, on a deployed cluster)
#   examples/kubernetes/kind/conform.sh up|down   (just the cluster)
#   examples/kubernetes/kind/conform.sh runc-logs [pod]
#                                                 (runc's log and the zygote log inside a runc grant Pod)
#   examples/kubernetes/kind/conform.sh restart|lane up|down|audit <event> <fence>|engine-kill <uid>|scope-lost
#                                                 (the hooks grant-conform calls)
#
# Runs from the repository root: the image build needs fiberd's tree (the
# example module builds against it) and grant-conform is fiberd's.
set -euo pipefail
cd "$(dirname "$0")/../../.."
KIND_DIR=examples/kubernetes/kind

CLUSTER=${KIND_CLUSTER:-fiberd}
IMAGE=${FIBERD_KIND_IMAGE:-fiberd:kind}
NS=tenant-a
POD=conform-grant
TARGET=${CONFORM_TARGET:-127.0.0.1:30084}
ISSUER_URL=http://grant-issuer.fiberd-system.svc:8080
STATE=${CONFORM_STATE:-bin/conform-state-kind}
KC=(kubectl --context "kind-$CLUSTER")

kexec() { "${KC[@]}" -n "$NS" exec "$POD" -c agent -- "$@"; }
admin() { kexec curl -sf --unix-socket /var/lib/fiberd/private/admin.sock "$@"; }

wait_for() { # wait_for <seconds> <description> <cmd...>
  local n=$1 what=$2; shift 2
  for _ in $(seq 1 "$n"); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "timed out waiting for $what" >&2
  return 1
}

healthy() { admin http://x/healthz; }

up() {
  if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
    kind create cluster --name "$CLUSTER" --config "$KIND_DIR/kind.yaml" --wait 120s
  fi
}

down() { kind delete cluster --name "$CLUSTER"; }

image() {
  hack/dev/run.sh true # the builder stage is the dev image
  docker build -t "$IMAGE" -f docker/kubernetes/Dockerfile \
    --build-arg "DEV_IMAGE=${FIBERD_DEV_IMAGE:-fiberd-dev:local}" .
  kind load docker-image --name "$CLUSTER" "$IMAGE"
}

deploy() {
  "${KC[@]}" apply -f "$KIND_DIR/manifests/00-namespaces.yaml" -f "$KIND_DIR/manifests/10-crd.yaml"
  "${KC[@]}" wait --for=condition=Established crd/capacitygrants.fiberd.io --timeout=60s
  "${KC[@]}" apply -f "$KIND_DIR/manifests/20-issuer.yaml" -f "$KIND_DIR/manifests/30-grant-rbac.yaml"
  "${KC[@]}" -n fiberd-system rollout status deploy/grant-issuer --timeout=120s
  "${KC[@]}" apply -f "$KIND_DIR/manifests/40-conform.yaml" -f "$KIND_DIR/manifests/41-conform-runc.yaml"
  # The controller creates the Pod and mints the grant; the agent admits
  # it, warms the template and sets the gate: the Pod becomes Ready. The
  # runc home (41-conform-runc.yaml) only has to get that far.
  wait_for 60 "grant pod created" "${KC[@]}" -n "$NS" get pod "$POD"
  wait_for 60 "runc grant pod created" "${KC[@]}" -n "$NS" get pod conform-runc-grant
  "${KC[@]}" -n "$NS" wait --for=condition=Ready "pod/$POD" --timeout=180s
  if ! "${KC[@]}" -n "$NS" wait --for=condition=Ready pod/conform-runc-grant --timeout=180s; then
    "${KC[@]}" -n "$NS" describe pod conform-runc-grant || true
    "${KC[@]}" -n "$NS" logs conform-runc-grant --tail=100 || true
    runc_logs conform-runc-grant
    exit 1
  fi
  wait_for 30 "status.ready on the CapacityGrant" cg_ready conform
  wait_for 30 "status.ready on the runc CapacityGrant" cg_ready conform-runc
  "${KC[@]}" -n "$NS" get cg
}

cg_ready() { [ "$("${KC[@]}" -n "$NS" get cg "$1" -o jsonpath='{.status.ready}')" = true ]; }

# runc_logs <pod>: the end of runc's own log and of the zygote log of
# every grant the Pod's agent warmed. runc's log is beside the bundle
# under the state volume, and the zygote log is in the grant's run
# directory (pkg/backend/runc). `runc run` removes its container on the
# way out, so these are the evidence when a runc grant never warms.
runc_logs() {
  echo "--- runc and zygote logs in $1:"
  "${KC[@]}" -n "$NS" exec "$1" -c agent -- sh -c \
    'for f in /var/lib/fiberd/runc/bundles/*.runc.log /run/fiberd/*/zygote.log; do [ -f "$f" ] || continue; echo "--- $f"; tail -c 4096 "$f"; done' || true
}

restart_count() { "${KC[@]}" -n "$NS" get pod "$POD" -o jsonpath='{.status.containerStatuses[0].restartCount}'; }

restarted_past() { [ "$(restart_count)" -gt "$1" ]; }

# Hooks: the target is a Pod, reached through kubectl exec.
restart() {
  local before
  before=$(restart_count)
  kexec kill 1 # SIGTERM to the agent: it stops, the kubelet restarts the container, the epoch bumps
  wait_for 60 "container restart" restarted_past "$before"
  wait_for 60 "agent healthy again" healthy
  "${KC[@]}" -n "$NS" wait --for=condition=Ready "pod/$POD" --timeout=60s >/dev/null
}

lane() {
  case "$1" in
    up)   admin -X POST http://x/lane -d '{"healthy":true}' >/dev/null ;;
    down) admin -X POST http://x/lane -d '{"healthy":false}' >/dev/null ;;
    *) echo "lane: up|down" >&2; return 2 ;;
  esac
}

# audit <event> <grant/epoch/seq>: the record is in the Pod's spool.
audit() {
  local event=$1 fence=$2 uid epoch seq
  IFS=/ read -r uid epoch seq <<<"$fence"
  kexec grep -q "\"event\":\"$event\".*\"fence\":{\"GrantUID\":\"$uid\",\"Epoch\":$epoch,\"Seq\":$seq}" /var/lib/fiberd/private/audit.jsonl
}

# The fiberd subtree sits under the container's cgroup: the mount root in
# a private cgroup namespace, the scope /proc/1/cgroup names in the host's
# (PID 1 has moved into that scope's `agent` leaf by then).
own_cgroup='own=/sys/fs/cgroup$(cut -d: -f3 /proc/1/cgroup | head -1); own=${own%/agent}; [ -d "$own" ] || own=/sys/fs/cgroup'

engine_kill() {
  kexec sh -c "$own_cgroup; kill -9 \$(cat \$own/fiberd/$1/zygote/cgroup.procs)"
}

scope_lost() { admin -X POST http://x/scope-lost >/dev/null; }

conform() {
  rm -rf "$STATE"; mkdir -p "$STATE"
  rm -f bin/grant-conform
  go test -c -o bin/grant-conform ./tests/conform
  "${KC[@]}" -n fiberd-system get secret grant-issuer-key -o jsonpath='{.data.key\.json}' | base64 -d >"$STATE/issuer-key.json"
  bin/grant-conform -test.v -target "$TARGET" -target-tier FIBER_CHECKPOINT -node-id "$POD" -isolation TRUSTED \
    -mint jwt -issuer-key "$STATE/issuer-key.json" -issuer "$ISSUER_URL" \
    -restart-cmd "$0 restart" -cp-health-cmd "$0 lane \$1" -audit-cmd "$0 audit \$1 \$2" \
    -engine-kill-cmd "$0 engine-kill \$1" -scope-cmd "$0 scope-lost" -case-timeout 60s
}

storm() {
  "${KC[@]}" apply -f "$KIND_DIR/manifests/50-storm.yaml"
  wait_for 60 "storm pod created" "${KC[@]}" -n "$NS" get pod storm-grant
  "${KC[@]}" -n "$NS" wait --for=condition=Ready pod/storm-grant --timeout=180s
  "${KC[@]}" -n "$NS" cp --no-preserve "$STATE/issuer-key.json" storm-grant:/tmp/issuer-key.json -c agent
  # The container's cgroup is the mount root in a private cgroup
  # namespace and the scope /proc/1/cgroup names in the host's (what a
  # privileged Pod gets); the OOM counter and the fiberd subtree are there.
  "${KC[@]}" -n "$NS" exec storm-grant -c agent -- sh -c "$own_cgroup"'
    exec storm -target 127.0.0.1:8484 -node-id storm-grant -issuer-key /tmp/issuer-key.json -issuer "$0" -isolation TRUSTED \
      -cgroup-root "$own/fiberd" -container-events "$own/memory.events" \
      -fibers 8 -ceiling 167772160 -overcommit 2 -step 2097152 -round 250ms' "$ISSUER_URL"
  echo "--- storm pod:"
  "${KC[@]}" -n "$NS" get pod storm-grant -o jsonpath='restarts={.status.containerStatuses[0].restartCount} lastState={.status.containerStatuses[0].lastState}'; echo
  [ "$("${KC[@]}" -n "$NS" get pod storm-grant -o jsonpath='{.status.containerStatuses[0].restartCount}')" = 0 ] || { echo "storm pod was restarted (OOM killed?)" >&2; return 1; }
}

# gvisor: an UNTRUSTED grant whose fibers are runsc sandboxes behind the
# Pod IP, checked from a second Pod. The grant Pod's endpoint family is
# inet4, which the gvisor runtime serves through the agent's relay.
gvisor() {
  local gpod=conform-gvisor-grant client=sessioncheck-client ip
  mkdir -p "$STATE"
  [ -s "$STATE/issuer-key.json" ] || "${KC[@]}" -n fiberd-system get secret grant-issuer-key -o jsonpath='{.data.key\.json}' | base64 -d >"$STATE/issuer-key.json"
  "${KC[@]}" apply -f "$KIND_DIR/manifests/60-gvisor.yaml"
  wait_for 60 "gvisor grant pod created" "${KC[@]}" -n "$NS" get pod "$gpod"
  "${KC[@]}" -n "$NS" wait --for=condition=Ready "pod/$gpod" --timeout=300s
  ip=$("${KC[@]}" -n "$NS" get pod "$gpod" -o jsonpath='{.status.podIP}')
  "${KC[@]}" -n "$NS" delete pod "$client" --ignore-not-found --wait=true >/dev/null
  "${KC[@]}" -n "$NS" run "$client" --image="$IMAGE" --image-pull-policy=Never --restart=Never --command -- sleep 600
  "${KC[@]}" -n "$NS" wait --for=condition=Ready "pod/$client" --timeout=120s
  "${KC[@]}" -n "$NS" cp --no-preserve "$STATE/issuer-key.json" "$client:/tmp/issuer-key.json"
  "${KC[@]}" -n "$NS" exec "$client" -- sessioncheck -target "$ip:8484" -node-id "$gpod" -issuer-key /tmp/issuer-key.json \
    -issuer "$ISSUER_URL" -isolation UNTRUSTED -want-scheme tcp
  echo "--- gvisor grant pod agent log (relay lines):"
  "${KC[@]}" -n "$NS" logs "$gpod" -c agent | grep -i "relay\|endpoints" | tail -5 || true
  "${KC[@]}" -n "$NS" delete pod "$client" --wait=false >/dev/null
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  image) image ;;
  deploy) deploy ;;
  restart) restart ;;
  lane) lane "$2" ;;
  audit) audit "$2" "$3" ;;
  engine-kill) engine_kill "$2" ;;
  scope-lost) scope_lost ;;
  conform) conform ;;
  storm) storm ;;
  gvisor) gvisor ;;
  runc-logs) runc_logs "${2:-conform-runc-grant}" ;;
  run)
    up; image; deploy; conform; storm; gvisor
    ;;
  *) echo "usage: $0 run|up|down|image|deploy|conform|storm|gvisor|runc-logs [pod]|restart|lane up|down|audit <event> <fence>|engine-kill <uid>|scope-lost" >&2; exit 2 ;;
esac
