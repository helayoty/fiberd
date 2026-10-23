#!/usr/bin/env bash
# Stand up a stub-runtime fiberd and run grant-conform against it.
#
#   hack/conform/stub.sh run            build, start, conform, stop
#   hack/conform/stub.sh start|stop|restart
#   hack/conform/stub.sh issuer-reachable up|down   flip whether the issuer is reachable (admin socket)
#   hack/conform/stub.sh seal-check     check the shared registry holds no template memory in the clear
#
# CONFORM_SIGNED=1 runs the signed-grant mode: a grant-issuer serves the
# JWKS, fiberd verifies with -verifier=jwks, and grant-conform mints real
# JWTs with the issuer's key. Otherwise grants are protobuf JSON through
# the insecure development verifier.
#
# CONFORM_TEMPLATE replaces the template command of the proc, gvisor or
# runc runtime, for another language's reference template (make
# conform-proc-python), CONFORM_ROOTFS_SH the script that builds the
# rootfs gvisor and runc run it in (hack/python/rootfs.sh), and
# CONFORM_W_BUDGET the W budget C6 minds, since a fiber of a template with
# a runtime dirties more at birth than the suite's 1 MiB default.
#
# State lives in $CONFORM_STATE (default bin/conform-state), so the
# restart hook keeps the epoch file and the audit spool across restarts.
#
# The proc runtime with its own reference template runs the mobility
# setup too (CONFORM_MOBILITY=0 turns it off). A local OCI registry keeps
# its blobs on disk, zygotectl builds the template with its images sealed
# to the fleet's public wrap key and pushes it, and the target pulls it
# by digest, so C1-C10 warm from author images. A second home, the peer,
# shares the registry and the delta keys. C11 moves a session to it and
# back. seal-check then reads every blob the registry holds. Each must be
# sealed, or be the zygote or its config.
#
# CONFORM_GPU=1 runs C14 on proc, runc, gvisor or hyperlight with the
# reference template. It needs the registry, the shared keys and the peer,
# which it sets up on every one of them, and a third home over the same
# registry and keys whose engine declares another layout (--layout
# raw512). The peer's engine names another GPU (--sim-name). C14 writes
# its events to $STATE/gpu-events.ndjson.
#
# fiberd is bin/fiberd-testhooks, fiberd built with -tags
# fiberd_testhooks so -admin-unsafe and the issuer and scope-lost hooks exist.
set -euo pipefail
cd "$(dirname "$0")/../.."

ADDR=${CONFORM_ADDR:-127.0.0.1:18484}
ISSUER_ADDR=${CONFORM_ISSUER_ADDR:-127.0.0.1:18686}
RUNTIME=${CONFORM_RUNTIME:-stub}          # stub | proc (proc: Linux, inside hack/dev)
NODE=${CONFORM_NODE:-conform-node}
STATE=${CONFORM_STATE:-bin/conform-state}
SIGNED=${CONFORM_SIGNED:-0}
WARM=${CONFORM_WARM:-0}   # fibers.warm of every minted grant
W_BUDGET=${CONFORM_W_BUDGET:-1048576}
LOG=$STATE/fiberd.log
ISSUER_URL="http://$ISSUER_ADDR"
GVISOR_ROOTFS=${CONFORM_GVISOR_ROOTFS:-/var/lib/fiberd/gvisor-rootfs}
ROOTFS_SH=${CONFORM_ROOTFS_SH:-hack/gvisor/rootfs.sh}
CGROOT=${FIBERD_CGROUP_ROOT:-/sys/fs/cgroup/fiberd}
MOBILITY=0
if [ "$RUNTIME" = proc ] && [ -z "${CONFORM_TEMPLATE:-}" ]; then MOBILITY=${CONFORM_MOBILITY:-1}; fi
REG_ADDR=${CONFORM_REGISTRY_ADDR:-127.0.0.1:18500}
PEER_ADDR=${CONFORM_PEER_ADDR:-127.0.0.1:18488}
PEER_NODE=${CONFORM_PEER_NODE:-conform-peer}
PEER_STATE=$STATE-peer
PEER_GPU=${CONFORM_PEER_GPU:-sim-peer}   # the GPU name the peer's engine declares
LAYOUT_ADDR=${CONFORM_LAYOUT_ADDR:-127.0.0.1:18490}
LAYOUT_NODE=${CONFORM_LAYOUT_NODE:-conform-layout}
LAYOUT_STATE=$STATE-layout
MOB=$STATE-mobility   # the registry's blobs, the shared keys, the artifact
GPU=${CONFORM_GPU:-0}
if [ "$GPU" = 1 ]; then
  case "$RUNTIME" in proc | runc | gvisor | hyperlight) ;; *) echo "CONFORM_GPU=1: C14 runs on proc, runc, gvisor or hyperlight, not $RUNTIME" >&2; exit 2 ;; esac
  [ -z "${CONFORM_TEMPLATE:-}" ] || { echo "CONFORM_GPU=1: C14 needs the reference template, not CONFORM_TEMPLATE" >&2; exit 2; }
fi
# The engine-loss hook (C9) ends the grant's warm instance, its zygote,
# through its cgroup leaf. Fork backends only.
ENGINE_HOOK=()
# The device engine fiberd starts for each grant with a device budget,
# the reference one with a simulated device, which is what C8 budgets.
# proc, runc, gvisor and hyperlight run it with the reference template,
# and run builds it. The peer's engine names another GPU, and the third
# home's declares another layout.
# A CONFORM_TEMPLATE (the Python ones) reserves no slice, so it runs
# without one, and C8's grant is refused loudly, which conformance
# accepts.
ENGINE=${CONFORM_ENGINE:-$PWD/bin/refengine}
ENGINE_FLAGS=()
PEER_ENGINE=()
LAYOUT_ENGINE=()
if [ -z "${CONFORM_TEMPLATE:-}" ]; then
  # hyperlight gets one only for C14, so its KVM row's C8 stays as it was.
  case "$RUNTIME" in
    proc | runc | gvisor) ENGINE_FLAGS=(-engine "$ENGINE --sim-mb 64") ;;
    hyperlight) if [ "$GPU" = 1 ]; then ENGINE_FLAGS=(-engine "$ENGINE --sim-mb 64"); fi ;;
  esac
  PEER_ENGINE=(${ENGINE_FLAGS[@]+"${ENGINE_FLAGS[@]}"})
  if [ "$GPU" = 1 ]; then
    PEER_ENGINE=(-engine "$ENGINE --sim-mb 64 --sim-name $PEER_GPU")
    LAYOUT_ENGINE=(-engine "$ENGINE --sim-mb 64 --layout raw512")
  fi
fi
# proc and runc fibers share the host kernel, so they serve trusted grants only.
ISOLATION=UNTRUSTED
if [ "$RUNTIME" = proc ] || [ "$RUNTIME" = runc ]; then ISOLATION=TRUSTED; fi
# proc and runc give each fiber a workspace, which C12 moves files through.
WORKSPACES=()
if [ "$RUNTIME" = proc ]; then
  WORKSPACES=(-workspaces)
  TIER=${CONFORM_TIER:-FIBER_CHECKPOINT}   # what proc offers when criu check passes
  RUNTIME_FLAGS=(-runtime proc -template "default=${CONFORM_TEMPLATE:-$PWD/bin/refzygote --heap-mb 32}")
  if [ "$MOBILITY" = 1 ]; then
    RUNTIME_FLAGS=(-runtime proc -registry "http://$REG_ADDR/zygotes/ref")
  fi
  ENGINE_HOOK=(-engine-kill-cmd "$0 engine-kill \$1")
elif [ "$RUNTIME" = gvisor ]; then
  TIER=${CONFORM_TIER:-FIBER_SNAPSHOT}
  RUNTIME_FLAGS=(-runtime gvisor -gvisor-rootfs "$GVISOR_ROOTFS" -template "default=${CONFORM_TEMPLATE:-/bin/refzygote --heap-mb 32 --gvisor}")
elif [ "$RUNTIME" = runc ]; then
  WORKSPACES=(-workspaces)
  TIER=${CONFORM_TIER:-FIBER_CHECKPOINT}
  RUNTIME_FLAGS=(-runtime runc -runc-rootfs "$GVISOR_ROOTFS" -template "default=${CONFORM_TEMPLATE:-/bin/refzygote --heap-mb 32}")
  ENGINE_HOOK=(-engine-kill-cmd "$0 engine-kill \$1")
elif [ "$RUNTIME" = hyperlight ]; then
  # CONFORM_HL_HELPER selects the helper: the Rust one where KVM exists,
  # else bin/fakehelper (built below), which speaks the same protocol.
  TIER=${CONFORM_TIER:-FIBER_SNAPSHOT}
  HL_HELPER=${CONFORM_HL_HELPER:-$PWD/bin/fakehelper}
  HL_GUEST=${CONFORM_HL_GUEST:-$PWD/bin/fake-guest.bin}
  HL_TEMPLATE="guest --heap-mb 32"
  [ -n "${CONFORM_HL_HELPER:-}" ] || HL_TEMPLATE="guest --init-ms 20"
  RUNTIME_FLAGS=(-runtime hyperlight -hyperlight-helper "$HL_HELPER" -hyperlight-guest "$HL_GUEST" -template "default=$HL_TEMPLATE")
elif [ "$RUNTIME" = cloudhv ]; then
  # CONFORM_CH_DIR holds the real VMM and guest images (make
  # cloudhv-images), else bin/cloudhv-fake gets the fake VMM and a
  # directory rootfs (built below). The template is a path in the rootfs.
  TIER=${CONFORM_TIER:-FIBER_SNAPSHOT}
  CH_DIR=${CONFORM_CH_DIR:-$PWD/bin/cloudhv-fake}
  RUNTIME_FLAGS=(-runtime cloudhv -cloudhv-vmm "$CH_DIR/cloud-hypervisor" -cloudhv-kernel "$CH_DIR/vmlinux"
    -cloudhv-rootfs "$CH_DIR/rootfs.img" -template "default=/fiberd/vmtemplate --heap-mb 32")
else
  TIER=${CONFORM_TIER:-FIBER_CHECKPOINT}
  RUNTIME_FLAGS=(-runtime stub -runtime-tier "$TIER")
fi
# Session mobility (C11, and C14 on every runtime it runs on): every home
# publishes and claims through the registry with the shared keys.
SHARED=0
if [ "$MOBILITY" = 1 ] || [ "$GPU" = 1 ]; then
  SHARED=1
  RUNTIME_FLAGS+=(-delta-registry "http://$REG_ADDR/deltas" -delta-key "$MOB/delta-key.json" -delta-seal-key "$MOB/delta-seal-key.json")
fi

wait_healthy() { # [state dir] [log]
  local state=${1:-$STATE} log=${2:-$LOG}
  for _ in $(seq 1 100); do
    if curl -sf --unix-socket "$state/private/admin.sock" http://x/healthz >/dev/null 2>&1; then return 0; fi
    sleep 0.1
  done
  echo "fiberd did not become healthy; log:" >&2; tail -20 "$log" >&2; return 1
}

start_issuer() {
  [ -f "$STATE/issuer-key.json" ] || bin/grant-issuer keygen -alg EdDSA -out "$STATE/issuer-key.json" >/dev/null
  bin/grant-issuer serve -key "$STATE/issuer-key.json" -addr "$ISSUER_ADDR" -issuer "$ISSUER_URL" >>"$STATE/issuer.log" 2>&1 &
  echo $! >"$STATE/issuer.pid"
  for _ in $(seq 1 50); do
    curl -sf "$ISSUER_URL/openid/v1/jwks" >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  echo "issuer did not come up" >&2; return 1
}

verify_flags() {
  if [ "$SIGNED" = 1 ]; then
    echo -verifier jwks -issuer "$ISSUER_URL" -jwks-max-stale 10m
  else
    echo -verifier insecure-json -issuer https://issuer.conform
  fi
}

start() {
  mkdir -p "$STATE"
  local verify; read -ra verify <<<"$(verify_flags)"
  bin/fiberd-testhooks -state "$STATE" -node-id "$NODE" "${verify[@]}" -insecure-plaintext \
    -listen "$ADDR" "${RUNTIME_FLAGS[@]}" ${ENGINE_FLAGS[@]+"${ENGINE_FLAGS[@]}"} -admin-unsafe \
    -stale-ttl 5s -status-interval 50ms >>"$LOG" 2>&1 &
  echo $! >"$STATE/pid"
  wait_healthy
}

# The peer: a second home over the same runtime, registry and delta keys,
# under a state directory and cgroup subtree of its own.
start_peer() {
  mkdir -p "$PEER_STATE"
  local verify; read -ra verify <<<"$(verify_flags)"
  bin/fiberd-testhooks -state "$PEER_STATE" -node-id "$PEER_NODE" -cgroup-root "$CGROOT-peer" "${verify[@]}" -insecure-plaintext \
    -listen "$PEER_ADDR" "${RUNTIME_FLAGS[@]}" ${PEER_ENGINE[@]+"${PEER_ENGINE[@]}"} -stale-ttl 5s -status-interval 50ms >>"$PEER_STATE.log" 2>&1 &
  echo $! >"$STATE/peer.pid"
  wait_healthy "$PEER_STATE" "$PEER_STATE.log"
}

# The third home, for C14 alone: the peer's registry and keys, and an
# engine that declares another layout, so it must refuse the session.
start_layout() {
  mkdir -p "$LAYOUT_STATE"
  local verify; read -ra verify <<<"$(verify_flags)"
  bin/fiberd-testhooks -state "$LAYOUT_STATE" -node-id "$LAYOUT_NODE" -cgroup-root "$CGROOT-layout" "${verify[@]}" -insecure-plaintext \
    -listen "$LAYOUT_ADDR" "${RUNTIME_FLAGS[@]}" ${LAYOUT_ENGINE[@]+"${LAYOUT_ENGINE[@]}"} -stale-ttl 5s -status-interval 50ms >>"$LAYOUT_STATE.log" 2>&1 &
  echo $! >"$STATE/layout.pid"
  wait_healthy "$LAYOUT_STATE" "$LAYOUT_STATE.log"
}

# The registry and the shared keys, which every home that moves sessions
# uses.
shared_setup() {
  mkdir -p "$MOB"
  bin/conform-registry -addr "$REG_ADDR" -dir "$MOB/blobs" >>"$MOB/registry.log" 2>&1 &
  echo $! >"$STATE/registry.pid"
  for _ in $(seq 1 50); do curl -sf "http://$REG_ADDR/v2/" >/dev/null 2>&1 && break; sleep 0.1; done
  bin/grant-issuer keygen -alg EdDSA -out "$MOB/delta-key.json" >/dev/null
  bin/grant-issuer keygen -alg A256GCM -out "$MOB/delta-seal-key.json" >/dev/null
}

# The template, after shared_setup: the reference zygote built with its
# images sealed to the fleet's public wrap key, which the seal key's
# keygen writes beside it. Prints the template digest.
mobility_setup() {
  bin/zygotectl build -zygote bin/refzygote -args "--heap-mb 32" -seal-to "$MOB/fleet-pub.json" -out "$MOB/art" >/dev/null
  bin/zygotectl push -dir "$MOB/art" -ref "http://$REG_ADDR/zygotes/ref:conform"
}

# seal-check: every blob the registry holds is sealed, or is the zygote,
# its config or the empty OCI config. Code and config may be read, the
# template's memory (author images, parents, deltas) may not.
seal_check() {
  local allowed sealed=0 f
  allowed=" $(sha256sum "$MOB/art/zygote" "$MOB/art/config.json" | cut -d' ' -f1 | tr '\n' ' ')$(printf '{}' | sha256sum | cut -d' ' -f1) "
  for f in "$MOB/blobs/sha256"/*; do
    if cmp -s -n 15 "$f" <(printf 'fiberd-seal-v1\n'); then sealed=$((sealed + 1)); continue; fi
    case "$allowed" in *" ${f##*/} "*) continue ;; esac
    echo "seal-check: $f ($(wc -c <"$f") bytes) is in the registry in the clear" >&2
    return 1
  done
  echo "seal-check: $sealed blobs sealed, and only the zygote and its config in the clear" >&2
  [ "$sealed" -ge 3 ] || { echo "seal-check: want the images, a parent and a delta sealed at least" >&2; return 1; }
}

stop_pidfile() {
  if [ -f "$1" ]; then
    kill "$(cat "$1")" 2>/dev/null || true
    wait "$(cat "$1")" 2>/dev/null || true
    rm -f "$1"
  fi
}

stop() { stop_pidfile "$STATE/pid"; }

issuer_reachable() {
  case "$1" in
    up)   curl -sf --unix-socket "$STATE/private/admin.sock" -X POST http://x/issuer -d '{"reachable":true}' >/dev/null ;;
    down) curl -sf --unix-socket "$STATE/private/admin.sock" -X POST http://x/issuer -d '{"reachable":false}' >/dev/null ;;
    *) echo "issuer-reachable up|down" >&2; return 2 ;;
  esac
}

# scope-lost: the standalone home's stand-in for losing its scope while
# running (a namespace, a DRA claim): fiberd bumps its epoch in
# place, which revokes every fence at once.
scope_lost() {
  curl -sf --unix-socket "$STATE/private/admin.sock" -X POST http://x/scope-lost >/dev/null
}

# engine-kill <grant>: end the grant's warm instance, its zygote, as a
# crash would (C9), through the cgroup leaf the runtime keeps it in.
engine_kill() {
  local procs="$CGROOT/$1/fibers/zygote/cgroup.procs"
  [ -r "$procs" ] || { echo "engine-kill: no zygote cgroup for $1" >&2; return 1; }
  local p; for p in $(cat "$procs"); do kill -9 "$p" 2>/dev/null || true; done
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  restart) stop; start ;;
  issuer-reachable) issuer_reachable "$2" ;;
  engine-kill) engine_kill "$2" ;;
  scope-lost) scope_lost ;;
  seal-check) seal_check ;;
  run)
    rm -rf "$STATE" "$PEER_STATE" "$PEER_STATE.log" "$LAYOUT_STATE" "$LAYOUT_STATE.log" "$MOB"; mkdir -p "$STATE"
    go build -o bin/ ./cmd/grant-issuer
    go build -tags fiberd_testhooks -o bin/fiberd-testhooks ./cmd/fiberd
    # bin/ is shared between the macOS host and the Linux container; go
    # refuses to overwrite a test binary built for the other OS.
    rm -f bin/grant-conform
    go test -c -tags integration -o bin/grant-conform ./tests/e2e/conform
    if [ "$RUNTIME" = proc ] && [ -z "${CONFORM_TEMPLATE:-}" ]; then make -s zygote; fi
    if [ ${#ENGINE_FLAGS[@]} -gt 0 ] && [ -z "${CONFORM_ENGINE:-}" ]; then make -s engine; fi
    if [ "$RUNTIME" = gvisor ] || [ "$RUNTIME" = runc ]; then "$ROOTFS_SH" "$GVISOR_ROOTFS" >/dev/null; fi
    if [ "$RUNTIME" = hyperlight ] && [ -z "${CONFORM_HL_HELPER:-}" ]; then
      go build -o bin/fakehelper ./hack/hyperlight/fakehelper; echo "fake guest" > bin/fake-guest.bin
    fi
    if [ "$RUNTIME" = cloudhv ] && [ -z "${CONFORM_CH_DIR:-}" ]; then hack/cloudhv/build.sh fake >/dev/null; fi
    trap 'stop; for p in issuer peer layout registry; do stop_pidfile "$STATE/$p.pid"; done' EXIT
    mint=(-mint insecure-json)
    if [ "$SIGNED" = 1 ]; then
      start_issuer
      mint=(-mint jwt -issuer-key "$STATE/issuer-key.json" -issuer "$ISSUER_URL")
    fi
    MOB_FLAGS=()
    if [ "$SHARED" = 1 ]; then
      go build -o bin/conform-registry ./hack/conform/registry
      shared_setup
      MOB_FLAGS=(-peer-target "$PEER_ADDR" -peer-node-id "$PEER_NODE")
    fi
    if [ "$MOBILITY" = 1 ]; then
      go build -o bin/ ./cmd/zygotectl
      TEMPLATE=$(mobility_setup)
      echo "template $TEMPLATE, its images sealed to the fleet key in $MOB/fleet-pub.json"
      MOB_FLAGS+=(-template "$TEMPLATE" -seal-check-cmd "$0 seal-check")
    fi
    if [ "$SHARED" = 1 ]; then start_peer; fi
    GPU_FLAGS=()
    if [ "$GPU" = 1 ]; then
      start_layout
      GPU_FLAGS=(-gpu -gpu-events "$STATE/gpu-events.ndjson" -gpu-backend "$RUNTIME" -peer-gpu-name "$PEER_GPU"
        -layout-target "$LAYOUT_ADDR" -layout-node-id "$LAYOUT_NODE")
    fi
    start
    bin/grant-conform -test.v -target "$ADDR" -target-tier "$TIER" -node-id "$NODE" -isolation "$ISOLATION" -fiber-warm "$WARM" -w-budget "$W_BUDGET" "${mint[@]}" \
      -restart-cmd "$0 restart" -cp-health-cmd "$0 issuer-reachable \$1" -audit-file "$STATE/private/audit.jsonl" \
      -scope-cmd "$0 scope-lost" ${ENGINE_HOOK[@]+"${ENGINE_HOOK[@]}"} ${MOB_FLAGS[@]+"${MOB_FLAGS[@]}"} ${WORKSPACES[@]+"${WORKSPACES[@]}"} \
      ${GPU_FLAGS[@]+"${GPU_FLAGS[@]}"} "${@:2}"
    if [ "$SHARED" = 1 ]; then
      grep -h 'published parent checkpoint\|claimed\|pulled parent' "$LOG" "$PEER_STATE.log" | sed 's/^/mobility: /' || true
    fi
    if [ "$GPU" = 1 ]; then
      grep -h 'fits engine\|parked device slice' "$LOG" "$PEER_STATE.log" "$LAYOUT_STATE.log" | sed 's/^/gpu: /' || true
    fi
    if [ "$WARM" -gt 0 ]; then
      pooled=$(grep -c '"detail":"pooled"' "$STATE/private/audit.jsonl" || true)
      echo "pool: $pooled clones served from the pool (fibers.warm=$WARM)"
      [ "$pooled" -gt 0 ] || { echo "pool: fibers.warm=$WARM but no clone was served from the pool" >&2; exit 1; }
    fi
    ;;
  *) echo "usage: $0 run|start|stop|restart|issuer-reachable up|down|seal-check" >&2; exit 2 ;;
esac
