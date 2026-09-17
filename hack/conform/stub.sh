#!/usr/bin/env bash
# Stand up a stub-runtime fiberd and run grant-conform against it.
#
#   hack/conform/stub.sh run            build, start, conform, stop
#   hack/conform/stub.sh start|stop|restart
#   hack/conform/stub.sh lane up|down   flip grant-lane health (admin socket)
#
# CONFORM_SIGNED=1 runs the signed-grant mode: a grant-issuer serves the
# JWKS, fiberd verifies with -verifier=jwks, and grant-conform mints real
# JWTs with the issuer's key. Otherwise grants are protobuf JSON through
# the insecure development verifier.
#
# State lives in $CONFORM_STATE (default bin/conform-state), so the
# restart hook keeps the epoch file and the audit spool across restarts.
set -euo pipefail
cd "$(dirname "$0")/../.."

ADDR=${CONFORM_ADDR:-127.0.0.1:18484}
ISSUER_ADDR=${CONFORM_ISSUER_ADDR:-127.0.0.1:18686}
RUNTIME=${CONFORM_RUNTIME:-stub}          # stub | proc (proc: Linux, inside hack/dev)
NODE=${CONFORM_NODE:-conform-node}
STATE=${CONFORM_STATE:-bin/conform-state}
SIGNED=${CONFORM_SIGNED:-0}
LOG=$STATE/fiberd.log
ISSUER_URL="http://$ISSUER_ADDR"
GVISOR_ROOTFS=${CONFORM_GVISOR_ROOTFS:-/var/lib/fiberd/gvisor-rootfs}
if [ "$RUNTIME" = proc ]; then
  TIER=${CONFORM_TIER:-FIBER_CHECKPOINT}   # what proc offers when criu check passes
  RUNTIME_FLAGS=(-runtime proc -template "default=$PWD/bin/refzygote --heap-mb 32" -run-dir /tmp/fz-conform)
elif [ "$RUNTIME" = gvisor ]; then
  TIER=${CONFORM_TIER:-FIBER_SNAPSHOT}
  RUNTIME_FLAGS=(-runtime gvisor -gvisor-rootfs "$GVISOR_ROOTFS" -template "default=/bin/refzygote --heap-mb 32 --gvisor" -run-dir /tmp/fz-conform)
elif [ "$RUNTIME" = runc ]; then
  TIER=${CONFORM_TIER:-FIBER_CHECKPOINT}
  RUNTIME_FLAGS=(-runtime runc -runc-rootfs "$GVISOR_ROOTFS" -template "default=/bin/refzygote --heap-mb 32" -run-dir /tmp/fz-conform)
elif [ "$RUNTIME" = hyperlight ]; then
  # CONFORM_HL_HELPER selects the helper: the Rust one where KVM exists,
  # else bin/fakehelper (built below), which speaks the same protocol.
  TIER=${CONFORM_TIER:-FIBER_SNAPSHOT}
  HL_HELPER=${CONFORM_HL_HELPER:-$PWD/bin/fakehelper}
  HL_GUEST=${CONFORM_HL_GUEST:-$PWD/bin/fake-guest.bin}
  HL_TEMPLATE="guest --heap-mb 32"
  [ -n "${CONFORM_HL_HELPER:-}" ] || HL_TEMPLATE="guest --init-ms 20"
  RUNTIME_FLAGS=(-runtime hyperlight -hyperlight-helper "$HL_HELPER" -hyperlight-guest "$HL_GUEST" -template "default=$HL_TEMPLATE" -run-dir /tmp/fz-conform)
else
  TIER=${CONFORM_TIER:-FIBER_CHECKPOINT}
  RUNTIME_FLAGS=(-runtime stub -runtime-tier "$TIER")
fi

wait_healthy() {
  for _ in $(seq 1 100); do
    if curl -sf --unix-socket "$STATE/admin.sock" http://x/healthz >/dev/null 2>&1; then return 0; fi
    sleep 0.1
  done
  echo "fiberd did not become healthy; log:" >&2; tail -20 "$LOG" >&2; return 1
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

start() {
  mkdir -p "$STATE"
  local verify=(-verifier insecure-json -issuer https://issuer.conform)
  if [ "$SIGNED" = 1 ]; then
    verify=(-verifier jwks -issuer "$ISSUER_URL" -jwks-max-stale 10m)
  fi
  bin/fiberd -state "$STATE" -node-id "$NODE" "${verify[@]}" \
    -listen "$ADDR" "${RUNTIME_FLAGS[@]}" -admin-unsafe \
    -stale-ttl 5s -status-interval 50ms >>"$LOG" 2>&1 &
  echo $! >"$STATE/pid"
  wait_healthy
}

stop_pidfile() {
  if [ -f "$1" ]; then
    kill "$(cat "$1")" 2>/dev/null || true
    wait "$(cat "$1")" 2>/dev/null || true
    rm -f "$1"
  fi
}

stop() { stop_pidfile "$STATE/pid"; }

lane() {
  case "$1" in
    up)   curl -sf --unix-socket "$STATE/admin.sock" -X POST http://x/lane -d '{"healthy":true}' >/dev/null ;;
    down) curl -sf --unix-socket "$STATE/admin.sock" -X POST http://x/lane -d '{"healthy":false}' >/dev/null ;;
    *) echo "lane up|down" >&2; return 2 ;;
  esac
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  restart) stop; start ;;
  lane) lane "$2" ;;
  run)
    rm -rf "$STATE"; mkdir -p "$STATE"
    go build -o bin/ ./cmd/fiberd ./cmd/grant-issuer
    go test -c -o bin/grant-conform ./cmd/grant-conform
    if [ "$RUNTIME" = proc ]; then make -s zygote; fi
    if [ "$RUNTIME" = gvisor ] || [ "$RUNTIME" = runc ]; then hack/gvisor/rootfs.sh "$GVISOR_ROOTFS" >/dev/null; fi
    if [ "$RUNTIME" = hyperlight ] && [ -z "${CONFORM_HL_HELPER:-}" ]; then
      go build -o bin/fakehelper ./hack/hyperlight/fakehelper; echo "fake guest" > bin/fake-guest.bin
    fi
    mint=(-mint insecure-json)
    if [ "$SIGNED" = 1 ]; then
      start_issuer
      trap 'stop; stop_pidfile "$STATE/issuer.pid"' EXIT
      mint=(-mint jwt -issuer-key "$STATE/issuer-key.json" -issuer "$ISSUER_URL")
    else
      trap stop EXIT
    fi
    start
    bin/grant-conform -test.v -target "$ADDR" -target-tier "$TIER" -node-id "$NODE" "${mint[@]}" \
      -restart-cmd "$0 restart" -cp-health-cmd "$0 lane \$1" -audit-file "$STATE/audit.jsonl" \
      "${@:2}"
    ;;
  *) echo "usage: $0 run|start|stop|restart|lane up|down" >&2; exit 2 ;;
esac
