#!/usr/bin/env bash
# Phase 6 standalone acceptance: a session moves between two homes.
#
# Run INSIDE the dev container with the registry up on the host:
#   make registry-start && make mobility
#
# Two fiberd agents (home-a, home-b) on one host, each with its own grant
# for the same zygote artifact, a delta registry between them. Count to
# three on A, park, Clone(S) on B resumes with the count, and A's stale
# copy is not served. Then B parks and A brings the session back.
set -euo pipefail
cd "$(dirname "$0")/../.."

REG=${FIBERD_REGISTRY:-fiberd-registry:5000}
ISSUER_ADDR=127.0.0.1:18686
ISSUER_URL="http://$ISSUER_ADDR"
STATE=${MOB_STATE:-/var/lib/fiberd/mob}
rm -rf "$STATE"; mkdir -p "$STATE"

curl -sf "http://$REG/v2/" >/dev/null || { echo "registry $REG not reachable (make registry-start on the host)"; exit 1; }
go build -o bin/ ./cmd/fiberd ./cmd/grant-issuer ./cmd/zygotectl ./hack/fibctl
make -s zygote
bin/zygotectl build -zygote bin/refzygote -args "--heap-mb 32" -out "$STATE/art" >/dev/null
DIGEST=$(bin/zygotectl push -dir "$STATE/art" -ref "$REG/zygotes/ref:mob" -plain-http)
echo "template $DIGEST"

bin/grant-issuer keygen -alg EdDSA -out "$STATE/issuer-key.json" >/dev/null
bin/grant-issuer serve -key "$STATE/issuer-key.json" -addr "$ISSUER_ADDR" -issuer "$ISSUER_URL" >"$STATE/issuer.log" 2>&1 &
PIDS=$!

start_home() { # name grpc http
  bin/fiberd -state "$STATE/$1" -node-id "$1" -verifier jwks -issuer "$ISSUER_URL" -jwks-max-stale 10m \
    -listen "127.0.0.1:$2" -http "127.0.0.1:$3" -runtime proc -run-dir "/tmp/fz-$1" \
    -registry "$REG/zygotes/ref" -delta-registry "$REG/deltas" -registry-plain-http \
    -status-interval 100ms >"$STATE/$1.log" 2>&1 &
  PIDS="$PIDS $!"
  for _ in $(seq 1 100); do curl -sf "http://127.0.0.1:$3/healthz" >/dev/null 2>&1 && return 0; sleep 0.1; done
  echo "$1 did not become healthy"; tail -20 "$STATE/$1.log"; exit 1
}
trap 'kill $PIDS 2>/dev/null; wait $PIDS 2>/dev/null || true' EXIT
start_home home-a 18484 18485
start_home home-b 18486 18487

mint() { bin/grant-issuer mint -key "$STATE/issuer-key.json" -issuer "$ISSUER_URL" -aud "$1" -template "$DIGEST" -max 4 -w-budget 64Mi -min-tier FIBER_CHECKPOINT -ttl 1h; }
TA=$(mint home-a); TB=$(mint home-b)
j() { python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$1" 2>/dev/null || printf '"%s"' "$1"; }
clone() { curl -s -X POST "http://127.0.0.1:$1/v1/clone" -d "{\"grantJwt\":$(j "$2"),\"session\":\"S\"}"; }
field() { sed -n "s/.*\"$1\": *\"\([^\"]*\)\".*/\1/p" | head -1; }
kind() { local k; k=$(echo "$1" | field kind); echo "${k:-CREATE}"; } # enum zero is omitted from JSON

R1=$(clone 18485 "$TA"); EP=$(echo "$R1" | field endpoint); F1=$(echo "$R1" | field fiberId)
echo "A: $(kind "$R1") $F1 $EP"
for _ in 1 2 3; do bin/fibctl "$EP" incr >/dev/null; done
bin/fibctl "$EP" dirty 1048576 >/dev/null
echo "A: counter = $(bin/fibctl "$EP" get)"
curl -s -X POST http://127.0.0.1:18485/v1/park -d "{\"fiberId\":\"$F1\",\"sync\":true}" >/dev/null
echo "A: parked and published"

R2=$(clone 18487 "$TB"); EP2=$(echo "$R2" | field endpoint); F2=$(echo "$R2" | field fiberId)
K2=$(echo "$R2" | field kind)
echo "B: $K2 $F2"
if [ -z "$EP2" ]; then
  echo "B clone response: $R2"; echo "--- home-b log:"; tail -15 "$STATE/home-b.log"; exit 1
fi
C2=$(bin/fibctl "$EP2" get)
echo "B: counter = $C2"
[ "$K2" = RESUME ] && [ "$C2" = 3 ] || { echo "FAIL: expected RESUME with counter 3 on B"; exit 1; }
bin/fibctl "$EP2" incr >/dev/null

R3=$(clone 18485 "$TA"); K3=$(kind "$R3")
echo "A again: $K3 (B holds the session; A must not resume its stale copy)"
[ "$K3" = CREATE ] || { echo "FAIL: A served a stale session"; exit 1; }
curl -s -X POST http://127.0.0.1:18485/v1/release -d "{\"fiberId\":\"$(echo "$R3" | field fiberId)\",\"discard\":true}" >/dev/null

curl -s -X POST http://127.0.0.1:18487/v1/park -d "{\"fiberId\":\"$F2\",\"sync\":true}" >/dev/null
R4=$(clone 18485 "$TA"); EP4=$(echo "$R4" | field endpoint); K4=$(echo "$R4" | field kind)
C4=$(bin/fibctl "$EP4" get)
echo "A: $K4 counter = $C4"
[ "$K4" = RESUME ] && [ "$C4" = 4 ] || { echo "FAIL: expected RESUME with counter 4 back on A"; exit 1; }
echo "--- deltas:"; grep -hE 'host: (parked|published|claimed)' "$STATE"/home-*.log
echo "PASS: session moved A -> B -> A with its state"
