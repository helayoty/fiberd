#!/usr/bin/env bash
# The Knative example end to end, inside fiberd's dev container:
#
#   1. a fiberd home with the Hyperlight backend (the Rust helper where
#      KVM exists, else the fake helper, which speaks the same protocol)
#      and the reference issuer as its control plane;
#   2. a grant for the revision, minted by the issuer;
#   3. fiberd-activator fronting the revision;
#   4. requests: the first is scale-from-zero (CREATE), the next attaches
#      and keeps the guest's state, an idle revision is parked, the next
#      request resumes it (RESUME) with the state intact.
#
#   examples/knative/run.sh            (from the repo root; needs go, curl)
#   CONFORM_HL_HELPER=bin/hyperlight-helper CONFORM_HL_GUEST=bin/hyperlight-guest examples/knative/run.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
STATE=${KNATIVE_STATE:-bin/knative-state}
HOME_ADDR=127.0.0.1:18494
ISSUER_ADDR=127.0.0.1:18696
ISSUER_URL="http://$ISSUER_ADDR"
ACT_ADDR=127.0.0.1:18080
NODE=knative-home
IDLE=${KNATIVE_IDLE:-2s}
HL_HELPER=${CONFORM_HL_HELPER:-$PWD/bin/fakehelper}
HL_GUEST=${CONFORM_HL_GUEST:-$PWD/bin/fake-guest.bin}
HL_TEMPLATE="guest --heap-mb 32"
[ -n "${CONFORM_HL_HELPER:-}" ] || HL_TEMPLATE="guest --init-ms 20"

rm -rf "$STATE"; mkdir -p "$STATE"
go build -o bin/ ./cmd/fiberd ./cmd/grant-issuer
(cd examples/knative && go build -o ../../bin/ ./cmd/fiberd-activator)
if [ -z "${CONFORM_HL_HELPER:-}" ]; then
  go build -o bin/fakehelper ./hack/hyperlight/fakehelper; echo "fake guest" > bin/fake-guest.bin
fi

pids=()
stop() { local p; for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; }
trap stop EXIT

# 1. the control plane and the home.
bin/grant-issuer keygen -alg EdDSA -out "$STATE/issuer-key.json" >/dev/null
bin/grant-issuer serve -key "$STATE/issuer-key.json" -addr "$ISSUER_ADDR" -issuer "$ISSUER_URL" >"$STATE/issuer.log" 2>&1 &
pids+=($!)
for _ in $(seq 1 50); do curl -sf --max-time 2 "$ISSUER_URL/openid/v1/jwks" >/dev/null 2>&1 && break; sleep 0.1; done
bin/fiberd -state "$STATE" -node-id "$NODE" -verifier jwks -issuer "$ISSUER_URL" -jwks-max-stale 10m \
  -listen "$HOME_ADDR" -runtime hyperlight -hyperlight-helper "$HL_HELPER" -hyperlight-guest "$HL_GUEST" \
  -template "default=$HL_TEMPLATE" -run-dir /tmp/fz-knative -status-interval 50ms -stale-ttl 30s \
  >"$STATE/fiberd.log" 2>&1 &
pids+=($!)
for _ in $(seq 1 100); do curl -sf --max-time 2 --unix-socket "$STATE/admin.sock" http://x/healthz >/dev/null 2>&1 && break; sleep 0.1; done
curl -sf --max-time 5 --unix-socket "$STATE/admin.sock" http://x/healthz >/dev/null || { echo "home did not come up"; tail -n 20 "$STATE/fiberd.log"; exit 1; }

# 2. the revision's grant: FIBER_SNAPSHOT, two fibers, 32 MiB each.
bin/grant-issuer mint -key "$STATE/issuer-key.json" -issuer "$ISSUER_URL" -aud "$NODE" \
  -template sha256:hello -max 2 -warm 1 -w-budget 32Mi -min-tier FIBER_SNAPSHOT -ttl 1h >"$STATE/hello.jwt"

# 3. the activator.
bin/fiberd-activator -home "$HOME_ADDR" -listen "$ACT_ADDR" -idle "$IDLE" -revision "hello=@$STATE/hello.jwt" \
  >"$STATE/activator.log" 2>&1 &
pids+=($!)
sleep 0.3

# 4. requests. Each reply's X-Fiberd-Clone says how the request was
# served; the body is the guest's answer.
ask() { # ask <body> -> prints "<clone kind> <body>"
  local out kind body
  # --max-time: a request the activator never answers must fail this
  # script, not hold it (and a CI job) until something else times out.
  # It is generous: a cold Hyperlight clone is milliseconds, a resume
  # from a snapshot on disk under load is seconds.
  out=$(curl -s -i --max-time 30 -X POST --data-binary "$1" "http://$ACT_ADDR/hello")
  kind=$(printf '%s' "$out" | tr -d '\r' | awk -F': ' 'tolower($1)=="x-fiberd-clone"{print $2}')
  body=$(printf '%s' "$out" | tr -d '\r' | awk 'f{print} /^$/{f=1}' | head -1)
  echo "$kind $body"
}
expect() { # expect <label> <got> <want>
  if [ "$2" != "$3" ]; then echo "FAIL $1: got '$2', want '$3'"; tail -n 20 "$STATE/activator.log" "$STATE/fiberd.log"; exit 1; fi
  echo "ok   $1: $2"
}
t0=$(date +%s%N)
expect "scale from zero"          "$(ask ping)" "CREATE pong"
t1=$(date +%s%N)
expect "attach, state carries"    "$(ask incr)" "ATTACH 1"
expect "attach again"             "$(ask incr)" "ATTACH 2"
echo "idle for $IDLE: the activator parks the revision"
# The park itself takes as long as the backend's checkpoint (a Hyperlight
# snapshot is hundreds of milliseconds; the fake helper's is nothing), so
# wait for it rather than assume it.
sleep "$IDLE"
parked=0
for _ in $(seq 1 60); do
  if grep -q "activator: parked hello-0" "$STATE/activator.log"; then parked=1; break; fi
  sleep 0.5
done
[ "$parked" = 1 ] || { echo "FAIL: no park logged within 30s"; tail -n 20 "$STATE/activator.log" "$STATE/fiberd.log" /tmp/fz-knative/*/zygote.log 2>/dev/null; exit 1; }
echo "ok   parked: $(grep 'activator: parked' "$STATE/activator.log" | tail -1 | sed 's/.*activator: //')"
t2=$(date +%s%N)
expect "resume with state intact" "$(ask incr)" "RESUME 3"
t3=$(date +%s%N)
echo "scale-from-zero $(( (t1 - t0) / 1000000 )) ms, resume $(( (t3 - t2) / 1000000 )) ms (activator round trips)"
echo "PASS knative example over $(basename "$HL_HELPER")"
