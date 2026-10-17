#!/usr/bin/env bash
# Interleaved A/B of two trees in the same dev image. Both trees run the
# NEW tree's benchmark harness (tests/bench is copied into OLD), so only the
# product code differs. Per harness, one discarded warm-up per side, then
# RUNS timed runs, old then new in each pair. Every log starts with the
# host's and the container's load at that moment.
#
#   hack/bench/ab.sh <old-tree> <new-tree> <out-dir>
#
# RUNS (default 3), HARNESSES (default "clone storm park"). AB_MAX_LOAD,
# when set, makes each run wait for the host's 1-minute load to fall under
# it, 30 minutes of waiting at most across the script.
set -uo pipefail
OLD=$(cd "$1" && pwd) NEW=$(cd "$2" && pwd) OUT=$3
RUNS=${RUNS:-3}
HARNESSES=${HARNESSES:-"clone storm park"}
mkdir -p "$OUT"
rm -rf "$OLD/tests/bench"
cp -R "$NEW/tests/bench" "$OLD/tests/bench"

waited=0
hostload() { if [ -r /proc/loadavg ]; then cut -d' ' -f1 /proc/loadavg; else sysctl -n vm.loadavg | awk '{print $2}'; fi; }
wait_load() {
  [ -n "${AB_MAX_LOAD:-}" ] || return 0
  while awk "BEGIN{exit !($(hostload) >= $AB_MAX_LOAD)}"; do
    [ "$waited" -ge 1800 ] && { echo "ab: load wait budget spent at $(hostload)" >&2; return 0; }
    sleep 20; waited=$((waited + 20))
  done
}

cmd_for() {
  case $1 in
    clone) echo "go test -tags integration -count=1 -v -run TestE2ECloneNumbers ./tests/bench/clone/" ;;
    storm) echo "go test -tags integration -count=1 -v -run TestStormNumbers ./tests/bench/storm/" ;;
    park)  echo "go test -tags integration -count=1 -v -run TestParkResumeNumbers ./tests/bench/park/" ;;
  esac
}

one() { # harness side label
  local h=$1 side=$2 label=$3 tree=$OLD
  [ "$side" = new ] && tree=$NEW
  wait_load
  local cmd
  read -ra cmd <<<"$(cmd_for "$h")"
  {
    echo "### $h $side $label $(date -u +%Y-%m-%dT%H:%M:%SZ) hostload=$(hostload) vmload=$(docker run --rm --entrypoint cat fiberd-dev:local /proc/loadavg 2>/dev/null | cut -d' ' -f1)"
    (cd "$tree" && FIBERD_DEV_NAME="fiberd-ab-$side" \
      hack/dev/run.sh env FIBERD_BENCH=1 "${cmd[@]}") 2>&1
    echo "### exit $?"
  } > "$OUT/$h-$side-$label.log"
  echo "ab: $h $side $label done"
}

for h in $HARNESSES; do
  one "$h" old warmup
  one "$h" new warmup
  for i in $(seq 1 "$RUNS"); do
    one "$h" old "$i"
    one "$h" new "$i"
  done
done
