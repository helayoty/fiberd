#!/usr/bin/env bash
# Measure which capabilities a runtime needs. Run it as root inside the
# dev container, through make linux-caps or by hand.
#
#   hack/dev/run.sh hack/test/caps.sh                      proc, its integration suite
#   hack/dev/run.sh env SUITE=gvisor hack/test/caps.sh     gvisor, its integration suite
#   hack/dev/run.sh env SUITE=gvisor CONFORM=1 hack/test/caps.sh   gvisor, the conformance suite
#
# The suite runs several times. First with every capability, as the
# reference. Then with every candidate in the bounding set, as the
# baseline, which must pass what the reference passes. Then once per
# candidate with only that one left out. Last with only the ones found
# needed, which catches capabilities that stand in for each other
# (CAP_SYS_ADMIN covers CAP_CHECKPOINT_RESTORE).
#
# A capability is needed when a test that passed in the baseline fails
# without it. A skipped test counts as failed, since tests skip when criu
# is not usable.
#
# Run it on a host with Yama (kernel.yama.ptrace_scope=1, the Ubuntu
# default). Docker Desktop's kernel has no Yama, so CRIU attaches without
# CAP_SYS_PTRACE there and the run misses that it is needed. The caps
# workflow runs it on a CI runner, which has Yama and /dev/kvm.
#
#   SUITE=proc|runc|gvisor|hyperlight   the runtime (default proc)
#   CONFORM=1              the conformance suite over SUITE, with fiberd
#                          under setpriv, instead of tests/integration/SUITE
#   CAPS="chown,kill,..."  candidates (default: every capability setpriv knows)
#   RUN="TestX|TestY"      only these tests (-test.run)
#   CAPS_OUT=dir           logs (default bin/caps, kept after the container)
#
# The conformance suite takes its own CONFORM_* settings from the
# environment, so a hyperlight run with the real helper sets
# CONFORM_HL_HELPER and CONFORM_HL_GUEST as make conform-hyperlight does.
#
# run.sh does not pass the environment through, so set it with env.
#   hack/dev/run.sh env CAPS=... hack/test/caps.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

SUITE=${SUITE:-proc}
CONFORM=${CONFORM:-0}
# Every capability by default, since a runtime's needs are not known
# before the run. runsc re-executes itself with ambient capabilities,
# and a shorter list missed one of them.
known=$(setpriv --list-caps)
CAPS=${CAPS:-$(paste -sd, <<<"$known")}
RUN=${RUN:-.}
OUT=$(realpath -m "${CAPS_OUT:-bin/caps}")
CG=${FIBERD_CGROUP_ROOT:-/sys/fs/cgroup/fiberd}
case "$SUITE" in proc | runc | gvisor | hyperlight) ;; *) echo "SUITE=$SUITE: want proc, runc, gvisor or hyperlight"; exit 1 ;; esac
case "$CONFORM" in 0 | 1) ;; *) echo "CONFORM=$CONFORM: want 0 or 1"; exit 1 ;; esac
rm -rf "$OUT"; mkdir -p "$OUT"

IFS=, read -ra cand <<<"$CAPS"
for c in "${cand[@]}"; do
  grep -qx "$c" <<<"$known" || { echo "setpriv does not know $c; drop it from CAPS"; exit 1; }
done

STATE=${CONFORM_STATE:-bin/conform-state}
if [ "$CONFORM" = 1 ]; then
  echo "measuring $SUITE over the conformance suite"
  # The settings CI's conform-* targets use, so the peer, the pool and
  # C14 run and their needs count. fiberd keeps the bounding set setpriv
  # gives it, since its own narrowing would hide a keep set that is too
  # small.
  export CONFORM_ALL_CAPS=1 CONFORM_SIGNED=${CONFORM_SIGNED:-1}
  case "$SUITE" in
    gvisor) export CONFORM_GPU=${CONFORM_GPU:-1} CONFORM_WARM=${CONFORM_WARM:-2} ;;
    proc | runc) export CONFORM_GPU=${CONFORM_GPU:-1} ;;
    hyperlight) [ -n "${CONFORM_HL_HELPER:-}" ] || export CONFORM_GPU=${CONFORM_GPU:-1} ;;
  esac
else
  echo "measuring $SUITE over tests/integration/$SUITE"
  go test -c -tags integration -o "$OUT/$SUITE.test" "./tests/integration/$SUITE"
fi

# cgclean kills and removes what earlier runs left under the test cgroup
# root, and under the subtrees the conformance stub gives its peer and
# layout homes, so each run starts from the same state.
cgclean() {
  local root d
  for root in "$CG" "$CG-peer" "$CG-layout"; do
    [ -d "$root" ] || continue
    for d in "$root"/*/; do
      [ -d "$d" ] || continue
      echo 1 >"$d/cgroup.kill" 2>/dev/null || true
    done
  done
  # A home the conformance restart check started is no child of the
  # stub, so the stub's stop may return before it is gone.
  pkill -f bin/fiberd-testhooks 2>/dev/null || true
  sleep 0.5
  for root in "$CG" "$CG-peer" "$CG-layout"; do
    [ -d "$root" ] || continue
    find "$root" -mindepth 1 -depth -type d -exec rmdir {} \; 2>/dev/null || true
  done
}

# run <label> [<cap>...] runs the suite under exactly these capabilities,
# or under all of them when the label is full. It writes the names of the
# tests and subtests that passed to $OUT/<label>.pass. In conformance mode
# the stub starts fiberd under the same setpriv, through
# CONFORM_FIBERD_WRAP, and the checks themselves run unrestricted.
run() {
  local label=$1 set=-all c; shift
  for c in "$@"; do set+=",+$c"; done
  local wrap=(setpriv --bounding-set "$set" --inh-caps -all --)
  [ "$label" = full ] && wrap=()
  cgclean
  if [ "$CONFORM" = 1 ]; then
    CONFORM_RUNTIME=$SUITE CONFORM_FIBERD_WRAP="${wrap[*]+"${wrap[*]}"}" \
      hack/conform/stub.sh run -test.run "$RUN" -test.timeout 20m >"$OUT/$label.log" 2>&1 || true
    # The homes' own logs say why a check failed, and the next run
    # deletes them.
    local f
    for f in "$STATE/fiberd.log" "$STATE-peer.log" "$STATE-layout.log"; do
      if [ -f "$f" ]; then cp "$f" "$OUT/$label.$(basename "$f")"; fi
    done
  else
    (cd "tests/integration/$SUITE" && ${wrap[@]+"${wrap[@]}"} \
      "$OUT/$SUITE.test" -test.v -test.count=1 -test.timeout 15m -test.run "$RUN") >"$OUT/$label.log" 2>&1 || true
  fi
  grep -oP '^\s*--- PASS: \K\S+' "$OUT/$label.log" | sort >"$OUT/$label.pass" || true
}

lost() { comm -23 "$OUT/baseline.pass" "$OUT/$1.pass" | paste -sd' '; }

run full
n=$(wc -l <"$OUT/full.pass")
[ "$n" -gt 0 ] || { echo "full: no test passed; see $OUT/full.log"; exit 1; }
echo "full: $n tests pass with every capability"
run baseline "${cand[@]}"
# No test passing at all is the suite not running, not a capability.
[ -s "$OUT/baseline.pass" ] || { echo "baseline: no test passed; see $OUT/baseline.log"; exit 1; }
l=$(comm -23 "$OUT/full.pass" "$OUT/baseline.pass" | paste -sd' ')
if [ -n "$l" ]; then
  echo "baseline: the ${#cand[@]} candidates are missing a capability; lost: $l (see $OUT/baseline.log)"
  exit 1
fi
echo "baseline: the same $n tests pass with ${#cand[@]} capabilities"

needed=()
for drop in "${cand[@]}"; do
  rest=()
  for keep in "${cand[@]}"; do [ "$keep" = "$drop" ] || rest+=("$keep"); done
  run "without-$drop" "${rest[@]}"
  l=$(lost "without-$drop")
  if [ -n "$l" ]; then
    needed+=("$drop")
    printf '  %-20s needed: %s\n' "$drop" "$l"
  else
    printf '  %-20s not needed\n' "$drop"
  fi
done

run minimal "${needed[@]}"
l=$(lost minimal)
echo "minimal set: $(IFS=,; echo "${needed[*]}")"
if [ -n "$l" ]; then
  echo "  NOT enough on its own; lost: $l (capabilities standing in for each other; see $OUT/minimal.log)"
  exit 1
fi
echo "  enough: every baseline test passes"
