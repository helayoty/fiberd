#!/usr/bin/env bash
# Measure which capabilities the proc runtime needs. Run it as root inside
# the dev container.
#
#   hack/dev/run.sh hack/test/caps.sh
#
# The tests/proc suite runs several times. First with every capability, as
# the reference. Then with every candidate in the bounding set, as the
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
# CAP_SYS_PTRACE there and the run misses that it is needed.
#
#   CAPS="chown,kill,..."  candidates (default below)
#   RUN="TestX|TestY"      only these tests (-test.run)
#   CAPS_OUT=dir           logs (default bin/caps, kept after the container)
#
# run.sh does not pass the environment through, so set it with env.
#   hack/dev/run.sh env CAPS=... hack/test/caps.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

CAPS=${CAPS:-chown,dac_override,dac_read_search,fowner,fsetid,kill,setgid,setuid,setpcap,net_bind_service,net_raw,net_admin,sys_chroot,sys_ptrace,sys_admin,sys_resource,sys_nice,sys_time,mknod,audit_write,ipc_lock,checkpoint_restore}
RUN=${RUN:-.}
OUT=$(realpath -m "${CAPS_OUT:-bin/caps}")
CG=${FIBERD_CGROUP_ROOT:-/sys/fs/cgroup/fiberd}
rm -rf "$OUT"; mkdir -p "$OUT"

known=$(setpriv --list-caps)
IFS=, read -ra cand <<<"$CAPS"
for c in "${cand[@]}"; do
  grep -qx "$c" <<<"$known" || { echo "setpriv does not know $c; drop it from CAPS"; exit 1; }
done

go test -c -o "$OUT/proc.test" ./tests/proc

# cgclean kills and removes what earlier runs left under the test cgroup
# root, so each run starts from the same state.
cgclean() {
  local d
  for d in "$CG"/t*/; do
    [ -d "$d" ] || continue
    echo 1 >"$d/cgroup.kill" 2>/dev/null || true
  done
  sleep 0.5
  find "$CG" -mindepth 1 -depth -type d -name '*' -exec rmdir {} \; 2>/dev/null || true
}

# run <label> [<cap>...] runs the suite under exactly these capabilities,
# or under all of them when the label is full. It writes the names of the
# top-level tests that passed to $OUT/<label>.pass.
run() {
  local label=$1 set=-all c; shift
  for c in "$@"; do set+=",+$c"; done
  local wrap=(setpriv --bounding-set "$set" --inh-caps -all --)
  [ "$label" = full ] && wrap=()
  cgclean
  (cd tests/proc && "${wrap[@]}" \
    "$OUT/proc.test" -test.v -test.count=1 -test.timeout 15m -test.run "$RUN") >"$OUT/$label.log" 2>&1 || true
  grep -oP '^--- PASS: \K\S+' "$OUT/$label.log" | sort >"$OUT/$label.pass" || true
}

lost() { comm -23 "$OUT/baseline.pass" "$OUT/$1.pass" | paste -sd' '; }

run full
n=$(wc -l <"$OUT/full.pass")
[ "$n" -gt 0 ] || { echo "full: no test passed; see $OUT/full.log"; exit 1; }
echo "full: $n tests pass with every capability"
run baseline "${cand[@]}"
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
