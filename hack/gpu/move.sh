#!/usr/bin/env bash
# The GPU PoC's hardware runs (docs/proposals/gpu-poc.md, "The hardware
# runs"), driven from the Mac over ssh. VM A has an A100 split into two MIG
# instances. VM B has another GPU model.
#
#   GPU_A=vm-a GPU_B=vm-b hack/gpu/move.sh <phase>
#
#   facts    runs hack/gpu/facts.sh on both VMs, saves both and diffs them
#   control  the local move on VM A, between its two MIG homes
#   cpu      a GPU-free proc move, VM A to VM B and back, through the registry
#   park     parks the GPU session on VM A and publishes it
#   resume   resumes it on VM B and checks the slice
#   all      the five above in order, stopping at the first failure
#
# Settings, all from the environment.
#   GPU_A, GPU_B     ssh aliases of the two VMs (required)
#   REPO_A, REPO_B   the fiberd checkout on each VM, relative to its home
#                    (default fiberd, that is ~/fiberd)
#   REGISTRY_ADDR    IP:PORT of the delta registry. Default: ask VM A's
#                    hack/gpu/registry.sh addr. 127.0.0.1:5055 for the Mac
#                    fallback (hack/gpu/registry.sh mac)
#   MOVE_SESSION     the session park and resume share (default gpu-move)
#   MOVE_LOGS        where the logs go (default bin/gpu-move/logs on the Mac)
#   MOVE_DOCKER_ARGS more docker run flags for the dev container
#   FIBERD_GPU_MOVE_DEVICES_A1, _A2, _B   the device each home's engine
#                    drives. Default: the first two MIG UUIDs that
#                    nvidia-smi -L lists on VM A, and the first GPU UUID
#                    on VM B
#
# Each phase runs in the dev container (hack/dev/run.sh) on the VM's host
# network, so the registry has one address on both VMs and in every
# container. The GPU phases add --gpus all.
#
# The issuer key, the delta key and the seal key are generated once on VM
# A, in ~/.fiberd-gpu-move/keys, outside the repo. They are copied to the
# same place on VM B through an ssh pipe, never through a file or a log on
# the Mac. The dev container mounts them at /keys. Remove that directory on
# VM A for a fresh set.
#
# Both VMs must have the same commit checked out. Each VM runs its own copy
# of this script for the steps inside the container (the in-* commands).
set -euo pipefail
cd "$(dirname "$0")/../.."

GPU_A=${GPU_A:-}
GPU_B=${GPU_B:-}
REPO_A=${REPO_A:-fiberd}
REPO_B=${REPO_B:-fiberd}
# A leading ~/ means the remote home, where ssh starts anyway.
REPO_A=${REPO_A#\~/}
REPO_B=${REPO_B#\~/}
SESSION=${MOVE_SESSION:-gpu-move}
LOG_ROOT=${MOVE_LOGS:-$PWD/bin/gpu-move/logs}
STAMP=$(date +%Y%m%d-%H%M%S)
KEYS_REL=.fiberd-gpu-move/keys
ENGINE=/src/bin/refengine
GPU_DOCKER_ARGS="--gpus all -e NVIDIA_DRIVER_CAPABILITIES=compute,utility"

# Set as the phases run.
PHASE_DIR=""
REG=""
HOME_A=""
HOME_B=""
A1=""
A2=""
B1=""

die() { echo "move.sh: $*" >&2; exit 1; }

usage() {
  # The working directory is the repo root by now.
  sed -n '2,/^set -euo/p' hack/gpu/move.sh | sed '$d' | sed 's/^# \{0,1\}//'
}

# ---- Talking to the VMs, from the Mac.

host_of() { if [ "$1" = A ]; then printf %s "$GPU_A"; else printf %s "$GPU_B"; fi; }
repo_of() { if [ "$1" = A ]; then printf %s "$REPO_A"; else printf %s "$REPO_B"; fi; }
home_of() { if [ "$1" = A ]; then printf %s "$HOME_A"; else printf %s "$HOME_B"; fi; }

# rsh <side> <snippet> runs a shell snippet on a VM, in its checkout. The
# snippet is expanded by the remote shell. stdin is not forwarded.
rsh() {
  local side=$1
  ssh -n -o BatchMode=yes "$(host_of "$side")" "cd $(printf %q "$(repo_of "$side")") && $2"
}

# rcmd <side> <cmd> [args...] runs one command on a VM, each argument
# quoted for the remote shell.
rcmd() {
  local side=$1
  shift
  rsh "$side" "$(printf '%q ' "$@")"
}

# devrun <side> <docker args> <cmd> [args...] runs a command in the dev
# container on a VM, on the host network, with the keys at /keys.
devrun() {
  local side=$1 extra=$2 dargs
  shift 2
  dargs="--network host -v $(home_of "$side")/$KEYS_REL:/keys:ro $extra ${MOVE_DOCKER_ARGS:-}"
  rcmd "$side" env "FIBERD_DEV_DOCKER_ARGS=$dargs" hack/dev/run.sh "$@"
}

# reach <side> checks ssh and the checkout, and learns the VM's home.
reach() {
  local side=$1 host home commit
  host=$(host_of "$side")
  [ -n "$host" ] || die "set GPU_$side to the ssh alias of VM $side"
  home=$(rsh "$side" 'test -f hack/gpu/move.sh && printf %s "$HOME"') ||
    die "$host: ssh failed, or there is no fiberd checkout at ~/$(repo_of "$side") (set REPO_$side)"
  [ -n "$home" ] || die "$host: no home directory"
  if [ "$side" = A ]; then HOME_A=$home; else HOME_B=$home; fi
  commit=$(rsh "$side" 'git rev-parse --short HEAD 2>/dev/null || echo unknown')
  echo "VM $side is $host, checkout ~/$(repo_of "$side") at $commit"
}

# same_commit fails when the two VMs have different commits checked out.
same_commit() {
  local a b m
  a=$(rsh A 'git rev-parse HEAD 2>/dev/null || true')
  b=$(rsh B 'git rev-parse HEAD 2>/dev/null || true')
  if [ -n "$a" ] && [ -n "$b" ] && [ "$a" != "$b" ]; then
    die "VM A is at $a and VM B at $b. Check out the same commit on both"
  fi
  m=$(git rev-parse HEAD 2>/dev/null || true)
  if [ -n "$m" ] && [ -n "$a" ] && [ "$m" != "$a" ]; then
    echo "note: the Mac is at $m and the VMs at $a. The VMs run their own copy of this script."
  fi
}

# docker_ok <side> fails when the VM has the fiberd-net network, which
# hack/dev/run.sh joins and which clashes with --network host.
docker_ok() {
  if rsh "$1" 'docker network inspect fiberd-net >/dev/null 2>&1'; then
    die "VM $1 has the docker network fiberd-net, which hack/dev/run.sh would join beside --network host. On VM $1 run: make registry-stop && docker network rm fiberd-net"
  fi
}

# registry finds the registry's address and checks each named VM reaches it.
registry() {
  REG=${REGISTRY_ADDR:-}
  if [ -z "$REG" ]; then
    REG=$(rsh A 'hack/gpu/registry.sh addr 2>/dev/null' || true)
  fi
  [ -n "$REG" ] || die "no registry. Run hack/gpu/registry.sh up on VM A, or set REGISTRY_ADDR"
  local side
  for side in "$@"; do
    rcmd "$side" curl -sf -m 5 -o /dev/null "http://$REG/v2/" ||
      die "VM $side cannot reach the registry at http://$REG/v2/. Allow the port between the VMs, or use hack/gpu/registry.sh mac"
  done
  echo "registry $REG, reached from VM $*"
}

# keys_a makes the shared keys on VM A, once. Only key ids are printed.
keys_a() {
  rcmd A mkdir -p -m 700 "$HOME_A/$KEYS_REL"
  rcmd A env "FIBERD_DEV_DOCKER_ARGS=-v $HOME_A/$KEYS_REL:/keys" hack/dev/run.sh bash hack/gpu/move.sh in-keygen
}

# keys_b copies VM A's keys to VM B. The bytes go from one ssh to the
# other through a pipe, and nothing of them reaches the log.
keys_b() {
  rcmd A tar -C "$HOME_A/$KEYS_REL" -cf - . |
    ssh -o BatchMode=yes "$GPU_B" "$(printf '%q ' sh -c 'umask 077 && mkdir -p "$1" && tar -C "$1" -xf -' sh "$HOME_B/$KEYS_REL")"
  echo "keys copied from VM A to VM B, ~/$KEYS_REL"
}

# devices_a picks the MIG UUIDs of VM A's two homes.
devices_a() {
  A1=${FIBERD_GPU_MOVE_DEVICES_A1:-}
  A2=${FIBERD_GPU_MOVE_DEVICES_A2:-}
  if [ -z "$A1" ] || [ -z "$A2" ]; then
    local migs
    migs=$(rsh A 'nvidia-smi -L 2>/dev/null || true' | sed -n 's/.*(UUID: \(MIG-[^)]*\)).*/\1/p') || migs=""
    [ -n "$A1" ] || A1=$(printf '%s\n' "$migs" | sed -n 1p)
    [ -n "$A2" ] || A2=$(printf '%s\n' "$migs" | sed -n 2p)
  fi
  if [ -z "$A1" ] || [ -z "$A2" ]; then
    die "VM A needs two MIG instances. nvidia-smi -L lists fewer. Set FIBERD_GPU_MOVE_DEVICES_A1 and _A2"
  fi
  [ "$A1" != "$A2" ] || die "A1 and A2 are the same device, $A1"
  echo "VM A homes: A1 on $A1, A2 on $A2"
}

# device_b picks the GPU UUID of VM B's home.
device_b() {
  B1=${FIBERD_GPU_MOVE_DEVICES_B:-}
  if [ -z "$B1" ]; then
    B1=$(rsh B 'nvidia-smi -L 2>/dev/null || true' |
      sed -n 's/^GPU [0-9]*: .*(UUID: \(GPU-[^)]*\)).*/\1/p' | sed -n 1p) || B1=""
  fi
  [ -n "$B1" ] || die "VM B lists no GPU in nvidia-smi -L. Set FIBERD_GPU_MOVE_DEVICES_B"
  echo "VM B home: B on $B1"
}

# gotest <side> <mode> [VAR=value...] runs TestMoveAcrossGPUs on a VM, in
# the dev container with --gpus all.
gotest() {
  local side=$1 mode=$2
  shift 2
  devrun "$side" "$GPU_DOCKER_ARGS" env \
    FIBERD_GPU_MOVE="$mode" \
    FIBERD_GPU_MOVE_REGISTRY="$REG" \
    FIBERD_GPU_MOVE_KEYS=/keys \
    FIBERD_GPU_MOVE_SESSION="$SESSION" \
    FIBERD_GPU_ENGINE="$ENGINE" \
    "$@" bash hack/gpu/move.sh in-test
}

# ---- The phases. Each runs in a subshell under set -e, its output teed.

phase_facts() {
  reach A
  reach B
  local side f rc
  for side in A B; do
    f=$PHASE_DIR/facts-vm-$(printf %s "$side" | tr AB ab).txt
    rc=0
    rcmd "$side" bash hack/gpu/facts.sh >"$f" || rc=$?
    [ "$rc" -ne 255 ] || die "ssh to VM $side failed"
    [ "$rc" -eq 0 ] || echo "note: facts.sh on VM $side exited $rc. Kept what it printed."
    echo "VM $side facts: $f, $(wc -l <"$f" | tr -d ' ') lines"
  done
  rc=0
  diff -u "$PHASE_DIR/facts-vm-a.txt" "$PHASE_DIR/facts-vm-b.txt" >"$PHASE_DIR/facts.diff" || rc=$?
  case $rc in
    0) echo "The two VMs agree on every fact." ;;
    1)
      echo "Facts that differ, - for VM A and + for VM B. Full diff: $PHASE_DIR/facts.diff"
      grep '^[-+][^-+]' "$PHASE_DIR/facts.diff" || true
      ;;
    *) die "diff failed" ;;
  esac
}

# The A1 to A2 move on VM A. Same GPU model, two MIG UUIDs, so a failure
# points at the move and not at the GPU.
phase_control() {
  reach A
  docker_ok A
  registry A
  devices_a
  keys_a
  gotest A local FIBERD_GPU_MOVE_DEVICES_A1="$A1" FIBERD_GPU_MOVE_DEVICES_A2="$A2"
}

# The GPU-free proc move, A to B and back. It uses only the shipped
# binaries (fiberd, grant-issuer, zygotectl, fibctl) as hack/test/mobility.sh
# does, but with one fiberd per VM and one step per container run. So a
# failure here is CRIU or the CPUs, never the GPU or the new move test.
# Each VM runs its own grant-issuer with the shared issuer key, under the
# same issuer URL, so a grant minted on either VM verifies on both.
phase_cpu() {
  reach A
  reach B
  same_commit
  docker_ok A
  docker_ok B
  registry A B
  keys_a
  keys_b
  local s=cpu-$STAMP digest
  echo "session $s. VM A creates and parks it, VM B resumes and parks it, VM A resumes it."
  cpustep A first home-a "$s" "" | tee "$PHASE_DIR/cpu-1-vm-a.out"
  digest=$(sed -n 's/^template //p' "$PHASE_DIR/cpu-1-vm-a.out" | sed -n '$p')
  [ -n "$digest" ] || die "VM A printed no template digest"
  cpustep B middle home-b "$s" "$digest" | tee "$PHASE_DIR/cpu-2-vm-b.out"
  cpustep A last home-a "$s" "$digest" | tee "$PHASE_DIR/cpu-3-vm-a.out"
}

# cpustep <side> <step> <home> <session> <digest> runs one step of the cpu
# phase in the dev container on a VM. No GPU.
cpustep() {
  devrun "$1" "" bash hack/gpu/move.sh in-cpu "$2" "$3" "$REG" "$4" "$5"
}

# Park on VM A's first MIG home, and publish.
phase_park() {
  reach A
  reach B
  same_commit
  docker_ok A
  registry A B
  devices_a
  keys_a
  keys_b
  echo "session $SESSION parks on VM A, A1 on $A1"
  gotest A park FIBERD_GPU_MOVE_DEVICES_A1="$A1"
}

# Resume on VM B's GPU, and check the slice.
phase_resume() {
  reach A
  reach B
  same_commit
  docker_ok B
  registry B
  device_b
  keys_b
  echo "session $SESSION resumes on VM B, on $B1"
  gotest B resume FIBERD_GPU_MOVE_DEVICES_B="$B1"
}

# ---- Inside the dev container, on a VM. move.sh calls these itself.

in_container() {
  [ "$PWD" = /src ] || die "the in-* commands run inside the dev container, started by move.sh"
}

# in_keygen writes the three shared keys to /keys, each only when missing,
# as hack/test/mobility.sh makes them. keygen prints key ids, never keys.
in_keygen() {
  in_container
  local d=/keys
  go build -o bin/ ./cmd/grant-issuer
  [ -s "$d/issuer-key.json" ] || bin/grant-issuer keygen -alg EdDSA -out "$d/issuer-key.json"
  [ -s "$d/delta-key.json" ] || bin/grant-issuer keygen -alg EdDSA -out "$d/delta-key.json"
  # The seal key's keygen writes the fleet's public wrap key beside it.
  if [ ! -s "$d/delta-seal-key.json" ] || [ ! -s "$d/fleet-pub.json" ]; then
    bin/grant-issuer keygen -alg A256GCM -out "$d/delta-seal-key.json"
  fi
  # Back to the VM's user, who copies them to VM B.
  chown -R "$(stat -c %u:%g "$d")" "$d"
  echo "shared keys on VM A: $(cd "$d" && ls | tr '\n' ' ')"
}

CPU_PIDS=""

cpu_fail() { # <log> <message>
  echo "FAIL: $2"
  echo "--- the last lines of $1"
  tail -40 "$1" 2>/dev/null || true
  exit 1
}

cpu_count() { # <log> <endpoint> <want>
  local got
  got=$(bin/fibctl "$2" get) || got="unreadable"
  echo "counter = $got"
  [ "$got" = "$3" ] || cpu_fail "$1" "counter $got, want $3"
}

json_str() { python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$1" 2>/dev/null || printf '"%s"' "$1"; }

json_field() { # <name> <json>
  printf '%s' "$2" | sed -n "s/.*\"$1\": *\"\([^\"]*\)\".*/\1/p" | sed -n 1p
}

# in_cpu <first|middle|last> <home> <registry> <session> [digest] is one
# step of the cpu phase. first builds and pushes the template, creates the
# session, counts to 3 and parks. middle resumes at 3, counts to 4 and
# parks. last resumes at 4. Every step starts a fresh fiberd that exits with
# the step, so only the registry carries the session between VMs.
in_cpu() {
  in_container
  local step=${1:?step} home=${2:?home} reg=${3:?registry} session=${4:?session} digest=${5:-}
  local keys=/keys state=/var/lib/fiberd/gpu-move-cpu
  local iss_addr=127.0.0.1:18786 grpc=18784 http=18785
  local iss_url=http://$iss_addr log=$state/$home.log
  rm -rf "$state"
  mkdir -p "$state"
  curl -sf -m 5 -o /dev/null "http://$reg/v2/" || die "registry $reg not reachable from the dev container"
  go build -o bin/ ./cmd/fiberd ./cmd/grant-issuer ./cmd/zygotectl ./hack/fibctl
  if [ "$step" = first ]; then
    make -s zygote
    bin/zygotectl build -zygote bin/refzygote -args "--heap-mb 32" -seal-to "$keys/fleet-pub.json" -out "$state/art" >/dev/null
    digest=$(bin/zygotectl push -dir "$state/art" -ref "http://$reg/zygotes/ref:gpu-move-cpu")
  fi
  [ -n "$digest" ] || die "no template digest"
  echo "template $digest"

  bin/grant-issuer serve -key "$keys/issuer-key.json" -addr "$iss_addr" -issuer "$iss_url" >"$state/issuer.log" 2>&1 &
  CPU_PIDS=$!
  trap 'kill $CPU_PIDS 2>/dev/null; wait $CPU_PIDS 2>/dev/null || true' EXIT
  # One state path on both VMs. A proc restore reopens the template where
  # the parking home cached it, and parity refuses another cache path.
  bin/fiberd -state "$state/home" -node-id "$home" -verifier jwks -issuer "$iss_url" -jwks-max-stale 10m \
    -insecure-plaintext -listen "127.0.0.1:$grpc" -http "127.0.0.1:$http" -runtime proc \
    -registry "http://$reg/zygotes/ref" -delta-registry "http://$reg/deltas" \
    -delta-key "$keys/delta-key.json" -delta-seal-key "$keys/delta-seal-key.json" >"$log" 2>&1 &
  CPU_PIDS="$CPU_PIDS $!"
  local up=no
  for _ in $(seq 1 100); do
    if curl -sf "http://127.0.0.1:$http/healthz" >/dev/null 2>&1; then
      up=yes
      break
    fi
    sleep 0.1
  done
  [ "$up" = yes ] || cpu_fail "$log" "$home did not become healthy"

  # The grant stays in this shell. It is never printed.
  local tok resp ep fid kind
  tok=$(bin/grant-issuer mint -key "$keys/issuer-key.json" -issuer "$iss_url" -aud "$home" -uid gpu-move-cpu \
    -tenant acme -template "$digest" -max 4 -w-budget 64Mi -min-tier FIBER_CHECKPOINT -isolation TRUSTED -ttl 1h)
  resp=$(curl -s -X POST "http://127.0.0.1:$http/v1/clone" \
    -d "{\"grantJwt\":$(json_str "$tok"),\"session\":$(json_str "$session")}") || resp=""
  ep=$(json_field endpoint "$resp")
  fid=$(json_field fiberId "$resp")
  kind=$(json_field kind "$resp")
  kind=${kind:-CREATE} # the enum's zero is left out of the JSON
  echo "$home: clone $kind, fiber $fid"
  [ -n "$ep" ] || cpu_fail "$log" "no endpoint. Clone response: $resp"
  case $step in
    first)
      [ "$kind" = CREATE ] || cpu_fail "$log" "expected CREATE on $home, got $kind"
      for _ in 1 2 3; do bin/fibctl "$ep" incr >/dev/null; done
      bin/fibctl "$ep" dirty 1048576 >/dev/null
      cpu_count "$log" "$ep" 3
      ;;
    middle)
      [ "$kind" = RESUME ] || cpu_fail "$log" "expected RESUME on $home, got $kind. A refused or failed restore on this CPU shows here"
      cpu_count "$log" "$ep" 3
      bin/fibctl "$ep" incr >/dev/null
      cpu_count "$log" "$ep" 4
      ;;
    last)
      [ "$kind" = RESUME ] || cpu_fail "$log" "expected RESUME on $home, got $kind. A refused or failed restore on this CPU shows here"
      cpu_count "$log" "$ep" 4
      ;;
    *) die "unknown cpu step $step" ;;
  esac
  if [ "$step" != last ]; then
    resp=$(curl -s -X POST "http://127.0.0.1:$http/v1/park" -d "{\"fiberId\":$(json_str "$fid"),\"sync\":true}") || resp=""
    # A park can answer and still fail, so the log decides.
    if grep -qE 'park.*failed' "$log" || ! grep -q 'host: published' "$log"; then
      cpu_fail "$log" "$home did not publish the session. Park response: $resp"
    fi
  fi
  echo "--- $home deltas"
  grep -hE 'host: (parked|published|claimed)' "$log" || true
  echo "PASS: cpu step $step on $home"
}

# in_test runs TestMoveAcrossGPUs with the FIBERD_GPU_* variables move.sh
# passed. None of them holds a secret, so they are printed for the log.
in_test() {
  in_container
  local v
  for v in FIBERD_GPU_MOVE FIBERD_GPU_MOVE_REGISTRY FIBERD_GPU_MOVE_KEYS FIBERD_GPU_MOVE_SESSION \
    FIBERD_GPU_MOVE_DEVICES_A1 FIBERD_GPU_MOVE_DEVICES_A2 FIBERD_GPU_MOVE_DEVICES_B FIBERD_GPU_ENGINE; do
    echo "$v=${!v:-}"
  done
  nvidia-smi -L 2>&1 || echo "nvidia-smi is not available in the container"
  make -s engine
  [ -x "${FIBERD_GPU_ENGINE:?}" ] || die "no engine at $FIBERD_GPU_ENGINE after make engine"
  exec go test -tags 'linux integration gpu' -count=1 -timeout 30m -v -run TestMoveAcrossGPUs ./tests/integration/gpu/
}

# ---- Main.

# run_phase <phase> runs one phase, tees it to its own log and says where.
run_phase() {
  local phase=$1 rc
  PHASE_DIR=$LOG_ROOT/$STAMP-$phase
  mkdir -p "$PHASE_DIR"
  echo "== $phase. Log: $PHASE_DIR/$phase.log"
  set +e
  (
    set -e
    case $phase in
      facts) phase_facts ;;
      control) phase_control ;;
      cpu) phase_cpu ;;
      park) phase_park ;;
      resume) phase_resume ;;
    esac
  ) 2>&1 | tee "$PHASE_DIR/$phase.log"
  rc=${PIPESTATUS[0]}
  set -e
  if [ "$rc" -ne 0 ]; then
    echo "== $phase FAILED (exit $rc). Log: $PHASE_DIR/$phase.log" >&2
    return "$rc"
  fi
  echo "== $phase passed. Log: $PHASE_DIR/$phase.log"
}

case ${1:-} in
  facts | control | cpu | park | resume) run_phase "$1" ;;
  all)
    for p in facts control cpu park resume; do run_phase "$p"; done
    echo "== all phases passed. Logs: $LOG_ROOT/$STAMP-*"
    ;;
  in-keygen) in_keygen ;;
  in-cpu)
    shift
    in_cpu "$@"
    ;;
  in-test) in_test ;;
  *)
    usage >&2
    exit 2
    ;;
esac
