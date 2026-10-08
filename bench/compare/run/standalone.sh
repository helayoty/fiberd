#!/usr/bin/env bash
# The standalone homes, inside the Linux dev container (hack/dev/run.sh):
# fiberd with the counter as its template on one backend at a time over
# loopback, no Kubernetes, the mechanism baselines of phase 2 and the
# Hyperlight row of phase 4. hack/conform/stub.sh is where the start
# sequence comes from.
#
#   standalone.sh proc runc gvisor         (phase 2)
#   standalone.sh hyperlight               (phase 4, with /dev/kvm and bin/hyperlight-helper)
#
# proc takes the counter from a -template path. The runc and gVisor
# homes pull it as a zygote artifact from the registry (make
# registry-start; fiberd-registry:5000 inside the container,
# FIBERD_REGISTRY overrides), the way a production home gets its
# templates, so the sandbox rootfs holds no workload.
set -euo pipefail
cd "$(dirname "$0")/../../.."
OUT=${COMPARE_OUT:-/src/bin/compare-state/phase2}
RUNS=${COMPARE_RUNS:-3}
BURSTS=${COMPARE_BURSTS:-1,10,50}
DENSITY=${COMPARE_DENSITY:-20}
ADDR=127.0.0.1:18484
ISSUER_ADDR=127.0.0.1:18686
ISSUER_URL="http://$ISSUER_ADDR"
STATE=/tmp/compare-home       # tmpfs: bin/ on macOS is too slow for sockets
ROOTFS=/tmp/compare-rootfs
CGROOT=${FIBERD_CGROUP_ROOT:-/sys/fs/cgroup/fiberd}
REG=${FIBERD_REGISTRY:-fiberd-registry:5000}
mkdir -p "$OUT" bin

build() {
  # The counters and the clients come from docker/compare/Dockerfile,
  # exported by phase2.sh before it enters the container.
  install -m 0755 bin/compare-bin/counter bin/compare-bin/counter-static bin/compare-bin/compare bin/compare-bin/summarize bin/
  go build -o bin/ ./cmd/fiberd ./cmd/grant-issuer ./cmd/zygotectl
}

# rootfs builds the sandbox root filesystem the runc and gVisor homes
# run their containers and sandboxes in. It holds no workload.
rootfs() {
  [ -d "$ROOTFS/bin" ] && return
  hack/gvisor/rootfs.sh "$ROOTFS" >/dev/null
}

# push_counter packs the static counter as a zygote artifact (no CRIU
# images: the backend checkpoints the warm template itself) with the
# given arguments and pushes it to the registry under tag. It prints the
# digest the grant names.
push_counter() { # push_counter <tag> <args>
  curl -sf "http://$REG/v2/" >/dev/null || { echo "registry $REG not reachable: make registry-start" >&2; exit 1; }
  bin/zygotectl build -zygote bin/counter-static -args "$2" -skip-images -out "$STATE/counter-art-$1" >/dev/null
  bin/zygotectl push -dir "$STATE/counter-art-$1" -ref "$REG/zygotes/counter:$1" -plain-http
}

issuer_pid=""
start_issuer() {
  mkdir -p "$STATE"
  [ -f "$STATE/issuer-key.json" ] || bin/grant-issuer keygen -alg EdDSA -out "$STATE/issuer-key.json" >/dev/null
  bin/grant-issuer serve -key "$STATE/issuer-key.json" -addr "$ISSUER_ADDR" -issuer "$ISSUER_URL" >>"$STATE/issuer.log" 2>&1 &
  issuer_pid=$!
  for _ in $(seq 1 50); do curl -sf "$ISSUER_URL/openid/v1/jwks" >/dev/null 2>&1 && return; sleep 0.1; done
  echo "issuer did not come up" >&2; exit 1
}

home_pid=""
start_home() { # start_home <runtime> <flags...>
  local rt=$1; shift
  rm -rf "$STATE/$rt" /tmp/fz-compare; mkdir -p "$STATE/$rt" /tmp/fz-compare
  bin/fiberd -state "$STATE/$rt" -node-id "compare-$rt" -verifier jwks -issuer "$ISSUER_URL" -jwks-max-stale 10m \
    -insecure-plaintext -listen "$ADDR" -runtime "$rt" -run-dir /tmp/fz-compare -cgroup-root "$CGROOT" \
    -status-interval 100ms "$@" >>"$STATE/$rt/fiberd.log" 2>&1 &
  home_pid=$!
  for _ in $(seq 1 100); do
    curl -sf --unix-socket "$STATE/$rt/private/admin.sock" http://x/healthz >/dev/null 2>&1 && return
    sleep 0.1
  done
  echo "fiberd ($rt) did not become healthy:" >&2; tail -20 "$STATE/$rt/fiberd.log" >&2; exit 1
}
stop_home() { [ -n "$home_pid" ] && { kill "$home_pid" 2>/dev/null || true; wait "$home_pid" 2>/dev/null || true; }; home_pid=""; }
trap 'stop_home; [ -n "$issuer_pid" ] && kill "$issuer_pid" 2>/dev/null || true' EXIT

measure() { # measure <system> <class> <runtime> <args...>
  local system=$1 class=$2 rt=$3; shift 3
  echo "== $system"
  bin/compare -adapter fiberd -system "$system" -class "$class" -runs "$RUNS" -bursts "$BURSTS" -out "$OUT/$system.jsonl" \
    -target "$ADDR" -node-id "compare-$rt" -issuer-key "$STATE/issuer-key.json" -issuer "$ISSUER_URL" \
    -cgroup-root "$CGROOT" -resume -density "$DENSITY" "$@"
}

build
start_issuer
for rt in "$@"; do
  case "$rt" in
    proc)
      start_home proc -template "default=$PWD/bin/counter --heap-mb 32" -template "sha256:line=$PWD/bin/counter --heap-mb 32 --framing line"
      measure fiberd-proc shared-kernel proc
      measure fiberd-proc-line shared-kernel proc -template sha256:line -framing line
      stop_home ;;
    runc)
      rootfs
      template=$(push_counter runc "--heap-mb 32")
      start_home runc -runc-rootfs "$ROOTFS" -registry "$REG/zygotes/counter" -registry-plain-http
      measure fiberd-runc shared-kernel runc -template "$template"
      stop_home ;;
    gvisor)
      rootfs
      template=$(push_counter gvisor "--heap-mb 32 --gvisor")
      start_home gvisor -gvisor-rootfs "$ROOTFS" -registry "$REG/zygotes/counter" -registry-plain-http
      measure fiberd-gvisor sandboxed gvisor -isolation UNTRUSTED -template "$template"
      stop_home ;;
    hyperlight)
      [ -x bin/hyperlight-helper ] || { echo "bin/hyperlight-helper missing: make hyperlight-helper" >&2; exit 1; }
      start_home hyperlight -hyperlight-helper "$PWD/bin/hyperlight-helper" -hyperlight-guest "$PWD/bin/hyperlight-guest" \
        -template "default=guest --heap-mb 32"
      measure fiberd-hyperlight microvm hyperlight -isolation UNTRUSTED -framing line
      stop_home ;;
    *) echo "unknown runtime $rt" >&2; exit 2 ;;
  esac
done
bin/summarize "$OUT"/*.jsonl | tee "$OUT/summary.txt"
