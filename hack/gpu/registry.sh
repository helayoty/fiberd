#!/usr/bin/env bash
# The delta registry for the GPU PoC's cross-VM move (docs/proposals/gpu-poc.md,
# "The registry"). A registry:2 container on VM A's private IP, which VM B
# reaches over the virtual network. hack/gpu/move.sh points both VMs at it.
#
#   hack/gpu/registry.sh up [IP[:PORT]]     on VM A. Starts it, bound to that address
#   hack/gpu/registry.sh down               removes it
#   hack/gpu/registry.sh check [IP[:PORT]]  curls /v2/ and prints the address to use
#   hack/gpu/registry.sh addr               prints the address it is bound to
#   hack/gpu/registry.sh mac                prints the Mac fallback, for when VM B
#                                           cannot reach VM A
#
# The address comes from the argument, else REGISTRY_ADDR, else VM A's
# private IP (the source address of its default route). The port defaults
# to REGISTRY_PORT, 5055, apart from make registry-start's 5000. It never
# binds 0.0.0.0. VM B reaches it only when a network rule allows the port.
#
# The image is REGISTRY_IMAGE, registry:2 by default. The repo pins no
# digest for it yet. "up" prints the digest it ran, so the next run can
# pin it with REGISTRY_IMAGE=registry@sha256:....
set -euo pipefail

NAME=fiberd-gpu-registry
PORT=${REGISTRY_PORT:-5055}
IMAGE=${REGISTRY_IMAGE:-registry:2}

die() { echo "registry.sh: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# private_ip prints the source address of the route out, which on an Azure
# VM is its private IP. The lookup sends no packet.
private_ip() {
  local ip=""
  if have ip; then
    ip=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | sed -n 1p) || ip=""
  fi
  if [ -z "$ip" ] && have hostname; then
    ip=$(hostname -I 2>/dev/null | awk '{print $1}') || ip=""
  fi
  printf '%s' "$ip"
}

# bound prints the address the running container publishes, or nothing.
bound() {
  docker port "$NAME" 5000/tcp 2>/dev/null | sed -n 1p || true
}

# want_addr prints IP:PORT from the argument, REGISTRY_ADDR or the private
# IP. It refuses an address every interface would answer on.
want_addr() {
  local a=${1:-${REGISTRY_ADDR:-}} ip port
  if [ -z "$a" ]; then
    a=$(private_ip)
    [ -n "$a" ] || die "cannot find this VM's private IP. Pass it, as in: $0 up 10.0.0.4"
  fi
  case $a in
    *:*) ip=${a%:*} port=${a##*:} ;;
    *) ip=$a port=$PORT ;;
  esac
  case $ip in
    0.0.0.0 | '' | '*' | '[::]' | '::') die "refusing to bind $ip. Give VM A's private IP" ;;
  esac
  [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "$ip is not an IPv4 address"
  [[ $port =~ ^[0-9]+$ ]] || die "$port is not a port"
  printf '%s:%s' "$ip" "$port"
}

ping_v2() { curl -sf -m 5 -o /dev/null "http://$1/v2/"; }

use_line() {
  echo "Both VMs use FIBERD_GPU_MOVE_REGISTRY=$1 (plain HTTP)."
  echo "From the Mac: REGISTRY_ADDR=$1 hack/gpu/move.sh <phase>"
}

up() {
  local addr cur running
  have docker || die "docker is not installed"
  addr=$(want_addr "${1:-}")
  case $addr in 127.*) echo "note: $addr is loopback. VM B cannot reach it, so only the control run on VM A works." ;; esac
  if docker container inspect "$NAME" >/dev/null 2>&1; then
    cur=$(bound)
    running=$(docker container inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null) || running=false
    if [ "$running" != true ] || [ "$cur" != "$addr" ]; then
      die "$NAME exists (running $running, bound to ${cur:-nothing}). Run $0 down first"
    fi
    echo "$NAME is already up at $addr"
  else
    docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull "$IMAGE"
    docker run -d --name "$NAME" -p "$addr:5000" \
      -e REGISTRY_STORAGE_DELETE_ENABLED=true "$IMAGE" >/dev/null
  fi
  for _ in $(seq 1 50); do ping_v2 "$addr" && break; sleep 0.2; done
  ping_v2 "$addr" || die "$NAME started, but http://$addr/v2/ does not answer. See docker logs $NAME"
  local digests
  digests=$(docker image inspect -f '{{join .RepoDigests " "}}' "$IMAGE" 2>/dev/null) || digests=""
  echo "image $IMAGE, digests ${digests:-unknown}"
  case $IMAGE in
    *@sha256:*) ;;
    *) echo "note: the image is not pinned. Pin it next time with REGISTRY_IMAGE=<one of the digests above>." ;;
  esac
  echo "registry up at http://$addr"
  use_line "$addr"
  echo "Check from VM B: curl -sf http://$addr/v2/ && echo ok"
}

down() {
  have docker || die "docker is not installed"
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  echo "$NAME removed"
}

check() {
  local addr=${1:-${REGISTRY_ADDR:-}}
  if [ -z "$addr" ] && have docker; then addr=$(bound); fi
  [ -n "$addr" ] || die "no address. Pass one, set REGISTRY_ADDR, or run $0 up"
  case $addr in *:*) ;; *) addr=$addr:$PORT ;; esac
  ping_v2 "$addr" || die "http://$addr/v2/ does not answer from $(hostname 2>/dev/null || echo this host)"
  echo "registry ok at http://$addr"
  use_line "$addr"
}

addr() {
  local a
  have docker || die "docker is not installed"
  a=$(bound)
  [ -n "$a" ] || die "$NAME is not running. Run $0 up on VM A"
  printf '%s\n' "$a"
}

# mac prints the fallback. A registry on the Mac's loopback, and one
# reverse tunnel per VM, so each VM reaches it at its own 127.0.0.1. The
# dev container sees that address because move.sh runs it on the host
# network. Every delta then crosses the Mac's uplink twice.
mac() {
  local a=${GPU_A:-<vm-a-alias>} b=${GPU_B:-<vm-b-alias>} p=$PORT
  cat <<EOF
# On the Mac, start the registry on loopback.
docker run -d --name $NAME -p 127.0.0.1:$p:5000 -e REGISTRY_STORAGE_DELETE_ENABLED=true $IMAGE

# Forward it to each VM. Leave both running, one per terminal.
ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -R 127.0.0.1:$p:127.0.0.1:$p $a
ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -R 127.0.0.1:$p:127.0.0.1:$p $b

# Check from each VM.
ssh $a curl -sf http://127.0.0.1:$p/v2/ && echo ok
ssh $b curl -sf http://127.0.0.1:$p/v2/ && echo ok

# Both VMs use FIBERD_GPU_MOVE_REGISTRY=127.0.0.1:$p.
REGISTRY_ADDR=127.0.0.1:$p GPU_A=$a GPU_B=$b hack/gpu/move.sh all

# Afterwards, stop the tunnels and run: hack/gpu/registry.sh down
EOF
}

case ${1:-} in
  up) up "${2:-}" ;;
  down) down ;;
  check) check "${2:-}" ;;
  addr) addr ;;
  mac) mac ;;
  *)
    echo "usage: $0 up [IP[:PORT]] | down | check [IP[:PORT]] | addr | mac" >&2
    exit 2
    ;;
esac
