#!/usr/bin/env bash
# Build the rootfs the gvisor backend runs the reference workload in: a
# statically linked refzygote at /bin/refzygote and the mount points a
# sandbox needs. Nothing else; the rootfs is a directory runsc's gofer
# serves, and every fiber sandbox is restored from a checkpoint taken of
# this workload after its init.
#
#   hack/gvisor/rootfs.sh <dir>        (inside the dev container)
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT=${1:?rootfs directory}
mkdir -p "$OUT"/{bin,proc,dev,tmp,host}
# The binary must be free of pointer authentication on aarch64: a process
# restored from a checkpoint keeps stale PAC keys and traps on a CPU with
# FEAT_FPAC. The dev image is Debian bookworm, whose libc has none; the
# flag keeps our own objects clean on a toolchain that defaults to PAC.
FLAGS=""
if [ "$(uname -m)" = aarch64 ]; then FLAGS="-mbranch-protection=none"; fi
gcc -static -O2 -Wall -pthread $FLAGS -o "$OUT/bin/refzygote" hack/zygote/refzygote.c hack/zygote/libfiberzygote.c
if [ "$(uname -m)" = aarch64 ] && command -v objdump >/dev/null; then
  n=$(objdump -d "$OUT/bin/refzygote" | grep -cE 'paciasp|autiasp' || true)
  [ "$n" = 0 ] || echo "warning: $n PAC instructions in $OUT/bin/refzygote; restores will trap on FEAT_FPAC CPUs" >&2
fi
echo "$OUT"
