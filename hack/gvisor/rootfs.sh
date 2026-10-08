#!/usr/bin/env bash
# Build the rootfs the gvisor and runc backends run the reference workload
# in. It holds a statically linked refzygote at /bin/refzygote and the
# mount points a sandbox needs, nothing else. runsc's gofer serves the
# directory, or runc copies it per grant, and every fiber is restored from
# a checkpoint taken of this workload.
#
#   hack/gvisor/rootfs.sh <dir>        (inside the dev container)
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT=${1:?rootfs directory}
mkdir -p "$OUT"/{bin,proc,dev,tmp,host}
# The binary must be free of pointer authentication on aarch64: a process
# restored from a checkpoint keeps stale PAC keys and traps on a CPU with
# FEAT_FPAC. The dev image is Debian bookworm, whose libc has none, and the
# flag keeps our own objects clean on a toolchain that defaults to PAC.
# Debian's libcrypto carries PAC in its arm64 assembly, so the dev image
# builds OpenSSL without it under /usr/local/openssl-nopac
# (docker/criu/Dockerfile) and the zygote links that one. On aarch64 it is
# required. Elsewhere the system OpenSSL is a fallback.
ARCH=$(uname -m)
SSL=${FIBERD_OPENSSL:-/usr/local/openssl-nopac}
FLAGS=""
if [ -d "$SSL/lib" ]; then
  FLAGS="-I$SSL/include -L$SSL/lib"
elif [ "$ARCH" = aarch64 ]; then
  echo "rootfs.sh: no PAC-free OpenSSL at $SSL; rebuild the dev image (docker/criu/Dockerfile)" >&2
  exit 1
fi
if [ "$ARCH" = aarch64 ]; then FLAGS="$FLAGS -mbranch-protection=none"; fi
# With TLS, so handoff grants work on the runc backend. The static
# OpenSSL's lookup warnings are about resolver calls the zygote never
# makes. ZYGOTE_CFLAGS and ZYGOTE_LDFLAGS from the Makefile, with
# -static-pie in place of -pie so the binary stays self-contained.
# shellcheck disable=SC2086  # $FLAGS is a list
gcc -static-pie -D_FORTIFY_SOURCE=3 -O2 -fstack-protector-strong -fstack-clash-protection -fPIE -Wformat=2 -Werror=format-security \
  -Wl,-z,relro,-z,now -Wall -pthread $FLAGS -DFZ_TLS -o "$OUT/bin/refzygote" zygote/refzygote.c zygote/libfiberzygote.c -lssl -lcrypto -ldl 2>&1 | grep -v "requires at runtime the shared libraries\|^/usr/bin/ld: .*in function" >&2 || true
[ -x "$OUT/bin/refzygote" ] || { echo "rootfs.sh: refzygote did not build" >&2; exit 1; }
if [ "$ARCH" = aarch64 ]; then
  command -v objdump >/dev/null || { echo "rootfs.sh: objdump is needed to check $OUT/bin/refzygote for PAC" >&2; exit 1; }
  # Count every pointer authentication instruction. A checkpoint can land
  # between a function's signing pair, and the signing returns and the
  # authenticated branches trap as well. The one exemption is the pair in
  # libgcc's unwinder (uw_update_context), which authenticates a return
  # address only for a frame whose unwind info says it was signed, and
  # this count is what proves no frame here is.
  n=$(objdump -d "$OUT/bin/refzygote" | awk '/^[0-9a-f]+ <.*>:/{sym=$2} $3 ~ /^(pac|aut|reta|bra|blra)/ && !(sym == "<uw_update_context>:" && ($3 == "autia1716" || $3 == "autib1716")){n++} END{print n+0}')
  [ "$n" = 0 ] || { echo "rootfs.sh: $n PAC instructions in $OUT/bin/refzygote; a restore would trap on a FEAT_FPAC CPU" >&2; exit 1; }
fi
echo "$OUT"
