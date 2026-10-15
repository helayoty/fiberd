#!/usr/bin/env bash
# Build the rootfs the gvisor and runc backends run the Python reference
# template in. It is hack/gvisor/rootfs.sh's rootfs plus the dev image's
# PAC-free CPython (docker/dev/Dockerfile, /usr/local/python-nopac), the
# shared libraries it and its stdlib modules load from the PAC-free
# sysroot, the stdlib itself and the fiberd package with its extension
# built by that interpreter, every file at the path it has here, and
# /usr/bin/python3 as a link to the interpreter. The template command is
# then
#
#   /usr/bin/python3 -m fiberd.template.ref --heap-mb 32
#
# On aarch64 every object copied is counted for pointer authentication
# instructions and one is enough to refuse, since a sandbox restored on a
# FEAT_FPAC CPU traps in the first signed frame. The image's own python3
# is sid's, which is signed, so it never goes in here.
#
# A production template on those backends is an artifact built from a
# Python image plus the package instead (docs/design/sdk.md). This recipe is
# for the conformance and integration runs.
#
#   hack/python/rootfs.sh <dir>        (inside the dev container)
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT=${1:?rootfs directory}
hack/gvisor/rootfs.sh "$OUT" >/dev/null

PY=${FIBERD_PYTHON_NOPAC:-/usr/local/python-nopac/bin/python3.14}
[ -x "$PY" ] || { echo "rootfs.sh: no PAC-free CPython at $PY; rebuild the dev image (docker/dev/Dockerfile)" >&2; exit 1; }
STDLIB=$("$PY" -c 'import sysconfig; print(sysconfig.get_paths()["stdlib"])')
PURELIB=$("$PY" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')
INTERP=$(readelf -l "$PY" | sed -n 's/.*Requesting program interpreter: \(.*\)\]/\1/p')
ARCH=$(uname -m)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# dir_chain makes a directory of this image in the rootfs with each
# symlinked directory on its way (/lib64 -> usr/lib64 on a merged-usr
# amd64 image, which the loader's path goes through) kept as a symlink
# whose target is made first, since mkdir over a symlink with no target
# yet fails with "File exists".
dir_chain() {
  local p="" c t parts
  IFS=/ read -ra parts <<<"${1#/}"
  for c in "${parts[@]}"; do
    p=$p/$c
    if [ -L "$p" ]; then
      t=$(readlink "$p")
      case "$t" in /*) ;; *) t=${p%/*}/$t ;; esac
      dir_chain "$t"
      [ -e "$OUT$p" ] || [ -L "$OUT$p" ] || ln -s "$(readlink "$p")" "$OUT$p"
    else
      mkdir -p "$OUT$p"
    fi
  done
}

# copy_chain copies a path into the rootfs with every symlink on its way
# kept as a symlink, so the loader's lookups resolve as they do here and
# the file lands where the chain ends.
copy_chain() {
  local p=$1 t
  while [ -L "$p" ]; do
    t=$(readlink "$p")
    dir_chain "$(dirname "$p")"
    [ -e "$OUT$p" ] || [ -L "$OUT$p" ] || ln -s "$t" "$OUT$p"
    case "$t" in /*) p=$t ;; *) p=$(dirname "$p")/$t ;; esac
  done
  dir_chain "$(dirname "$p")"
  [ -e "$OUT$p" ] || cp -p "$p" "$OUT$p"
}

# needed lists the shared objects an executable or module loads, resolved
# by the interpreter's own loader, so its rpath counts as it does at run
# time. ldd would print the system loader for the interpreter line.
needed() {
  local f
  for f in "$@"; do "$INTERP" --list "$f" 2>/dev/null; done | awk '$2 == "=>" && $3 ~ /^\// {print $3}' | sort -u
}

# copy_tree copies a directory into the rootfs at dst, less the names
# given as tar excludes.
copy_tree() {
  local src=$1 dst=$2
  shift 2
  mkdir -p "$OUT$dst"
  tar -C "$src" "$@" -cf - . | tar -C "$OUT$dst" -xf -
}

# The extension, built by this interpreter against the sysroot its
# compiler points at, into scratch, so the in-tree build (build.sh, for
# the image's python3) is left alone. The interpreter carries no
# setuptools of its own, so it borrows the image's, which is pure Python.
SETUPTOOLS=$(python3 -c 'import os, setuptools; print(os.path.dirname(os.path.dirname(setuptools.__file__)))')
(cd sdk/python && PYTHONPATH=$SETUPTOOLS "$PY" setup.py -q build_ext --build-lib "$work/lib" --build-temp "$work/tmp" >/dev/null)

copy_chain "$PY"
copy_chain "$INTERP"
mkdir -p "$OUT/usr/bin"
ln -sfn "$PY" "$OUT/usr/bin/python3"
# The stdlib, less what no template imports, and its own compiled modules.
# The bytecode is compiled here, since the root is read-only in a sandbox.
copy_tree "$STDLIB" "$STDLIB" --exclude=__pycache__ --exclude=./test --exclude=./idlelib --exclude=./tkinter --exclude=./turtledemo --exclude=./ensurepip --exclude='./config-*'
copy_tree sdk/python/src/fiberd "$PURELIB/fiberd" --exclude=__pycache__ --exclude='*_test.py' --exclude=conftest.py --exclude=_testtable.py --exclude='*.c' --exclude='*.so'
cp -p "$work"/lib/fiberd/_zygote*.so "$OUT$PURELIB/fiberd/"
# shellcheck disable=SC2046  # the module and library paths are one per line, with no spaces
for so in $(needed "$PY" "$OUT$STDLIB"/lib-dynload/*.so "$OUT$PURELIB"/fiberd/_zygote*.so); do copy_chain "$so"; done
[ ! -e /etc/ld.so.cache ] || copy_chain /etc/ld.so.cache
"$PY" -m compileall -q "$OUT$STDLIB" "$OUT$PURELIB/fiberd" >/dev/null

if [ "$ARCH" = aarch64 ]; then
  # Count every pointer authentication instruction in what was copied: the
  # interpreter, its loader, every stdlib module, the extension and every
  # library they load. A checkpoint can land in any of their frames, and
  # a signed one traps on restore on a FEAT_FPAC CPU, so one is enough to
  # refuse. The count is what hack/python/pac.sh takes of a wheel.
  pac() { objdump -d "$1" | awk '$3 ~ /^(pac|aut|reta|bra|blra)/ {n++} END{print n+0}'; }
  bad=0
  # shellcheck disable=SC2046  # one path per line, no spaces
  for f in "$OUT$(readlink -f "$PY")" "$OUT$(readlink -f "$INTERP")" "$OUT$STDLIB"/lib-dynload/*.so "$OUT$PURELIB"/fiberd/_zygote*.so \
           $(needed "$PY" "$OUT$STDLIB"/lib-dynload/*.so "$OUT$PURELIB"/fiberd/_zygote*.so | sed "s|^|$OUT|"); do
    n=$(pac "$f")
    [ "$n" = 0 ] || { echo "rootfs.sh: $n PAC instructions in ${f#"$OUT"}; a restore would trap on a FEAT_FPAC CPU" >&2; bad=1; }
  done
  [ "$bad" = 0 ] || exit 1
fi
echo "$OUT"
