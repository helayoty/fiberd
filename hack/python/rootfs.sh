#!/usr/bin/env bash
# Build the rootfs the gvisor and runc backends run the Python reference
# template in. It is hack/gvisor/rootfs.sh's rootfs plus this image's
# CPython, the shared libraries it and its stdlib modules load, the stdlib
# itself and the fiberd package with its built extension, every file at
# the path it has here. The template command is then
#
#   /usr/bin/python3 -m fiberd.template.ref --heap-mb 32
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
hack/python/build.sh

PY=$(readlink -f "$(command -v python3)")
STDLIB=$("$PY" -c 'import sysconfig; print(sysconfig.get_paths()["stdlib"])')
PURELIB=$("$PY" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')
ARCH=$(uname -m)

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

# needed lists the shared objects an executable or module loads.
needed() {
  ldd "$@" 2>/dev/null | awk '/=> \//{print $3} /^[ \t]*\/.*\(0x/{print $1}' | sort -u
}

copy_chain "$(command -v python3)"
copy_chain "$PY"
# copy_tree copies a directory into the rootfs at dst, less the names
# given as tar excludes.
copy_tree() {
  local src=$1 dst=$2
  shift 2
  mkdir -p "$OUT$dst"
  tar -C "$src" "$@" -cf - . | tar -C "$OUT$dst" -xf -
}

# The stdlib, less what no template imports, and its own compiled modules.
# The bytecode is compiled here, since the root is read-only in a sandbox.
copy_tree "$STDLIB" "$STDLIB" --exclude=__pycache__ --exclude=./test --exclude=./idlelib --exclude=./tkinter --exclude=./turtledemo --exclude=./ensurepip
copy_tree sdk/python/src/fiberd "$PURELIB/fiberd" --exclude=__pycache__ --exclude='*_test.py' --exclude=conftest.py --exclude=_testtable.py --exclude='*.c'
# shellcheck disable=SC2046  # the module and library paths are one per line, with no spaces
for so in $(needed "$PY" "$OUT$STDLIB"/lib-dynload/*.so "$OUT$PURELIB"/fiberd/_zygote*.so); do copy_chain "$so"; done
[ ! -e /etc/ld.so.cache ] || copy_chain /etc/ld.so.cache
"$PY" -m compileall -q "$OUT$STDLIB" "$OUT$PURELIB/fiberd" >/dev/null

if [ "$ARCH" = aarch64 ]; then
  # The extension is ours and must be free of pointer authentication, as
  # rootfs.sh demands of refzygote. The interpreter and the libraries are
  # not ours. A checkpoint can land in a signed frame of theirs only while
  # a fiber runs their code, and a fiber is parked idle in accept, so they
  # are counted and reported rather than refused. A count above zero is
  # what docs/design/sdk.md records for this image.
  pac() { objdump -d "$1" | awk '$3 ~ /^(pac|aut|reta|bra|blra)/ {n++} END{print n+0}'; }
  n=$(pac "$OUT$PURELIB"/fiberd/_zygote*.so)
  [ "$n" = 0 ] || { echo "rootfs.sh: $n PAC instructions in fiberd._zygote; a restore would trap on a FEAT_FPAC CPU" >&2; exit 1; }
  for f in "$OUT$PY" $(needed "$PY" "$OUT$STDLIB"/lib-dynload/*.so | sed "s|^|$OUT|"); do
    n=$(pac "$f")
    [ "$n" = 0 ] || echo "rootfs.sh: $n PAC instructions in ${f#"$OUT"} (not ours, left as is)" >&2
  done
fi
echo "$OUT"
