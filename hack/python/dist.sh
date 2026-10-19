#!/usr/bin/env bash
# Build the sdist, then a wheel from that sdist, and test the installed
# wheel, as the release does with cibuildwheel. The sdist vendors the
# zygote library's libc, from cargo's registry or crates.io. Everything
# after it is offline, inside the dev container. Nothing is written into the tree,
# since it builds from a copy.
# The wheel is linux_<arch> here. auditwheel makes it manylinux in CI.
#
#   hack/python/dist.sh [outdir]      default /tmp/fiberd-python-dist
set -euo pipefail
cd "$(dirname "$0")/../.."
out=${1:-/tmp/fiberd-python-dist}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
rm -rf "$out"
mkdir -p "$out" "$work/repo/sdk/c/template/core" "$work/sdist"

# What setup.py reads, laid out as in the tree.
cp LICENSE NOTICE "$work/repo/"
cp sdk/c/template/libfiberzygote.h "$work/repo/sdk/c/template/"
(cd sdk/c/template/core && cp -R Cargo.toml Cargo.lock rust-toolchain.toml build.rs src "$work/repo/sdk/c/template/core/")
tar -C sdk -cf - --exclude=build --exclude='*.so' --exclude=__pycache__ --exclude='*.egg-info' python |
  tar -C "$work/repo/sdk" -xf -
(cd "$work/repo/sdk/python" && python3 setup.py -q sdist -d "$out" >/dev/null)
sdist=$(echo "$out"/fiberd-*.tar.gz)
tar -C "$work/sdist" -xzf "$sdist"
src=$(echo "$work"/sdist/fiberd-*)

# sid's crti.o and crtn.o sign _init and _fini, which would put four PAC
# instructions into our extension, so the link takes the dev image's
# PAC-free sysroot (docker/dev/Dockerfile) when it has one. -B puts its
# start files ahead of the -L the interpreter's sysconfig adds, which
# gcc searches for them too. setuptools reads LDSHARED from the
# environment.
sysroot=${FIBERD_SYSROOT:-/usr/local/sysroot-nopac}
if [ -d "$sysroot/usr/include" ]; then
  LDSHARED="$(python3 -c 'import sysconfig; print(sysconfig.get_config_var("LDSHARED"))') --sysroot=$sysroot -B$sysroot/usr/lib/$(gcc -print-multiarch)"
  export LDSHARED
fi
python3 -m venv --system-site-packages "$work/venv"
export PATH="$work/venv/bin:$PATH"
# The sdist must carry the crate and libc. An empty CARGO_HOME hides the
# registry, so the wheel builds from what the sdist holds or not at all.
CARGO_HOME="$work/cargo" CARGO_NET_OFFLINE=true pip wheel -q --no-index --no-build-isolation --no-deps -w "$out" "$sdist"
wheel=$(echo "$out"/fiberd-*.whl)
case "$wheel" in
  *-cp314-abi3-linux_*.whl) ;;
  *) echo "dist.sh: $wheel is not a cp314-abi3 wheel" >&2; exit 1 ;;
esac
names=$(python3 -m zipfile -l "$wheel")
grep -q 'fiberd/_zygote.abi3.so' <<<"$names" || { echo "dist.sh: no fiberd/_zygote.abi3.so in $wheel" >&2; exit 1; }
if grep -E '_test\.py|conftest\.py|/_test[^/]*\.py|\.c ' <<<"$names"; then
  echo "dist.sh: the wheel ships tests or C sources" >&2; exit 1
fi
[ "$(uname -m)" != aarch64 ] || hack/python/pac.sh "$wheel"

pip install -q --no-index --no-deps "$wheel"
sh "$src/wheel-test.sh" "$src"
ls -l "$out"
