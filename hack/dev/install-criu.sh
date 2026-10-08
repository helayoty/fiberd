#!/bin/sh
# Build and install criu from the release tarball GitHub serves for the
# tag, with one upstream patch (see docker/criu/Dockerfile). The tarball
# is verified against a pinned sha256 before it is unpacked. Another
# version needs CRIU_SHA256 set beside CRIU_VERSION.
set -eu

version=${CRIU_VERSION:-4.1.1}
case "$version" in
  4.1.1) default_sha256=a5338fe696395843543e6e09c85ccaf36614bf172c26fe8506191b7b930d2dae ;;
  *) default_sha256= ;;
esac
sha256=${CRIU_SHA256:-$default_sha256}
if [ -z "$sha256" ]; then
  echo "install-criu: no pinned checksum for criu $version; set CRIU_SHA256" >&2
  exit 1
fi

source_dir="/tmp/criu-${version}"
tarball="/tmp/criu-${version}.tar.gz"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

curl -fsSL "https://github.com/checkpoint-restore/criu/archive/refs/tags/v${version}.tar.gz" -o "$tarball"
echo "$sha256  $tarball" | sha256sum -c - >/dev/null
tar -xzf "$tarball" -C /tmp
rm -f "$tarball"
cd "$source_dir"
patch -p1 < "$script_dir/criu-4b7398595-passcred-families.patch"
if ! make -j"$(nproc)" criu >/tmp/criu-build.log 2>&1; then
  tail -40 /tmp/criu-build.log
  exit 1
fi
install -m 0755 criu/criu /usr/local/sbin/criu
cd /
rm -rf "$source_dir" /tmp/criu-build.log
criu --version
