#!/usr/bin/env bash
# Build what fiberd's cloudhv backend runs, inside the dev container.
#
#   hack/cloudhv/build.sh         bin/cloudhv: the pinned static cloud-hypervisor,
#                                 the guest kernel and a read-only ext4 rootfs
#                                 holding the guest init and the reference template
#   hack/cloudhv/build.sh fake    bin/cloudhv-fake: the fake VMM, a placeholder
#                                 kernel and a directory rootfs, for CI without KVM
#
# Both name their files the same, so fiberd takes either through
# -cloudhv-vmm <dir>/cloud-hypervisor -cloudhv-kernel <dir>/vmlinux
# -cloudhv-rootfs <dir>/rootfs.img. Every download is checked against its
# pinned sha256, and the build writes SHA256SUMS of what it made. The
# backend records the kernel's and the rootfs's hashes as parity facts,
# so a snapshot restores only where both match.
#
# The kernel is Cloud Hypervisor's own build of the release the spikes
# pin (hack/cloudhv/spike/env.sh), whose config has virtio-vsock,
# virtio-blk and ext4 built in. CLOUDHV_KERNEL_SOURCE=1 builds one from
# kernel.org with the minimal config in kernel.config instead, which
# needs KERNEL_SHA256 pinned and flex, bison, bc and libelf.
set -euo pipefail
cd "$(dirname "$0")/../.."

# Cloud Hypervisor v54.0, the static x86_64 build. The same pins as the
# spikes, read from the release assets' digests on 2026-10-22, and
# v54.0's on 2026-10-23.
CH_VERSION=v54.0
CH_URL=https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/$CH_VERSION/cloud-hypervisor-static
CH_SHA256=4f4f98a3d661a40f3e5272627cc895a1b2e525f2f6bedf5f895f9cd21ba5c65b
KERNEL_TAG=ch-release-v6.16.9-20260508
KERNEL_URL=https://github.com/cloud-hypervisor/linux/releases/download/$KERNEL_TAG/vmlinux-x86_64
KERNEL_PREBUILT_SHA256=9d3570b47d5abb069ca00edfbfcef4c68306a9c3d078a01f10082b258f1001b8
# The source build. Pin KERNEL_SHA256 from kernel.org's sha256sums.asc
# before the first run, which refuses without it and prints the hash.
KERNEL_VERSION=6.16.9
KERNEL_SRC_URL=https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KERNEL_VERSION.tar.xz
KERNEL_SHA256=${KERNEL_SHA256:-}
# The rootfs image's size. The guest init and the template are a few MiB.
ROOTFS_MB=${ROOTFS_MB:-32}

fail() { echo "cloudhv build: $*" >&2; exit 1; }
need() { local c; for c in "$@"; do command -v "$c" >/dev/null 2>&1 || fail "missing command: $c"; done; }

# fetch <url> <sha256 pin> <dest>. A file already in place is checked again.
fetch() {
  local url=$1 pin=$2 dest=$3 got
  if [ -f "$dest" ] && [ -n "$pin" ] && [ "$(sha256sum "$dest" | cut -d' ' -f1)" = "$pin" ]; then return; fi
  curl -fsSL --retry 3 -o "$dest.part" "$url" || fail "download failed: $url"
  got=$(sha256sum "$dest.part" | cut -d' ' -f1)
  if [ -z "$pin" ]; then rm -f "$dest.part"; fail "no sha256 pin for $url; it hashed to $got. Check it and pin it"; fi
  [ "$got" = "$pin" ] || { rm -f "$dest.part"; fail "sha256 mismatch for $url: got $got, pinned $pin"; }
  mv "$dest.part" "$dest"
}

# The reference template, static, since neither the guest nor the fake
# VMM's jail holds libraries. build_template <dest> <goarch>. The real
# guest is x86_64, while the fake VMM execs it natively on the host.
build_template() {
  CGO_ENABLED=0 GOOS=linux GOARCH=$2 go build -trimpath -o "$1" ./hack/cloudhv/vmtemplate
}

if [ "${1:-}" = fake ]; then
  out=bin/cloudhv-fake
  need go
  rm -rf "$out"
  mkdir -p "$out/rootfs.img/fiberd"
  CGO_ENABLED=0 go build -trimpath -o "$out/cloud-hypervisor" ./hack/cloudhv/fakevmm
  build_template "$out/rootfs.img/fiberd/vmtemplate" "$(go env GOHOSTARCH)"
  echo "fakevmm has no kernel" >"$out/vmlinux"
  chmod 0755 "$out" "$out/rootfs.img" "$out/rootfs.img/fiberd"
  chmod 0644 "$out/vmlinux"
  echo "$out/cloud-hypervisor $out/vmlinux $out/rootfs.img/"
  exit 0
fi

[ "$(uname -m)" = x86_64 ] || fail "x86_64 only, as the pins are"
need curl sha256sum cc go mke2fs
out=bin/cloudhv
dl=$out/dl
mkdir -p "$out" "$dl"

fetch "$CH_URL" "$CH_SHA256" "$dl/cloud-hypervisor-static"
install -m 0755 "$dl/cloud-hypervisor-static" "$out/cloud-hypervisor"

if [ "${CLOUDHV_KERNEL_SOURCE:-0}" = 1 ]; then
  need make flex bison bc tar xz
  fetch "$KERNEL_SRC_URL" "$KERNEL_SHA256" "$dl/linux-$KERNEL_VERSION.tar.xz"
  src=$dl/linux-$KERNEL_VERSION
  [ -d "$src" ] || tar -C "$dl" -xJf "$dl/linux-$KERNEL_VERSION.tar.xz"
  make -C "$src" -s tinyconfig
  "$src/scripts/kconfig/merge_config.sh" -m -O "$src" "$src/.config" hack/cloudhv/kernel.config >/dev/null
  make -C "$src" -s olddefconfig
  make -C "$src" -s -j"$(nproc)" vmlinux
  install -m 0644 "$src/vmlinux" "$out/vmlinux"
else
  fetch "$KERNEL_URL" "$KERNEL_PREBUILT_SHA256" "$dl/vmlinux-x86_64"
  install -m 0644 "$dl/vmlinux-x86_64" "$out/vmlinux"
fi

# The rootfs. Only the guest init and the template, with the mount points
# the guest init fills, every file root's and dated at the epoch so two
# builds from one tree differ only where mke2fs does.
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
mkdir -p "$root/fiberd" "$root/dev" "$root/proc" "$root/sys" "$root/run" "$root/tmp"
cc -static -O2 -Wall -Wextra -o "$root/fiberd/init" hack/cloudhv/guest/init.c
build_template "$root/fiberd/vmtemplate" amd64
chmod 0755 "$root/fiberd/init" "$root/fiberd/vmtemplate"
find "$root" -exec touch -h -d @0 {} +
rm -f "$out/rootfs.img"
E2FSPROGS_FAKE_TIME=1 mke2fs -q -t ext4 -L fiberd-guest -U 66696265-7264-4775-6573-740000000000 -m 0 \
  -E root_owner=0:0 -d "$root" "$out/rootfs.img" "${ROOTFS_MB}M"
chmod 0644 "$out/rootfs.img"
chmod 0755 "$out"

(cd "$out" && sha256sum cloud-hypervisor vmlinux rootfs.img >SHA256SUMS)
"$out/cloud-hypervisor" --version
cat "$out/SHA256SUMS"
