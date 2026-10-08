#!/usr/bin/env bash
# The Firecracker guest's root filesystem: an ext4 image holding the
# static counter binary and nothing else. The kernel runs it as init
# (boot_args in firecracker.go), and the counter brings eth0 up itself,
# so there is no shell, no init script and no busybox in the guest.
# mke2fs -d populates the image without a mount, so no root is needed.
#
#   rootfs.sh <counter-static> <out.ext4>
set -euo pipefail
counter=${1:?static counter binary} out=${2:?ext4 image path}
[ -x "$counter" ] || { echo "rootfs.sh: $counter is not executable" >&2; exit 1; }
file "$counter" | grep -q "statically linked\|static-pie" || echo "rootfs.sh: warning: $counter does not look static" >&2
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
mkdir -p "$dir/dev" "$dir/proc" "$dir/sys"
install -m 0755 "$counter" "$dir/counter"
rm -f "$out"
mke2fs -q -t ext4 -d "$dir" -L rootfs "$out" 16M
echo "$out"
