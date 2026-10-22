#!/usr/bin/env bash
# Setup for the Cloud Hypervisor spikes, run once per host. Idempotent.
#
#   bash hack/cloudhv/spike/setup.sh            (SPIKE_DIR defaults to /var/tmp/cloudhv-spike)
#
# It downloads the pinned static cloud-hypervisor and guest kernel (env.sh),
# refuses any file whose sha256 differs from the pin, and builds the guest:
# a static init from guest.c, alone in a gzip'd initramfs. It needs no root.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

[ "$(uname -m)" = x86_64 ] || fail "x86_64 only (the pins are the x86_64 assets)"
need_cmd curl sha256sum cc cpio gzip find
mkdir -p "$SPIKE_DIR/bin" "$SPIKE_DIR/guest" "$SPIKE_DIR/dl"

# fetch <url> <sha256 pin> <dest>. A file already in place is checked again.
fetch() {
  local url=$1 pin=$2 dest=$3 got
  if [ -f "$dest" ] && [ -n "$pin" ] && [ "$(sha256sum "$dest" | cut -d' ' -f1)" = "$pin" ]; then
    ok "$(basename "$dest") already in place, sha256 matches"
    return
  fi
  curl -fsSL --retry 3 -o "$dest.part" "$url" || fail "download failed: $url"
  got=$(sha256sum "$dest.part" | cut -d' ' -f1)
  if [ -z "$pin" ]; then
    rm -f "$dest.part"
    fail "no sha256 pin for $url. The download hashed to $got. Check it against the release page, pin it in env.sh, and run again"
  fi
  if [ "$got" != "$pin" ]; then
    rm -f "$dest.part"
    fail "sha256 mismatch for $url: got $got, pinned $pin"
  fi
  mv "$dest.part" "$dest"
  ok "$(basename "$dest") downloaded, sha256 $got"
}

fetch "$CH_URL" "$CH_SHA256" "$SPIKE_DIR/dl/cloud-hypervisor-static"
install -m 0755 "$SPIKE_DIR/dl/cloud-hypervisor-static" "$CH"
fetch "$KERNEL_URL" "$KERNEL_SHA256" "$KERNEL"

# The guest. Rebuilt only when guest.c is newer than the init it made.
init=$SPIKE_DIR/guest/init
if [ ! -x "$init" ] || [ "$SPIKE_SRC/guest.c" -nt "$init" ] || [ ! -f "$INITRAMFS" ]; then
  cc -static -O2 -Wall -o "$init" "$SPIKE_SRC/guest.c" || fail "cannot build the guest init (needs a static libc, e.g. libc6-dev)"
  root=$(mktemp -d)
  trap 'rm -rf "$root"' EXIT
  install -m 0755 "$init" "$root/init"
  mkdir -p "$root/dev" "$root/proc"
  (cd "$root" && find . -print0 | cpio --null -o -H newc -R 0:0 --quiet) | gzip -9n >"$INITRAMFS.part"
  mv "$INITRAMFS.part" "$INITRAMFS"
  ok "guest initramfs $INITRAMFS ($(wc -c <"$INITRAMFS") bytes)"
else
  ok "guest initramfs already built"
fi

ok "$("$CH" --version 2>&1 | head -1)"
ok "setup done in $SPIKE_DIR"
