#!/usr/bin/env bash
# Build the Hyperlight guest and helper (inside the dev container, which
# has rustup, cargo-hyperlight and clang) into bin/. Compiling needs no
# hypervisor; running the helper does.
#
#   make hyperlight-helper
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p bin
( cd hack/hyperlight/guest && cargo hyperlight build --release )
guest=$(find hack/hyperlight/guest/target -type f -name fiberd-guest -path '*release*' | head -1)
[ -n "$guest" ] || { echo "guest binary not found under hack/hyperlight/guest/target" >&2; exit 1; }
cp "$guest" bin/hyperlight-guest
( cd hack/hyperlight/helper && cargo build --release )
cp hack/hyperlight/helper/target/release/hyperlight-helper bin/hyperlight-helper
echo "bin/hyperlight-guest bin/hyperlight-helper"
