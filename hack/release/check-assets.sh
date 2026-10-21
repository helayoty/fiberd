#!/usr/bin/env bash
# Checks the release archives before anything is published.
#
#   hack/release/check-assets.sh <dist> <version>
#
# - The archive names are exactly the ones below, each with its SBOM.
# - SHA256SUMS lists every file in <dist> and matches it.
# - Every archive member is 0755 or 0644, the ./ entry included.
# - Each Linux zygote library holds the expected files, is built for its
#   own arch and passes sdk/c/template/core/check.sh. On arm64 that means
#   no pointer authentication instruction.
# - The source archive holds the core crate, and both archives build from
#   it unpacked.
#
# On a host that is not aarch64 the arm64 archive is disassembled with
# aarch64-linux-gnu-objdump (Debian and Ubuntu binutils-aarch64-linux-gnu).
# Nothing is written outside a temporary directory.
set -euo pipefail

dist=${1:?usage: check-assets.sh <dist> <version>}
version=${2:?usage: check-assets.sh <dist> <version>}
root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail() { echo "check-assets.sh: $*" >&2; exit 1; }

# The names. The SDK packages are checked by the jobs that build them.
want=()
for t in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64; do
  want+=("fiberd_${version}_$t.tar.gz" "fiberd_${version}_$t.tar.gz.spdx.json")
done
for t in linux_amd64 linux_arm64 src; do
  want+=("libfiberzygote_${version}_$t.tar.gz" "libfiberzygote_${version}_$t.tar.gz.spdx.json")
done
expected=$(printf '%s\n' "${want[@]}" | sort)
have=$(cd "$dist" && find . -maxdepth 1 -type f | sed 's|^\./||' | { grep -E '^(fiberd|libfiberzygote)_' || true; } | sort)
if [[ "$have" != "$expected" ]]; then
  diff <(echo "$expected") <(echo "$have") >&2 || true
  fail "the archive names differ from the expected ones (- expected, + found)"
fi
listed=$(awk '{print $2}' "$dist/SHA256SUMS" | sort)
files=$(cd "$dist" && find . -maxdepth 1 -type f ! -name SHA256SUMS | sed 's|^\./||' | sort)
[[ "$listed" == "$files" ]] || fail "SHA256SUMS does not list exactly the files in $dist"
(cd "$dist" && sha256sum --quiet -c SHA256SUMS) || fail "SHA256SUMS does not match"
echo "check-assets.sh: $(echo "$have" | wc -l | tr -d ' ') archive names as expected, SHA256SUMS matches"

# The modes. Every directory, ./ included, is 0755 and every file 0644 or
# 0755, so unpacking into the current directory leaves it as it was.
for a in $(echo "$have" | grep '\.tar\.gz$'); do
  bad=$(tar -tvzf "$dist/$a" | awk '$1 !~ /^(drwxr-xr-x|-rw-r--r--|-rwxr-xr-x)$/ {print $1, $NF}')
  [[ -z "$bad" ]] || fail "$a has members with other modes: ${bad//$'\n'/, }"
done
echo "check-assets.sh: every archive member is 0755 or 0644"

# The zygote library of each Linux arch.
for arch in amd64 arm64; do
  dir="$work/$arch"
  mkdir "$dir"
  tar -xzf "$dist/libfiberzygote_${version}_linux_$arch.tar.gz" -C "$dir"
  members=$(cd "$dir" && find . -mindepth 1 | sort | tr '\n' ' ')
  [[ "$members" == "./LICENSE ./NOTICE ./README.md ./libfiberzygote.a ./libfiberzygote.h " ]] ||
    fail "libfiberzygote linux_$arch holds $members"
  machine=AArch64 objdump=objdump
  if [[ "$arch" == amd64 ]]; then machine="Advanced Micro Devices X86-64"; fi
  if [[ "$arch" == arm64 && "$(uname -m)" != aarch64 ]]; then objdump=aarch64-linux-gnu-objdump; fi
  # Every member, not only the first, is for this arch.
  got=$(readelf -h "$dir/libfiberzygote.a" | awk -F: '/Machine:/ {gsub(/^[ \t]+/, "", $2); print $2}' | sort -u)
  [[ "$got" == "$machine" ]] || fail "libfiberzygote linux_$arch is built for: $got"
  OBJDUMP=$objdump "$root/sdk/c/template/core/check.sh" "$dir/libfiberzygote.a"
done

# The source archive.
src="$work/src"
mkdir "$src"
tar -xzf "$dist/libfiberzygote_${version}_src.tar.gz" -C "$src"
for f in libfiberzygote.h core/Cargo.toml core/Cargo.lock core/rust-toolchain.toml core/build.rs core/src/lib.rs; do
  [[ -f "$src/$f" ]] || fail "libfiberzygote src has no $f"
done
(cd "$src/core" &&
  for triple in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu; do
    cargo build --quiet --release --locked --target "$triple" --target-dir "$work/target"
    [[ -s "$work/target/$triple/release/libfiberzygote_core.a" ]] || fail "the source archive built no $triple library"
  done)
echo "check-assets.sh: the source archive holds the core crate and builds both archives"
