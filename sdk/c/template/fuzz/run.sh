#!/usr/bin/env bash
# Build the libFuzzer harness of the reference workload (fuzz_refzygote,
# refzygote.c's own parsers) with clang and run it for FUZZTIME seconds
# (default 120) over its seed corpus. Needs clang with libFuzzer, which
# Debian and Ubuntu ship as libclang-rt-<N>-dev. Exits non-zero when it
# crashes, and leaves the crashing input under $FUZZ_OUT/crashes/
# (default bin/fuzz/crashes/). The zygote library itself is fuzzed by
# the cargo-fuzz targets of its Rust crate (core/fuzz, make fuzz-core).
#
#   sdk/c/template/fuzz/run.sh                     build and run
#   sdk/c/template/fuzz/run.sh build               build only
#   FUZZTIME=10 sdk/c/template/fuzz/run.sh fuzz_refzygote
set -euo pipefail
cd "$(dirname "$0")/../../../.."

CLANG=${CLANG:-clang}
OUT=${FUZZ_OUT:-bin/fuzz}
FUZZTIME=${FUZZTIME:-120}
CFLAGS="-g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
  -Wall -Wextra -pthread"

all=(fuzz_refzygote)
# refzygote.c calls the library, so the harness links the core's product
# archive (sdk/c/template/core), as make zygote does. The harness reaches
# none of it, since it never calls fz_init or fz_serve.
CORE=sdk/c/template/core/target/release/libfiberzygote_core.a
mode=run
if [ "${1:-}" = build ]; then mode=build; shift; fi
harnesses=("$@")
[ ${#harnesses[@]} -gt 0 ] || harnesses=("${all[@]}")

mkdir -p "$OUT/crashes"
(cd sdk/c/template/core && cargo build --release --locked)
for h in "${harnesses[@]}"; do
  # shellcheck disable=SC2086  # $CFLAGS is a list
  if ! $CLANG $CFLAGS -o "$OUT/$h" "sdk/c/template/fuzz/$h.c" "$CORE"; then
    echo "run.sh: $h did not build; is libFuzzer installed (libclang-rt-<N>-dev)?" >&2
    exit 1
  fi
done
[ "$mode" = run ] || exit 0

failed=()
for h in "${harnesses[@]}"; do
  echo "--- $h for ${FUZZTIME}s"
  # New inputs land in the work corpus, never in the seeds.
  mkdir -p "$OUT/corpus/$h"
  if ! "$OUT/$h" -max_total_time="$FUZZTIME" -timeout=10 -rss_limit_mb=2048 \
      -max_len=4096 -artifact_prefix="$OUT/crashes/$h-" \
      "$OUT/corpus/$h" "sdk/c/template/fuzz/corpus/$h" 2>&1 | tee "$OUT/$h.log" | grep -E '^(#[0-9]+\s+(DONE|INITED)|==|SUMMARY|Test unit written|MS: )' ; then
    failed+=("$h")
  fi
done
if [ ${#failed[@]} -gt 0 ]; then
  echo "run.sh: crashes in ${failed[*]}; inputs under $OUT/crashes/, logs under $OUT/*.log" >&2
  exit 1
fi
echo "run.sh: no crashes"
