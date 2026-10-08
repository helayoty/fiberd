#!/usr/bin/env bash
# Build the libFuzzer harnesses in this directory with clang and run each
# one for FUZZTIME seconds (default 120) over its seed corpus. Needs clang
# with libFuzzer, which Debian and Ubuntu ship as libclang-rt-<N>-dev.
# Exits non-zero when any harness crashes, and leaves the crashing input
# under $FUZZ_OUT/crashes/ (default bin/fuzz/crashes/).
#
#   zygote/fuzz/run.sh                     build and run every harness
#   zygote/fuzz/run.sh build               build only
#   FUZZTIME=10 zygote/fuzz/run.sh fuzz_rundir fuzz_control
set -euo pipefail
cd "$(dirname "$0")/../.."

CLANG=${CLANG:-clang}
OUT=${FUZZ_OUT:-bin/fuzz}
FUZZTIME=${FUZZTIME:-120}
# No FORTIFY, because it would redefine the libc calls the harnesses
# shim, and ASan covers what it checks.
CFLAGS="-g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
  -U_FORTIFY_SOURCE -Wall -Wextra -pthread"

all=(fuzz_recv_line fuzz_identity fuzz_procfiles fuzz_rundir fuzz_control fuzz_refzygote)
mode=run
if [ "${1:-}" = build ]; then mode=build; shift; fi
harnesses=("$@")
[ ${#harnesses[@]} -gt 0 ] || harnesses=("${all[@]}")

mkdir -p "$OUT/crashes"
for h in "${harnesses[@]}"; do
  extra=()
  # The reference workload includes only refzygote.c; the library is a
  # second translation unit beside it.
  [ "$h" = fuzz_refzygote ] && extra=(zygote/libfiberzygote.c)
  # shellcheck disable=SC2086  # $CFLAGS is a list
  if ! $CLANG $CFLAGS -o "$OUT/$h" "zygote/fuzz/$h.c" "${extra[@]}"; then
    echo "run.sh: $h did not build; is libFuzzer installed (libclang-rt-<N>-dev)?" >&2
    exit 1
  fi
done
[ "$mode" = run ] || exit 0

# Inputs long enough to pass each parser's buffer, where the code has a
# branch for it.
max_len() {
  case $1 in
    fuzz_recv_line|fuzz_control) echo 70000 ;; # MAX_LINE is 65536
    fuzz_identity) echo 9000 ;;                # IDENTITY_MAX is 8192
    fuzz_procfiles) echo 20000 ;;              # lock_sys buffers 8192
    *) echo 4096 ;;
  esac
}

failed=()
for h in "${harnesses[@]}"; do
  echo "--- $h for ${FUZZTIME}s"
  # New inputs land in the work corpus, never in the seeds.
  mkdir -p "$OUT/corpus/$h"
  if ! "$OUT/$h" -max_total_time="$FUZZTIME" -timeout=10 -rss_limit_mb=2048 \
      -max_len="$(max_len "$h")" -artifact_prefix="$OUT/crashes/$h-" \
      "$OUT/corpus/$h" "zygote/fuzz/corpus/$h" 2>&1 | tee "$OUT/$h.log" | grep -E '^(#[0-9]+\s+(DONE|INITED)|==|SUMMARY|Test unit written|MS: )' ; then
    failed+=("$h")
  fi
done
if [ ${#failed[@]} -gt 0 ]; then
  echo "run.sh: crashes in ${failed[*]}; inputs under $OUT/crashes/, logs under $OUT/*.log" >&2
  exit 1
fi
echo "run.sh: no crashes"
