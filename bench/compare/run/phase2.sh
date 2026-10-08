#!/usr/bin/env bash
# Phase 2: the mechanism baselines without Kubernetes. fiberd proc (both
# framings), runc and gVisor standalone over loopback in the Linux dev
# container, with park and resume and density. Results land in
# bin/compare-state/phase2.
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
cd "$ROOT"
bench/compare/run/phase0.sh
hack/registry/run.sh start   # the gVisor home pulls its template from it
hack/dev/run.sh true   # the build stage is the dev image
docker build --target binaries -o bin/compare-bin -f docker/compare/Dockerfile .
[ $# -gt 0 ] || set -- proc runc gvisor
hack/dev/run.sh env COMPARE_RUNS="$RUNS" COMPARE_BURSTS="$BURSTS" COMPARE_DENSITY="$DENSITY" \
  COMPARE_OUT=/src/bin/compare-state/phase2 bench/compare/run/standalone.sh "$@"
