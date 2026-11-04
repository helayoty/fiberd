#!/usr/bin/env bash
# Run a command inside the Linux dev container with the repo mounted at
# /src. Pulls the image on first use, or when its inputs change, and builds
# it when the registry does not have it.
#
#   hack/dev/run.sh bash                 interactive shell
#   hack/dev/run.sh go test ./...        anything else
#
# Module, build and cargo registry caches live in named volumes so
# rebuilds are fast. The fiberd-conform volume at /conform holds
# conformance state and logs on macOS (see CONFORM_DIR in the Makefile).
set -euo pipefail
cd "$(dirname "$0")/../.."

IMAGE=${FIBERD_DEV_IMAGE:-fiberd-dev:local}
NAME=${FIBERD_DEV_NAME:-fiberd-dev}

# Most CI jobs have no time limit of their own, so a stalled registry must
# fail the pull and reach the build. macOS has no timeout, and a person
# watching there can interrupt.
pull() {
  if command -v timeout >/dev/null; then
    timeout --foreground 1200 docker pull "$1"
  else
    docker pull "$1"
  fi
}

# Replace the image when its inputs changed: their hash is kept as a label
# on the image, so the check does not depend on clocks or on how this
# host's `date` parses timestamps. A failed pull means a tag not published
# yet, as on a change to the inputs, which then builds and tests its own
# image, or a registry out of reach.
want=$(bash hack/dev/image-tag.sh)
have=$(docker image inspect -f '{{index .Config.Labels "io.fiberd.dev.hash"}}' "$IMAGE" 2>/dev/null || true)
remote=ghcr.io/azure/fiberd-dev:$want
if [ "${FIBERD_DEV_BUILD:-}" = 1 ] || [ "$want" != "$have" ]; then
  if [ "${FIBERD_DEV_BUILD:-}" != 1 ] && pull "$remote" >&2; then
    docker tag "$remote" "$IMAGE"
  else
    docker build -t "$IMAGE" -f docker/dev/Dockerfile --label "io.fiberd.dev.hash=$want" . >&2
  fi
fi

tty=""
if [ -t 0 ] && [ -t 1 ]; then tty="-it"; fi
net=""
if docker network inspect fiberd-net >/dev/null 2>&1; then net="--network fiberd-net"; fi

# FIBERD_DEV_DOCKER_ARGS adds docker run flags (e.g. --memory=384m for the
# overcommit storm).
# shellcheck disable=SC2086  # $tty and the extra args are intentionally unquoted
exec docker run --rm $tty $net ${FIBERD_DEV_DOCKER_ARGS:-} \
  --name "$NAME-$$" \
  --privileged --cgroupns=private \
  --tmpfs /run --tmpfs /tmp:exec \
  -v "$PWD:/src" \
  -v fiberd-gomod:/go/pkg/mod \
  -v fiberd-gocache:/root/.cache/go-build \
  -v fiberd-cargo-registry:/usr/local/cargo/registry \
  -v fiberd-conform:/conform \
  -e GOTOOLCHAIN=auto \
  -w /src \
  "$IMAGE" "$@"
