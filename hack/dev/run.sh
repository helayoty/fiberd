#!/usr/bin/env bash
# Run a command inside the Linux dev container with the repo mounted at
# /src. Builds the image on first use (or when hack/dev changes).
#
#   hack/dev/run.sh bash                 interactive shell
#   hack/dev/run.sh go test ./...        anything else
#
# Module and build caches live in named volumes so rebuilds are fast.
set -euo pipefail
cd "$(dirname "$0")/../.."

IMAGE=${FIBERD_DEV_IMAGE:-fiberd-dev:local}
NAME=${FIBERD_DEV_NAME:-fiberd-dev}

# Rebuild when the Dockerfile or entrypoint changed: their hash is kept as
# a label on the image, so the check does not depend on clocks or on how
# this host's `date` parses timestamps.
want=$(cat hack/dev/Dockerfile hack/dev/entrypoint.sh | shasum -a 256 | cut -c1-16)
have=$(docker image inspect -f '{{index .Config.Labels "io.fiberd.dev.hash"}}' "$IMAGE" 2>/dev/null || true)
if [ "$want" != "$have" ]; then
  docker build -t "$IMAGE" -f hack/dev/Dockerfile --label "io.fiberd.dev.hash=$want" . >&2
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
  -e GOTOOLCHAIN=auto \
  -w /src \
  "$IMAGE" "$@"
