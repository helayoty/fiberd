#!/usr/bin/env bash
# A local OCI registry for zygote artifacts and parked deltas.
#
#   hack/registry/run.sh start   registry:2 as fiberd-registry on network fiberd-net,
#                                published at 127.0.0.1:5000 for the host
#   hack/registry/run.sh stop
#
# The dev container (hack/dev/run.sh) joins fiberd-net when it exists, so
# inside it the registry is fiberd-registry:5000 (plain HTTP).
set -euo pipefail
case "${1:-}" in
  start)
    docker network inspect fiberd-net >/dev/null 2>&1 || docker network create fiberd-net >/dev/null
    if ! docker ps --format '{{.Names}}' | grep -qx fiberd-registry; then
      docker rm -f fiberd-registry >/dev/null 2>&1 || true
      docker run -d --name fiberd-registry --network fiberd-net -p 127.0.0.1:5000:5000 \
        -e REGISTRY_STORAGE_DELETE_ENABLED=true registry:2 >/dev/null
    fi
    for _ in $(seq 1 50); do curl -sf http://127.0.0.1:5000/v2/ >/dev/null && break; sleep 0.2; done
    echo "registry: host 127.0.0.1:5000, dev container fiberd-registry:5000"
    ;;
  stop) docker rm -f fiberd-registry >/dev/null 2>&1 || true; echo "registry stopped" ;;
  *) echo "usage: $0 start|stop" >&2; exit 2 ;;
esac
