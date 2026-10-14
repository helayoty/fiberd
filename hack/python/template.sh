#!/usr/bin/env bash
# Run the Python reference template from the tree, with the extension
# build.sh made. fiberd gives a zygote no environment but PATH, so this is
# how an in-tree template finds the package.
#
#   -template "default=hack/python/template.sh --heap-mb 32"
#
# The working directory stays as fiberd set it, since a fiber is
# checkpointed there.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
exec env PYTHONPATH="$root/sdk/python/src" python3 -m fiberd.template.ref "$@"
