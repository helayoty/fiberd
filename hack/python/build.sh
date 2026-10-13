#!/usr/bin/env bash
# Build the fiberd._zygote extension in place, beside the sources in
# sdk/python/src/fiberd, so the package runs from the tree with
# PYTHONPATH=sdk/python/src (see template.sh). Linux only, inside the dev
# container. Objects go to a scratch directory, never into the tree.
#
#   hack/python/build.sh
set -euo pipefail
cd "$(dirname "$0")/../../sdk/python"
python3 setup.py -q build_ext --inplace --build-temp "${FIBERD_PYTHON_BUILD:-/tmp/fiberd-python-build}"
