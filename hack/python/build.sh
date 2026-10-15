#!/usr/bin/env bash
# Build the fiberd._zygote extension in place, beside the sources in
# sdk/python/src/fiberd, so the package runs from the tree with
# PYTHONPATH=sdk/python/src (see template.sh). Linux only, inside the dev
# container. Objects go to a scratch directory, never into the tree.
#
#   hack/python/build.sh
set -euo pipefail
cd "$(dirname "$0")/../../sdk/python"
# sid's crti.o and crtn.o sign _init and _fini, which would put four PAC
# instructions into our extension, so the link takes the dev image's
# PAC-free sysroot (docker/dev/Dockerfile) when it has one. -B puts its
# start files ahead of the -L the interpreter's sysconfig adds, which
# gcc searches for them too. setuptools reads LDSHARED from the
# environment.
sysroot=${FIBERD_SYSROOT:-/usr/local/sysroot-nopac}
if [ -d "$sysroot/usr/include" ]; then
  LDSHARED="$(python3 -c 'import sysconfig; print(sysconfig.get_config_var("LDSHARED"))') --sysroot=$sysroot -B$sysroot/usr/lib/$(gcc -print-multiarch)"
  export LDSHARED
fi
python3 setup.py -q build_ext --inplace --build-temp "${FIBERD_PYTHON_BUILD:-/tmp/fiberd-python-build}"
