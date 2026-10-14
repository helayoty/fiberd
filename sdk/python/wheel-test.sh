#!/bin/sh
# Run the unit tests against an installed fiberd, not the sources.
# cibuildwheel runs it after it installs each wheel, with the extracted
# sdist as the argument. The wheel leaves the tests out, so they are copied
# beside the installed package and pytest runs there. Use it only in a
# throwaway environment, since it writes into that package.
#
#   sh wheel-test.sh <sdist or sdk/python directory>
set -eu
src="$1/src/fiberd"
pkg=$(cd / && python -c 'import fiberd, os; print(os.path.dirname(os.path.realpath(fiberd.__file__)))')
case "$pkg" in
  "$(cd "$src" && pwd -P)") echo "wheel-test.sh: fiberd imports from $pkg, the sources, not an install" >&2; exit 1 ;;
esac
# The extension must be in the wheel on Linux. The tests replace it, so
# this import is the one check that it loads.
if [ "$(uname -s)" = Linux ]; then
  (cd / && python -c 'from fiberd import _zygote; print("fiberd._zygote", _zygote.__file__)')
fi
(cd "$src" && find . \( -name '*_test.py' -o -name conftest.py -o -name '_test*.py' \) -print | tar -cf - -T -) |
  tar -C "$pkg" -xf -
cd "$pkg/.."
PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider --rootdir . -o python_files='*_test.py' fiberd
