"""The one extension, fiberd._zygote, over sdk/c/template/libfiberzygote.c.

The extension is built against the limited API (abi3, CPython 3.14 and
later) and compiled with the Makefile's ZYGOTE_CFLAGS, with -fPIC in place
of -fPIE since it is a shared object. Off Linux there is no extension, and
fiberd.template says so when it is used. The unit tests beside the sources
and their conftest are left out of the wheel. The sdist keeps them, for the
wheel test (wheel-test.sh).

The version is FIBERD_PYTHON_VERSION, which the release workflow sets from
the tag (v0.2.0-rc.1 is 0.2.0rc1). An sdist carries it in PKG-INFO, so a
wheel built from the sdist has it too. A build with neither is 0.0.0.dev0+local,
which PyPI refuses.
"""

from __future__ import annotations

import os
import platform
import shutil
import sys

from setuptools import Extension, setup
from setuptools.command.build_py import build_py as _build_py
from setuptools.command.sdist import sdist as _sdist

HERE = os.path.abspath(os.path.dirname(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", ".."))

# The C library is sdk/c/template in the tree. An sdist holds nothing outside
# this directory, so it carries a copy in libfiberzygote/.
C_SDIST = "libfiberzygote"
C_DIR = os.path.join(HERE, C_SDIST)
if not os.path.isdir(C_DIR):
    C_DIR = os.path.join(REPO, "sdk", "c", "template")
C_FILES = ("libfiberzygote.c", "libfiberzygote.h")

# Mirrors ZYGOTE_CFLAGS and ZYGOTE_LDFLAGS in the Makefile. The -U comes
# first because the interpreter's own flags may define _FORTIFY_SOURCE.
CFLAGS = [
    "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=3", "-O2", "-fstack-protector-strong", "-fstack-clash-protection",
    "-fPIC", "-Wformat=2", "-Werror=format-security", "-Wall", "-Wextra",
]
if platform.machine() in ("aarch64", "arm64"):
    CFLAGS.append("-mbranch-protection=none")
LDFLAGS = ["-Wl,-z,relro,-z,now"]


def is_test_module(name: str) -> bool:
    """A unit test or one of its helpers (conftest, _testtable, _testhome)."""
    return name.endswith("_test") or name.startswith("_test") or name == "conftest"


def version() -> str:
    v = os.environ.get("FIBERD_PYTHON_VERSION")
    if v:
        return v
    try:
        with open(os.path.join(HERE, "PKG-INFO"), encoding="utf-8") as fp:
            for line in fp:
                if line.startswith("Version:"):
                    return line.split(":", 1)[1].strip()
    except FileNotFoundError:
        pass
    return "0.0.0.dev0+local"


class build_py(_build_py):
    """Leaves the unit tests and their helpers out of the wheel."""

    def find_package_modules(self, package, package_dir):
        return [m for m in super().find_package_modules(package, package_dir) if not is_test_module(m[1])]


class sdist(_sdist):
    """Adds the C library, LICENSE and NOTICE, which live outside this directory."""

    def make_release_tree(self, base_dir, files):
        super().make_release_tree(base_dir, files)
        self.mkpath(os.path.join(base_dir, C_SDIST))
        for name in C_FILES:
            shutil.copyfile(os.path.join(C_DIR, name), os.path.join(base_dir, C_SDIST, name))
        for name in ("LICENSE", "NOTICE"):
            src = os.path.join(HERE, name)
            if not os.path.exists(src):
                src = os.path.join(REPO, name)
            shutil.copyfile(src, os.path.join(base_dir, name))


ext_modules = []
if sys.platform == "linux":
    ext_modules.append(Extension(
        "fiberd._zygote",
        # Relative and inside the package, since setuptools refuses absolute
        # sources in a wheel. _libfiberzygote.c includes the library source.
        sources=["src/fiberd/_zygote.c", "src/fiberd/_libfiberzygote.c"],
        include_dirs=[C_DIR],
        define_macros=[("Py_LIMITED_API", "0x030E0000")],
        py_limited_api=True,
        extra_compile_args=CFLAGS,
        extra_link_args=LDFLAGS,
    ))

os.chdir(HERE)
setup(version=version(), ext_modules=ext_modules, cmdclass={"build_py": build_py, "sdist": sdist})
