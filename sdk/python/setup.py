"""The one extension, fiberd._zygote, over sdk/c/template/libfiberzygote.c.

The extension is built against the limited API (abi3, CPython 3.10 and
later) and compiled with the Makefile's ZYGOTE_CFLAGS, with -fPIC in place
of -fPIE since it is a shared object. Off Linux there is no extension, and
fiberd.template says so when it is used. The unit tests beside the sources
and their conftest are left out of the package.
"""

from __future__ import annotations

import os
import platform
import sys

from setuptools import Extension, setup
from setuptools.command.build_py import build_py as _build_py

HERE = os.path.abspath(os.path.dirname(__file__))
C_DIR = os.path.normpath(os.path.join(HERE, "..", "c", "template"))

# Mirrors ZYGOTE_CFLAGS and ZYGOTE_LDFLAGS in the Makefile. The -U comes
# first because the interpreter's own flags may define _FORTIFY_SOURCE.
CFLAGS = [
    "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=3", "-O2", "-fstack-protector-strong", "-fstack-clash-protection",
    "-fPIC", "-Wformat=2", "-Werror=format-security", "-Wall", "-Wextra",
]
if platform.machine() in ("aarch64", "arm64"):
    CFLAGS.append("-mbranch-protection=none")
LDFLAGS = ["-Wl,-z,relro,-z,now"]

TEST_MODULES = ("conftest", "_testtable", "_testhome")


class build_py(_build_py):
    """Leaves the unit tests and their helpers out of the package."""

    def find_package_modules(self, package, package_dir):
        return [m for m in super().find_package_modules(package, package_dir)
                if not m[1].endswith("_test") and m[1] not in TEST_MODULES]


ext_modules = []
if sys.platform == "linux":
    ext_modules.append(Extension(
        "fiberd._zygote",
        # Relative and inside the package, since setuptools refuses absolute
        # sources in a wheel. _libfiberzygote.c includes the library source.
        sources=["src/fiberd/_zygote.c", "src/fiberd/_libfiberzygote.c"],
        include_dirs=[C_DIR],
        define_macros=[("Py_LIMITED_API", "0x030A0000")],
        py_limited_api=True,
        extra_compile_args=CFLAGS,
        extra_link_args=LDFLAGS,
    ))

os.chdir(HERE)
setup(ext_modules=ext_modules, cmdclass={"build_py": build_py})
