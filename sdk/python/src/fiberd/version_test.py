"""fiberd.__version__, read from the install's metadata on first use."""

from __future__ import annotations

from importlib import metadata

import pytest

import fiberd
from fiberd._testtable import table


def _installed() -> str:
    try:
        return metadata.version("fiberd")
    except metadata.PackageNotFoundError:
        return "0.0.0.dev0+local"


def _missing(_name):
    raise metadata.PackageNotFoundError("fiberd")


CASES = [
    # name, the metadata lookup (None for the real one), the version wanted
    ("the install's version", None, _installed()),
    ("from the sources, with no install", _missing, "0.0.0.dev0+local"),
]


@table(CASES)
def test_version(monkeypatch, name, f0, f1):
    if f0 is not None:
        monkeypatch.setattr(metadata, "version", f0)
    assert fiberd.__version__ == f1


@table([("an unknown name", "nope"), ("a dunder other than __version__", "__author__")])
def test_unknown_attribute(name, f0):
    with pytest.raises(AttributeError, match=f0):
        getattr(fiberd, f0)
