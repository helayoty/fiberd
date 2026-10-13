"""table() parametrizes a unit test over a cases table whose first field is the name. Not shipped (see setup.py)."""

from __future__ import annotations

import pytest


def table(cases):
    return pytest.mark.parametrize(
        "name," + ",".join(f"f{i}" for i in range(len(cases[0]) - 1)), cases, ids=[c[0] for c in cases]
    )
