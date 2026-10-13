"""fiberd-template pkg.module:on_fiber, which runs init() before the module is imported.

For an author who wants the ordering enforced for them. The module's
import is the warm-up, and the named function is on_fiber.
"""

from __future__ import annotations

import argparse
import importlib
import sys

import fiberd.template as ft


def resolve(target: str):
    """The callable a pkg.module:name target names, after importing the module."""
    module, _, attr = target.partition(":")
    if not module:
        raise ft.TemplateError(f"{target!r} is not pkg.module:on_fiber")
    mod = importlib.import_module(module)
    fn = getattr(mod, attr or "on_fiber", None)
    if not callable(fn):
        raise ft.TemplateError(f"{module} has no callable {attr or 'on_fiber'}")
    return fn


def main(argv: list[str] | None = None) -> int:
    ft.init()
    p = argparse.ArgumentParser(prog="fiberd-template", description="run a Python module as a fiberd template")
    p.add_argument("target", help="pkg.module:on_fiber (the function defaults to on_fiber)")
    p.add_argument("--threads", choices=("refuse", "warn"), default="refuse", help='what to do about extra threads at serve (default refuse)')
    args = p.parse_args(argv)
    return ft.serve(resolve(args.target), threads=args.threads)


if __name__ == "__main__":
    sys.exit(main())
