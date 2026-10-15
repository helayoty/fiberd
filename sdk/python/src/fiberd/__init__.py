"""The fiberd SDK.

``fiberd.template`` is for code that runs inside a fiber. ``fiberd.client``
is for callers of fiberd and needs the ``client`` extra.
"""


def __getattr__(name: str) -> str:
    # __version__ is looked up on first use, so a template's import pays
    # nothing for it. A run from the sources has no install to ask.
    if name == "__version__":
        from importlib.metadata import PackageNotFoundError, version

        try:
            return version("fiberd")
        except PackageNotFoundError:
            return "0.0.0.dev0+local"
    raise AttributeError(f"module 'fiberd' has no attribute {name!r}")
