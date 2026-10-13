# fiberd for Python

The Python SDK. `fiberd.template` is for code that runs inside a [fiber](../../docs/glossary.md#fiber), such as an AI agent. `fiberd.client`, for callers of fiberd, comes in a later stage.

## Template

A template warms up once and forks a fiber for every [Clone](../../docs/glossary.md#clone). Call `init()` first, do the warm-up, then `serve(on_fiber)`.

```python
import json
import fiberd.template as ft

ft.init()                                # first line, before any thread
model = load_model()                     # the warm-up, paid once

def on_fiber(f: ft.Fiber) -> int:        # runs in the fiber, a fork of the warm process
    task = json.loads(f.payload)         # the bytes the caller sent with the Clone
    def handle(conn):
        conn.sendall(model.answer(task, conn.recv(4096)))
    f.serve(handle)                      # listens on f.endpoint, reports ready, hands each connection over
    return 0

ft.serve(on_fiber)
```

`fiberd-template pkg.module:on_fiber` runs a module the same way, with `init()` before the import.

A `Fiber` carries `fence`, `fence_parts`, `endpoint`, `kind` (unix or tcp), `payload`, `session`, `env` and `incarnation`. `listen()` returns a bound socket for an author who runs their own server, `ready()` reports to fiberd once listening, `check_fence()` notices a resume, and `stopping` is set when the fiber is asked to stop. `@ft.on_incarnation` runs a function in every copy of the template, after `random` and OpenSSL are reseeded. The rules `serve()` enforces, and why, are in [docs/design/sdk.md](../../docs/design/sdk.md).

## Build and test

The extension needs Linux and a C toolchain. In the dev container, from the repository root.

```bash
make python-test          # build the extension in place and run the unit tests
make conform-proc-python  # C1-C10 against the reference template, fiberd.template.ref
```

Elsewhere, `pip install -e sdk/python` builds it, and `python3 -m pytest sdk/python` runs the unit tests, which start no process. Wheels come in a later stage.
