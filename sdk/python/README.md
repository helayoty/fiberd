# fiberd for Python

The Python SDK. `fiberd.template` is for code that runs inside a [fiber](../../docs/glossary.md#fiber), such as an AI agent. `fiberd.client` is for callers of fiberd, such as the activator that asks for one.

## Install

```bash
pip install fiberd
```

The wheels are for CPython 3.14 or later on Linux, x86_64 or aarch64, with glibc 2.28 or later. Anywhere else pip builds the sdist. On Linux that needs a C compiler, the Python headers and cargo. The build needs no network. Off Linux it builds without the extension. There `fiberd.client` works and `fiberd.template` raises `ImportError` when used.

## Template

A template warms up once and forks a fiber for every [Clone](../../docs/glossary.md#clone). Call `init()` first, do the warm-up, then `serve(on_fiber)`.

```python
import json
import fiberd.template as ft

ft.init()                                # first line, before any thread

# Your own slow setup goes here (imports, model weights, config). It runs
# once, and every fiber is a fork of this process, born with it loaded.
with open("prompts.json") as fp:
    prompts = json.load(fp)

def on_fiber(f: ft.Fiber) -> int:        # runs in the fiber
    task = json.loads(f.payload)         # the bytes the caller sent with the Clone
    def handle(conn):
        question = conn.recv(4096).decode()
        conn.sendall(f"{prompts[task['kind']]} {question}".encode())
    f.serve(handle)                      # listens on f.endpoint, reports ready, hands each connection over
    return 0

ft.serve(on_fiber)
```

`fiberd-template pkg.module:on_fiber` runs a module the same way, with `init()` before the import.

A `Fiber` carries `fence`, `fence_parts`, `endpoint`, `kind` (unix, tcp or handoff), `payload`, `session`, `env`, `incarnation` and `backend` (fork or gvisor). `listen()` returns a bound socket for an author who runs their own server, `ready()` reports to fiberd once listening, in every incarnation, `parking` is set when fiberd asks for a park and `park()` answers it once nothing is served, and `stopping` is set when the fiber is asked to stop. `@ft.on_incarnation` runs a function in every copy of the template, after `random` and OpenSSL are reseeded. The rules `serve()` enforces, and why, are in [docs/design/sdk.md](../../docs/design/sdk.md).

A [handoff](../../docs/glossary.md#handoff) fiber listens on nothing. `f.serve(handle)` works the same there. Each `conn` is an `ssl.SSLSocket`, with TLS terminated under the grant's identity and the bound caller's certificate the one the handshake admits, as `f.accept()` returns it.

`on_fiber` may be `async def`. Then `await f.serve_async(handler)` serves an `async def handler(reader, writer)`, and `async for reader, writer in f.connections()` is the async twin of `accept()`.

## Client

A caller holds a signed [grant](../../docs/glossary.md#grant) and asks a [home](../../docs/glossary.md#home) for fibers under it. `pip install 'fiberd[client]'` adds grpcio and protobuf, which a template never needs.

```python
import time
from fiberd.client import Client, Shed, Deferred

def clone(c, jwt, session):
    while True:
        try:
            return c.clone(jwt, session=session, payload=b'{"task":1}')  # a Fiber, with id, fence, endpoint and kind
        except Shed as e:                                                 # the home is busy, retry after the hint
            time.sleep(e.retry_after)

with Client.dial_tls("home:7443", cert="me.pem", key="me-key.pem", ca="ca.pem") as c:
    try:
        f = clone(c, jwt, "conv-42")
    except Deferred as e:              # this home cannot serve it, take the ordinary path or go to e.preferred_home
        raise SystemExit(f"deferred: {e.reason}")
    with f.dial() as sock:             # its unix or tcp endpoint
        sock.sendall(b"hello\n")
    c.park(f)                          # checkpoint it and free its place
    f = clone(c, jwt, "conv-42")       # kind RESUME, under the next fence
    c.release(f, discard=True)         # end it, and drop its parked delta
```

`Client.dial(addr)` is the plaintext form for a home started with `-insecure-plaintext`. A [handoff](../../docs/glossary.md#handoff) fiber is reached with `f.dial_handoff(cert, key)`, which sends its routing key as the server name, admits only the fiber's certificate from the Clone in the handshake and checks its key pin after it. `TierGap` and `NotFound` are the other typed outcomes, and any other failure is the `grpc.RpcError` as raised. `c.watch()` yields one status per grant as the home publishes it. `fiberd.client.aio.Client` has the same methods as coroutines, with `watch` as an async iterator. The token is accepted as a string or a callable that returns one, and it is never stored, logged or shown by a repr.

## Build and test

The extension needs Linux, a C toolchain and cargo. In the dev container, from the repository root.

```bash
make python-test            # build the extension in place and run the unit tests
make conform-proc-python    # C1-C10 against the reference template, fiberd.template.ref
make conform-gvisor-python  # the same on gVisor, from a rootfs hack/python/rootfs.sh builds with CPython in it
make conform-runc-python    # and on runc, from the same rootfs
make python-dist            # the sdist, a wheel built from it, and the unit tests against that wheel
```

The same template serves on proc, runc and gVisor. On runc and gVisor it runs from a root filesystem that holds the interpreter and the package, which `hack/python/rootfs.sh <dir>` builds from the dev image for those runs.

Elsewhere, `pip install -e 'sdk/python[client]' cryptography` builds it with what the client's tests import, and `python3 -m pytest sdk/python` runs the unit tests, which start no process.
