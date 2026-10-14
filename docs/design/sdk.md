# Design: SDK

This doc explains the SDK under `sdk/`, the two edges other people's code touches, and the rules a template written in a language with a runtime must keep. It is for template authors and readers of `sdk/python`. Read [zygote.md](zygote.md) first, since the C library is the one implementation of the template side and every other language binds it.

## Purpose

A [template](../glossary.md#template) author writes code that runs inside a [fiber](../glossary.md#fiber), and a caller writes code that asks for one. `sdk/c/template` is the template side's C ABI, `libfiberzygote.h`, which `FZ_ABI_VERSION` names and every binding checks at build time. `sdk/go/client` is the Go client. `sdk/python` binds the C library as a CPython extension, `fiberd._zygote`, built against the limited API so one wheel serves every CPython from 3.10, and puts `fiberd.template` over it. The extension is compiled with the same hardening flags as the Makefile's `ZYGOTE_CFLAGS`, so a Python template's library is as hardened as refzygote. `fiberd.client` is the Python client, the messages generated from `api/grant/v1/grant.proto` (`make python-proto`, checked for drift in CI), the four stubs written by hand, and one wrapper mirroring the Go client in sync and `grpc.aio` form. It needs the `client` extra (grpcio and protobuf), so a template never pulls them, and it reads a miss off the status trailer with a wire walker of its own rather than grpcio-status.

## How it works

**The fork.** The library forks with a raw `clone3` and runs no atfork handler. The child is a byte copy of the one thread that called `fz_serve`, with the GIL released. `serve()` runs `PyOS_BeforeFork` once in the zygote, flushes stdio, collects and freezes the garbage collector so warm pages are not copied for nothing, releases the GIL and blocks in `fz_serve`. In each child the C trampoline takes the GIL back, runs `PyOS_AfterFork_Child`, which reinitialises the GIL and the runtime locks and runs every `os.register_at_fork` hook, rebuilds `os.environ` from the scrubbed C `environ`, then calls the author's `on_fiber` with a `Fiber`. When fiberd closes the channel, `fz_serve` returns and the zygote runs `PyOS_AfterFork_Parent`.

```mermaid
sequenceDiagram
  participant A as author
  participant T as fiberd.template
  participant C as libfiberzygote
  A->>T: init()
  T->>C: fz_init, re-exec with ASLR off
  A->>T: serve(on_fiber)
  T->>T: the rules, gc.freeze, PyOS_BeforeFork, release the GIL
  T->>C: fz_serve(3, trampoline)
  C->>C: clone3 per CLONE, scrub, confine
  C->>T: trampoline, in the child
  T->>T: take the GIL, PyOS_AfterFork_Child, os.environ, reseed, hooks
  T->>A: on_fiber(Fiber)
```

**The session.** The CLONE line carries the session the caller named, hex so it may hold any character, and the fiber finds it as `Fiber.session` and `FIBERD_SESSION`. For an anonymous fiber the attribute is empty and the variable is unset.

**Incarnations.** Every copy of the template holds its random state, and a fork is not the only copy. `Fiber.serve` checks the fence file fiberd publishes beside the endpoint before each connection, as refzygote does, so a fiber resumed from a [park](../glossary.md#park) is reseeded before it serves. On every incarnation the SDK reseeds `random`, every `random.Random` registered with `register_random`, and OpenSSL through `ssl.RAND_add`, then runs the `@on_incarnation` hooks in registration order with an `Incarnation(kind, generation, fence, seed)` whose seed is zeroed afterwards. The kind is `fork`, `resume` or, on gVisor, `restore`.

**gVisor.** Nothing forks there. `serve()` notices a sandbox by what it was given, no control socket at descriptor 3 and the Sentry's `/proc/gvisor/checkpoint`, and runs refzygote's `gvisor_main` in Python instead. It touches `/host/warm.ready`, blocks in the checkpoint read, and in every sandbox restored from the image takes the identity on fiberd's channel (`fz_gvisor_identity`), reseeds from the host's 32 bytes mixed with the kernel's, runs the hooks and calls `on_fiber`. `ready()` is `fz_gvisor_ack` there. A pooled sandbox waits in `fz_gvisor_identity` until it is handed out, and a park comes back the same way with kind `resume`. The park's `SIGUSR1` sets `stopping`, `serve` returns with the endpoint closed and unlinked, and the loop waits for the next checkpoint. `init()` tells the library nothing there, since no layout is pinned, and the fork rules below are not checked, since a restored sandbox carries its threads and descriptors with it. The identity record carries the session, so `Fiber.session` is the same on every backend.

**Handoff.** A [handoff](../glossary.md#handoff) fiber listens on nothing. `accept()` takes the next connection fiberd passed down the channel and returns it as an `ssl.SSLSocket`, with TLS 1.3 terminated under the grant's identity. `serve()` does the same for each connection. `accept()` raises `ConnectionResetError` at release and when the fiber is asked to stop. The SDK writes the key and certificate to a sealed memfd and loads them through `/proc/self/fd`, so the key is never a file. `ssl` has no verify callback, so the fiber makes the bound caller's certificate, which the identity message carries, the context's one trust anchor, with `VERIFY_X509_PARTIAL_CHAIN` so OpenSSL takes a leaf as one. Any other certificate fails the handshake, with or without the home's CA behind it. The thumbprint is checked again after the handshake.

**Async.** `on_fiber` may be `async def`. It runs under `asyncio.run` in the fiber, so the loop is born after the fork. `serve_async(handler)` then runs `handler(reader, writer)` for each connection, over `asyncio.start_unix_server`, `start_server` or the handoff channel. `connections()` is the async `accept()`, and waits on the channel with `loop.add_reader`.

## Backends

| Backend | The template is | How a fiber is born | Park and resume | Run from |
| --- | --- | --- | --- | --- |
| proc | a zygote on fiberd's control socket | a fork with the hooks above | CRIU, the fence file reseeds | any CPython with the package installed |
| runc | the same zygote as the init of the grant's container, which appends `--log /host/zygote.log` to the command | the same fork, in the container's user namespace | the same, with the container's mounts named external | a rootfs with CPython and the package in it |
| gVisor | the sandbox's init, checkpointed once warm | a restore of that image, identity on the channel | `runsc checkpoint`, the identity reseeds | the same rootfs, read-only |

`hack/python/rootfs.sh` builds that rootfs for the conformance and integration runs from the dev image's CPython. A template of one's own on runc or gVisor is an [artifact](artifact.md) built from a Python image plus the package.

## The rules serve() enforces

Each refusal is a `TemplateError` whose message names the rule and the fix, and a template that breaks one never warms.

| Rule | Check | Why |
| --- | --- | --- |
| `init()` ran, before any thread | a flag set in this process, and `/proc/self/task` at `init()` | `fz_init` re-execs to turn ASLR off and takes the mount namespace, both of which need one thread |
| one thread | `/proc/self/task` has one entry. The refusal names each other thread's `comm` and tid | a lock another thread holds at the clone stays held in the copy forever. OpenBLAS, tokenizers, torch, grpcio and uvloop start threads the `threading` module never sees |
| no live descriptor but stdio and the control socket | `/proc/self/fd` holds no socket, pipe, epoll, eventfd, timerfd or signalfd. A regular file is a warning, a memfd is fine | the scrub closes every inherited descriptor in the fiber, so a Python object over one is a dangling wrapper. A memory map survives its descriptor |
| the main thread | `threading.main_thread()` | signals and `PyOS_AfterFork_Child` assume it |
| the GIL | `sys._is_gil_enabled()` | abi3 does not cover a free-threaded build, and the rules above assume the GIL |

`serve(threads="warn")` turns the one-thread refusal into a warning, for an author who stops their pools around clones. It is unsupported. Clients, pools and loops are made in `on_fiber`, where they are one fiber's own, and a fiber never forks again.

## Security notes and known gaps

- The string hash seed is set at interpreter start and shared by every fiber of a template, the prefork trade-off every Python server makes.
- A CPython fiber dirties about 2 MiB at birth before it does any work, since every reference count it touches copies a warm page. Measured on proc, it is 2.1 MiB on 3.11, 1.8 MiB on 3.12 and 2.3 MiB on 3.13. A grant's W budget must leave room for that, and the Python conformance run sets 8 MiB where the C one sets 1 MiB.
- A `threads="warn"` template can deadlock a fiber, and the SDK cannot tell.
- The Python client trusts the fiber's certificate from the Clone (`server_cert`) as its one anchor, so another certificate fails the handshake, and it checks the key pin after it. A Python handoff fiber trusts the bound caller's certificate the same way. Both checks after the handshake are a second look, not the first. The grant token is never stored, logged or shown by a repr, and nothing in the client reads the environment.
- A regular file open at `serve()` is closed in the fiber while its Python object thinks it is open.
- On arm64 a parked Python fiber is restored with the interpreter's own pointer-authentication state, which the SDK's objects avoid and the interpreter's may not. `hack/python/rootfs.sh` counts the PAC instructions in every object it copies and refuses only its own extension. On the dev image (Debian bookworm, CPython 3.11) the interpreter, libc, libssl and every stdlib module count zero and `libcrypto.so.3` counts 78, in its arm64 assembly, as the dev image's note on OpenSSL says. A fiber is parked idle in `accept`, with no libcrypto frame on its stack, and a Python fiber parks and resumes on proc, runc and gVisor on the arm64 dev container (a `paca pacg` CPU under Linux 6.12), measured at 21 ms and 30 ms on proc, 559 ms and 151 ms on runc, 570 ms and 47 ms on gVisor. An interpreter built with branch protection, Debian trixie's, would trap in its first signed frame on a FEAT_FPAC CPU, so a rootfs for runc or gVisor keeps a PAC-free interpreter.
