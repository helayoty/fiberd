# The fiberd SDK

The two edges other people's code touches, one folder per language.

| Folder | What it is | For whom |
| --- | --- | --- |
| [c/template/](c/template/README.md) | libfiberzygote, the C library a template links to become a zygote. Also refzygote, the reference template, and the fuzz harnesses | template authors, and every other language's template SDK, which binds it |
| [go/client/](go/client) | The Go client for Clone, Park, Release and Watch, with misses as typed errors | callers of fiberd written in Go, such as the examples |
| [python/](python/README.md) | `fiberd.template`, the Python template SDK over the C library, with its reference template `fiberd.template.ref`, and `fiberd.client`, the Python client with the same calls and misses as the Go one | AI agents written in Python, and their activators |
| [typescript/](typescript/README.md) | `@fiberd/client`, the Node.js client with the same calls and typed misses as the Go one | callers of fiberd written in TypeScript or JavaScript |

`c/template/libfiberzygote.h` is the stable contract. `FZ_ABI_VERSION` in it names the ABI every binding is built against, and a binding checks it at build time. The Go package has no promise beyond this repository, since nothing outside it imports fiberd yet. The contract a template must keep is in [docs/design/zygote.md](../docs/design/zygote.md), and what a binding adds for a language with a runtime is in [docs/design/sdk.md](../docs/design/sdk.md).
