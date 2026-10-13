# The fiberd SDK

The two edges other people's code touches, one folder per language.

| Folder | What it is | For whom |
| --- | --- | --- |
| [c/](c/README.md) | libfiberzygote, the C library a template links to become a zygote. Also refzygote, the reference template, and the fuzz harnesses | template authors, and every other language's template SDK, which binds it |
| [go/consumer/](go/consumer) | The Go client for Clone, Park, Release and Watch, with misses as typed errors | callers of fiberd written in Go, such as the examples |
| [python/](python/README.md) | `fiberd.template`, the Python template SDK over the C library, with its reference template `fiberd.template.ref`. `fiberd.client` is not here yet | AI agents written in Python, and later their activators |

`c/libfiberzygote.h` is the stable contract. `FZ_ABI_VERSION` in it names the ABI every binding is built against, and a binding checks it at build time. The Go package has no promise beyond this repository, since nothing outside it imports fiberd yet. The contract a template must keep is in [docs/design/zygote.md](../docs/design/zygote.md), and what a binding adds for a language with a runtime is in [docs/design/sdk.md](../docs/design/sdk.md).
