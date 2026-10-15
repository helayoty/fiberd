# libfiberzygote

The C library a [template](../../../docs/glossary.md#template) links to become a fiberd [zygote](../../../docs/glossary.md#zygote). fiberd starts the template, which warms up once and then forks a [fiber](../../../docs/glossary.md#fiber) for every [Clone](../../../docs/glossary.md#clone). `libfiberzygote.h` is the API, `refzygote.c` is the reference template the tests and images use, and `fuzz/` holds the libFuzzer harnesses.

Build a template from source.

```bash
cc -O2 -pthread -o mytemplate main.c libfiberzygote.c
```

Or link the prebuilt static library from a release.

```bash
cc -O2 -pthread -o mytemplate main.c -L. -lfiberzygote
```

On arm64, add `-mbranch-protection=none` to the whole program.

fiberd launches the template itself. Map the grant's template digest to its command with `-template`, such as `-template "default=/path/to/mytemplate --flag"`, where `default` matches any digest. `zygotectl build` and `zygotectl push` instead publish it as an artifact that a home pulls by digest.

The contract for template authors, the wire protocol and the fork-safety rules are in [docs/design/zygote.md](../../../docs/design/zygote.md).

One rule on randomness. Every copy of the template holds its random state, and a fork is not the only copy. Reseed every generator the template owns in each new run, not only in `on_fiber`. That is after a restore returns (gVisor) and when the fence file fiberd publishes changes (a CRIU resume on proc or runc, [runtime-host.md](../../../docs/design/runtime-host.md) says where it is), as `refzygote.c` does in `reseed_rngs`. `getrandom` itself answers afresh after a resume, since fiberd parks only with a criu that leaves libc's vDSO random state out of the dump ([backends.md](../../../docs/design/backends.md)).

On gVisor there is no fork. The template runs as a sandbox's init, checkpoints itself, and every fiber is a sandbox restored from that image. After its checkpoint read answers `restore`, it calls `fz_gvisor_identity`, which blocks until fiberd hands it a fence, an endpoint, a payload, the session and 32 bytes of fresh entropy on a channel. It reseeds from that seed, binds the endpoint and calls `fz_gvisor_ack`, as `refzygote.c` does in `gvisor_main`. A template that cannot get its identity exits with 122.
