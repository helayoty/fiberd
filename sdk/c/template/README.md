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

One rule on randomness. Every copy of the template holds its random state, and a fork is not the only copy. Reseed every generator the template owns in each new run, from the 32-byte seed on the fiber's record (`fz_incarnation_t.seed`) mixed with `getrandom`, as `refzygote.c` does in `reseed_rngs_from`. That is in `on_fiber`, after a restore returns (gVisor) and when `fz_incarnation_poll`, called before each connection, hands over the record a CRIU resume wrote on the fiber's channel (proc or runc). The library zeroes the seed at `fz_fiber_ready`, and `fz_seed_forget` zeroes a polled one once the generators are reseeded. `getrandom` itself answers afresh after a resume, since fiberd parks only with a criu that leaves libc's vDSO random state out of the dump ([backends.md](../../../docs/design/backends.md)).

On gVisor there is no fork. The template runs as a sandbox's init, checkpoints itself, and every fiber is a sandbox restored from that image. After its checkpoint read answers `restore`, it calls `fz_gvisor_identity`, which blocks until fiberd hands it the same record a forked fiber gets, with the fence, the endpoint, the payload, the session, the generation and the seed, on a channel. It reseeds from that seed, binds the endpoint and calls `fz_gvisor_ack`, which zeroes the seed, as `refzygote.c` does in `gvisor_main`. A template that cannot get its record exits with 122.
