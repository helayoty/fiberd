# libfiberzygote

The library a [template](../../../docs/glossary.md#template) links to become a fiberd [zygote](../../../docs/glossary.md#zygote). fiberd starts the template, which warms up once and then forks a [fiber](../../../docs/glossary.md#fiber) for every [Clone](../../../docs/glossary.md#clone). `libfiberzygote.h` is the C API, `core/` is the library itself, a Rust crate that builds a static archive with that API, and `refzygote.c` is the reference template the tests and images use. `core/fuzz/` holds the library's cargo-fuzz targets, and `fuzz/` the libFuzzer harness of refzygote.

Build a template from source. The library needs cargo.

```bash
(cd core && cargo build --release --locked)
cc -O2 -pthread -o mytemplate main.c core/target/release/libfiberzygote_core.a
```

Or link the prebuilt static library from a release.

```bash
cc -O2 -pthread -o mytemplate main.c -L. -lfiberzygote
```

On arm64, add `-mbranch-protection=none` to the whole program.

An engine template formats its report line itself and hands it to `fz_report_line`, which adds the newline.

```c
char line[FZ_REPORT_MAX];
snprintf(line, sizeof line, "DEVICE %s %llu 0", fence, bytes);
fz_report_line(line);
```

fiberd launches the template itself. Map the grant's template digest to its command with `-template`, such as `-template "default=/path/to/mytemplate --flag"`, where `default` matches any digest. `zygotectl build` and `zygotectl push` instead publish it as an artifact that a home pulls by digest.

`zygotectl build` runs the template the way a home does, waits for READY and checkpoints it with criu. The checkpoint is the template's memory, so it is sealed to the fleet's public wrap key, `-seal-to fleet-pub.json`, which `grant-issuer keygen -alg A256GCM` writes beside the fleet's seal key. Only homes holding that seal key open it ([artifact.md](../../../docs/design/artifact.md)). A build with a checkpoint and no `-seal-to` is refused. With `-skip-images` it takes no checkpoint and needs no criu, but still runs the template to READY once as a smoke test, so a template that cannot start fails the build rather than its first warm. `-no-smoke` skips that run, for a slow warm-up or a template the build host cannot run, such as a `--gvisor` one, which waits on `/proc/gvisor/checkpoint` that only a sandbox has.

The contract for template authors, the wire protocol and the fork-safety rules are in [docs/design/zygote.md](../../../docs/design/zygote.md).

One rule on randomness. Every copy of the template holds its random state, and a fork is not the only copy. Reseed every generator the template owns in each new run, from the 32-byte seed on the fiber's record (`fz_incarnation_t.seed`) mixed with `getrandom`, as `refzygote.c` does in `reseed_rngs_from`. That is in `on_fiber`, after a restore returns (gVisor) and when `fz_incarnation_wait` hands over the record a CRIU resume wrote on the fiber's channel (proc or runc). The library zeroes the seed at `fz_fiber_ready`, and `fz_seed_forget` zeroes one sooner once the generators are reseeded.

One rule on parks. A park is cooperative. On `SIGUSR1` the template stops serving, closes its listener and every connection it accepted, calls `fz_quiesce` and blocks in `fz_incarnation_wait`, as `refzygote.c` does between connections. The wait returns the resume's record, after which the template reseeds, listens again and calls `fz_fiber_ready`, which acks, or 0 when the park failed and the fiber serves on. A template that keeps serving is never parked, and a resumed one that never acks is ended. Keep `SIGUSR1` blocked and let it through only inside `ppoll` before every blocking wait, the accept, the channel and each read, as `refzygote.c` does in `wait_readable`, so the signal can never land between a look at the park flag and a wait that nothing else would end. The park waits the grant's resume deadline, so a long request looks at the signal as it goes, as `refzygote.c` does in `dirty`, since the signal comes under memory pressure when every page fault is throttled. `getrandom` itself answers afresh after a resume, since fiberd parks only with a criu that leaves libc's vDSO random state out of the dump ([backends.md](../../../docs/design/backends.md)).

On gVisor there is no fork. The template runs as a sandbox's init, checkpoints itself, and every fiber is a sandbox restored from that image. After its checkpoint read answers `restore`, it calls `fz_gvisor_identity`, which blocks until fiberd hands it the same record a forked fiber gets, with the fence, the endpoint, the payload, the session, the generation and the seed, on a channel. It reseeds from that seed, binds the endpoint and calls `fz_gvisor_ack`, which zeroes the seed, as `refzygote.c` does in `gvisor_main`. A template that cannot get its record exits with 122.
