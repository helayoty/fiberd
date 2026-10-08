# libfiberzygote

The library a template links to become a fiberd zygote. fiberd starts the
template, which warms up once and then forks a fiber for every Clone.
`libfiberzygote.h` documents the API and the protocol it speaks with the agent.
`refzygote.c` is the reference template that the tests and images use.

Build a template from source.

```bash
cc -O2 -pthread -o mytemplate main.c libfiberzygote.c
```

Or link the prebuilt static library from a release.

```bash
cc -O2 -pthread -o mytemplate main.c -L. -lfiberzygote
```

On arm64, add `-mbranch-protection=none` to the whole program. A process that
CRIU restores cannot run pointer-authentication instructions signed before the
checkpoint.

The library needs Linux 5.3 or later for `clone3`. Older kernels fall back to
`fork`.
