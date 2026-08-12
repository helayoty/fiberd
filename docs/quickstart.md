# fiberd Quickstart

How to build and exercise the two pieces of the prototype locally. All commands run from the repository root (`fiberd/`).

There are two independent parts, split along the design's own seam:

- `zygote_bench.c` - the **mechanism**: real `fork()` + copy-on-write cloning, measured.
- the Go agent under `cmd/` and `pkg/` - the **semantics**: the warm-path contract (`core/` never forks; `adapter/` and `runtime/` are the seams). Stdlib-only, builds anywhere.

For what these exercises prove and their current status, see [status.md](status.md).

## Mechanism bench (C)

Optional and independent of the Go core; it measures raw fork/CoW, which the Go core's stub runtime does not yet perform.

```bash
gcc -O2 -o zb zygote_bench.c
./zb warm 50 128 4 && ./zb cold 8 128
```

Linux only for meaningful numbers: Darwin's `fork()` is ~10x slower (the warm/cold ratio collapses to ~2.5x) and `/proc` is absent, so the PSS density measurement is unavailable. On a Mac, run it inside a Linux container for real numbers.

## Go agent

Requires Go 1.26+.

```bash
go build -o fiberd ./cmd/fiberd

export FIBERD_STATE=$(mktemp -d)        # export ONCE - reuse across restarts,
                                        # or the epoch demo always shows 1
FIBERD_BASE_RATE=5 ./fiberd &           # 5 clones/sec so the shed demo can trip
until curl -sf localhost:8484/healthz >/dev/null; do sleep 0.2; done

# warm path - anonymous fiber:
curl -s -X POST localhost:8484/v0/clone -d '{"GrantUID":"demo"}'

# named session twice - 2nd call returns Resumed:true, same Endpoint (attach):
curl -s -X POST localhost:8484/v0/clone -d '{"GrantUID":"demo","Session":"S1"}'
curl -s -X POST localhost:8484/v0/clone -d '{"GrantUID":"demo","Session":"S1"}'

# over-budget burst -> mostly 429 + Retry-After (SHED) once the 5-token burst drains:
for i in $(seq 1 30); do curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST localhost:8484/v0/clone -d '{"GrantUID":"demo"}'; done | sort | uniq -c

kill %1 && ./fiberd &                    # same FIBERD_STATE -> epoch 1 -> 2
until curl -sf localhost:8484/healthz >/dev/null; do sleep 0.2; done
curl -s localhost:8484/healthz           # fence rotation = revocation, node-local
```

## Notes

- `000` from `curl` means the loop outran server startup - always poll `/healthz` first.
- A sequential `curl` loop cannot outrun the default 200/s budget; that is why the shed demo pins `FIBERD_BASE_RATE=5`.
- Auth is a stub (`JWKSVerifier` accepts everything) - localhost only.
