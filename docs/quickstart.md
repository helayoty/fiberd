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

Linux only for meaningful numbers: Darwin's `fork()` is ~10x slower (the warm/cold ratio collapses to ~2.5x) and `/proc` is absent, so the PSS density measurement is unavailable. On a Mac, run it inside the Linux dev container:

```bash
make linux-check                        # probes cgroup v2, PSI, criu, gcc inside the container
make linux-shell                        # then: gcc -O2 -o /tmp/zb zygote_bench.c && /tmp/zb warm 50 128 4
```

The container (`hack/dev/`) is Debian bookworm with criu 4.1.1 built from source: bookworm because its arm64 userland has no pointer authentication (a process restored from a CRIU or gVisor checkpoint keeps stale PAC keys and traps on Apple silicon, which is what trixie's glibc, musl and gcc defaults would cause), criu 4.x because the 3.17 in bookworm cannot read the 6.17 kernel of GitHub's runners. It is privileged with a private cgroup namespace and a delegated subtree at `/sys/fs/cgroup/fiberd`; it is the workbench for the fork runtime, the W budget, the pressure ladder and CRIU park/resume. `make linux-test` runs the Go tests inside it, `make conform-proc` runs the conformance suite against the fork runtime, and `make overcommit` runs the 2x overcommit storm under a 384 MiB container cap and prints a timeline of grant memory, PSI and parks. Numbers from Docker Desktop's VM are slower than bare metal (fork-to-ready under a 50-way storm measured ~50 ms p50 on an M-series Mac) and are for relative comparison only.

## Go agent

Requires Go 1.26+. Build-time tools (buf, the protoc plugins, golangci-lint) are pinned in `hack/tools/go.mod` and run through `go tool`, so nothing else needs installing; `make help` lists the targets (`make proto` regenerates `api/`, `make lint` runs golangci-lint with the depguard rule that keeps `pkg/core` home-invariant).

The agent speaks gRPC (`api/grant/v1`, see [protocol.md](protocol.md)) on `-listen`; `-http` adds a JSON gateway of the same service for `curl`. Grants are signed JWTs from `grant-issuer`; the agent verifies them offline against the issuer's published keys (`-verifier=jwks`). The issuer is the standalone control plane: while its key set keeps refreshing the grant lane is healthy, and when it goes silent for `-stale-ttl` capacity misses turn from `DEFERRED_FALLBACK` into `SHED`.

```bash
make build                              # binaries land in bin/
export FIBERD_STATE=$(mktemp -d)        # export ONCE - reuse across restarts,
                                        # or the epoch demo always shows 1

# the issuer: one key, discovery + JWKS on :8686
bin/grant-issuer keygen -alg EdDSA -out $FIBERD_STATE/issuer.json
bin/grant-issuer serve -key $FIBERD_STATE/issuer.json -addr 127.0.0.1:8686 &

# the agent, verifying against that issuer
bin/fiberd -node-id node-a -verifier jwks -issuer http://127.0.0.1:8686 \
  -http :8485 -admin-unsafe -stale-ttl 5s &
until curl -sf localhost:8485/healthz >/dev/null; do sleep 0.2; done

# a grant for this node: 2 fibers max, 1 MiB working set each, 10 minute lease
T=$(bin/grant-issuer mint -key $FIBERD_STATE/issuer.json -issuer http://127.0.0.1:8686 \
     -aud node-a -uid g1 -max 2 -w-budget 1Mi -min-tier FIBER_WARM -ttl 10m)
J=$(python3 -c "import json,sys;print(json.dumps(sys.argv[1]))" "$T")   # JSON-encode the token
clone() { curl -s -w ' [http %{http_code}]\n' -X POST localhost:8485/v1/clone -d "$1"; }

clone "{\"grantJwt\":$J,\"session\":\"S\"}"    # kind CREATE, fence g1/1/1
clone "{\"grantJwt\":$J,\"session\":\"S\"}"    # kind ATTACH, same endpoint and fence
curl -s -X POST localhost:8485/v1/park -d '{"fiberId":"g1/1/1"}'
clone "{\"grantJwt\":$J,\"session\":\"S\"}"    # kind RESUME, fence seq 2
clone "{\"grantJwt\":$J,\"image\":\"evil\"}"   # 400: admission completeness
clone "{\"grantJwt\":$J}"                       # anonymous: fills the grant (2/2)
clone "{\"grantJwt\":$J}"                       # 503 + Miss{DEFERRED_FALLBACK}: full, lane healthy

# drop the grant lane (test-only admin control), then the same miss is SHED:
curl -s --unix-socket "$FIBERD_STATE/admin.sock" -X POST http://x/lane -d '{"healthy":false}'
clone "{\"grantJwt\":$J}"                       # 429 + Retry-After + Miss{SHED}

curl -s localhost:8485/v1/status                # running, parked, w_used_bytes, latest fence
cat "$FIBERD_STATE/audit.jsonl"                 # one record per transition, with the fence

kill %2; bin/fiberd -node-id node-a -verifier jwks -issuer http://127.0.0.1:8686 -http :8485 &   # same state dir
until curl -sf localhost:8485/healthz >/dev/null; do sleep 0.2; done
curl -s localhost:8485/healthz                  # epoch 1 -> 2: every prior fence is invalid
curl -s -X POST localhost:8485/v1/park -d '{"fiberId":"g1/1/1"}'            # 404: unknown in this epoch

# an expired grant is a capacity miss, not an auth error (revocation = lease non-renewal):
E=$(bin/grant-issuer mint -key $FIBERD_STATE/issuer.json -issuer http://127.0.0.1:8686 -aud node-a -ttl -1m)
clone "{\"grantJwt\":$(python3 -c "import json,sys;print(json.dumps(sys.argv[1]))" "$E")}"   # 503 DEFERRED_FALLBACK
kill %1                                          # stop the issuer; after -stale-ttl the same call is 429 SHED
```

Pre-warming: drop `*.jwt` files into `-grants-dir` and the agent admits them (and warms their template) before the first `Clone`; removing a file revokes the grant. `-verifier=insecure-json` accepts unsigned protobuf-JSON grants for development only.

Templates as artifacts (Linux, needs the dev container and a registry): `make registry-start` runs a local OCI registry, `make zygote-artifact` builds the reference zygote into an artifact (executable, config, CRIU images of the warm zygote) and pushes it, printing the digest to put in a grant's `template_digest`. A home started with `-runtime proc -registry fiberd-registry:5000/zygotes/ref -registry-plain-http` pulls any digest it is asked for into `<state>/templates/` and warms from it. `bin/zygotectl inspect -dir bin/zygote-artifact` shows the config, the digest, and whether this host could warm from its images (`usable_here`): the artifact records the build host's arch, kernel and libc, and a home refuses images from another kernel or libc unless started with `-parity kernel=series`, `-parity kernel=off,libc=off` or `-parity off` (the architecture always has to match).

The runc backend (Linux, needs `runc` and `criu`; the dev container has both) puts the same fork zygote inside an OCI container: `fiberd -runtime runc -runc-rootfs <dir> -template "default=/bin/refzygote --heap-mb 32"` with the rootfs from `hack/gvisor/rootfs.sh`; fibers are forks inside the container, parks are CRIU deltas, and `make conform-runc` runs the conformance suite against it.

The Hyperlight backend drives a helper process over `hack/hyperlight/PROTOCOL.md`: `fiberd -runtime hyperlight -hyperlight-helper bin/hyperlight-helper -hyperlight-guest bin/hyperlight-guest -template "default=guest --heap-mb 32"`. `make hyperlight-helper` builds the Rust helper and guest in the dev container; running them needs a hypervisor, so `make linux-hyperlight-check` and `make conform-hyperlight` pass `/dev/kvm` into the container and are what CI runs. Without one, `make conform-hyperlight-fake` runs the same backend and conformance suite over the Go fake helper.

The gVisor backend (Linux, needs `runsc`; the dev container has it): `hack/gvisor/rootfs.sh <dir>` builds a rootfs with a static reference workload, then `fiberd -runtime gvisor -gvisor-rootfs <dir> -template "default=/bin/refzygote --heap-mb 32 --gvisor"` serves `FIBER_SNAPSHOT` fibers, each its own sandbox restored from the warm template's image. `make conform-gvisor` runs the conformance suite against it and `make linux-gvisor-check` probes what runsc can do on this host. Flags: `-runsc`, `-gvisor-overhead` (0 = measured with a probe restore), `-gvisor-debug`.

Moving a session between homes: with the registry up, `make mobility` runs `hack/test/mobility.sh` in the dev container. It starts two agents (`home-a`, `home-b`) with their own grants for one template and `-delta-registry fiberd-registry:5000/deltas`, counts to three in a session on A, parks it (the delta is published), clones the same session name on B (it is pulled, claimed and resumed with the count), shows that A now refuses its stale copy, then parks on B and resumes on A again. The log lines it prints (`parked`, `published`, `claimed`) show the W bytes that actually travelled.

To run the protocol conformance suite against this or any other target: `make conform-stub` stands up a stub agent and runs all seven cases over unsigned grants, `make conform-signed` does the same with a live issuer and real JWTs; `bin/grant-conform -target host:port -node-id <audience> -mint jwt -issuer-key key.json -issuer <url> [-restart-cmd ... -cp-health-cmd ... -audit-file ...]` runs them against a target you manage (see `cmd/grant-conform/main.go` for the hook contract; cases without their hook are skipped).

With `grpcurl` the same calls go to `localhost:8484` (`grpcurl -plaintext -proto api/grant/v1/grant.proto -d '{...}' localhost:8484 fiberd.grant.v1.Fibers/Clone`), and `Fibers/Watch` streams status.

## Notes

- `000` from `curl` means the loop outran server startup - always poll `/healthz` first.
- `/healthz` HTTP 200 means the process is up; `grantLaneHealthy` is grant-lane liveness (idle is not down), not readiness.
- The thrash budget defaults to 200 clones/s; pass `-base-rate 5` to see budget SHED from a sequential loop.
- `-lane-dies-after 2s` simulates the lane dying on its own; `-stale-ttl` is how long silence counts as healthy.
- A `Miss` whose `code` is absent in JSON is `SHED`: it is the enum's zero value and protobuf JSON omits it.
- `-verifier=insecure-json` is development only; nothing is signed. Phase 2 replaces it with JWT + JWKS.
