# Quickstart

Build fiberd, run an agent on this machine, and exercise the four protocol
operations. This page covers the runnable path. The conceptual guides explain
the results, while each environment and consumer has its own example README.

## Build

Go 1.26 or newer. The build tools are pinned in `hack/tools/go.mod` and run through `go tool`; nothing else needs installing.

```bash
make build      # bin/fiberd, bin/grant-issuer, bin/zygotectl
```

## Run the protocol on this machine

The in-memory runtime runs anywhere. The agent speaks gRPC on `-listen` and, with `-http`, a JSON gateway of the same service. Grants are signed JWTs from `grant-issuer`, verified offline against the issuer's published keys.

```bash
export FIBERD_STATE=$(mktemp -d)       # reused across restarts below
bin/grant-issuer keygen -alg EdDSA -out $FIBERD_STATE/issuer.json
bin/grant-issuer serve -key $FIBERD_STATE/issuer.json -addr 127.0.0.1:8686 &
bin/fiberd -node-id node-a -verifier jwks -issuer http://127.0.0.1:8686 \
  -http :8485 -admin-unsafe -stale-ttl 5s &
until curl -sf localhost:8485/healthz >/dev/null; do sleep 0.2; done

# a grant for this node: 2 fibers, 1 MiB working set each, a 10 minute lease
T=$(bin/grant-issuer mint -key $FIBERD_STATE/issuer.json -issuer http://127.0.0.1:8686 \
     -aud node-a -uid g1 -max 2 -w-budget 1Mi -min-tier FIBER_WARM -ttl 10m)
J=$(python3 -c "import json,sys;print(json.dumps(sys.argv[1]))" "$T")
clone() { curl -s -w ' [http %{http_code}]\n' -X POST localhost:8485/v1/clone -d "$1"; }

clone "{\"grantJwt\":$J,\"session\":\"S\"}"    # CREATE, fence g1/1/1
clone "{\"grantJwt\":$J,\"session\":\"S\"}"    # ATTACH, same endpoint and fence
curl -s -X POST localhost:8485/v1/park -d '{"fiberId":"g1/1/1"}'
clone "{\"grantJwt\":$J,\"session\":\"S\"}"    # RESUME, fence seq 2
clone "{\"grantJwt\":$J,\"image\":\"evil\"}"   # 400: admission completeness
clone "{\"grantJwt\":$J}"                       # anonymous CREATE; the grant is now full (2/2)
clone "{\"grantJwt\":$J}"                       # 503 DEFERRED_FALLBACK: full, issuer reachable
curl -s --unix-socket $FIBERD_STATE/admin.sock -X POST http://x/lane -d '{"healthy":false}'
clone "{\"grantJwt\":$J}"                       # 429 SHED + Retry-After: issuer unreachable
curl -s localhost:8485/v1/status                # running, parked, w_used_bytes, latest fence
cat $FIBERD_STATE/audit.jsonl                   # one record per transition

kill %2; bin/fiberd -node-id node-a -verifier jwks -issuer http://127.0.0.1:8686 -http :8485 &
until curl -sf localhost:8485/healthz >/dev/null; do sleep 0.2; done
curl -s localhost:8485/healthz                  # epoch 1 -> 2: every prior fence is invalid
curl -s -X POST localhost:8485/v1/park -d '{"fiberId":"g1/1/1"}'   # 404
```

`-grants-dir` pre-admits `*.jwt` files dropped there and revokes them when removed. `-verifier insecure-json` takes unsigned protobuf-JSON grants, for development only. `grpcurl -plaintext -proto api/grant/v1/grant.proto localhost:8484 fiberd.grant.v1.Fibers/Clone` reaches the gRPC service directly.

## Real fibers

The fork zygote, cgroups, CRIU and the sandbox backends need a Linux kernel. On a Mac the dev container in `hack/dev` is that kernel: privileged, cgroup v2, criu built from source (see the Dockerfile for why bookworm and which criu). Every Linux target below runs inside it.

```bash
make linux-check      # cgroup v2, PSI, criu, gcc
make linux-test       # unit and integration tests
make conform-proc     # the conformance suite against the fork zygote
```

| Backend | Conformance target | Additional requirement |
| --- | --- | --- |
| proc | `make conform-proc` | cgroup v2 and CRIU |
| runc | `make conform-runc` | runc, CRIU, and a root filesystem |
| gVisor | `make conform-gvisor` | runsc and a root filesystem |
| Hyperlight | `make conform-hyperlight-fake` or `make conform-hyperlight` | the real-helper target requires KVM |

See the [runtime model](runtime-model.md) for backend behavior and tiers.
`fiberd -h` lists every configuration flag.

## Conformance

`grant-conform` (built from `tests/conform`) is the executable contract: cases C1 to C10, driven through the public gRPC surface plus hooks a target supplies as commands (restart it, flip the grant lane, look up an audit record, end the engine, lose the scope). The outcomes are defined in [protocol.md](protocol.md). Cases without their hook are skipped and say so.

```bash
make conform-stub      # the in-memory runtime, unsigned grants
make conform-signed    # the same with a live issuer and real JWTs
bin/grant-conform -target host:port -node-id <audience> -mint jwt -issuer-key key.json -issuer <url> \
  [-restart-cmd ...] [-cp-health-cmd ...] [-audit-file ...] [-engine-kill-cmd ...] [-scope-cmd ...]
```

## Next

Continue with an environment or consumer example:

- [Kubernetes](../examples/kubernetes/README.md)
- [Slurm](../examples/slurm/README.md)
- [Knative](../examples/knative/README.md)
- [Kata-shaped containerd shim](../examples/kata/README.md)
- [Agent Substrate](../examples/substrate/README.md)
