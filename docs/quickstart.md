# Quickstart

This page builds fiberd and runs the four protocol calls on this machine, then dials a real [fiber](glossary.md#fiber) on Linux. It is for anyone trying fiberd for the first time. Read the [README](../README.md) first, and [architecture.md](architecture.md) after this to understand what you saw.

![The quickstart in four rows. Set up builds fiberd, starts the issuer and an agent on the in-memory runtime, and mints a grant. Session S is created, attached, parked and resumed as g1/1/2. The guide then probes refusals, stops the agent to verify its signed audit, restarts at epoch 2, and Park of g1/1/2 returns 404. On Linux, a real agent counts to 2, parks, resumes, and counts 3 with its state kept.](./images/quickstart-flow.svg)

## Build

You need Go 1.26 or newer and curl. The Linux steps below also need Docker.

```bash
make build
```

## Run the protocol on this machine

The [agent](glossary.md#agent) speaks gRPC and, with `-http`, a JSON gateway of the same service. Without a `-runtime` flag it uses the `stub` [runtime](glossary.md#runtime), which runs no code, so it works on any OS. [Grants](glossary.md#grant) are signed tokens from `grant-issuer`, verified offline against the [issuer](glossary.md#issuer)'s published keys. `-insecure-plaintext` skips mutual TLS, for development only.

A grant is `UNTRUSTED` unless its issuer says otherwise, and the stub runtime counts as isolating tenants because it runs no tenant code, so it admits this grant.

```bash
export STATE=$(mktemp -d)              # reused across the restart below
bin/grant-issuer keygen -alg EdDSA -out $STATE/issuer.json
bin/grant-issuer serve -key $STATE/issuer.json -addr 127.0.0.1:8686 &
bin/fiberd -state $STATE -node-id node-a -verifier jwks -issuer http://127.0.0.1:8686 \
  -insecure-plaintext -http :8485 -stale-ttl 5s &
until curl -sf localhost:8485/healthz >/dev/null; do sleep 0.2; done

# a grant for this node (-aud must equal the agent's -node-id),
# 2 fibers of 1 MiB working set each, a 10 minute lease
T=$(bin/grant-issuer mint -key $STATE/issuer.json -issuer http://127.0.0.1:8686 \
     -aud node-a -uid g1 -tenant demo -max 2 -w-budget 1Mi -min-tier FIBER_WARM -ttl 10m)
clone() { curl -s -w ' [http %{http_code}]\n' -X POST localhost:8485/v1/clone -d "$1"; }

clone "{\"grantJwt\":\"$T\",\"session\":\"S\"}"   # CREATE, fiberId g1/1/1
clone "{\"grantJwt\":\"$T\",\"session\":\"S\"}"   # ATTACH, the same fiberId, endpoint and fence
curl -s -X POST localhost:8485/v1/park -d '{"fiberId":"g1/1/1"}'
clone "{\"grantJwt\":\"$T\",\"session\":\"S\"}"   # RESUME, a new fiberId g1/1/2
clone "{\"grantJwt\":\"$T\",\"image\":\"evil\"}"  # 400, an unknown field is refused
clone "{\"grantJwt\":\"$T\"}"                      # anonymous CREATE g1/1/3, the grant is full (2/2)
clone "{\"grantJwt\":\"$T\"}"                      # 503 DEFERRED_FALLBACK, full while the issuer is reachable
kill %1; sleep 6                                   # stop the issuer, the lane goes stale after -stale-ttl
clone "{\"grantJwt\":\"$T\"}"                      # 429 SHED with Retry-After, issuer unreachable
curl -s localhost:8485/v1/status                   # running fibers and the latest fence

kill %2; wait %2                                   # stop the agent, which signs its audit spool
bin/audit-verify -spool $STATE/private/audit.jsonl -trust $STATE/private/audit-key.json

bin/grant-issuer serve -key $STATE/issuer.json -addr 127.0.0.1:8686 &
bin/fiberd -state $STATE -node-id node-a -verifier jwks -issuer http://127.0.0.1:8686 \
  -insecure-plaintext -http :8485 &
until curl -sf localhost:8485/healthz >/dev/null; do sleep 0.2; done
curl -s localhost:8485/healthz                     # epoch 2, every fence of epoch 1 is invalid
curl -s -X POST localhost:8485/v1/park -d '{"fiberId":"g1/1/2"}'   # 404, the restart ended g1/1/2
```

- The fiber ID is the [fence](glossary.md#fence), so each command uses the ID the call before it returned.
- When the issuer stops answering, the home's [lane](glossary.md#lane) goes stale and misses turn from deferred to [shed](glossary.md#shed-and-deferred).
- `audit-verify` checks the agent's local, signed record of every state change ([audit.md](design/audit.md)). The agent signs it when it stops, so the check runs after the stop.

[protocol.md](protocol.md) explains each reply. `-grants-dir` pre-admits `*.jwt` files dropped there, and removing one revokes the grant on this [home](glossary.md#home) ([home.md](design/home.md)).

## Dial a real fiber

The fork [zygote](glossary.md#zygote), [cgroups](glossary.md#cgroup), [CRIU](glossary.md#criu) and the sandbox [backends](glossary.md#backend) need a Linux kernel. On a Mac, `hack/dev/run.sh bash` opens a shell in the Linux dev container, with this repository at `/src`. Run these steps there, since the container has every tool they use, `jq` included. They start the agent with `-runtime proc`, the proc backend, and refzygote, the reference template, serving HTTP. Their `make build zygote` replaces the Mac binaries in `bin/` with Linux ones, so run `make build` on the Mac again afterwards.

```bash
make build zygote
bin/grant-issuer keygen -alg EdDSA -out /tmp/issuer.json
bin/grant-issuer serve -key /tmp/issuer.json -addr 127.0.0.1:8686 &
bin/fiberd -state /tmp/fiberd -node-id node-a -verifier jwks -issuer http://127.0.0.1:8686 \
  -insecure-plaintext -http :8485 -runtime proc -template "default=$PWD/bin/refzygote --http" &
until curl -sf localhost:8485/healthz >/dev/null; do sleep 0.2; done
T=$(bin/grant-issuer mint -key /tmp/issuer.json -issuer http://127.0.0.1:8686 -aud node-a -uid g1 -tenant demo -isolation TRUSTED)
EP=$(curl -s -X POST localhost:8485/v1/clone -d "{\"grantJwt\":\"$T\",\"session\":\"S\"}" | jq -r .endpoint)
curl -s --unix-socket ${EP#unix://} -X POST http://fiber/incr           # 1, the fiber's own counter
curl -s --unix-socket ${EP#unix://} -X POST http://fiber/incr           # 2
curl -s -X POST localhost:8485/v1/park -d '{"fiberId":"g1/1/1"}'
curl -s -X POST localhost:8485/v1/clone -d "{\"grantJwt\":\"$T\",\"session\":\"S\"}"   # RESUME, g1/1/2
curl -s --unix-socket ${EP#unix://} -X POST http://fiber/incr           # 3, the state survived the park
```

The grant is `TRUSTED` because proc fibers share the host kernel, and a home refuses an `UNTRUSTED` grant on proc ([security.md](security.md#admission-and-isolation)). The resumed fiber listens on its parked socket again, so the last `curl` reuses `$EP` from the first Clone.

## Write your own template

A template is your program linked with libfiberzygote. [zygote/README.md](../zygote/README.md) builds one, and [design/zygote.md](design/zygote.md) is the contract it must keep. Point `-template` at it instead of refzygote.

## Conformance

The [conformance suite](glossary.md#conformance-suite) checks these.

- Idempotent [clones](glossary.md#clone).
- Monotonic [fences](glossary.md#fence).
- The [epoch](glossary.md#epoch) bump on restart.
- Revocation by [lease](glossary.md#lease).
- Admission completeness.
- The [W](glossary.md#w-working-set) [budget](glossary.md#budget).
- The [tier](glossary.md#tier) floor.
- The [device budget](glossary.md#device-budget).
- The loss of the [warm](glossary.md#warm) template.
- [Scope](glossary.md#scope) loss.

```bash
make conform-proc
```

That runs it against the fork zygote with real cgroups, in the dev container. `make conform-stub` runs it against the in-memory runtime on any OS. `make conform-runc`, `make conform-gvisor` and `make conform-hyperlight-fake` cover the other backends ([backends.md](design/backends.md)), and each example README names the target for its platform.
