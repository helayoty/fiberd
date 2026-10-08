# Design docs

The design docs explain how each fiberd module works inside, for contributors and reviewers. Read [architecture.md](../architecture.md) first, and look up terms in the [glossary](../glossary.md).

A suggested order is agent, home, grant, core, audit, runtime-host, backends and zygote, then the rest as needed.

| Design doc | What it covers | Packages |
| --- | --- | --- |
| [core.md](core.md) | The ledger of [grants](../glossary.md#grant) and [sessions](../glossary.md#session), [fences](../glossary.md#fence), revocation and the pressure ladder | `pkg/core` |
| [audit.md](audit.md) | The hash-chained audit spool, its signed checkpoints and how it is verified | `pkg/core`, `cmd/audit-verify` |
| [grant.md](grant.md) | Grant verification, caller identity over mutual TLS (Transport Layer Security) and admission | `pkg/grant`, `pkg/rpc`, `pkg/tlsconf` |
| [agent.md](agent.md) | The [agent](../glossary.md#agent)'s startup order, state layout and the checks that fail at start | `pkg/agent`, `cmd/fiberd` |
| [home.md](home.md) | The [home](../glossary.md#home) seam, grant delivery, control-plane health and [scope](../glossary.md#scope) loss | `pkg/home`, `pkg/home/standalone`, `pkg/home/filelane` |
| [handoff.md](handoff.md) | Routing callers' TLS connections to [fibers](../glossary.md#fiber) through one address | `pkg/handoff`, `pkg/runtime/host` |
| [artifact.md](artifact.md) | [Template](../glossary.md#template) artifacts, signing, sealing, moving [deltas](../glossary.md#delta) between homes, and [parity](../glossary.md#parity) | `pkg/artifact`, `pkg/runtime/host` |
| [runtime-host.md](runtime-host.md) | [Warm](../glossary.md#warm) templates, per-fiber [cgroups](../glossary.md#cgroup), [W](../glossary.md#w-working-set) enforcement and what a fiber can see | `pkg/runtime/host` |
| [networking.md](networking.md) | Endpoint forms, ports and address families for each [backend](../glossary.md#backend) | `pkg/runtime/host` |
| [resources.md](resources.md) | The cgroup hierarchy, the memory formula and sizing | `pkg/runtime/host`, `pkg/sys/cgroup` |
| [backends.md](backends.md) | The backend interface and how proc, runc, gVisor and Hyperlight make a fiber | `pkg/backend`, `pkg/backend/proc`, `pkg/backend/runc`, `pkg/backend/gvisor`, `pkg/backend/hyperlight` |
| [sys.md](sys.md) | Cgroup delegation, [CRIU](../glossary.md#criu) dump and restore, capability narrowing and network namespaces | `pkg/sys/caps`, `pkg/sys/cgroup`, `pkg/sys/criu`, `pkg/sys/netns` |
| [zygote.md](zygote.md) | The C library a template links to, its wire protocol and how a [zygote](../glossary.md#zygote) forks a fiber | `zygote` |
| [user-namespaces.md](user-namespaces.md) | Why runc fibers get a user namespace per grant, and how their ids are assigned | `pkg/backend/runc` |
| [readiness.md](readiness.md) | The acceptance gates a deployment passes before production | none |
| [kubernetes.md](kubernetes.md) | The Kubernetes home, its grant controller and the grant Pod | `examples/kubernetes` |
| [slurm.md](slurm.md) | The Slurm home inside a job allocation | `examples/slurm` |
| [knative.md](knative.md) | A Knative activator that scales from zero with fibers | `examples/knative` |
| [kata.md](kata.md) | A Kata-style containerd shim whose Pod containers are fibers | `examples/kata` |
| [substrate.md](substrate.md) | An Agent Substrate worker whose actors are fibers | `examples/substrate` |
| [compare.md](compare.md) | The activation benchmark of fiberd against Pods, agent-sandbox and Firecracker | `bench/compare` |

## Small pieces

These have no design doc of their own.

| Piece | What it is |
| --- | --- |
| `api/grant/v1` | The wire contract, described in [protocol.md](../protocol.md) |
| `pkg/consumer` | A client for [Clone](../glossary.md#clone), [Park](../glossary.md#park), [Release](../glossary.md#release) and Watch that turns misses into typed errors |
| `pkg/endpoint` | How a fiber's address is written, chosen and dialled |
| `pkg/tlsconf/tlsconftest` | Throwaway certificates for tests that need mutual TLS |
| `pkg/runtime/stub` | An in-memory runtime for tests and the conformance suite |
| `pkg/core/coretest` | Helpers for tests of code built on `pkg/core` |
| `internal/cli` | The plumbing the commands share, which is subcommand dispatch and the version `-version` prints |
| `cmd/fiberd` | The agent on a standalone host |
| `cmd/grant-issuer` | The reference [issuer](../glossary.md#issuer), which mints grants and serves its public keys |
| `cmd/audit-verify` | Checks a home's audit spool |
| `cmd/zygotectl` | Builds, pushes, pulls and inspects template artifacts |
| [hack/hyperlight/PROTOCOL.md](../../hack/hyperlight/PROTOCOL.md) | The line protocol between fiberd and the Hyperlight helper process |
