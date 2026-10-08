# Architecture

This page describes how the current fiberd implementation is assembled. It focuses on package boundaries, state transitions, persistence, and runtime extension points. For the operator-facing model, start with [Runtime model](runtime-model.md), [Resources and limits](resources.md), [Networking](networking.md), and [Identity](identity.md). For exact request and response behavior, see the [Protocol reference](protocol.md).

![Containment view: one home contains one fiberd agent and separate sibling grant scopes. Each grant owns its warm template and fiber set; nesting shows resource ownership, not a request sequence or a universal security boundary.](images/containment.svg)

The component map uses repository package names and the concrete `core.Spool` type as its primary labels. Short subtitles describe their roles; labeled interfaces show how the implementations connect to `pkg/core`.

![pkg/rpc and pkg/home reach pkg/core, which uses home callbacks, pkg/grant through core.Verifier, core.Spool through core.Auditor, and a selected core.Runtime implementation. pkg/runtime/host depends on pkg/backend and pkg/artifact; pkg/runtime/stub is an independent alternative. Arrows show relationships, not execution order.](images/architecture-components.svg)

## Component boundaries

fiberd keeps scheduling policy in a small core and injects the environment-specific parts around it.

- `cmd/fiberd` parses configuration and starts the reference agent.
- `pkg/agent` assembles the home, runtime, verifier, ledger, audit spool, pressure controller, and network servers.
- `pkg/core` owns grant admission, session resolution, fences, budgets, pressure reactions, snapshots, and the runtime interfaces.
- `pkg/rpc` exposes the core through gRPC and the optional JSON gateway.
- `pkg/grant` verifies and converts signed CapacityGrants.
- `pkg/runtime/host` implements the host runtime over a selected backend.
- `pkg/backend` defines the backend boundary. The `proc`, `runc`, `gvisor`, and `hyperlight` packages implement it.
- `pkg/home` supplies control-plane health, scope claims, grants, and optional fabric channels. The reference binary currently includes standalone and file-lane homes.
- `pkg/artifact` manages templates, checkpoints, deltas, registry exchange, and platform-parity metadata.
- `pkg/sys` contains Linux integrations such as cgroups and CRIU.

The core does not import Kubernetes APIs, container runtimes, or a particular control plane. It consumes home-provided callbacks and the verifier, audit, and runtime interfaces; artifact handling belongs to the host runtime.

## Startup and reconciliation

The reference agent starts in the following order:

1. It creates the selected home and asks it for the cgroup root, health source, scope claims, and optional fabric provider.
2. It creates the runtime and backend.
3. It opens the persistent epoch. Opening the epoch advances it, which invalidates fences from the previous process.
4. It creates an empty ledger, opens the local audit spool, and loads the last ledger snapshot.
5. Reconciliation re-admits unexpired grants, restores parked-session metadata, removes unusable entries, and asks the runtime to terminate orphaned running fibers from the old epoch.
6. It starts the W sampler, lease reaper, pressure loop when supported, home grant lane, admin server, and public RPC servers.

Running fibers are not recovered after an agent restart. Parked named sessions can remain resumable when their delta and parent checkpoint are still available.

## Admission and the warm path

A home can deliver a CapacityGrant before traffic arrives. Admission checks
the required tier, lease, and available device capacity, provisions any
grant-scoped fabric channel, and prepares the grant's warm template. The
current host validator does not compare the requested device class with the
reported engine class. Concurrent admissions for the same grant are
coalesced.

A valid Clone request can also self-admit an unknown grant. The signed grant travels with the request, so the verifier can authenticate it locally and the agent can prepare its template without a synchronous control-plane call. Pre-admission avoids that setup on the first request.

The grant UID is also the warm-runtime key. A redelivery with the same UID
currently replaces ledger grant fields while template preparation returns the
already-warm runtime. The implementation does not enforce field immutability.
Treat template, capacity, W budget, tier, device, audience, issuer, and policy
fields as immutable for a UID; only renew the lease for an otherwise identical
grant. Drain and issue a new UID when those fields change.

After verification, the core asks the ledger to resolve the session and reserve
any required fiber slot. Budget and pressure checks run before new runtime
work. A successful runtime call commits the reservation, records the action,
and returns the endpoint. A failure releases the reservation. The
[protocol reference](protocol.md) defines the wire-visible actions and
outcomes.

## Ledger, sessions, and fences

The in-memory ledger is the authority for admitted grants, running fibers,
parked named sessions, per-grant sequence counters, and status. Ledger
mutations are serialized around session resolution. A reservation is committed
only after the runtime succeeds, so concurrent requests for the same name
cannot create two active incarnations. Fence structure and session behavior
are defined in the [protocol reference](protocol.md#fences-and-epochs) and
their trust meaning is covered in [Identity](identity.md).

## Runtime and backend seam

`pkg/core.Runtime` is the core's required execution boundary. A runtime must prepare templates, clone or restore fibers, park and release fibers, report stats and exits, reconcile discovered work, and advertise its tier.

The host runtime uses a narrower backend interface for mechanism-specific operations. Backends can additionally implement optional capabilities:

- endpoint scheme reporting.
- fixed-overhead and W measurement.
- device usage and pressure reporting.
- runtime-selected create and resume deadlines.
- self-checkpointing or external checkpoint support.
- delta encoding and platform facts.
- grant pruning and fabric attachment.

The optional interfaces keep the core independent of whether a fiber is a process, container, sandbox, or micro-VM. A backend must not claim a stronger tier or endpoint form than it implements. Current backend behavior and limitations are summarized in [Runtime model](runtime-model.md).

## Home seam

A home represents the environment that supplies capacity. It has four responsibilities:

- report whether the asynchronous grant lane is healthy.
- deliver grants to the agent.
- identify the scope in which the agent is running.
- optionally allocate a grant-scoped fabric channel.

The standalone home uses local configuration. The file-lane home accepts
grants from a directory-backed lane. The repository also contains a reference
Kubernetes home and controller under `examples/kubernetes`. They demonstrate
the seam but are not core fiberd or a production operator.

The core uses the home's control-plane health when it selects a capacity miss.
The wire outcomes and caller behavior are defined in the [protocol reference](protocol.md#outcomes).

## Checkpoints and session mobility

Parking asks the runtime to capture a fiber's mutable state and returns a delta reference. The 
ledger retains that reference only for a named session. The runtime can publish the delta 
so another home can discover and claim it.

The artifact layer separates a reusable parent checkpoint from session-specific delta state:

- the parent is keyed by template and platform information.
- the delta carries the parked session's mutable state.
- platform facts prevent restore on an incompatible host.
- ownership metadata identifies the home that published the delta.
- every delta and parent is signed, and a home takes only what a key it trusts signed.
- every delta is encrypted for its session domain and session before it leaves the home, and expires 24 hours after the park.
- optional parity data can protect registry chunks.

Mobility is conditional. If no delta finder is configured, the session stays
local. If a discovered delta exceeds `w_budget_bytes` or the target platform
is incompatible, the miss points to the home that currently holds the state.
The reference registry claim is not atomic: pull, owner comparison, and delete
are separate operations, so two homes can race and both resume the same
published state. If the shared store is unavailable, the current
implementation can create a fresh session instead of waiting for it. Do not
enable cross-home mobility where duplicate resume or fresh-state fallback is
unacceptable.

## Persistence and failure handling

The snapshot store writes admitted grants and parked-session metadata after
state transitions. Running fibers are intentionally not restored from the
snapshot. The epoch, snapshot, audit spool, and any local checkpoint state
must live on storage whose lifetime matches the logical home. Losing the epoch
can reuse an earlier fence after a replacement starts again at epoch 1.

The runtime reports asynchronous exits such as normal exit, signal, or OOM. The agent removes the fiber from the ledger, frees its slot, forgets any running named session, and records the exit. An exit that arrives before Clone commits is held briefly and settled after the commit so the slot is not leaked.

The lease reaper periodically yields expired grants. Yielding revokes the grant, releases its running fibers, and retains parked deltas. A later delivery can admit the grant again. A grant the home removes from its lane is also yielded, and its UID is denied until its tokens expire or the lane delivers it again.

Release during Yield or scope loss is currently best effort. If a runtime
release fails, the agent logs the error and can still remove ledger ownership,
leaving untracked work while freeing its slot. Production integrations need a
retryable cleanup and quarantine mechanism before relying on this path for
hard revocation.

## Pressure controller

When the runtime exposes pressure data, `PressureController` polls each
admitted grant and can combine memory and device sources through
`MaxPressure`. It maintains the shedding state consulted by Clone and invokes
the agent's Park, Release, and Yield operations for reclamation. The
W-dependent rate budget is a separate token bucket whose current curve is a
placeholder. See [Resources and limits](resources.md) for watermarks, victim
selection, and operator-visible behavior.

## Audit path

Every state-changing operation attempts to append an audit record with the
fence and, when available, session, fiber, scope, and fabric details. The
spool abstraction supports best-effort and synchronous durability modes.
Records are hash-chained, and failed writes and torn lines leave `gap`
records. Signed `checkpoint` records follow at intervals and at shutdown
(see [Security](security.md#audit)).

The spool is local only. Synchronous durability waits for a local `fsync`. A deployment that needs the records off the host must copy the spool there itself.

A failed `fsync` is sticky. The spool then refuses every synchronous record until the agent restarts, because the kernel drops the pages a failed `fsync` could not write and a later `fsync` does not retry them. Best-effort records are still written.

Runtime and ledger state change before the audit append. A synchronous append
failure can therefore return `Internal` after the operation already completed;
a best-effort append failure is logged while the operation succeeds. Callers
must not assume that `Internal` proves no state change, and operators must
monitor spool failures and disk capacity.

## Device and fabric seams

A home may allocate a grant-scoped fabric channel before the template is
prepared. A device-capable runtime reports device usage or pressure through
optional interfaces. The current host checks for a reporting engine with
nonzero capacity but does not enforce `device_budget.class`; operators must
not treat the requested class as an isolation or compatibility guarantee.

The repository's device engine is a simulation used to exercise accounting and pressure behavior. It is not a production CUDA, GPU, DRA, or RDMA integration. The `FABRIC` runtime tier is reserved and is not implemented.

## Security boundaries

The implementation separates several boundaries that should not be conflated:

- signed grants authorize capacity and bind the request to a home audience.
- fences order fiber incarnations and become invalid when the epoch changes.
- home scope claims describe where the agent is running.
- backend isolation determines the OS boundary around a fiber.
- workload credentials and network identity remain deployment concerns unless a backend or sidecar provides them.

The detailed identity model is in [Identity](identity.md), networking behavior is in [Networking](networking.md), and resource containment is in [Resources and limits](resources.md).
The reference control API is plaintext and has no caller authorization beyond
grant verification on Clone. Review the deployment blockers and mitigations in
[Production readiness](production-readiness.md) before exposing an agent.
