# Production readiness

fiberd is a reference implementation and protocol laboratory with executable
conformance coverage. The core model is coherent, but the current repository
does not yet provide every guarantee required for an untrusted, multi-tenant
production deployment. This page separates implemented behavior from required
hardening so operators do not infer guarantees from the design documents or
examples.

![The reference implementation becomes production-ready only after authenticated control transport, durable fencing state, deterministic revocation and cleanup, atomic bounded mobility, observable audit and readiness, and deployment-specific conformance evidence are supplied.](./images/production-readiness.svg)

## Current deployment blockers

| Area | Current behavior | Production requirement |
| --- | --- | --- |
| Control API | The reference gRPC server, JSON gateway, and client use plaintext transport. Only Clone verifies a grant; Park, Release, and Watch have no caller identity. | Put every control operation behind authenticated TLS or mTLS and explicit authorization. Restrict network reachability. |
| Grant removal | Removing a grant from the lane releases its running fibers and denies its UID on that home until its tokens expire. Release is best effort, and the denial covers only the home that removed it. | Retry or quarantine failed releases, remove the grant on every home, and set `-max-lease` so the denial covers every token. |
| Cleanup failure | Yield and epoch-change cleanup can log a runtime Release failure and still remove ledger ownership. | Retry or quarantine failed cleanup and keep capacity unavailable until termination is confirmed. |
| Epoch persistence | Fence safety depends on a monotonically persistent epoch. The Kubernetes example stores state on `emptyDir`. | Persist the epoch for the lifetime of the logical home and use a new home identity when that state is lost. |
| Parked-state deletion | Release addresses running fiber IDs. There is no public operation that deletes an already parked session delta, and anonymous Park has no resumable name. | Add explicit parked-session deletion and deterministic checkpoint, port, and disk garbage collection. |
| Mobility claims | The reference registry claim performs pull, owner comparison, and delete as separate operations. | Use an atomic claim, lease, or compare-and-swap before enabling cross-home resume. |
| Grant refresh | Redelivery of a grant UID can replace ledger fields while the old template remains warm. | Enforce immutable authority fields per UID and define exactly which lease fields may be renewed. |
| Audit result | State changes precede audit append. A synchronous append failure can return `Internal` after completion; best-effort failure can return success without a record, though the next record written is a `gap` naming it. After one failed `fsync` the spool refuses every synchronous record until the agent restarts. | Define idempotent recovery, monitor spool failures, restart the agent after an `fsync` failure, and operate bounded durable storage. Copy the spool off the host where required. |
| Watch set | Watch has no batch boundary or deletion tombstone. | Add authoritative snapshot framing and removal events, or reconcile through another inventory source. |
| Device class | The host currently validates nonzero device capacity but not the requested class. | Enforce class compatibility before admitting device-backed grants. |

## Control-plane and credential security

- Treat every signed grant JWT as a bearer credential. Do not place it in Pod
  annotations, logs, command histories, or broadly readable files.
- Set both JWT `exp` and grant `lease_expiry`. Grants with neither value do not
  expire at those layers.
- Terminate TLS or mTLS before the gRPC and JSON listeners and authorize Clone,
  Park, Release, Watch, status, and administrative operations separately.
- Bind control listeners to a private interface and restrict callers with host
  firewall rules, security groups, or Kubernetes NetworkPolicy.
- Protect issuer signing keys and serve discovery and JWKS over an
  authenticated, integrity-protected path.
- Plan for stale JWKS behavior. Offline verification helps during an outage
  only while cached keys, the grant lease, home scope, and local runtime remain
  valid.
- Add workload-level authentication and encryption to fiber data endpoints.
  An endpoint and fence are not credentials.

## Persistence and fencing

Persist the following according to the recovery guarantee a deployment
advertises:

- epoch state, so replacement processes cannot reuse old fences
- ledger snapshots for admitted grants and parked-session metadata
- audit spool data until it has been copied off the host, where that is required
- parent checkpoints and session deltas needed for resume

The storage lifetime must match the logical home identity. If the epoch is
lost, start with a new audience/home identity rather than reusing the prior
grant UID and epoch namespace.

The Kubernetes reference controller currently mounts `/var/lib/fiberd` from
`emptyDir`. Container restart in the same Pod can retain that volume, but Pod
replacement, rescheduling, and node loss do not. A production integration
needs a deliberate PVC, host-local identity, or external fencing design; the
example does not supply one.

Also define:

- snapshot corruption and missing-state behavior
- disk quotas, retention, and rotation for the audit spool
- checkpoint and delta retention, failed-publish cleanup, and port reclamation
- recovery when a synchronous state or audit write fails

## Grant lifecycle and revocation

For one grant UID, keep the template digest, audience, issuer, capacity, W
budget, tier, policy, and device fields immutable. Renew only the lease for an
otherwise identical grant. Drain the old grant and issue a new UID when its
workload or authority changes.

Removing a grant from a home's lane releases its running fibers and persists
a deny-list entry, so the same token can't self-admit there again (see
[Security](security.md#grants)). Release is still best effort: a release
that fails is logged, and the work can outlive the ledger entry. Set
`-max-lease`, so that denials cover every token that may exist. Remove the
grant on every home that holds it, and confirm runtime termination.

## Cleanup and state lifecycle

Park only named sessions that have a defined retention and deletion policy.
Avoid anonymous Park because no session name remains for resume or deletion.

Treat Release, scope loss, pressure Yield, and lease expiry as incomplete until
the backend confirms termination. The current agent can forget a fiber after a
failed cleanup. Monitor backend processes or sandboxes independently and keep
the corresponding capacity quarantined.

For cross-home mobility:

- require an atomic state claim
- ensure the target can bind and route the stored endpoint
- define behavior for registry outage, partial publish, partial delete, and
  duplicate claim
- reject fresh-state fallback where losing session continuity is unsafe

## Kubernetes example gaps

The reference integration demonstrates the home seam; it is not a production
operator.

- `CapacityGrant.status.ready` currently mirrors the custom
  `fiberd.io/zygote-ready` condition, not the complete Pod `Ready` condition.
- The example RoleBinding cannot grant access to the cluster-scoped Namespace
  resource, so Namespace termination is not reliably observed by the shown
  manifests.
- The controller creates a missing Pod but has no rollout policy for changing
  an existing Pod.
- The controller has no finalizer or graceful scale-in workflow.
- A proc grant's Pod holds `SYS_ADMIN` and shares the host's user namespace,
  other runtimes' Pods are privileged by default, and the issuer serves HTTP
  inside the example cluster.
- Epoch, snapshot, audit, and checkpoint state use `emptyDir`.

A production operator must correct those behaviors, minimize privileges,
protect signing keys, define rollout and drain semantics, and validate both
ordinary Pod readiness and warm-template readiness.

## Failure and retry semantics

Do not infer that an error means no state change:

- Clone runtime or deadline failure is returned as `DEFERRED_FALLBACK`.
- Park and Release runtime failures return `Internal`.
- A synchronous audit failure can return `Internal` after the runtime and
  ledger already changed.
- Retrying an anonymous Clone after an ambiguous failure can create another
  fiber.

Use named sessions when idempotent resolution is required. Record the returned
fiber ID and fence, reconcile through a trusted inventory source, and design
consumer retries around the typed `SHED` and `DEFERRED_FALLBACK` outcomes.

## Production acceptance gates

Before production use, require evidence for all of these:

1. Authenticated transport and per-operation authorization are enforced.
2. Grant replay, removal, expiry, and issuer-key outage behavior are tested.
3. Epoch monotonicity survives process restart and the intended home
   replacement scenarios.
4. Failed backend cleanup is retried and does not free capacity early.
5. Parked-state retention and deletion keep disk and ports bounded.
6. Mobility uses atomic claims and a compatible endpoint topology.
7. Audit disk-full and synchronous failure behavior are observable and
   recoverable.
8. Readiness, scope loss, drain, rollout, and deletion are tested against the
   real platform rather than only administrative hooks.
9. Resource, endpoint, backend, and security conformance are run for the exact
   production configuration.
10. Benchmark evidence records commit, environment, raw output, concurrency,
    and statistical method as defined in [Benchmarks](benchmarks.md).

For the component model, see [Architecture](architecture.md). For exact wire
behavior, see [Protocol](protocol.md). For Kubernetes-specific configuration,
see [Operating fiberd on Kubernetes](operating-kubernetes.md).
