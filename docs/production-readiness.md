# Production readiness

This page lists what stands between the reference implementation and a production deployment, for anyone deciding whether to run fiberd for real. Read [security.md](security.md) first. Each row links the design doc that owns the gap, and the acceptance gates are in [design/readiness.md](design/readiness.md).

![A path from fiberd, a reference implementation, to production through four groups of acceptance gates. Transport and grants needs TLS everywhere, lease-only grant changes and a locked lane directory. State needs a durable epoch, a failed release retried or held, bounded parked state and reconciliation beyond Watch. Mobility, audit and devices needs an atomic claim, an audit spool monitored and copied off the host, and matched device classes. Every deployment also tests the grant lifecycle and platform events and passes conformance. Production means every gate passed with recorded evidence.](./images/production-readiness.svg)

## Blockers

| Area | What the code does | What production needs | Owner |
| --- | --- | --- | --- |
| Control transport | Mutual TLS by default, with each [grant](glossary.md#grant) bound to the caller's certificate. Every example runs `-insecure-plaintext`, and the Knative and Kata consumers dial without TLS | Serve TLS in every [home](glossary.md#home) and dial with a client certificate | [grant.md](design/grant.md) |
| [Release](glossary.md#release) | A [yield](glossary.md#yield), [scope](glossary.md#scope) loss and the [epoch](glossary.md#epoch) bump log a failed runtime release and still drop the [fiber](glossary.md#fiber) from the ledger | Retry or quarantine a failed release before freeing the slot | [core.md](design/core.md) |
| Grant fields | A [lane](glossary.md#lane) redelivery replaces the admitted fields in place, and the [warm](glossary.md#warm) [template](glossary.md#template) stays | Change only the lease for a UID, and mint a new UID for anything else | [core.md](design/core.md) |
| Epoch | [Fence](glossary.md#fence) safety needs a persistent epoch. The Kubernetes example stores it on `emptyDir` | A state directory that lives as long as the home's identity, its audience and grant UIDs | [kubernetes.md](design/kubernetes.md) |
| [Parked](glossary.md#park) state | Release addresses a running fiber. Nothing in the API deletes an already parked [session](glossary.md#session)'s [delta](glossary.md#delta), and an anonymous park has no name to resume | An operation that deletes parked state, and garbage collection of deltas and ports | [protocol.md](protocol.md#release) |
| Mobility | The registry claim is pull, tag check and delete as separate calls, and an unreachable registry falls back to a fresh session | An atomic claim, and no fresh-state fallback where continuity matters | [artifact.md](design/artifact.md) |
| Audit | Park and Release write their record after the change ([protocol.md](protocol.md#outcomes)). The spool is local, and the first failed fsync poisons sync records until restart | Copy the spool off the host, monitor failures, restart after an fsync failure | [audit.md](design/audit.md) |
| Watch | No batch boundary and no deletion tombstone | Reconcile through another inventory | [core.md](design/core.md) |
| Device class | Admission checks for nonzero capacity, not the requested class | Enforce class compatibility | [runtime-host.md](design/runtime-host.md) |
| Lane directory | Whoever can write the grants directory can deny a UID on that home | Only the control plane can write it | [home.md](design/home.md) |

## Operations

- The agent's open-file limit (`RLIMIT_NOFILE`) must cover the [relay](glossary.md#relay). Each relayed connection takes two descriptors and each relayed fiber one more, with up to 256 connections per fiber and 4,096 per home ([networking.md](design/networking.md)).
