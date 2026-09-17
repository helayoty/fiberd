# fiberd

**A capability-grant protocol that lets any execution environment mint instances locally in milliseconds from capacity a control plane charged once, and lets callers fall back sanely when it cannot.**

> Instances that cost nothing to create but still count.

![fiberd: the control plane issues a grant once; the node mints fibers on the warm path with no call home](./docs/images/fiberd-hero.png)

## Prior art: the mechanisms are known

Fast, dense instance creation is a solved mechanism. fiberd does not claim any of the rows below as novel; it reuses them.

| System | Mechanism it proves | What it gives | What it leaves open |
| --- | --- | --- | --- |
| **SOCK** (Oakes et al., ATC '18) | Zygote-provisioned lean containers: fork from a warm, package-cached interpreter | Millisecond starts, shared pages across instances | Capacity and authorization stay per instance in the orchestrator; one runtime, one home |
| **SAND** (Akkus et al., ATC '18) | Application-level sandboxing: fork worker processes inside a per-app container | Cheap instances within an app's isolation boundary | No signed authority a foreign environment can verify; no miss semantics tied to control-plane health |
| **Catalyzer** (Du et al., ASPLOS '20) | `sfork` + on-demand restore of a gVisor sandbox image | Sub-millisecond restore, snapshot-as-template | Mechanism only: no delegation of capacity, no cost model for dirtied state |
| **Firecracker snapshots** | MicroVM snapshot/restore behind a KVM boundary | Multi-tenant-safe warm instances | Each VM is still a control-plane record; nothing says who may restore what, or when to give up |
| **Orleans** (virtual actors) | Activation on demand: an actor identity is attached, resumed, or created, idempotently | The session model: name survives incarnations | Single cluster, single runtime; no portable authority, no memory-priced budget |
| **Slurm** | Allocation as a block: capacity granted once, jobs run inside it with no scheduler contact | Block delegation, prolog-time authorization | No millisecond instances inside the block, no fence/miss protocol, not portable to Kubernetes |

## What is new

fiberd is the **protocol between a control plane and an environment that runs instances on its behalf**, not the daemon that runs them. Three properties are the contribution, and every phase of the work preserves all three:

1. **The signed capability grant.** Authorization travels with the work as a signed `CapacityGrant`; the receiving node or environment verifies it offline, and revocation is lease non-renewal. Nothing on the activation path calls home.
2. **Two miss codes keyed on control-plane health.** A clone that cannot be served returns `SHED` when the control plane is unreachable (back off; never queue on a dead control plane) and `DEFERRED_FALLBACK` when it is healthy (route the caller back to its home's ordinary path). Conflating them is what makes routers retry into outages.
3. **A W-priced cost model.** Activation rate, park cost, and reclaim are all priced in the same quantity: the working set W a fiber dirties after fork. W is also the mobility budget for moving a parked session between environments.

## How it works

The components as specified. [docs/status.md](docs/status.md) says which parts exist today.

| Component | What it is |
| --- | --- |
| **CapacityGrant** | A signed JWT the control plane issues once per block of capacity: template digest, `fibers: {max, warm}`, `w_budget_bytes`, minimum runtime tier, lease expiry, policy. Billing charges it exactly once, at issue. |
| **Home** | The environment that holds the grant and runs fibers under it: standalone host, Kubernetes grant Pod, or Slurm allocation. Homes implement the protocol; the core is home-invariant. |
| **Grant agent** (`fiberd`) | One process per home instance. Holds the ledger, budget, fences, audit spool, and pressure ladder; forks fibers from a warm zygote. |
| **Fibers** | Node-minted instances inside a grant: copy-on-write clones of a warm zygote, addressed by an endpoint, scoped by a fence, held by a lease. |

The warm-path contract is one verb with three costs:

```
Clone(grant, deadline)              -> anonymous fiber          (fungible worker)
Clone(grant, deadline, session: S)  -> attach | resume | create (idempotent: "my worker")
Park(fiberID, sync)                 -> checkpoint delta, keep name
Release(fiberID)                    -> destroy state, free name
```

## Documentation

- [docs/overview.md](docs/overview.md) - start here: the thesis and a reading guide.
- [docs/quickstart.md](docs/quickstart.md) - build and exercise the prototype locally.
- [docs/status.md](docs/status.md) - what is implemented, what is measured, what is novel.
- [docs/architecture.md](docs/architecture.md) - the design reference.
- [docs/status.md](docs/status.md) - what is implemented today versus specified.

## License

See [LICENSE](LICENSE).
