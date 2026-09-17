# fiberd overview

**A node-level execution fabric for serverless and agent platforms: charge capacity once as a block, mint instances locally in milliseconds, survive control-plane outages by construction.**

> **Instances that cost nothing to create but still count.**

fiberd lets a platform issue a *block* of capacity once, then create individual instances ("fibers") on the node itself — in milliseconds, with no control-plane call on the request path. One core runs in many homes: standalone platforms, Kubernetes, and Slurm.

---

## The problem

Serverless container instances fight a three-way tension. An instance must be:

- **cheap** — thousands per host, or the economics fail;
- **fast** — created inside the request path, or cold starts leak into latency SLOs;
- **billable** — attributed to a tenant with a hard ceiling, or capacity leaks into overcommit incidents.

Existing designs pick two:

| Approach | cheap | fast | billable |
|---|:---:|:---:|:---:|
| Per-instance control-plane records (e.g. a Pod) | no | yes | yes |
| Warm pools | no | yes | yes |
| Userspace multiplexers | yes | yes | no |

Per-instance records resist removal because one record fuses scheduling, accounting, isolation, identity, lifecycle, ecosystem contract, and network identity, and pays for all of them every time. The mechanisms that make instances cheap (zygote fork, snapshot restore, virtual actors, block allocation) are established prior art; the [README](../README.md) lists them. What they leave open is the **protocol** between the control plane and the environment that mints instances on its behalf.

## The core inversion

fiberd resolves the tension by inverting *who does what*: the control plane's involvement ends at **issuing capacity as a signed grant**; the home **exercises** it locally.

![Delegated capacity: the control plane issues a grant once; the node mints fibers on the warm path with no call home](./images/delegated-capacity.svg)

Two proven systems already work this way: an IP router is delegated a prefix once and hosts mint addresses with no allocator involvement; Android keeps one warm *zygote* and forks every app copy-on-write. fiberd applies both moves, and adds the three things the prior art leaves open: the **signed capability grant** that carries authorization with the work, the **two miss codes** (`SHED` when the control plane is unreachable, `DEFERRED_FALLBACK` when it is healthy) that tell the caller what to do on a miss, and the **W-priced cost model** in which activation, parking and mobility are all priced in the working set a fiber dirties.

## The three components

| Component | What it is |
|---|---|
| **CapacityGrant** | An authenticated artifact the control plane issues once per block of capacity (template reference, `fibers: {max, warm}`, policy, expiry). Billing charges it exactly once, at issue. |
| **Grant agent** (`fiberd`) | One agent per home instance (a node, a grant Pod, a Slurm allocation) — the sole runtime client. Holds the ledger, the fence, the thrash budget, the audit spool, and the pressure ladder. |
| **Fibers** | Instances minted by the home inside a grant: clones of a warm engine zygote — a copy-on-write fork or a snapshot restore, by backend. Known to exactly two parties — the agent's ledger and the caller. |

The control plane sees the grant and its batched status — never individual fibers — the same way an IP allocator sees the prefix, never the addresses.

## What you get

- **Synchronous, node-local activation** — millisecond clones, no control-plane read/write/lease on the warm path.
- **Outage tolerance by construction** — a control-plane outage freezes new supply but never breaks binds against supply already on the node.
- **Accounting precedes activation** — the block is charged once; the node's authenticated copy of the grant is the proof at activation time.
- **One core, many homes** — the identical agent and semantics run standalone, under Kubernetes, and inside a Slurm allocation; only thin home adapters differ, and one conformance suite proves each.

## Reading guide

- **[quickstart.md](quickstart.md)** — build, run, and exercise the protocol on this machine; real fibers in the Linux dev container.
- **[protocol.md](protocol.md)** — the wire semantics: the grant, the four verbs, the two miss codes, fences, mobility, and the conformance suite.
- **[architecture.md](architecture.md)** — the design reference: the inversion, the components, the contract, CPU vs GPU, the backend seam, the homes, and the cross-cutting model.
- **[concepts.md](concepts.md)** — a glossary with an analogy and a diagram per term.
- **[status.md](status.md)** — what exists, what it measured, what blocks the rest.
- The examples' READMEs — [Kubernetes](../examples/kubernetes/README.md), [Slurm](../examples/slurm/README.md), [Knative over Hyperlight](../examples/knative/README.md), [a Kata-shaped shim](../examples/kata/README.md), and the in-progress [Substrate herder](../examples/substrate/README.md) — each a worked integration.
