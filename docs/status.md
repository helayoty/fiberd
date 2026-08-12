# fiberd Implementation Status and Evidence

This page tracks what the prototype actually does today versus what the design specifies, plus the measurements and semantic checks that back the design's claims. For how to reproduce these locally, see [quickstart.md](quickstart.md). For the design itself, see [architecture.md](architecture.md).

The prototype is deliberately split into two pieces along the design's own seam: a C bench that measures the raw `fork()`/CoW **mechanism**, and a Go agent that exercises the warm-path **semantics**.

## PoC data flow

```mermaid
flowchart LR
    R(["router / curl"]) ==> A["fiberd agent (Go)"]
    A ==> D{"session S ?"}
    A -->|"over budget"| S["shed · 429"]
    D ==>|"running"| T["attach<br/>~0 ms"]
    D ==>|"parked"| U["resume delta<br/>sub-second"]
    D ==>|"new / anonymous"| F["fork zygote<br/>~4 ms"]
    T ==> E(["endpoint + fence"])
    U ==> E
    F ==> E
    F -.-> B["zygote_bench.c<br/>measured: 4 ms warm · 56x vs cold · 20x CoW sharing"]
```

## PoC component map (real vs planned)

```mermaid
flowchart TD
    C["POST /v0/clone<br/>GrantUID, Session S, deadline"]

    subgraph core["Go core - real semantics"]
        FE["RPC frontend<br/>payload cap · authn (JWKS stub)"]
        BU["Budget enforcer<br/>token bucket, rate = f(W)"]
        LG["Ledger<br/>per-session lock = idempotency<br/>fibers.max ceiling · reserve/rollback"]
        EP["EpochStore<br/>epoch++ on every boot"]
        GS["GrantSource - async lane<br/>AdmitGrant / RevokeGrant"]
        A1["attach<br/>reuse existing fence"]
        A2["resume<br/>mint fence seq+1"]
        A3["create<br/>mint fence seq+1"]
    end

    RT{{"Runtime interface<br/>Clone(sandbox, src, fence, deadline)"}}

    subgraph today["today: runtime/stub"]
        ST["in-memory handles<br/>NO process created"]
    end

    subgraph m1["next: runtime/proc"]
        PR["control socket"]
        ZY["zygote self-forks<br/>fork · scrub · adopt identity"]
    end

    subgraph bench["mechanism evidence: zygote_bench.c"]
        ZB["raw fork + CoW, measured:<br/>~4ms warm · 56x vs cold · 20x PSS sharing"]
    end

    RESP["FiberID · Endpoint · Fence"]
    SHED["429 + Retry-After (SHED)"]
    DFB["503 (DEFERRED_FALLBACK)"]

    C --> FE --> BU --> LG
    BU -->|over budget| SHED
    LG -->|at fibers.max| DFB
    GS --> LG
    EP --> LG
    LG -->|S running| A1
    LG -->|S parked| A2
    LG -->|S unknown or anonymous| A3
    A1 --> RESP
    A2 --> RT
    A3 --> RT
    RT --> ST
    RT -. "replaces stub" .-> PR
    PR --> ZY
    ZY -. "same syscall, measured here" .- ZB
    RT --> RESP

    classDef real fill:#d5e8d4,stroke:#2e7d32,color:#1b3a1b
    classDef fake fill:#f8cecc,stroke:#b85450,color:#4a1210
    classDef plan fill:#fff2cc,stroke:#b8860b,color:#4a3a00
    class FE,BU,LG,EP,GS,A1,A2,A3,ZB real
    class ST fake
    class PR,ZY plan
```

## Measured results (1-CPU sandbox, Aug 2026)

| Measurement | Result | Design claim validated |
| --- | --- | --- |
| Warm clone: fork from 128MB zygote + dirty 4MB | ~4 ms | ms-scale activation |
| Cold start: full init per instance | ~225 ms | clone-not-create is the only path (56x) |
| 50-way pure-fork storm, p99 | 33 ms | fork survives concurrency |
| Storm throughput W=1MB vs W=4MB | ~110/s vs ~32/s | thrash budget is genuinely f(W) |
| 51 procs x 128MB heap, total PSS | 180-330 MB (vs 6.5 GB naive) | CoW density basis for ~1000/node |

## Semantic proofs (exercised live in the prototype)

The Go core reproduces the attach, shed, and epoch rows today; the park/resume, signed-grant, and audit rows are next-step items. The `fibers.max` capacity ceiling is enforced in the ledger.

| Demo | Output observed | Design invariant |
| --- | --- | --- |
| Grant signature verified before boot | boot refuses on bad sig | accounting precedes activation; offline proof |
| `Clone(S)` twice | 2nd returns `attach`, same endpoint/fence | idempotency on the request path |
| hit x4, Park, `Clone(S)` | `resume`, count continues 4 -> 5, new pid, new seq | identity != incarnation; continuity contract |
| `{"image": "evil"}` on Clone | rejected: un-admitted fields | admission completeness (structural, not policy) |
| 12-clone burst at 5/s limit | accepted=5 shed=7, `code: SHED` | thrash budget backpressure |
| agent restart | epoch 1 -> 2 in status | fence rotation = revocation, node-local |
| `state/audit.jsonl` | one record per op with fence | audit spool, async-shippable |

## What is real vs planned

| Component | Prototype today | In the full design |
| --- | --- | --- |
| Clone mechanism | prestarted process pool in the agent; true CoW fork only in the C bench | CRI CloneFiber against a zygote checkpoint (containerd >= 2.0 restore path) |
| Capacity ceiling | ledger enforces `fibers.max`: reserve at `Resolve`, roll back on abandon, free on `Park`/`Release`; `ErrGrantFull` -> 503 (DEFERRED_FALLBACK); unit-tested in `pkg/core/ledger_test.go` | same, plus the cgroup slice hard ceiling and per-fiber `memory.max` + `oom.group` |
| Isolation | none - plain processes | runtime tiers; leaf cgroups + oom.group |
| Park delta | worker serializes its own state | CRIU incremental / snapshot layer diff |
| Grant source | local signed JSON | k8s adapter (watch) or platform adapter (signed) |
| Identity | none | grant capability -> per-fiber delegation |
| Pressure ladder | HTTP-triggered demo ordering | PSI-driven, racing kubelet eviction (measure!) |
| Orphan adoption on boot | missing (running fibers lost on restart) | ledger reconcile from CRI ListFibers |
