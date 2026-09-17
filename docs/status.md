# Status

What exists, what it measured, and what blocks the rest. The mechanics are in [architecture.md](architecture.md) and [protocol.md](protocol.md); each example's README is its walkthrough; [quickstart.md](quickstart.md) has the commands. Numbers are from Docker Desktop on an M-series Mac unless marked CI (GitHub's ubuntu-24.04 runners, x86, Linux 6.17); they are for comparison between rows, not against bare metal.

## The three claims

| Claim | Carried by | Evidence |
| --- | --- | --- |
| A signed capability grant: authorization travels with the work, verified offline, revoked by lease non-renewal | `pkg/grant` (JWT, JWKS cache, issuer), `core.Verifier`, the lease reaper | a signed JWT in every `Clone`, verified against cached keys; expired grants are capacity misses; conformance C4 on every target |
| Two miss codes keyed on control-plane health | `core.SourceHealth`, `pkg/rpc` `Miss` detail | every miss carries `Miss`; C4 proves the flip between `DEFERRED_FALLBACK` and `SHED`; `preferred_home` names where a parked session lives |
| A W-priced cost model: activation rate, park cost and mobility all in dirtied working set | `core.Budget`, per-fiber cgroup `memory.max`, deltas over the zygote's checkpoint | W is the leaf's `memory.current`; an 8 MiB dirty parks as 8 MiB + 12 pages; the same size gates whether a peer may pull the session |

## Conformance, C1 to C10

| Target | Where | Result | Notes |
| --- | --- | --- | --- |
| in-memory runtime, unsigned grants | `make conform-stub` | pass | C9 skipped: no engine to kill |
| in-memory runtime, signed grants | `make conform-signed` | pass | |
| proc | `make conform-proc` | pass (~15 s) | C6 is the kernel's OOM kill |
| runc | `make conform-runc` | pass (~18 s) | |
| gVisor | `make conform-gvisor` | pass (~8 s) | C8 is the loud refusal (no device); C9 skipped |
| Hyperlight, fake helper | `make conform-hyperlight-fake` | pass | no hypervisor |
| Hyperlight, Rust helper on KVM | `make conform-hyperlight`, CI | pass | CI only: needs `/dev/kvm` |
| Kubernetes grant Pod in kind | `make conform-kind`, CI | pass (~9 s) | hooks over `kubectl exec`; C3 restarts the container |
| Slurm allocation in Docker | `make conform-slurm`, CI | pass (~13 s) | hooks over `docker exec`; C3 restarts the agent in place |

## Backends

| Backend | Tier | Warm | Clone | Park | Resume | Park size | Blocker or next |
| --- | --- | --- | --- | --- | --- | --- | --- |
| proc (fork zygote + CRIU) | `FIBER_CHECKPOINT` | fork-to-ready 0.2 to 0.4 ms | 21 to 34 ms p50 under a 50-way storm; 720 to 920 clone+release/s sustained | ~120 ms sync, 32 MB heap | ~70 ms | the delta: 8 MiB dirtied is 8 MiB + 12 pages | a restored fiber charges its whole image until it parks again |
| runc (the zygote in a bundle) | `FIBER_CHECKPOINT` | 108 ms | 0 to 3 ms | 102 ms | 37 ms | 4 MiB dirtied is 4.1 MiB | rootfs from a template artifact |
| gVisor (a `runsc` sandbox per fiber) | `FIBER_SNAPSHOT` | 230 ms incl. the footprint probe | 60 to 75 ms | 60 to 80 ms | 60 to 70 ms | 67 MB, the whole image | a delta codec over `pages.img`; CPU-feature pinning as a parity fact; no device channel |
| Hyperlight (micro-VMs, Rust helper) | `FIBER_SNAPSHOT` | 236 ms (CI) | 1.5 ms (CI) | 215 ms (CI) | not measured | 135 MB image (CI) | W from Hyperlight's dirty tracking instead of the helper's tally; the `hyperlight-sandbox` Python and JS guests as templates |

Density and the ladder, proc backend, `make overcommit`: a zygote plus 50 fibers charges 242 MiB to the grant (1632 MB naive); under 2x overcommit against a 160 MiB grant ceiling inside a 384 MiB cap the ladder parks largest-W first and the container's OOM counter stays at zero.

## Environments and consumers

| Example | Proves | Result | Measured | Blocker or next |
| --- | --- | --- | --- | --- |
| [Kubernetes](../examples/kubernetes/README.md): the agent as PID 1 of a grant Pod, an issuer controller | the home seam is enough: projected grant, readiness gate, the Pod's own cgroup as the ceiling, Pod-IP endpoints, DRA claim as fabric, scope loss as an epoch bump | C1 to C10 and the storm pass in kind, locally and in CI | first park at PSI ~40%, no OOM kill, no restart | DRA with a real driver; a Pod whose `spec.pod` changed is not recreated |
| [Slurm](../examples/slurm/README.md): the agent inside an allocation | the same seam with a job's cgroup as the ceiling, `scontrol` as liveness, GRES as fabric, `fibers.max` bounded by the allocation's CPUs | C1 to C10 and the storm pass in Slurm-in-Docker, locally and in CI; `pkg/core` unchanged | first park at PSI ~50%, no OOM kill | a second node; a real GRES |
| [Knative over Hyperlight](../examples/knative/README.md): an activator serving scale-from-zero with fibers | a consumer needs only Clone, Park and Release: CREATE, ATTACH with state kept, park when idle, RESUME with state; misses are Knative's fallbacks | passes over the fake helper locally and in CI, and over the Rust helper on KVM in CI | scale-from-zero 139 ms and resume 35 ms as activator round trips (fake helper, this Mac); 39 ms and 13 ms in CI | manifests placing the activator beside a Hyperlight grant Pod; a guest that serves HTTP |
| [Kata-shaped shim](../examples/kata/README.md): a containerd runtime-v2 shim whose containers are fibers | a RuntimeClass whose sandboxes come from Clone; Kill parks or releases; a later Pod on the same session resumes | passes in kind, locally and in CI | CREATE, park on delete, RESUME under the same grant, release | exec and stats through the home; adding the calls to a real Kata shim |
| [Substrate herder](../examples/substrate/README.md): a worker image whose actors are fibers | a cluster-level consumer needs only the four verbs: Substrate's run, checkpoint, restore and terminate map to `Clone`, `Park` + export, import + `Clone`, `Release` | in progress | | the end-to-end run in a Substrate kind cluster |

## Mechanisms in the core

| Mechanism | Evidence |
| --- | --- |
| Admission completeness, idempotent `Clone(S)`, fence monotonic, epoch bump on restart, tier floor | conformance C1, C2, C3, C5, C7 on every target above |
| Pressure ladder: shed, then park largest-W, then release, then yield; PSI and the engine's device occupancy through one ladder | `make overcommit` and the storms in kind and Slurm; `pkg/core/pressure_test.go` |
| Session mobility through an OCI registry: park publishes the delta, `Clone(S)` on a peer pulls and claims it, too large to move is `DEFERRED_FALLBACK` with `preferred_home` | `make mobility`: count to three on home A, park, resume on B with three, A refuses its stale copy, B parks, A resumes with four |
| Platform parity: arch, kernel, libc and backend on every checkpoint; a mismatch refuses the template or defers the session | `tests/proc` with homes that believe they are on another kernel or libc |
| Device budget and engine multiplexing: `DEVICE` and `EVICT` lines, a fiber over its slice is killed, the engine's occupancy feeds the ladder, re-warm after engine loss | C8 and C9 on proc and runc with the reference zygote's simulated device |
| Scope and fabric channels: claims stamped on every audit record, `BumpEpoch` on scope loss, a fabric channel per grant | C10 on every target; the Kubernetes and Slurm homes assert their claims and bump on loss |
| Lease reaper, orphan adoption on boot, the audit spool (`BEST_EFFORT` and `SYNC`) | `pkg/core` tests; C3 on proc proves a session parked before a restart resumes after it |
| Own cgroup, delegated: the agent finds its container or job-step cgroup and carves beneath it; the environment's limit above is the ceiling; the grant cgroup closes swap | both environment examples; `pkg/sys/cgroup` tests |

## The fork/CoW mechanism (prior art, measured here)

| Measurement (C bench, 1 CPU) | Result |
| --- | --- |
| warm clone: fork from a 128 MB zygote and dirty 4 MB | ~4 ms |
| cold start: full init per instance | ~225 ms (56x) |
| 50-way fork storm, p99 | 33 ms |
| storm throughput, W = 1 MB vs 4 MB | ~110/s vs ~32/s |
| 51 processes with 128 MB heaps, total PSS | 180 to 330 MB (6.5 GB naive) |

## Not built

Per-fiber identities (fibers share the grant's identity, told apart by port); `FIBER_FABRIC`; a real GPU engine (the device protocol is exercised with a simulated one); the cross-home session move between Kubernetes and Slurm on one kernel; the KEP draft.
