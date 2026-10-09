# Benchmarks

This page is the canonical source for fiberd performance measurements. It separates benchmark results from conformance and acceptance tests, and it records enough context to explain what each number measures.

The head-to-head comparison below is the latest run. The runs after it are historical results that were not rerun. Results from different runs should not be combined because the harness, concurrency, backend, and environment change the outcome.

![One uncached activation, with nested measurement spans: runtime call to ready sits inside the activator's Clone RPC, which sits inside the client's HTTP request and response. Verification and ledger work precede activation; audit and commit precede the Clone result; workload connection and execution follow.](./images/benchmark-methodology.svg)

The diagram compares **measurement boundaries**, not durations. It shows a
representative CREATE or RESUME path; ATTACH and cached routes can skip
activation. The methodology and per-run qualifications remain below.

## How to read the results

- **Warm** is the one-time cost of preparing a template.
- **Start** measures the runtime call until the fiber reports ready. It does not include control-plane placement.
- **Burst start** measures each activation while several fibers start concurrently.
- **Park** includes checkpointing and the configured synchronous durability path.
- **Resume** restores a parked fiber and waits for readiness.
- **Delta or image size** is the state produced by Park, not the running fiber's total memory.
- **Resident memory** is aggregate cgroup memory or PSS as identified for that run.

These are development measurements, not service-level objectives. Docker Desktop, hosted CI runners, storage, CRIU, and hypervisor availability can materially change them.

## Required record for new results

Archive the raw output and record all of the following before adding or
updating a table:

- repository commit and dirty-tree state
- UTC date and exact command
- host CPU, memory, architecture, and virtualization layer
- OS, kernel, container runtime, CRIU, runc, runsc, and Hyperlight versions
- backend, endpoint family, grant fields, template configuration, and storage
- sample count, concurrency, warm-up method, quantile calculation, and failures

Store each run separately. Do not merge measurements from different commits or
environments into one row, and do not promote development measurements to an
SLO without a controlled production-like test.

## Head-to-head activation

How fast a new instance of the same workload answers, from fiberd and from what a cluster uses today. The design and fairness rules are in [compare.md](design/compare.md). Kubernetes, Pods and agent-sandbox are the baselines fiberd runs beside, not rivals.

- **Run.** [bench-compare 37967792284](https://github.com/helayoty/fiberd/actions/runs/37967792284), commit `621bb72`, 2026-10-09. GitHub ubuntu-24.04 runner, AMD EPYC 9V74, 4 vCPU, 15 GiB, kernel 6.17. kind v0.30 (Kubernetes 1.34, containerd 2.1.3), runsc 20260817.0, Firecracker v1.17.0 with guest kernel 6.1.155.
- **Workload.** A static HTTP counter holding a 32 MiB heap. Every instance gets a 64 MiB limit.
- **Method.** Client clock from the activation request to the first 200. Median over 3 timed runs of each run's p50, cold run discarded. Bursts of 1, 10 and 50 at once. Every activation in this run succeeded. The host load before and after each row is in the raw records.

**Shared kernel, in kind** (ms, p50)

| Burst | fiberd proc | fiberd runc | Pod, image cached | Pod, cold pull | agent-sandbox, pool 1 | agent-sandbox, pool 10 |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 2.8 | 3.0 | 1,055 | 1,596 | 25 | 37 |
| 10 | 7.6 | 10 | 3,357 | 3,064 | 2,221 | 212 |
| 50 | 27 | 44 | 10,331 | 9,434 | 9,921 | 9,802 |

**Sandboxed with gVisor, in kind** (ms, p50)

| Burst | fiberd gVisor | Pod on gVisor | agent-sandbox, pool 1 | agent-sandbox, pool 10 |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 117 | 2,776 | 92 | 116 |
| 10 | 765 | 4,204 | 4,212 | 123 |
| 50 | 2,784 | 21,374 | 20,900 | 18,348 |

**MicroVMs, on the host with KVM** (ms, p50)

| Burst | fiberd Hyperlight | Firecracker, snapshot from file |
| ---: | ---: | ---: |
| 1 | 5.1 | 68 |
| 10 | 10 | 342 |
| 50 | 42 | 1,708 |

**Without Kubernetes**, fiberd alone in a container over loopback: proc 2.0, 6.0 and 22 ms at bursts of 1, 10 and 50, runc 1.9, 6.3 and 25 ms, and gVisor 109, 569 and 2,305 ms.

**Resume, idle memory and control-plane work**

| System | Resume after park, ms | Idle memory per instance | API objects per run, in kind |
| --- | ---: | ---: | ---: |
| fiberd proc, alone | 60 | 0.0 MiB, 1.8 MiB with the template | 0 |
| fiberd runc, alone | 55 | 0.0 MiB, 1.8 MiB with the template | 0 |
| Pod, image cached | none | 32.6 MiB | 327 |
| agent-sandbox runc, pool 1 | 1,102 | 32.6 MiB | 561 |
| fiberd gVisor, alone | 109 | 89.9 MiB | 0 |
| Pod on gVisor | none | 62.9 MiB | 315 |
| agent-sandbox gVisor, pool 1 | one of four timed out | 61.5 MiB | 592 |
| fiberd Hyperlight | 4.6 | 0.0 MiB, 9.0 MiB with the template | no cluster |
| Firecracker | 72 | 21.3 MiB | no cluster |

Idle memory is what each instance adds, read from its cgroup after 30 seconds idle. A proc or runc fiber shares its template's heap copy-on-write, so it adds almost nothing.

**Read with care.**

- **gVisor costs memory.** A restored sandbox holds about 90 MiB, more than a Pod on gVisor (63 MiB), and a pool of pre-made sandboxes beats on-demand restore while it lasts (123 ms against 765 ms at 10).
- **Cold Pods at 50.** The kubelet pulls at most 5 images a second by default, so part of the cold Pod tail (p99 24 s) is pull throttling.
- **One runner, one run.** Runners differ: on an older EPYC, Pods were about a quarter slower and fiberd about the same. Compare rows within this run only.
- **agent-sandbox with a pool of 10** has no idle memory figure here. Its pool refilled too slowly to read in one run.

## Run A: backend lifecycle comparison

This run compared gVisor, proc, and runc during the same minute.

**Environment**

- Apple Silicon Mac, with the exact model not recorded.
- Docker Desktop and the repository's Linux development container.
- The original run did not record a commit identifier, Docker version, kernel version, or date. The values were preserved with the benchmark source in this repository.

**Recorded command**

```bash
FIBERD_BENCH=1 go test -run TestStormNumbers ./tests/{proc,runc,gvisor}
```

Add `-v` to display the measurements from a new successful run.

**Harness**

- [`tests/proc/bench_linux_test.go`](../tests/proc/bench_linux_test.go)
- [`tests/runc/bench_linux_test.go`](../tests/runc/bench_linux_test.go)
- [`tests/gvisor/bench_linux_test.go`](../tests/gvisor/bench_linux_test.go)

| Measurement | gVisor | proc | runc |
| --- | ---: | ---: | ---: |
| Warm template, paid once | 655 ms | 194 ms | 273 ms |
| Single start, p50 | 214 ms | 0.7 ms | 1.6 ms |
| Concurrent burst start, p50 | 1.16 s at 10-way | 58 ms at 50-way | 37 ms at 50-way |
| Park, p50 | 109 ms and 71 MB image | 164 ms and 4.2 MB delta | 164 ms and 4.2 MB delta |
| Resume, p50 | 110 ms | 57 ms | 57 ms |

The proc run also recorded 242 MiB in the grant cgroup for one 32 MiB zygote and 50 fibers that each dirtied 4 MiB. Treating every process as an independent 32 MiB copy would total 1,632 MiB. This result demonstrates copy-on-write sharing for that workload, not a general density ratio.

The burst sizes differ because each gVisor sandbox has a much larger fixed footprint than a forked process. Compare latency only together with the concurrency shown.

## Run B: fork and copy-on-write mechanism

These numbers came from a standalone C microbenchmark that isolated `fork()` and copy-on-write behavior. It did not use the fiberd agent, protocol, ledger, cgroups, or CRIU. That benchmark has since been removed. [`tests/proc/bench_linux_test.go`](../tests/proc/bench_linux_test.go) now measures the same shapes through the real proc runtime (Run A).

**Environment**

- Apple Silicon Mac using the Linux development container under Docker Desktop.
- The exact Mac model, Docker version, kernel version, date, and separate commit identifier were not recorded.

**Method**

The warm run initialized a 128 MiB parent, started 50 children concurrently, and dirtied 4 MiB in each child. The cold run initialized the same 128 MiB independently for each of 10 processes.

| Measurement | Historical result |
| --- | ---: |
| Warm fork-to-ready | about 4 ms |
| Cold initialization per process | about 225 ms |
| Warm 50-way burst, p99 | 33 ms |
| Total PSS for parent and 50 children | 180 to 330 MiB |
| Memory without sharing | 6.5 GiB |

The broad PSS range reflects repeated development runs rather than one archived output file. Read these numbers as a check of the mechanism, not as a fiberd end-to-end latency claim.

To measure these shapes today, run `make bench`. It runs `TestStormNumbers` from [`tests/proc/bench_linux_test.go`](../tests/proc/bench_linux_test.go) in the development container. Its results are not comparable with this table. They include the agent, the control socket and cgroups, and the zygote heap is 32 MiB. There is no cold run.

## Run C: Knative-shaped activator

This acceptance script measures HTTP round trips through the example activator. It includes Clone or Resume, endpoint connection, guest processing, and the activator response.

**Harness**

- Command: `make example-knative`
- Source: [`examples/knative/run.sh`](../examples/knative/run.sh)
- Backend: Hyperlight protocol through the fake helper
- Environment: Docker Desktop on the same Apple Silicon development machine used for the recorded local run

| Operation | Historical result |
| --- | ---: |
| First request and CREATE | 139 ms |
| Request after idle Park and RESUME | 35 ms |

A separate GitHub-hosted `ubuntu-24.04` KVM run reported 39 ms for CREATE and 13 ms for RESUME with `make example-knative-kvm`. Hosted-runner CPU details and the original log were not retained, so these values remain a separate run and should not be compared directly with the local fake-helper result.

## Run D: Slurm acceptance

This is an integration duration and pressure observation rather than a backend microbenchmark.

**Environment**

- Docker Desktop on an Apple Silicon Mac.
- The repository's one-node Slurm-in-Docker environment.

**Command**

```bash
make conform-slurm
```

The recorded run completed conformance cases C1 to C10 in 13 seconds. During the overcommit phase, the first park occurred at 13 seconds with memory PSI near 50 percent, and the job reported no OOM kill.

The script and checks are in [`examples/slurm/conform.sh`](../examples/slurm/conform.sh).

## Run E: Substrate-shaped worker lifecycle

This run exercised two in-process workers and copied checkpoint files between
them without an object store.

**Environment**

- The repository's Linux development container on the Apple Silicon
  development machine used for Run A.
- The exact host model, Docker version, kernel version, date, and commit were
  not recorded with the result.

**Command**

```bash
make linux-test
```

| Operation | Historical result |
| --- | ---: |
| Run the golden actor, including template warm | 183 ms |
| Checkpoint and export | 175 ms |
| Import, claim, resume, and readiness probe on the other worker | 414 ms |
| Files copied | 8.6 MB, comprising an 8 MB parent and a 0.5 MB delta after rounding |

The measured path is implemented by
[`TestActorLifecycleAcrossWorkers`](../examples/substrate/herder/herder_linux_test.go).
It demonstrates the example's mapping to fiberd and does not include object
storage or a Substrate control plane.

## Run F: end-to-end Clone over gRPC

This run measures Clone the way a consumer sees it and splits each round trip into stages. The client calls the Fibers service over loopback TCP. The grant is signed by an in-process issuer and verified through its JWKS. The agent uses the production ledger, budget, audit spool, and snapshot store with the proc backend.

**Environment**

- Apple M3 Mac (Mac15,3) with 16 GiB of memory.
- Docker Desktop 29.1.3 running the repository's Linux development container with 3 CPUs and 5.8 GiB of memory.
- Linux 6.12.54-linuxkit on arm64, Go 1.26.8, and glibc 2.36.
- Commit 6e58535 with uncommitted changes in the tree, run on 2026-10-06.
- The audit spool and snapshot were on a Docker named volume, so fsync reached a disk. The development container's `/tmp` is a tmpfs, where fsync costs nothing.
- Two kind clusters, a registry, and a proxy were running in the same Docker virtual machine and competed for its CPUs.

**Command**

```bash
make bench-e2e
```

**Harness**

- [`tests/proc/e2e_bench_linux_test.go`](../tests/proc/e2e_bench_linux_test.go)
- Every stage is timed where it runs and matched to the fiber it creates.
- Host is the host runtime's work around the backend. That covers the cgroup leaf and its limits, the run directory, and the endpoint.
- Zygote is the backend round trip from `CLONE` to `CLONED`, including any wait behind other clones.
- Audit is the create record. A sync record also waits for fsync.
- Agent is everything else. That covers gRPC, protobuf, admission, grant verification, the budget, the ledger, and the snapshot store.
- Verify is also reported on its own because it is a part of agent.
- Each case warms its grant with one clone first, which is reported separately and excluded from the quantiles. Sequential cases run 100 clones and release each one before the next. Burst cases run 5 rounds of 50 concurrent clones and release each round before the next.

| Case, p50 (p99) | Round trip | Host | Zygote | Audit | Agent | Of which verify |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Sequential, best-effort audit | 1.81 ms (9.01 ms) | 0.15 ms | 0.93 ms | 0.02 ms | 0.50 ms | 0.18 ms |
| Sequential, sync audit | 2.49 ms (21.87 ms) | 0.13 ms | 0.72 ms | 0.65 ms (14.42 ms) | 0.39 ms | 0.13 ms |
| Sequential, no snapshot store | 1.47 ms (22.34 ms) | 0.14 ms | 0.86 ms | 0.02 ms | 0.33 ms | 0.16 ms |
| 50-way burst, best-effort audit | 25.19 ms (48.49 ms) | 0.22 ms | 13.23 ms | 0.01 ms | 9.62 ms | 0.09 ms |
| 50-way burst, sync audit | 51.56 ms (124.37 ms) | 0.47 ms | 7.21 ms | 28.07 ms | 12.32 ms | 0.09 ms |
| 50-way burst, no snapshot store | 14.69 ms (29.84 ms) | 0.18 ms | 6.22 ms | 0.00 ms | 6.74 ms | 0.08 ms |

The stage columns are each stage's own p50, so they do not add up to the round trip. A 50-way burst took 45 ms of wall time at p50 with the snapshot store and 20 ms without it. The first clone of each grant took 116 to 259 ms. That covers admitting the grant, warming the template, and fetching the JWKS.

**What the run shows**

- One clone is about 2 ms end to end. The zygote round trip is half of that. The agent's own work, including signature verification, is about 0.5 ms.
- Under a burst, time is spent waiting rather than computing. Zygote time grows because the zygote handles `CLONE` requests one at a time. Agent time grows to several milliseconds while verification stays under 0.1 ms.
- The snapshot store writes the whole ledger after every clone. Without it, a burst finished in less than half the wall time.
- Sync audit records wait for fsync one at a time, which made audit the largest stage in the sync burst.
- Concurrent snapshot saves shared one temporary file. During bursts some saves failed with `rename ... ledger.json.tmp: no such file or directory`.
- Burst results vary between runs on this shared 3-CPU virtual machine. A second run of the same command had burst p90 values above 200 ms. Compare cases from the same run only.

## Run G: end-to-end Clone after the audit group commit

This rerun of Run F measures the change that lets concurrent sync audit records share one fsync. The environment and command match Run F. The commit was 252bb7e with uncommitted changes, and the run was on 2026-10-06.

The machine was busier than during Run F, with a load average of 7 to 15. Only the audit stage compares cleanly between the two runs. The other stages moved with the load.

| 50-way burst, sync audit, p50 | Run F | Run G |
| --- | ---: | ---: |
| Audit | 28.07 ms | 3.53 ms |
| Round trip | 51.56 ms | 34.92 ms |
| Burst wall time | 81.92 ms | 56.13 ms |

Sequential sync audit records took 0.56 ms at p50, against 0.65 ms in Run F. A single record still waits for its own fsync, so group commit helps bursts and not single clones.

## Overcommit acceptance

`make overcommit` is a pass or fail resource test rather than a latency benchmark. It runs a proc home inside a container with a 384 MiB memory and swap limit, sets the grant ceiling to 160 MiB, and drives eight fibers toward twice that grant ceiling.

The test passes only when the pressure ladder reclaims fibers while the agent remains alive and the container's OOM counter stays unchanged. Its parameters and checks are in [`hack/test/overcommit.sh`](../hack/test/overcommit.sh).

## Reproducing backend measurements

The benchmark tests are disabled by default. Run them manually because they require Linux mechanisms and can consume substantial memory.

```bash
make linux-check
FIBERD_BENCH=1 make linux-test
```

For a focused run inside the development container:

```bash
make linux-shell
FIBERD_BENCH=1 go test -v -run TestStormNumbers ./tests/proc
FIBERD_BENCH=1 go test -v -run TestStormNumbers ./tests/runc
FIBERD_BENCH=1 go test -v -run TestStormNumbers ./tests/gvisor
```

The end-to-end Clone breakdown has its own target. It mounts a Docker volume for the audit spool and snapshot so that fsync reaches a disk.

```bash
make bench-e2e
```
