# Benchmarks

This page is the canonical source for fiberd performance measurements. It separates benchmark results from conformance and acceptance tests, and it records enough context to explain what each number measures.

The values below are historical results already recorded in this repository. They were not rerun during the documentation rewrite. Results from different runs should not be combined because the harness, concurrency, backend, and environment change the outcome.

## How to read the results

- **Warm** is the one-time cost of preparing a template.
- **Start** measures the runtime call until the fiber reports ready. It does not include control-plane placement.
- **Burst start** measures each activation while several fibers start concurrently.
- **Park** includes checkpointing and the configured synchronous durability path.
- **Resume** restores a parked fiber and waits for readiness.
- **Delta or image size** is the state produced by Park, not the running fiber's total memory.
- **Resident memory** is aggregate cgroup memory or PSS as identified for that run.

These are development measurements, not service-level objectives. Docker Desktop, hosted CI runners, storage, CRIU, and hypervisor availability can materially change them.

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

This C benchmark isolates `fork()` and copy-on-write behavior. It does not use the fiberd agent, protocol, ledger, cgroups, or CRIU.

**Environment**

- Apple Silicon Mac using the Linux development container under Docker Desktop.
- The exact Mac model, Docker version, kernel version, date, and separate commit identifier were not recorded.

**Commands**

```bash
make linux-shell
make bench
./bin/zb warm 50 128 4
./bin/zb cold 10 128
```

The warm command initializes a 128 MiB parent, starts 50 children concurrently, and dirties 4 MiB in each child. The cold command initializes the same 128 MiB independently for each of 10 processes.

| Measurement | Historical result |
| --- | ---: |
| Warm fork-to-ready | about 4 ms |
| Cold initialization per process | about 225 ms |
| Warm 50-way burst, p99 | 33 ms |
| Total PSS for parent and 50 children | 180 to 330 MiB |
| Memory without sharing | 6.5 GiB |

The broad PSS range reflects repeated development runs rather than one archived output file. Use this benchmark to validate the mechanism on a machine, not as a fiberd end-to-end latency claim.

The source and output definitions are in [`zygote_bench.c`](../zygote_bench.c).

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
