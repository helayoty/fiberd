# fiberd

![The control plane issues a signed capacity grant once. The home verifies it, warms one template and creates fibers locally. It returns endpoints to callers and reports aggregate status.](./docs/images/fiberd-hero.svg)

Platforms often need many instances of the same workload, started on demand. The workload may be a container, an agent or a plain process. Each new instance usually boots, loads its code and fills its own memory, and often waits on a control plane first, even though it is a copy of one that already runs. fiberd creates those instances from one warm copy, fast and densely, inside whatever already places the workload, such as Kubernetes or Slurm. It is a reference implementation, not yet production-ready, and [production-readiness.md](docs/production-readiness.md) lists what is missing.

## What fiberd does

- A [template](docs/glossary.md#template) starts once and stays [warm](docs/glossary.md#warm).
- Each [fiber](docs/glossary.md#fiber) is a cheap fork or snapshot restore of that template, so it starts in milliseconds.
- An [issuer](docs/glossary.md#issuer) grants a block of capacity once, as a signed [grant](docs/glossary.md#grant).
- The [home](docs/glossary.md#home) checks the grant locally and mints fibers from it without calling back.

## Why fiberd

fiberd works with the scheduler, not instead of it. Fast starts from a warm copy are not new either. Android's zygote forks warm processes, and Firecracker and Lambda SnapStart restore snapshots. fiberd's part is making that safe to run at scale.

- **Placement once, instances locally.** The scheduler places a signed block of capacity once. The home creates instances inside it with no API write or scheduler call per instance, so the scheduler sees one placement instead of one object per instance.
- **Every instance stays checkable.** Each fiber's [fence](docs/glossary.md#fence) ties it to its grant and to the agent's [epoch](docs/glossary.md#epoch), so revocation and restarts reach every fiber. Each operation lands in a hash-chained audit log with signed checkpoints. A caller that misses gets a typed answer that says whether to back off or fall back.
- **One contract, any scheduler, any isolation.** The same grant works on Kubernetes, Slurm or a bare host, and over plain processes, runc, gVisor or Hyperlight.
- **Sessions move.** A parked session can resume on another home, verified and sealed to its tenant.

The fastest path, proc and runc, shares the host kernel, so it suits trusted code. Untrusted code runs on gVisor or Hyperlight, where a fiber is a snapshot restore.

## The four verbs

- **[Clone](docs/glossary.md#clone)** returns a fiber for a grant, anonymous or by [session](docs/glossary.md#session) name.
- **[Park](docs/glossary.md#park)** saves a session and frees its fiber's memory.
- **[Release](docs/glossary.md#release)** ends a fiber.
- **[Watch](docs/glossary.md#watch)** streams a summary of each grant.

[protocol.md](docs/protocol.md) is the wire contract for all four.

## Reading path

Read in this order, and look up any term in the [glossary](docs/glossary.md).

1. [Quickstart](docs/quickstart.md) to see it run.
2. [Architecture](docs/architecture.md) for how it is designed.
3. [Security](docs/security.md) for the trust boundaries.
4. The operator guides, which are [Operating on Kubernetes](docs/operating-kubernetes.md), [Networking](docs/networking.md), [Resources](docs/resources.md) and [Production readiness](docs/production-readiness.md).
5. The [design docs](docs/design/README.md) for each module in depth.
6. The [examples](#examples) for fiberd in real environments.
7. [Protocol](docs/protocol.md) for the wire contract, and [Benchmarks](docs/benchmarks.md) for measured results.

## Install

Each release has an archive per platform, named `fiberd_<version>_<os>_<arch>.tar.gz`, for linux or darwin on amd64 or arm64. The libfiberzygote archives hold the [zygote library](zygote/README.md). Check the checksum and provenance before you unpack.

```bash
gh release download v0.1.0 -R helayoty/fiberd -p fiberd_0.1.0_linux_amd64.tar.gz -p SHA256SUMS
shasum -a 256 --ignore-missing -c SHA256SUMS
gh attestation verify fiberd_0.1.0_linux_amd64.tar.gz -R helayoty/fiberd
tar -xzf fiberd_0.1.0_linux_amd64.tar.gz
./fiberd -version
```

The image `ghcr.io/helayoty/fiberd:<version>` holds fiberd, criu and the zygote library.

```bash
gh attestation verify oci://ghcr.io/helayoty/fiberd:0.1.0 -R helayoty/fiberd
```

## Start

```bash
make build
make conform-stub   # the conformance suite on the in-memory runtime, on any OS
make conform-proc   # the same on real fibers, in the Linux dev container (hack/dev)
```

The [quickstart](docs/quickstart.md) walks through each call. To write your own template, read [zygote/README.md](zygote/README.md) and [the zygote design](docs/design/zygote.md).

## Examples

- [Kubernetes](examples/kubernetes/README.md) is a controller that turns each `CapacityGrant` custom resource into a signed grant and one Pod running the agent.
- [Slurm](examples/slurm/README.md) runs the [agent](docs/glossary.md#agent) inside a job allocation.
- [Knative](examples/knative/README.md) is an activator, the component that holds requests while a service scales from zero, here with fibers in Hyperlight micro-VMs.
- [Kata-shaped shim](examples/kata/README.md) is a containerd shim, the plug-in that starts a Pod's containers. It has the shape of the Kata Containers shim without using Kata, and its containers are fibers.
- [Agent Substrate](examples/substrate/README.md) is a worker for a platform that starts, suspends and resumes actors in worker Pods. Its actors are fibers.

## Contributing

CI runs the unit tests on linux/amd64 and macOS as a non-root user, so privileged tests skip there. The Linux suites run as root in a container. Run `make test` and `make lint` before sending a change.

## License

[Apache-2.0](LICENSE).
