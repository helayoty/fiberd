# fiberd under Agent Substrate: a sandbox class whose actors are fibers

This directory is an example of a **consumer** of fiberd's protocol, not
part of fiberd. It is its own Go module and builds against the checkout
it sits in. It plugs fiberd into [Agent Substrate](https://github.com/agent-substrate/substrate)
as a worker image, so Substrate's control plane creates, suspends and
resumes actors that are fibers.

## Why fibers fit

Substrate starts, suspends, restores, and terminates actors. The example maps
those operations to Clone, Park with delta export, delta import followed by
Clone, and Release. The worker keeps one admitted template warm, so actor
state can be separated from reusable parent state.

The lifecycle and resource behavior are documented in
[Runtime model](../../docs/runtime-model.md) and
[Resources](../../docs/resources.md). Backend comparisons and the
Substrate-shaped worker measurement are centralized in
[Benchmarks](../../docs/benchmarks.md#run-a-backend-lifecycle-comparison) and
[Run E](../../docs/benchmarks.md#run-e-substrate-shaped-worker-lifecycle).

## How it fits

Substrate gives everything outside the worker Pod: the control plane,
scheduling, request parking, the router, snapshot upload and download,
Pod certificates. What it asks of a sandbox class is the worker image,
and that image must bring three things; their `ateom-gvisor` and
`ateom-microvm` bring the same three.

| Substrate asks the worker image for | this example's answer |
|---|---|
| a gRPC server on the shared socket speaking `Ateom` (run, checkpoint, restore, terminate, stats), driven by atelet | `herder/`: RunWorkload is `Clone(actor uid)` (a fresh session), CheckpointWorkload is `Park(sync)` then `host.ExportDelta` (the session leaves as files atelet ships), RestoreWorkload is `host.ImportDelta` then `Clone(uid)` (kind RESUME), TerminateWorkload is `Release(discard)`, the stats calls read `Watch`; misses map to the codes their router parks on |
| the worker side of the router's tunnel: mTLS on :443, the actor named by the `ate-target-actor` header | `ingress/`: verifies the router's SPIFFE identity, proxies to the fiber's endpoint; 421 with `X-Ate-Assignment-Stale` when the actor is not here, as their `atunnel` does |
| the sandbox runtime | fiberd's agent, embedded (`pkg/agent`), with `home/`: the worker's own issuer minting one grant per ActorTemplate sized by the actor's memory limit, liveness from atelet's socket, readiness once the template is warm |

The `Ateom` service is copied from Substrate's `internal/proto`
(Apache-2.0, unchanged but for the Go package) and generated with buf;
the wire contract is the package name, the service and the field
numbers, so an unmodified atelet drives this herder.

Two facts about Substrate shape the first phase. Its sandbox class list
(`gvisor`, `microvm`) is hard-coded in the CRD, the API and the
controller, so a fiberd pool declares `sandboxClass: gvisor` and only
the image differs; atelet fetches gVisor assets the herder never uses.
And its Worker record holds one actor at a time, so this herder runs one
actor per worker; the gain is in the start, the delta and the resume.
Many actors per worker is the second phase, which needs a class
registry (a TODO in their controller) and a worker capacity above one,
proposed upstream first, as their integration policy asks.

The workload in this phase is fiberd's reference zygote in HTTP mode
(`refzygote --http`), named by the image's `ATEOM_FIBERD_TEMPLATE`
(`"<atespace>/<name>=<command>"` per ActorTemplate, or `default`). The
ActorTemplate's container image is pulled and prepared by atelet but not
run: a Substrate image is not a zygote. Its readiness probe and memory
limit are honoured.

## Running it

Unit tests need nothing; the whole-worker test needs the dev container:

```bash
cd examples/substrate && go test ./...
make linux-test                      # includes herder's TestActorLifecycleAcrossWorkers
```

The end-to-end run installs Substrate itself into a kind cluster of its
own (their scripts, at the pinned commit), builds the worker image from
fiberd's dev image, applies a WorkerPool of two fiberd workers and an
ActorTemplate, then drives an actor through Substrate's router:

```bash
make example-substrate               # docker, kubectl, go, jq; ten minutes the first time
```

It prints each request's latency: the first request resumes the actor
from the template's golden snapshot onto a free worker, three POSTs
count to three, `kubectl ate suspend` checkpoints it (a park, an export,
the upload), and the next request resumes it on whichever worker is free
with the count intact. `examples/substrate/kind/run.sh down` deletes
the cluster.

## What this is not

It is not a fork of Substrate and changes nothing in it. The point is
the shape: a worker image that answers Substrate's contract with
fiberd's four verbs, so a Substrate cluster gets clone-not-boot, W-sized
suspends, and resumable state without a change to its control plane. A
Substrate that registered sandbox classes and let a worker hold more
than one actor would get the density column too.
