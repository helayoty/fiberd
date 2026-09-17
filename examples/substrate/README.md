# fiberd under Agent Substrate: a sandbox class whose actors are fibers

This directory is an example of a **consumer** of fiberd's protocol, not
part of fiberd. It is its own Go module and builds against the checkout
it sits in. It plugs fiberd into [Agent Substrate](https://github.com/agent-substrate/substrate)
as a worker image, so Substrate's control plane creates, suspends and
resumes actors that are fibers.

## Why: the same lifecycle, an order of magnitude cheaper

Substrate multiplexes many idle actors onto a few pre-started worker
Pods by snapshotting a whole sandbox to object storage on suspend and
restoring it on the next request. fiberd's claim is that every step of
that lifecycle costs an order of magnitude less when the actor is a
fiber: a copy-on-write child of a warm template, parked as the pages it
dirtied. The table is the same lifecycle measured on the same machine in
the same minute (fiberd's dev container on an M-series Mac, Docker
Desktop, `FIBERD_BENCH=1 go test -run TestStormNumbers ./tests/{proc,runc,gvisor}`),
plus the Hyperlight column from the CI job that has a hypervisor.

| lifecycle step | whole sandbox (gVisor `runsc` checkpoint/restore, what Substrate's `gvisor` class does) | fiber, fork (`proc`) | fiber, container (`runc`) | fiber, micro-VM (Hyperlight, CI on KVM) |
|---|---|---|---|---|
| warm the template, paid once | 655 ms | 194 ms | 273 ms | 236 ms |
| start one actor (to ready), p50 | 214 ms | 0.7 ms | 1.6 ms | 1.5 ms |
| start under a burst, p50 | 1.16 s (10 at once) | 58 ms (50 at once) | 37 ms (50 at once) | not measured |
| suspend, p50 | 109 ms, 71 MB image | 164 ms, 4.2 MB delta | 164 ms, 4.2 MB delta | 215 ms, 135 MB image |
| resume, p50 | 110 ms | 57 ms | 57 ms | 1.6 ms |
| 50 actors resident, each with 4 MiB of its own | 50 sandboxes | 242 MiB for all (1632 MiB as copies) | same | one snapshot each |

Read it by column, not just by row:

- **Start** is where fibers win by three orders of magnitude: a fork or a
  micro-VM restore from a resident snapshot, not a sandbox boot. This is
  the "activation latency" Substrate's north-star metric names (100 ms at
  the 95th percentile); a fiber spends its budget on the request.
- **Suspend** writes what moved. A fiber's park is the delta over the
  template's checkpoint, 4.2 MB for 4 MiB dirtied, which is what travels
  to the object store and back; a sandbox image is the whole address
  space. Substrate's roadmap lists incremental snapshots and storage
  tiering; the delta is that, priced as W.
- **Resume** from a delta merges it over the parent the worker already
  holds; the Hyperlight resume is a snapshot already in memory.
- **Density** is what the copy-on-write column shows: fifty resident
  actors cost a seventh of fifty copies, before any of them is suspended.
  Substrate's Worker holds one actor at a time; a fiberd worker can hold
  many, which is the second phase below.
- **Isolation** is the honest cost of the fork column: fibers of one
  template share a kernel. Hyperlight is the answer where actors are
  mutually untrusted: each fiber its own micro-VM with no guest kernel to
  boot, restored in 1.5 ms. It runs Hyperlight guests (or the Python and
  JavaScript guests of `hyperlight-sandbox`), not arbitrary images.

The Substrate-shaped cycle end to end, in the herder's own test (two
in-process workers, files shipped between them as atelet would, no
object store): run the golden actor 183 ms including the template's
warm, checkpoint 175 ms, restore on the other worker 414 ms (import,
claim, resume, readiness probe), 8.6 MB shipped of which the parent
checkpoint is 8 MB and the delta 0.5 MB.

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
suspends and instant resumes without a change to its control plane. A
Substrate that registered sandbox classes and let a worker hold more
than one actor would get the density column too.
