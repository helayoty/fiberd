# Knative over Hyperlight

This example is a Knative-style activator that scales from zero with [fibers](../../docs/glossary.md#fiber) instead of Pods. It is for anyone who wants scale from zero without a cold start. It is a consumer of fiberd's protocol, in its own Go module, and is not imported by fiberd.

![Request and idle sequence: the activator calls Clone for CREATE or RESUME, forwards workload data to the guest, reuses a cached endpoint as local ATTACH without a Clone RPC, and parks the session after idle time.](../../docs/images/example-knative.svg)

## What it proves

Requests go through the activator to a Hyperlight [home](../../docs/glossary.md#home), and show four things.

- The first request [clones](../../docs/glossary.md#clone) the revision's [session](../../docs/glossary.md#session) from zero, as CREATE.
- The next requests reuse the fiber the activator holds, with state carried.
- An idle revision is [parked](../../docs/glossary.md#park).
- The request after the park resumes the session with its state intact.

This example runs the [agent](../../docs/glossary.md#agent) with `-insecure-plaintext`.

## Run it

It runs in fiberd's dev container, with the fake Hyperlight helper and no hypervisor.

```bash
make example-knative
```

The latest result is in [benchmarks](../../docs/benchmarks.md).

## Design

How requests, idle parks and misses map to the protocol is in [the Knative design](../../docs/design/knative.md).
