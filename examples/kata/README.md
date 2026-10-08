# A Kata-shaped shim

This example is a containerd shim whose containers are [fibers](../../docs/glossary.md#fiber). Where a Kata shim boots a micro-VM, `containerd-shim-fiberd-v1` [clones](../../docs/glossary.md#clone) a fiber. It is for anyone who wants Kubernetes Pods whose containers are fibers. It is a consumer of fiberd's protocol, in its own Go module, and is not imported by fiberd.

![One node-side shim bridges containerd to a separate fiberd home. Pod 1 Create clones a fiber; stopping with Park retains session data at the home; replacement Pod 2 Create resumes that session with a new fence. Fibers and parked data stay outside the application Pods.](../../docs/images/example-kata.svg)

## What it proves

It runs on the Kubernetes example's cluster, made with kind (Kubernetes in Docker, which runs a test cluster on one machine), with a `fiberd` RuntimeClass. It shows four things.

- A Pod's container becomes a fresh fiber, and `kubectl logs` names it.
- Deleting the Pod with `on-stop=park` [parks](../../docs/glossary.md#park) its [session](../../docs/glossary.md#session) at the [home](../../docs/glossary.md#home).
- A second Pod on the same session resumes it with a new [fence](../../docs/glossary.md#fence).
- Deleting that Pod [releases](../../docs/glossary.md#release) the fiber.

Kubernetes and the Pod spec are unchanged beyond the `io.fiberd/*` annotations. This example runs the [agent](../../docs/glossary.md#agent) with `-insecure-plaintext`.

## Run it

Run it from the repository root. It needs Docker, kind, kubectl and Go.

```bash
make example-kata
```

## Design

How containerd calls map to the protocol, and the known gaps, are in [the Kata design](../../docs/design/kata.md).
