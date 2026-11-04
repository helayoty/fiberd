# A Kata-shaped shim

This example is a containerd shim whose containers are [fibers](../../docs/glossary.md#fiber). Where a Kata shim boots a micro-VM, `containerd-shim-fiberd-v1` [clones](../../docs/glossary.md#clone) a fiber. It is for anyone who wants Kubernetes Pods whose containers are fibers. It is a caller of fiberd's protocol, in its own Go module, and is not imported by fiberd.

![One node-side shim bridges containerd to a separate fiberd home. Pod 1 Create clones a fiber; stopping with Park retains session data at the home; replacement Pod 2 Create resumes that session with a new fence. Fibers and parked data stay outside the application Pods.](../../docs/images/example-kata.svg)

## What it proves

In kind (Kubernetes in Docker, which runs a test cluster on one machine), with a `fiberd` RuntimeClass, it shows four things. That kind run waits for the controller project to create grant Pods and mint grants in kind.

- A Pod's container becomes a fresh fiber, and `kubectl logs` names it.
- Deleting the Pod with `on-stop=park` [parks](../../docs/glossary.md#park) its [session](../../docs/glossary.md#session) at the [home](../../docs/glossary.md#home).
- A second Pod on the same session resumes it with a new [fence](../../docs/glossary.md#fence).
- Deleting that Pod [releases](../../docs/glossary.md#release) the fiber.

Kubernetes and the Pod spec are unchanged beyond the `io.fiberd/*` annotations. This example runs [fiberd](../../docs/glossary.md#fiberd) with `-insecure-plaintext`.

## Run it

`make example-kata` waits for the controller project, [Azure/fiberd-k8s-controller](https://github.com/Azure/fiberd-k8s-controller). Until it lands, the target says so and exits 2.

The shim installs on the node of an existing kind cluster, named `fiberd` unless `KIND_CLUSTER` says otherwise. Run it from the repository root. It needs Docker, kubectl and Go.

```bash
examples/kata/kind/run.sh shim
```

## Design

How containerd calls map to the protocol, and the known gaps, are in [the Kata design](../../docs/design/kata.md).
