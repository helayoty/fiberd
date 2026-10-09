# fiberd on Kubernetes

This example runs fiberd on a cluster. A controller turns each CapacityGrant resource into a signed [grant](../../docs/glossary.md#grant) and a grant Pod that runs the fiberd [agent](../../docs/glossary.md#agent). It is for anyone who wants to run fiberd on a Kubernetes cluster. It is its own Go module and is not imported by fiberd.

![Controller setup is separate from local serving: a CapacityGrant resource produces one Pod and an owned grant Secret; projection and warm-up precede the custom readiness gate, while repeated Clone and direct fiber traffic stay off the controller path.](../../docs/images/example-kubernetes.svg)

## What it proves

- A [home](../../docs/glossary.md#home) for Kubernetes needs only the home seam. fiberd is unmodified.
- The grant Pod passes fiberd's conformance suite, run from the host against the Pod.
- Under a 384 MiB Pod limit, a burst of clones that asks for more memory than the Pod has [parks](../../docs/glossary.md#park) [fibers](../../docs/glossary.md#fiber) before any out-of-memory (OOM) kill.
- An `UNTRUSTED` grant on gVisor ([60-gvisor.yaml](kind/manifests/60-gvisor.yaml)) serves a client in another Pod over the Pod IP, and its fiber keeps its state across a park and resume. `make conform-kind` runs this check last, and `kind/conform.sh gvisor` runs it alone.

This example runs the agent with `-insecure-plaintext`.

## Run it

Run it from the repository root. It needs Docker, kind (Kubernetes in Docker, which runs a test cluster on one machine), kubectl and Go.

```bash
make conform-kind
```

## Design

How the controller, the grant Pod and the home work, and the known gaps, are in [the Kubernetes design](../../docs/design/kubernetes.md).
