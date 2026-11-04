# Operating fiberd on Kubernetes

This page is for whoever runs fiberd on a cluster, in [grant](glossary.md#grant) Pods a controller creates. Read the [quickstart](quickstart.md) first. How the [home](glossary.md#home) and the grant Pod work inside, and their known gaps, is in [design/kubernetes.md](design/kubernetes.md). The `CapacityGrant` resource, the controller's install and its fields are documented in the [fiberd-k8s-controller](https://github.com/Azure/fiberd-k8s-controller) repository.

## The grant Pod

A grant Pod holds signed [fiber](glossary.md#fiber) capacity. Its one container runs fiberd's own image with `fiberd -home kubernetes`. No Pod is created per fiber, and Kubernetes schedules grant Pods, not fibers.

## From CapacityGrant to a ready home

![A tenant creates a CapacityGrant. The fiberd-k8s-controller Deployment reconciles it and creates a grant Deployment, whose grant Pod's one container runs fiberd -home kubernetes. The kubelet projects a service-account token bound to the Pod, and fiberd fetches its grant from the controller with it. fiberd holds one warm template and its local fibers, handles Clone and answers the healthz and readyz probes. Kubernetes schedules grant Pods, not fibers.](./images/kubernetes-runtime-model.svg)

1. A tenant creates a `CapacityGrant`.
2. The controller creates a Deployment for it. Its Pod lists the readiness gate `fiberd.io/zygote-ready`.
3. The kubelet projects a service-account token bound to the Pod.
4. fiberd fetches its grant from the controller with that token and writes it into `-grants-dir`.
5. fiberd admits the grant, warms the [template](glossary.md#template) and sets the gate.

To scale out, create another `CapacityGrant`. [Clone](glossary.md#clone) never schedules a Pod.

## Identity and grant flags

The downward API fills the Pod's identity. `-pod-name`, `-pod-namespace` and `-pod-uid` default to `POD_NAME`, `POD_NAMESPACE` and `POD_UID`, and fiberd refuses to start without all three. Without `-node-id`, the Pod's name is the node id, so it matches the grant's audience.

| Flag | What it does |
| --- | --- |
| `-grant-token-file` | The Pod's bound service-account token. It turns the grant fetch on, which then needs `-issuer` and `-grants-dir` |
| `-issuer` | The controller's https address. The grant endpoint is `/v1/grant` under it |
| `-grant-ca-file` | The PEM bundle the endpoint's certificate must chain to. Empty means the system roots |
| `-grant-fetch-timeout` | How long the first fetch retries before fiberd refuses to start. Defaults to 60 seconds |

fiberd renews the grant at half its remaining lease. Through a controller outage it keeps serving the current grant until that lease ends. A container that restarts with an unexpired grant file starts on it. The retry rules are in [grant fetch](design/kubernetes.md#grant-fetch). Without `-grant-token-file`, grants arrive only as `*.jwt` files in `-grants-dir`.

## Probes and drain

- `fiberd healthz` asks the admin socket under `-state` for `/healthz` and exits non-zero on anything but 200. `/healthz` answers 503 once the [audit](design/audit.md#health) spool is poisoned. Use it as the liveness probe.
- `fiberd readyz` asks for `/readyz`, which answers 503 whenever `/healthz` does and while fiberd drains. Use it as the readiness probe.
- Run both with the same `-state` as fiberd. Each gives up after 5 seconds, so set the probe timeout above that.
- Kubernetes marks the Pod Ready only when the readiness probe and the gate both pass. Route on the Pod's `Ready` condition.
- Deleting the Pod sends fiberd SIGTERM, and fiberd stops at once. To keep sessions across that stop, set `-drain-timeout`, so fiberd [drains](glossary.md#drain) first ([fiberd.md](design/fiberd.md)).
- Keep `-drain-timeout` below the Pod's `terminationGracePeriodSeconds`, 30 seconds by default, with room for the stop that follows.
- A caller sends the current grant's JWT with every `Clone`. A successful `Clone` returns a separate endpoint for the fiber ([networking.md](networking.md)).

## Persistence

fiberd keeps its state, the [epoch](glossary.md#epoch) included, in `/var/lib/fiberd` on an `emptyDir`. A container restart keeps it. A Pod replacement loses it and starts again at epoch 1 ([why that matters](design/kubernetes.md#security-notes-and-known-gaps)). The replacement has a new Pod UID, so its grant has a new grant UID and audience.

## Privileges

- fiberd narrows its capabilities at start to the set its [backend](glossary.md#backend) needs ([capabilities](design/sys.md)). A proc Pod runs unprivileged with only those.
- An unprivileged Pod gets cgroupfs and the [CRIU](glossary.md#criu) sysctls read-only. fiberd makes them writable at start.
- The container needs an Unconfined seccomp profile, because CRIU cannot dump from under a filter.
- On a node whose containerd applies its default AppArmor profile, an unprivileged Pod also needs `appArmorProfile: Unconfined`. Otherwise fiberd's remounts are denied.
- Put untrusted workloads on gVisor or Hyperlight, never on proc or runc.
- Serve the API with `-tls-cert`, `-tls-key` and `-client-ca`, so every call carries a caller identity and grants are bound to it ([security.md](security.md#control-plane)).
- Apply a NetworkPolicy to the grant Pod. It selects the Pod, not a fiber.

## When a Pod never passes the gate

The Pod's `fiberd.io/zygote-ready` condition shows `NoWarmTemplate` until a template is warm. fiberd's log names the reason, so read it with `kubectl logs <pod>`. The usual causes are a missing Pod identity, a grant fetch the controller refused or that timed out, a grant whose UID is not the Pod's, and a template that would not warm.
