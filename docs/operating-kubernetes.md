# Operating fiberd on Kubernetes

This page is the operator's how-to for the Kubernetes example in `examples/kubernetes`, for anyone running a [grant](glossary.md#grant) Pod on a cluster. Read the [quickstart](quickstart.md) first. How the controller, the grant Pod and the [home](glossary.md#home) work inside, and their known gaps, is in [design/kubernetes.md](design/kubernetes.md). The example demonstrates the [home seam](design/home.md) and passes the [conformance suite](glossary.md#conformance-suite). It is not a production-grade Kubernetes controller.

## Components

A `CapacityGrant` custom resource describes signed [fiber](glossary.md#fiber) capacity and the Pod that holds it. The `grant-issuer` Deployment runs `grant-controller`, which is the [issuer](glossary.md#issuer) here and takes the place of the standalone `grant-issuer` command. Each grant Pod runs `fiberd-k8s` in its only container, and no Pod is created per fiber.

## Image

The released `fiberd` image does not contain `fiberd-k8s`. Build the example image, which holds `fiberd-k8s`, `grant-controller`, the reference [zygote](glossary.md#zygote), [CRIU](glossary.md#criu), `runsc` and a gVisor rootfs, and point `spec.pod.image` at it.

```bash
docker build -t registry.example/fiberd-k8s:dev -f docker/kubernetes/Dockerfile .
```

## Install

The manifests in `examples/kubernetes/kind/manifests` install the namespaces, the `CapacityGrant` custom resource definition, the controller's Deployment and the grant Pods' role-based access control (RBAC). Set the controller's image in `20-issuer.yaml` to the image built above, then apply them.

```bash
kubectl apply -f examples/kubernetes/kind/manifests/{00-namespaces,10-crd,20-issuer,30-grant-rbac}.yaml
```

## From CapacityGrant to a ready home

![The grant-issuer Deployment runs grant-controller, which reconciles CapacityGrant resources and creates grant Pods and their projected JWT Secrets. Each grant Pod's one container holds fiberd-k8s, its warm template and local fibers. Kubernetes schedules grant Pods, and Clone does not schedule Pods.](./images/kubernetes-runtime-model.svg)

1. A platform component creates a `CapacityGrant`.
2. The controller creates the Pod `<name>-grant` and signs a grant whose UID is the resource UID and whose audience is the Pod name.
3. The token lands in an owned Secret, projected into the Pod. The volume is optional, so the Pod can start before the Secret exists.
4. `fiberd-k8s` admits the grant, warms the [template](glossary.md#template) and sets the readiness gate `fiberd.io/zygote-ready`.
5. The controller copies placement, readiness, lease expiry and the [agent](glossary.md#agent) endpoint into `status`.

To scale out, create another `CapacityGrant`. The controller never decides to add one, and [Clone](glossary.md#clone) never schedules a Pod.

## Readiness and status

| Field | Meaning |
| --- | --- |
| `status.placed` | The scheduler assigned the Pod to a node |
| `status.ready` | Mirrors only the `fiberd.io/zygote-ready` gate, not the Pod's `Ready` condition |
| `status.endpoint` | The agent's control endpoint, from the Pod's primary `podIP` |
| `status.expiresAt` | The lease expiry of the current signed grant |
| `status.message` | The latest reconciliation error |

- Route on both `status.ready` and the Pod's own `Ready` condition. The Pod has a TCP readiness probe on the agent's port, so Kubernetes marks it Ready only when the probe and the gate both pass.
- The Pod's liveness probe runs `fiberd-k8s -healthz` in the agent container. It asks the admin socket's `/healthz` and exits non-zero on anything but 200. `/healthz` answers 503 once the [audit](design/audit.md#health) spool is poisoned, and the kubelet restarts the agent within about 30 seconds. A startup probe gives the agent 2 minutes to come up first.
- A [consumer](glossary.md#consumer) sends the grant's JWT with every `Clone`. It reads the JWT from the grant Secret `<name>-grant`, key `grant.jwt`.
- The controller renews that Secret in place, so read the JWT again after each renewal.
- A successful `Clone` returns a separate endpoint for the fiber ([networking.md](networking.md)).
- A Pod that never passes the gate has the reason in its agent log (`kubectl logs <name>-grant`).

## Persistence

The grant Pod keeps its state, the [epoch](glossary.md#epoch) included, in `/var/lib/fiberd` on an `emptyDir` ([why that matters](design/kubernetes.md#security-notes-and-known-gaps)). Give that path a lifetime that matches the home's identity, its audience and grant UID, or start a replacement Pod with a new audience and grant UID.

## CapacityGrant fields

| Field | Meaning |
| --- | --- |
| `spec.template` | The template digest. `spec.pod.args` must make it resolvable with `-template` |
| `spec.fibers.max` | Live fibers at once. Set a positive value, since zero means unlimited |
| `spec.fibers.warm` | Signed, but no home acts on it, so leave it 0 ([grant fields](protocol.md#grant-fields)) |
| `spec.wBudget` | The [W](glossary.md#w-working-set) ceiling per fiber. Set it, since zero means unlimited |
| `spec.minTier` | The lowest [tier](glossary.md#tier) the grant accepts. Defaults to `FIBER_BASIC` |
| `spec.isolation` | `UNTRUSTED` (default) is served only by gVisor or Hyperlight. `TRUSTED` by any runtime. The controller refuses `UNTRUSTED` on proc or runc, the default runtime included, and creates nothing |
| `spec.lease` | The signed lifetime, renewed at half-life. Defaults to `10m` |
| `spec.durability` | `best-effort` or `sync` audit records. Sync records are fsynced to the Pod's local spool and nothing ships them |
| `spec.sessionClass` | The grant's [session class](glossary.md#session-class), signed into its policy. The grant's [tenant](glossary.md#tenant) is the CapacityGrant's namespace |
| `spec.deviceBudget` | The [device budget](glossary.md#device-budget), when the template is an [engine](glossary.md#engine) |
| `spec.pod.image` | An image containing `fiberd-k8s` |
| `spec.pod.runtime` | The agent's [runtime](glossary.md#runtime), which is one backend, `proc` (default), `runc`, `gvisor` or `hyperlight`. `gvisor` needs `-gvisor-rootfs <dir>` in `spec.pod.args`, and the example image ships one at `/usr/share/fiberd/gvisor-rootfs` |
| `spec.pod.args` | Appended agent flags, such as `-template` and `-parity` |
| `spec.pod.resources` | The container's requests and limits. The limits are the ceiling on everything in the Pod ([resources.md](resources.md)) |
| `spec.pod.serviceAccountName` | Defaults to `fiberd-grant` |
| `spec.pod.endpointFamily` | `inet4` (default) or `inet6`. Fibers of every runtime are reached over the Pod IP ([networking.md](networking.md)) |
| `spec.pod.nodeSelector`, `spec.pod.nodeName` | Placement |
| `spec.pod.resourceClaims`, `spec.pod.devices` | The grant's [fabric channel](glossary.md#fabric-channel). The claim belongs to the Pod, not to a fiber |
| `spec.pod.privileged` | When unset, a proc Pod runs unprivileged with only the capabilities proc needs, and a Pod for any other runtime runs privileged ([the grant Pod](design/kubernetes.md)) |
| `spec.pod.labels`, `spec.pod.annotations` | Added to the Pod |
| `spec.pod.unsafeAdmin` | Test-only controls, which need an image built with the test hooks ([agent.md](design/agent.md)). Keep it false |

A changed `spec.pod` never reaches a running Pod, so recreate the `CapacityGrant` for a Pod-level change. Renewals reuse the resource UID as the grant UID, so change only the lease in place and create a new resource for anything else ([why](design/core.md#security-notes-and-known-gaps)).

## Example

```yaml
apiVersion: fiberd.io/v1alpha1
kind: CapacityGrant
metadata:
  name: web
  namespace: tenant-a
spec:
  template: sha256:0123456789abcdef
  fibers:
    max: 10
  wBudget: 64Mi
  minTier: FIBER_CHECKPOINT
  isolation: TRUSTED   # proc shares the node's kernel
  lease: 10m
  durability: best-effort
  pod:
    image: registry.example/fiberd-k8s:dev
    runtime: proc
    endpointFamily: inet4
    args:
      - -template
      - sha256:0123456789abcdef=/app/web-zygote
    resources:
      requests: { cpu: "2", memory: 1Gi }
      limits: { cpu: "4", memory: 1536Mi }
```

This creates one Pod, `web-grant`, whose agent can run up to ten fibers from one [warm](glossary.md#warm) template. `/app/web-zygote` stands for your template, built as [zygote/README.md](../zygote/README.md) shows and added to the image. Replace the image, digest and resource values with measurements from the workload.

## Security checklist

- The example controller builds every grant Pod with `-insecure-plaintext`. A production controller passes `-tls-cert`, `-tls-key` and `-client-ca` instead, so every call carries a caller identity and grants are bound to it ([security.md](security.md#control-plane)).
- Treat the grant JWT in the Secret as a bearer token until mTLS binds it. Keep it out of logs and annotations.
- Serve discovery and the key set over an authenticated path. The example issuer serves plain HTTP inside the cluster.
- Give the Pod's ServiceAccount only what the ClusterRole and RoleBinding in `30-grant-rbac.yaml` grant, and bind it per tenant namespace.
- Apply a NetworkPolicy to the grant Pod. It selects the Pod, not a fiber.
- Review whether the chosen runtime needs a privileged Pod, and protect the issuer's signing-key Secret.
- Put untrusted workloads on gVisor or Hyperlight, never on proc or runc.
