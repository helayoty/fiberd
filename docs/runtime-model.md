# Runtime model

fiberd separates reserved capacity from the instances that use it. A control
plane issues a `CapacityGrant` to a home. The home runs a fiberd agent, and the
agent verifies the grant and prepares one warm template. Callers then create
fibers from that capacity without another placement call.

These terms describe different parts of the model:

- A **grant** authorizes a bounded block of capacity and fixes the admitted
  workload.
- A **home** is the environment that receives the grant and supplies its
  resource, network, and scope boundaries.
- A **warm template** is the initialized source from which fibers are forked
  or restored. Process backends call it a zygote.
- A **fiber** is one running or parked workload instance managed through the
  grant protocol.

## A fiber is not inherently a container

The backend determines the operating-system boundary around a fiber and the
mechanism used to create or restore it.

| Backend | What one fiber is | Creation and endpoints | Park and resume |
| --- | --- | --- | --- |
| `proc` | A child process in its own cgroup leaf | Copy-on-write fork; unix or TCP | CRIU delta when CRIU is available |
| `runc` | A child process inside the warm OCI container | Copy-on-write fork; unix or TCP | CRIU delta when CRIU is available |
| gVisor | A separate `runsc` sandbox | Restore from an image; unix only, with networking disabled | Sandbox snapshot |
| Hyperlight | A micro-VM sandbox inside one grant helper process | Restore from a snapshot; unix only | Helper snapshot |
| `stub` | An in-memory protocol record | Synthetic test endpoint | In-memory park for tests |

Hyperlight fibers do not have their own host process or cgroup leaf. They are
sandboxes inside the grant helper process, which remains inside the grant
boundary.

The Kata-shaped example deliberately presents a fiber through containerd's
container API as a consumer integration, but it does not change the core
meaning of a fiber or make every fiber an OCI container. The
[identity model](identity.md) describes the filesystem and credential
boundaries of each backend.

## What runs in a fiber

The template fixes the executable workload. It includes the image or artifact,
command, arguments, environment contract, mounts, security context, and
resource shape that the control plane admitted. `Clone` selects **already admitted** 
capacity and cannot replace the image or reshape the workload.

Each fiber runs one instance of the admitted workload. For example, when the
template contains a web server, every successful create starts a separately
addressable server process or sandbox from that warm template. The resulting
fibers have these properties.

- Expensive application initialization happens once in the warm template.
- Each fiber receives its own endpoint and fence.
- Each fiber serves its own requests and owns its mutable process state.
- Copy-on-write backends continue sharing unchanged memory pages.

One home can therefore host many independently addressable web servers without
placing each server independently. When a home uses TCP, the fibers share the
home address and use different ports. The caller uses the exact endpoint
returned by `Clone`.

## How fiberd uses the zygote

Zygote is the process-backend name for the initialized warm template. Sandbox
backends use a warm snapshot for the same role.

The lifecycle is:

1. **Warm.** After admitting the grant, fiberd starts the template and waits
   for it to become ready. Where supported, it also records the parent
   checkpoint used for delta checkpoints.
2. **Create.** fiberd reserves a ledger slot, mints a fence and endpoint, and
   asks the backend to fork or restore the template. Process backends also
   place the fiber in its cgroup leaf.
3. **Scrub and start.** Process backends close inherited descriptors, clear
   inherited environment variables, reseed entropy, and publish the new
   endpoint and fence before the workload starts serving.
4. **Observe.** The agent tracks the fiber's endpoint, fence, lease, working
   set, exit, and optional device usage.
5. **Park or release.** A named session may be checkpointed and resumed later
   when the backend satisfies the checkpoint tier. Release destroys the
   running state and can discard retained checkpoint data.

There is one warm template per grant per home. An agent capable of holding
multiple grants keeps a separate warm template for each grant.

### CPU and device execution differ

On CPU, proc and runc fibers are copy-on-write children of the zygote. Device
memory and driver contexts cannot be forked the same way. The device model
uses one grant-wide engine that owns the device state. Fibers communicate with
it over local IPC and hold logical slices such as KV-cache allocations.

The device engine in this repository is a simulation for accounting and
pressure behavior. It is not production CUDA, GPU, DRA, or RDMA support.

An engine failure interrupts every running fiber that depends on that engine.
Parked CPU state remains available and can resume after the template is warm
again. The [protocol reference](protocol.md) defines how anonymous and named
Clone requests resolve to CREATE, ATTACH, or RESUME.

## Scaling within and beyond a home

Scaling within an admitted grant is local. Callers continue cloning until the
grant reaches `fibers.max`, resource pressure causes shedding, or the grant
expires. The control plane does not place those individual fibers.

Scaling out requires another block of capacity. The platform creates another
`CapacityGrant`, assigns it to another home, waits for that home to become
ready, and routes new Clone requests to it. fiberd reconciles capacity that it
has received, but it does not decide when the platform should add a home.

The [protocol outcomes](protocol.md#outcomes) tell a caller whether unavailable
capacity should use the platform's provisioning path or retry later.

## Boundaries to keep in mind

- A fiber is not a platform placement object or universally an OCI container.
- A clone cannot select a new image, command, mount, or security context.
- A home is finite, so local activation does not create unbounded capacity.
- Individual fibers are absent from the control plane. The agent reports
  aggregate grant status instead.
- Network endpoint, resource, and identity behavior are properties of the home
  and backend, not implied by the word `fiber`.

For CPU, memory, sizing, and OOM behavior, continue with the
[resource model](resources.md). For endpoint allocation and network
boundaries, see [networking](networking.md). For grant authentication,
fences, and workload credentials, see [identity](identity.md). For internal
component boundaries and backend contracts, see the [architecture
reference](architecture.md). The [protocol reference](protocol.md) defines the
grant lifecycle visible to callers. For the Kubernetes mapping, see
[Kubernetes operations](operating-kubernetes.md).
