# Glossary

This page defines each fiberd term in one or two plain sentences, for anyone new to fiberd who has read the [README](../README.md). The other docs link here the first time they use a term.

## Grant
A signed, time-limited permission to run one program on one [home](#home), with limits on how many [fibers](#fiber) it may have and how much memory each may use. The [issuer](#issuer) signs it once and the home checks the signature locally, so starting a fiber never waits on a remote service. On the wire the signed message is a `CapacityGrant`, and the Kubernetes example's custom resource of the same name asks its controller to sign one.

## Issuer
The control plane that decides who gets capacity and signs [grants](#grant). It publishes its public keys, so every [home](#home) can verify a grant offline.

## Lease
How long a [grant](#grant) is valid, as its [issuer](#issuer) signed it. When the lease runs out the home [yields](#yield) the grant, and a token with a later lease admits it again.

## Home
The environment that holds a [grant](#grant) and runs the [agent](#agent), such as a plain host, a Kubernetes Pod or a Slurm job. It delivers grants to the agent, reports whether the [issuer](#issuer) is reachable, and gives the agent a slice of the machine to manage.

## Seam
An interface where an environment or a sandbox plugs its own code into fiberd without changing the [agent](#agent). The home seam and the [backend](#backend) seam are the two main ones.

## Lane
The [home](#home)'s channel to the [agent](#agent) about [grants](#grant), with two jobs. It delivers grants ahead of traffic, such as token files in a directory, and a grant removed from it is revoked on that home. Its health tells the agent whether the [issuer](#issuer) is reachable. Every home has a lane, so a standalone home with nothing to deliver still reports health.

## Agent
The fiberd process on a [home](#home). It verifies [grants](#grant), keeps the record of every [fiber](#fiber) and [session](#session), and serves the API that callers use to [clone](#clone), [park](#park) and [release](#release).

## Consumer
Any program that calls the [agent](#agent)'s API, such as a serverless activator or a containerd shim. It gets a [fiber](#fiber)'s endpoint from [Clone](#clone), then talks to the fiber directly.

## Template
The program a [grant](#grant) runs, named by the content digest of its image or artifact. It starts once and does its slow setup once, and every [fiber](#fiber) is then forked or restored from it.

## Zygote
A [template](#template) linked with fiberd's small C library, libfiberzygote, so the [agent](#agent) can ask it to fork a new [fiber](#fiber). The proc and runc [backends](#backend) use one, and the fork is cheap because the child shares the zygote's memory until it writes to it.

## Warm
A [template](#template) that has started and finished its setup, and waits to make [fibers](#fiber). The [agent](#agent) keeps one warm instance per [grant](#grant), so a new fiber skips the slow start.

## Fiber
One worker made from a [warm](#warm) [template](#template). On proc and runc it is a forked process, and on gVisor and Hyperlight it is a sandbox restored from a snapshot of the template, so it starts in milliseconds and costs mainly the memory it writes, its [W](#w-working-set).

## Incarnation
One run of a [fiber](#fiber), from the create or resume that starts it until it is parked or ends. Each incarnation has a [fence](#fence) of its own.

## Slot
One unit of a [grant](#grant)'s fiber count, `fibers.max`. A running [fiber](#fiber) holds a slot, and a [parked](#park) session does not.

## Clone
The one call that returns a [fiber](#fiber) for a [grant](#grant). The caller may name a [session](#session), and the [agent](#agent) decides whether to [create, attach or resume](#create-attach-and-resume).

## Payload
Opaque bytes, at most 4096, that a caller may send with a [clone](#clone). The new [fiber](#fiber) reads them, and fiberd never interprets them.

## Create, attach and resume
The three outcomes of a [clone](#clone). Create forks a new [fiber](#fiber), attach returns the fiber a running [session](#session) already has, and resume restores a [parked](#park) session from its [delta](#delta).

## Session
A name the caller gives a [fiber](#fiber) whose state should last, such as "my worker". The name stays the same while the fiber behind it is parked, resumed or moved, and a clone without a name gets an anonymous fiber that nothing can resume later.

## Session class
A label in a [grant](#grant)'s policy that names the domain its [deltas](#delta) are published and encrypted under. Only a grant of the same class can resume them, and a grant without one uses its [template](#template) digest as the domain.

## Park
Save a running [session](#session)'s state as a [delta](#delta) and stop its [fiber](#fiber), which frees its memory. A later [clone](#clone) of the same session resumes it, on this [home](#home) or on another one.

## Delta
The saved state of a [parked](#park) [session](#session). It is usually only what the fiber changed since it was forked from its [template](#template), so it is small enough to move to another [home](#home).

## Registry
The storage between [homes](#home) that holds templates and published [deltas](#delta), such as an OCI registry or a shared directory. fiberd treats it as untrusted, so nothing from it is used before its signature and checks pass.

## Release
End a [fiber](#fiber) and free its [slot](#slot) and memory. The caller may also discard the [session](#session)'s [delta](#delta), so the session cannot be resumed.

## Yield
Give up a [grant](#grant) on one [home](#home). The [agent](#agent) revokes it, [releases](#release) its running fibers and keeps its parked [deltas](#delta). A lapsed [lease](#lease), a removal from the [lane](#lane) and the last rung of the pressure ladder each yield a grant.

## Watch
The fourth API call, a stream that summarises each of the caller's [grants](#grant), such as its running fibers and its [W](#w-working-set), as it changes.

## Fence
The identity of one [incarnation](#incarnation) of a [fiber](#fiber), made of its [grant](#grant), the [agent](#agent)'s [epoch](#epoch) and a sequence number. Every create and resume mints a fresh one, and [Clone](#clone) also returns it as the fiber ID, written `grant/epoch/seq`, such as `g1/1/2`.

## Epoch
A counter the [agent](#agent) keeps on disk and raises on every start, and whenever its [home](#home) loses its [scope](#scope). Raising it makes every [fence](#fence) minted before it invalid at once.

## Scope
The facts about where a [home](#home) runs, such as a Kubernetes namespace and Pod or a Slurm job, which the [agent](#agent) stamps on every audit record. When that place goes away, the home has lost its scope and the agent raises its [epoch](#epoch).

## Tier
The level of capability a [home](#home) offers, from basic (a worker in an already running sandbox) through warm (a fork of a [warm](#warm) template) and checkpoint ([park](#park) and resume) to snapshot (an isolated sandbox per fiber). A fifth tier, `FIBER_FABRIC`, is reserved for fibers spread across several nodes, and nothing implements it. It has nothing to do with a [fabric channel](#fabric-channel).

## Tier gap
A [clone](#clone) miss because the [home](#home) is below the [tier](#tier) the grant needs, or lacks what the grant asks for, such as tenant isolation, [handoff](#handoff) or a device. Unlike [shed and deferred](#shed-and-deferred), retrying on this home never helps.

## cgroup
A Linux control group, the kernel's way to limit and count the memory, CPU and processes of a group of processes. fiberd gives each [grant](#grant) a cgroup and, on most [backends](#backend), each [fiber](#fiber) its own cgroup inside it.

## W (working set)
The memory a [fiber](#fiber) has written since it was forked or restored, which is the memory it does not share with its [template](#template). fiberd samples it many times a second, because W is what a fiber costs to keep running and what its [delta](#delta) costs to move.

## Budget
The most [W](#w-working-set) one [fiber](#fiber) of a [grant](#grant) may use, also called its W budget. A fiber over it is killed as if it ran out of memory.

## Thrash budget
The [agent](#agent)'s cap on the rate of [clones](#clone), attaches included, which falls as the average [W](#w-working-set) of running fibers grows. A clone over it is [shed](#shed-and-deferred).

## PSI
Pressure Stall Information, a Linux measure of how much recent time processes spent waiting for memory. fiberd reads it for each grant's [cgroup](#cgroup) and reacts before the machine runs out, first by refusing new fibers, then by [parking](#park) or [releasing](#release) existing ones.

## Shed and deferred
Shed is a [clone](#clone) miss that means back off and retry, because the [home](#home) is under pressure, over its [thrash budget](#thrash-budget) or cut off from the [issuer](#issuer). Deferred is a miss that means this home lacks the capacity while the issuer is reachable, so the caller takes its ordinary path, such as starting the workload the slow way.

## Preferred home
The [home](#home) a deferred miss names when the [session](#session)'s parked [delta](#delta) lives there. The caller can send its next [clone](#clone) to that home.

## Endpoint mode
How callers reach a [grant](#grant)'s fibers. `DIRECT`, the default, gives each fiber an endpoint of its own, and `HANDOFF` puts them all behind the home's one [handoff](#handoff) address.

## Handoff
A way to reach [fibers](#fiber) through one shared address. The [agent](#agent) accepts each caller's Transport Layer Security (TLS) connection, picks the fiber from the server name the caller sent, and passes the open connection to that fiber, which proves itself with a key the caller checks.

## Relay
The [agent](#agent)'s TCP listener in front of a fiber whose [backend](#backend) cannot bind TCP, such as runc, gVisor or Hyperlight. It copies each connection's bytes to the fiber's unix socket without reading them.

## Runtime
What the [agent](#agent) makes fibers with, chosen by its `-runtime` flag. It is either `stub`, an in-memory runtime that runs no code, or a [backend](#backend) such as `proc`, driven through the [runtime host](#runtime-host).

## Runtime host
The shared layer of the [agent](#agent) between its ledger and the [backend](#backend). It gives every fiber the same [cgroup](#cgroup) limits, endpoint rules and hidden paths, whichever backend makes it.

## Backend
The mechanism that makes a [fiber](#fiber). It is proc (a plain process), runc (a container), gVisor (a sandbox with its own kernel in user space) or Hyperlight (a small virtual machine), and they differ in start time and in how strongly they keep tenants apart.

## Engine
A [warm](#warm) template that owns device state, such as a GPU's memory, and lends each [fiber](#fiber) a slice of it. It reports every slice to the [agent](#agent), and the reference template simulates one.

## Device budget
The most of an [engine](#engine)'s device state one [fiber](#fiber) may hold, the device-side twin of the W [budget](#budget). A fiber over it is killed, and a home whose template is not an engine refuses a grant that sets one.

## Fabric channel
The devices a [home](#home) hands a [grant](#grant)'s [engine](#engine), such as a static device list, a Kubernetes Dynamic Resource Allocation (DRA) claim or a Slurm job's generic resources (GRES). The home provides it before the template warms and takes it back with the grant. It is unrelated to the reserved `FIBER_FABRIC` [tier](#tier).

## CRIU
Checkpoint/Restore In Userspace, a Linux tool that saves a running process to files and later restores it. fiberd uses it on the proc and runc [backends](#backend) to save [warm](#warm) [templates](#template) and [parked](#park) [sessions](#session).

## Parity
The check that saved state, a [template](#template) checkpoint or a [delta](#delta), was made on a machine this [home](#home) can restore it on. The CPU architecture and the [backend](#backend) must always match, and by default the kernel and C library versions must match too, so a mismatch is refused rather than attempted.

## Conformance suite
The protocol's executable contract, a set of cases run through the public API against a running [agent](#agent). A [home](#home) or [backend](#backend) is conformant when every case passes.
