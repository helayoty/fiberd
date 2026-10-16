# Glossary

This page defines each fiberd term in one or two plain sentences, for anyone new to fiberd who has read the [README](../README.md). The other docs link here the first time they use a term.

## Grant
A signed, time-limited permission to run one program on one [home](#home), with limits on how many [fibers](#fiber) it may have and how much memory each may use. The [issuer](#issuer) signs it once and the home checks the signature locally, so starting a fiber never waits on a remote service. On the wire the signed message is a `CapacityGrant`, and the Kubernetes example's custom resource of the same name asks its controller to sign one.

## Issuer
The control plane that decides who gets capacity and signs [grants](#grant). It publishes its public keys, so every [home](#home) can verify a grant offline.

## Lease
How long a [grant](#grant) is valid, as its [issuer](#issuer) signed it. When the lease runs out the home [yields](#yield) the grant, and a token with a later lease admits it again.

## Home
Where [fiberd](#fiberd) runs, such as a plain host, a Kubernetes Pod or a Slurm job. It delivers [grants](#grant) ahead of traffic and revokes one it takes back. It tells fiberd whether the [issuer](#issuer) is reachable, and gives fiberd a slice of the machine.

## fiberd
The one process on a [home](#home). It verifies [grants](#grant), keeps the record of every [fiber](#fiber) and [session](#session), serves the API that callers use to [clone](#clone), [park](#park) and [release](#release), and streams each grant's state to the callers that watch it.

## Template
The program a [grant](#grant) runs, named by the content digest of its image or artifact. It starts once and does its slow setup once, and every [fiber](#fiber) is then forked or restored from it.

## Zygote
A [template](#template) linked with fiberd's small C library, libfiberzygote, so [fiberd](#fiberd) can ask it to fork a new [fiber](#fiber). The proc and runc [backends](#backend) use one, and the fork is cheap because the child shares the zygote's memory until it writes to it.

## Warm
A [template](#template) that has started and finished its setup, and waits to make [fibers](#fiber). [fiberd](#fiberd) keeps one warm instance per [grant](#grant), so a new fiber skips the slow start.

## Fiber
One worker made from a [warm](#warm) [template](#template). On proc and runc it is a forked process, and on gVisor and Hyperlight it is a sandbox restored from a snapshot of the template, so it starts in milliseconds and costs mainly the memory it writes, its [W](#w-working-set). A running fiber counts toward the grant's `fibers.max`, and a [parked](#park) session does not.

## Clone
The one call that returns a [fiber](#fiber) for a [grant](#grant). The caller may name a [session](#session), and [fiberd](#fiberd) then creates a new fiber, attaches to the one a running session already has, or resumes a [parked](#park) session from its [delta](#delta). The caller may also send up to 4096 opaque bytes, which the new fiber reads and fiberd never interprets.

## Session
A name the caller gives a [fiber](#fiber) whose state should last, such as "my worker". The name stays the same while the fiber behind it is parked, resumed or moved, and a clone without a name gets an anonymous fiber that nothing can resume later.

## Tenant
Who a [grant](#grant) belongs to at the [issuer](#issuer), such as a Kubernetes namespace or a Slurm account. A named [session](#session) is filed under its tenant, so a grant of another tenant never finds it, and a grant without a tenant runs anonymous [fibers](#fiber) only.

## Session class
A label in a [grant](#grant)'s policy that names, within the grant's [tenant](#tenant), the domain its [deltas](#delta) are published and encrypted under. Only a grant of the same tenant and class can resume them, and a grant without a class uses its [template](#template) digest in place of one.

## Park
Save a running [session](#session)'s state as a [delta](#delta) and stop its [fiber](#fiber), which frees its memory and its place under `fibers.max`. A later [clone](#clone) of the same session resumes it, on this [home](#home) or on another one.

## Delta
The saved state of a [parked](#park) [session](#session). It is usually only what the fiber changed since it was forked from its [template](#template), so it is small enough to move to another [home](#home).

## Registry
The storage between [homes](#home) that holds templates and published [deltas](#delta), such as an OCI registry or a shared directory. fiberd treats it as untrusted, so nothing from it is used before its signature and checks pass.

## Release
End a [fiber](#fiber) and free its memory and its place under `fibers.max`. The caller may also discard the [session](#session)'s [delta](#delta), so the session cannot be resumed.

## Yield
Give up a [grant](#grant) on one [home](#home). [fiberd](#fiberd) revokes it, [releases](#release) its running fibers and keeps its parked [deltas](#delta). A lapsed [lease](#lease), a grant the home takes back and the last rung of the pressure ladder each yield a grant.

## Fence
The identity of one run of a [fiber](#fiber), from the create or resume that starts it until it is parked or ends. It is made of the fiber's [grant](#grant), [fiberd](#fiberd)'s [epoch](#epoch) and a sequence number, and [Clone](#clone) returns it as the fiber ID, written `grant/epoch/seq`, such as `g1/1/2`.

## Generation

A [fiber](#fiber)'s place in its lineage, which [fiberd](#fiberd) counts and hands the template on every incarnation record. A fork of the warm [template](#template), a restore of its image or a pooled hand-out is 1. A resume is the [parked](#park) generation plus one, kept in the park's manifest, so a [session](#session) moved to another [home](#home) counts on. A template that counts its own incarnations can tell a missed one from the number.

## Epoch
A counter [fiberd](#fiberd) keeps on disk and raises on every start, and whenever its [home](#home) loses its [scope](#scope). Raising it makes every [fence](#fence) minted before it invalid at once.

## Scope
The facts about where a [home](#home) runs, such as a Kubernetes namespace and Pod or a Slurm job, which [fiberd](#fiberd) stamps on every audit record. When that place goes away, the home has lost its scope and fiberd raises its [epoch](#epoch).

## Tier
The level of capability a [home](#home) offers, from basic (a worker in an already running sandbox) through warm (a fork of a [warm](#warm) template) and checkpoint ([park](#park) and resume) to snapshot (an isolated sandbox per fiber). A grant names the lowest tier it accepts.

## cgroup
A Linux control group, the kernel's way to limit and count the memory, CPU and processes of a group of processes. fiberd gives each [grant](#grant) a cgroup and, on most [backends](#backend), each [fiber](#fiber) its own cgroup inside it.

## W (working set)
The memory a [fiber](#fiber) has written since it was forked or restored, which is the memory it does not share with its [template](#template). fiberd samples it many times a second, because W is what a fiber costs to keep running and what its [delta](#delta) costs to move.

## Budget
The most [W](#w-working-set) one [fiber](#fiber) of a [grant](#grant) may use, also called its W budget. A fiber over it is killed as if it ran out of memory.

## Clone rate limit
[fiberd](#fiberd)'s cap on the rate of [clones](#clone), attaches included, which falls as the average [W](#w-working-set) of running fibers grows. A clone over it is [shed](#clone-misses).

## PSI
Pressure Stall Information, a Linux measure of how much recent time processes spent waiting for memory. fiberd reads it for each grant's [cgroup](#cgroup) and reacts before the machine runs out, first by refusing new fibers, then by [parking](#park) or [releasing](#release) existing ones.

## Clone misses
The three answers a [clone](#clone) gets when it returns no fiber. Shed means back off and retry here, because the [home](#home) is under pressure, over its [clone rate limit](#clone-rate-limit) or cut off from the [issuer](#issuer). Deferred means this home lacks the capacity while the issuer is reachable, so the caller takes its ordinary path, such as starting the workload the slow way, or sends its next clone to the home the miss names as holding the [session](#session)'s parked [delta](#delta). Needs tier means the home is below the [tier](#tier) the grant needs, or lacks what the grant asks for, such as tenant isolation, [handoff](#handoff) or a device, so retrying on this home never helps.

## Handoff
A way to reach [fibers](#fiber) through one shared address, which a [grant](#grant) asks for with endpoint mode `HANDOFF` instead of the default `DIRECT`, where each fiber has an endpoint of its own. [fiberd](#fiberd) accepts each caller's Transport Layer Security (TLS) connection, picks the fiber from the server name the caller sent, and passes the open connection to that fiber, which proves itself with a key the caller checks.

## Relay
[fiberd](#fiberd)'s TCP listener in front of a fiber whose [backend](#backend) cannot bind TCP, such as runc, gVisor or Hyperlight. It copies each connection's bytes to the fiber's unix socket without reading them.

## Backend
The mechanism that makes a [fiber](#fiber), chosen with [fiberd](#fiberd)'s `-runtime` flag. It is proc (a plain process), runc (a container), gVisor (a sandbox with its own kernel in user space) or Hyperlight (a small virtual machine), and they differ in start time and in how strongly they keep tenants apart. The flag also accepts `stub`, an in-memory runtime for tests that runs no code.

## Engine
A [warm](#warm) template that owns device state, such as a GPU's memory, and lends each [fiber](#fiber) a slice of it. It reports every slice to [fiberd](#fiberd), and the reference template simulates one.

## Device budget
The most of an [engine](#engine)'s device state one [fiber](#fiber) may hold, the device-side twin of the W [budget](#budget). A fiber over it is killed, and a home whose template is not an engine refuses a grant that sets one.

## Device channel
The devices a [home](#home) hands a [grant](#grant)'s [engine](#engine), such as a static device list, a Kubernetes Dynamic Resource Allocation (DRA) claim or a Slurm job's generic resources (GRES). The home provides it before the template warms and takes it back with the grant.

## CRIU
Checkpoint/Restore In Userspace, a Linux tool that saves a running process to files and later restores it. fiberd uses it on the proc and runc [backends](#backend) to save [warm](#warm) [templates](#template) and [parked](#park) [sessions](#session).

## Parity
The check that saved state, a [template](#template) checkpoint or a [delta](#delta), was made on a machine this [home](#home) can restore it on. The CPU architecture and the [backend](#backend) must always match, and by default the kernel and C library versions must match too, so a mismatch is refused rather than attempted.
