# Resources

This page says what bounds a [fiber](glossary.md#fiber)'s CPU and memory and how to size a [home](glossary.md#home). It is for operators. Read [architecture.md](architecture.md) first. The [cgroup](glossary.md#cgroup) formulas, hierarchy and out-of-memory (OOM) handling are in [design/resources.md](design/resources.md), and the pressure ladder in [design/core.md](design/core.md).

![Inherited resource limits with two alternative backend layouts: proc and runc use process leaves under the grant cgroup, sharing unchanged template pages while consuming unequal private W. Hyperlight sandboxes share a grant helper process and report W through the helper rather than per-fiber process cgroups. W budgets are ceilings, not reservations. The fiberd/ subtree is capped below the home's limits, keeping an eighth for the agent.](./images/resource-hierarchy.svg)

## The home is the outer bound

The environment that owns the home puts the [agent](glossary.md#agent) in a cgroup with limits, such as a Pod's container limits or a Slurm step. fiberd carves its own cgroups beneath it, so every limit it sets is bounded by the home's. The agent, the [warm](glossary.md#warm) [template](glossary.md#template), [backend](glossary.md#backend) helpers and every fiber share that one allocation. The runtime keeps a slice of it for the agent, so fibers cannot starve the process that serves them ([design/resources.md](design/resources.md)).

## CPU is shared

fiberd sets no per-fiber CPU limit. Fibers, the template and the agent compete for the home's CPU, so a four-CPU home does not give four CPUs to each fiber. Choose `fibers.max` so the fibers that are runnable at once fit the home's CPU.

## Memory is shared pages plus W

On proc and runc, a fiber pays only for its [W](glossary.md#w-working-set). The [grant](glossary.md#grant)'s W [budget](glossary.md#budget) caps each fiber's leaf, so a fiber that runs away ends alone. Sandbox backends add a fixed footprint per fiber. The budget is a ceiling, not a reservation. Eight fibers with a 64 MiB budget do not reserve 512 MiB, but the home must be able to hold them if they all reach it.

On proc and runc the grant's cgroup starts to throttle at `1.25 × (fibers.max × W budget + the template's footprint)` ([design/resources.md](design/resources.md) has the sandbox variant), and the [pressure ladder](design/core.md) acts on memory pressure before that hard stop. A [Clone](glossary.md#clone) refused for pressure is [shed](glossary.md#shed-and-deferred), never sent to another home.

## What controls the fiber count

`fibers.max` counts live fibers, so [parked](glossary.md#park) [sessions](glossary.md#session) hold no slot. Set it and the W budget, since zero means unlimited ([grant fields](protocol.md#grant-fields)).

## Sizing a home

1. Measure the warm template's resident footprint.
2. Measure a fiber's W after representative requests, and set `wBudget` above it.
3. Choose `fibers.max` from the concurrency the home should serve and the CPU it has.
4. Give the home the template, `fibers.max` working sets, backend and agent overhead, and headroom. Provision for every fiber at its budget if that must never shed, and for less if the pressure ladder may park and shed under contention.

A grant's [device budget](glossary.md#device-budget) is separate from CPU and memory, and applies only when its template is an [engine](glossary.md#engine). The device seam is in [design/runtime-host.md](design/runtime-host.md).
