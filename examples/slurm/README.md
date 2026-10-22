# fiberd on Slurm

This example runs [fiberd](../../docs/glossary.md#fiberd) inside a Slurm allocation, as the allocation's job. It is for anyone who wants to run fiberd on a batch cluster. It is its own Go module and is not imported by fiberd.

![One sbatch creates a bounded Slurm allocation; the job script starts fiberd-slurm inside it, and repeated Clone calls activate fibers under the same resource ceiling without new scheduler submissions.](../../docs/images/example-slurm.svg)

## What it proves

- One `sbatch` is enough. Repeated [Clone](../../docs/glossary.md#clone) calls start [fibers](../../docs/glossary.md#fiber) under the allocation's ceiling with no new submission.
- A [home](../../docs/glossary.md#home) for Slurm needs only the home interface. fiberd is unmodified.
- fiberd passes fiberd's conformance suite inside a one-node Slurm-in-Docker cluster.
- Under a 384 MiB job memory limit, a burst of clones that asks for more memory than the job has [parks](../../docs/glossary.md#park) fibers before any out-of-memory (OOM) kill.

This example runs fiberd with `-insecure-plaintext`.

## Run it

Run it from the repository root. It needs Docker and Go.

```bash
make conform-slurm
```

After the storm, it runs the same storm without fiberd, in jobs of the same size. That baseline only measures, so its OOM kills are expected. The latest result is in [benchmarks](../../docs/benchmarks.md).

## Design

How the home, the job script and the prolog work, and the known gaps, are in [the Slurm design](../../docs/design/slurm.md).
