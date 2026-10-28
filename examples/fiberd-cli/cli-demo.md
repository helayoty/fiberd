# Local demo

Five short steps that show what [fiberd](../docs/glossary.md#fiberd) does, on one machine, with `fiberd run`. Each step is one command. Together they take a few minutes. The [quickstart](../docs/quickstart.md) makes the same calls one at a time, with a signed grant.

`fiberd run` is a one-shot mode of fiberd. In each step it runs fiberd on the proc [backend](../docs/glossary.md#backend), admits one [grant](../docs/glossary.md#grant), does that step and stops. A [fiber](../docs/glossary.md#fiber) is a fork of a warm [template](../docs/glossary.md#template), so the template's start-up runs once per run, however many fibers it serves.

On a terminal `fiberd run` shows a table, one row per step, with what fiberd did and what the fiber said. Piped, it prints only what the fibers said, and its own notes go to stderr. `-o table` and `-o raw` pick one either way.

The grant is unsigned and the API is plaintext on loopback (`-trust insecure`, the only mode so far), so run this on your own machine only.

## Set up

`fiberd run` needs Linux. Step 3 also needs [CRIU](../docs/glossary.md#criu) 4.2 or later to park. The dev container has both, so on a Mac open it first.

```bash
hack/dev/run.sh bash
```

Then build the Python SDK and fiberd's commands, and point Python at the SDK.

```bash
hack/python/build.sh
make build
export PYTHONPATH=$PWD/sdk/python/src
```

The demo uses two templates, both in [examples/fiber-cli](../examples/fiberd-cli). `hello.py` answers each connection with `hello, world`. `counter.py` counts the connections it answers.

In the output below, `<ms>` stands for the times your machine prints. They describe that one run, not a comparison with anything.

## 1. One fiber

```bash
bin/fiberd run examples/hello/hello.py
```

```text
fiberd is up. Cloning 1 fiber from examples/fiberd-cli/hello.py.

  FIBER        EVENT    TIME      SAYS
  hello/1/1    clone    <ms>      hello, world

1 fiber from one template, released.
The first clone's time includes warming the template.
```

fiberd started the template, waited for it to warm, and forked one fiber from it. `hello/1/1` is the fiber's [fence](../docs/glossary.md#fence), meaning grant `hello`, [epoch](../docs/glossary.md#epoch) 1 and sequence number 1. Each run starts fresh, so it is always `hello/1/1` here.

## 2. Many fibers from one warm template

```bash
bin/fiberd run -n 50 -time examples/hello/hello.py
```

```text
fiberd is up. Cloning 50 fibers from examples/fiberd-cli/hello.py.

  FIBER        EVENT    TIME      SAYS
  hello/1/1    clone    <ms>      hello, world
  hello/1/2    clone    <ms>      hello, world
  ...
  hello/1/50   clone    <ms>      hello, world

50 fibers from one template, released.
The first clone's time includes warming the template.
The other 49 clones took p50 <ms>, p99 <ms>.
```

All 50 fibers run at once, each a fork of the one template. Only the first [clone](../docs/glossary.md#clone) paid for Python's start-up and the template's imports, and every later clone skipped them.

## 3. State that survives a park

```bash
bin/fiberd run -park examples/fiberd-cli/counter.py
```

```text
fiberd is up. Cloning 1 fiber from examples/hello/counter.py.

  FIBER        EVENT    SESSION  TIME      SAYS
  hello/1/1    clone    s1       <ms>      count 1
  hello/1/1    ask      s1                 count 2
  hello/1/1    park     s1       <ms>
  hello/1/2    resume   s1       <ms>      count 3

1 fiber from one template, released. 1 session parked and resumed.
The first clone's time includes warming the template.
```

The fiber answered twice, so its count is 2. fiberd then [parked](../docs/glossary.md#park) it, which checkpointed its memory and freed its place. The next clone of [session](../docs/glossary.md#session) `s1` resumed it from that checkpoint, and it answered 3. The template never writes the count anywhere. It lives in the fiber's memory, and the park kept that memory. The resumed fiber has a new fence, `hello/1/2`, because a fence names one run of a fiber. Add `-n 3` to park and resume three sessions in turn.

## 4. A grant is a limit

```bash
bin/fiberd run -n 3 -max 2 examples/fiberd-cli/hello.py
```

```text
fiberd is up. Cloning 3 fibers from examples/fiberd-cli/hello.py.

  FIBER        EVENT    TIME      SAYS
  hello/1/1    clone    <ms>      hello, world
  hello/1/2    clone    <ms>      hello, world
  -            refused            clone 3, deferred: ledger: grant at fibers.max, no capacity for a new fiber

2 fibers from one template, released. 1 clone refused, the grant holds 2.
The first clone's time includes warming the template.
```

`-max` sets the grant's `fibers.max`, the most fibers fiberd runs for it at once. The grant allows two, so the third clone is refused. The refusal is a `DEFERRED_FALLBACK` [miss](../docs/glossary.md#clone-misses), which tells the caller to take its ordinary path, such as starting the workload some other way.

## 5. What fiberd did

```bash
bin/fiberd run -v -park examples/fiberd-cli/counter.py
```

`-v` adds fiberd's own log to any step, including its warning that the grant is unsigned.

## Next

[architecture.md](../docs/architecture.md) explains what you just saw. To write a template of your own, start from [sdk/python/README.md](../sdk/python/README.md) and run it with `bin/fiberd run your_template.py`.
