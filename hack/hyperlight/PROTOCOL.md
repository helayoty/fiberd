# The helper protocol

A [backend](../../docs/glossary.md#backend) whose mechanism is not reachable from Go plugs into fiberd through a **helper process**. Hyperlight has a Rust host API only, so it is one. fiberd starts one helper per [warm](../../docs/glossary.md#warm) [template](../../docs/glossary.md#template), inside the [grant](../../docs/glossary.md#grant)'s [cgroup](../../docs/glossary.md#cgroup), with a unix socketpair as the helper's fd 3, and speaks this line protocol on it. It is the [zygote](../../docs/glossary.md#zygote) protocol of `sdk/c/template/libfiberzygote.h` extended with [park](../../docs/glossary.md#park) and resume, with [fibers](../../docs/glossary.md#fiber) named by [fence](../../docs/glossary.md#fence) rather than pid, because the helper's fibers are sandboxes inside one process, not processes of their own, and with the [generation](../../docs/glossary.md#generation) and seed on the `CLONE` and `RESUME` lines rather than on a channel.

![Runtime/helper sequence: PARKED acknowledges snapshot writing, the host fsyncs before KILL, and Park returns after manifest writing and exit cleanup. A later RESUME restores state under a new fence. CLONE and RESUME carry the generation and a fresh seed.](../../docs/images/hyperlight-helper-protocol.svg)

A sync park fsyncs every file under the snapshot directory, nested ones and the manifest included, before KILL.

Every message is one line. Fields are separated by single spaces, and no field contains a space. Paths are absolute host paths. One operation per fence is outstanding at a time, save the `KILL` fiberd sends for a `CLONE` or `RESUME` whose deadline it gave up on (below). The helper's version fact changes with this protocol and is part of every park's platform, so a park made under another revision fails parity ([artifact.md](../../docs/design/artifact.md)).

## helper -> fiberd

| line | meaning |
| --- | --- |
| `READY <helper> <hyperlight> <hypervisor> <cpu>` | The template is warm. The guest is loaded, its init ran, and the warm snapshot is taken. The four facts are what its snapshots depend on (the helper's version, the hyperlight_host crate, the hypervisor in use, the CPU vendor), and fiberd records them as the platform of every park |
| `CLONED <fence>` | The fiber serves on the endpoint it was given |
| `PARKED <fence> <bytes>` | Snapshot creation completed in the directory it was given, and `bytes` is what it costs to move. Host-side sync is separate and covers the whole directory |
| `ERROR <fence> <text...>` | The operation on that fence failed. The text may contain spaces |
| `EXITED <fence> exit:<n>\|signal:<name>\|oom` | The fiber is gone. Sent for every end, asked for or not |
| `W <fence> <bytes>` | The fiber's working set changed. `bytes` is what it dirtied since the warm snapshot |

Before any of this, `helper --version` prints the same four facts on one line and exits. fiberd reads them at open and refuses a READY that disagrees.

## fiberd -> helper

| line | meaning |
| --- | --- |
| `CLONE <fence> <endpoint> <deadline_ms> <payload-hex\|-> <generation> <seed-hex>` | Make a fiber from the warm snapshot, tell it who it is, and serve on `endpoint` (a unix socket path) within the deadline. The payload is delivered to the guest as data |
| `PARK <fence> <dir> <0\|1>` | Close the endpoint and write the fiber's state into `dir`. With `1` (sync) keep the fiber alive afterwards until `KILL`, with `0` end it |
| `RESUME <fence> <dir> <endpoint> <deadline_ms> <generation> <seed-hex>` | Make a fiber from the state in `dir`, tell it who it is, and serve on `endpoint` under the new fence |
| `KILL <fence>` | End the fiber |

`generation` is fiberd's count of the fiber's lineage, 1 for a clone of the warm snapshot and the parked generation plus one for a resume. `seed-hex` is 32 bytes of fresh entropy, drawn per line and zeroed by fiberd once written. The helper hands both, with the fence, to the guest's `Incarnate(generation, fence, seed)` before it binds the endpoint, so a sandbox restored from a snapshot reseeds before anything can reach it, and a guest that refuses the call is an `ERROR`. The helper logs every command line it reads, with the seed and the payload shown by size (`seed:32B`, `payload:14B`), never by value.

## What fiberd guarantees the helper

- The helper runs inside the grant's cgroup, so every sandbox's memory is charged to the grant and the grant's ceiling applies.
- `dir` for `PARK` exists and is empty. `dir` for `RESUME` holds what a `PARK` wrote plus fiberd's own `manifest.json`, which the helper ignores.
- Endpoints live in the grant's run directory and are removed by fiberd after `EXITED`.
- The helper's stdout and stderr go to `<run dir>/<grant>/zygote.log`.
- Right after `READY`, fiberd sends one probe `CLONE` under the fence `<grant>/probe`, with endpoint `<run dir>/<grant>/probe.sock`, a 5000 ms deadline, no payload, generation 1 and a fresh seed. It times the clone from `CLONE` to `CLONED` to size the grant's default deadlines: four times the probe, never under 500 ms for a create and 2 s for a resume and never over 5 s, and the 5 s cap for a probe that does not clone in time, or answers `ERROR` within 250 ms of its 5000 ms deadline. It then sends the probe's `KILL` and waits up to 2 s for its `EXITED` before the warm is done, so the grant's footprint is read without the probe's sandbox. An `ERROR` for the probe leaves the floors and is not waited on, since the helper made no sandbox or freed it before the `ERROR`, and a helper that exits during it fails the warm. A caller that gives up during it still gets the warm instance, with defaults sized from how long the probe ran, after the same wait for its `EXITED`. The helper serves the probe like any other `CLONE`: the guest takes `Incarnate` under that fence, so template code runs once more per warm than the fibers fiberd is asked for. No real fence (grant/epoch/seq) is ever that fence, and fiberd keeps no fiber for it and ignores its `W`. It comes before the grant's device engine is told the helper's fibers, and the engine may still be starting, so a guest that calls the engine as it is born gets `err fence` or finds the engine unreachable, fails its probe and keeps the floors.

## What the helper guarantees fiberd

- `W` is honest. It is what the guest dirtied, not the sandbox's fixed footprint, and it is reported at least once after `CLONED`.
- A `PARK` ends serving before the state is written, and the snapshot is complete when `PARKED` is sent. For `sync=true`, fiberd then fsyncs the host-side state before replying to the caller.
- `CLONED` means the guest took its generation, fence and seed through `Incarnate` before the endpoint existed. No seed appears in the helper's log or in a park.
- An `EXITED` follows every end, including one fiberd asked for. It, and the `ERROR` of a `CLONE` or `RESUME` that failed, is sent once the sandbox's memory is freed, so the grant's footprint read after it does not count the sandbox.
- A `KILL` can reach the helper before the `CLONE` or `RESUME` it ends has answered, when fiberd gave up on its deadline. The helper ends that fiber as it comes, with an `EXITED`, or answers the birth's `ERROR` if it fails first, which fiberd takes as its end. A helper that sees the `KILL` before it binds the endpoint sends no `CLONED` and never serves there. One whose `CLONED` crossed the `KILL` on the socket sends its `EXITED` after it, as for any `KILL`.

## Implementations

- `hack/hyperlight/fakehelper` (Go). Sandboxes are goroutines serving the reference workload's line protocol, each with a generator seeded from its line, and state is a JSON file. It exists so the backend, the host runtime and the conformance suite run without a hypervisor, and its library (`hack/hyperlight/fakehelper/helper`) serves the same protocol in process for the unit tests.
- `hack/hyperlight/helper` (Rust, `hyperlight_host`). Sandboxes are Hyperlight micro-VMs restored from the warm snapshot. `PARK` is `Snapshot::save` (an OCI image layout), and `RESUME` builds a sandbox from it. The reference guest (`hack/hyperlight/guest`) seeds a xoshiro256** generator from `Incarnate`, mixed with `rdrand` where the CPU has it, and answers `random`, `generation` and `fence` through it. Needs KVM, MSHV or Windows Hypervisor Platform.
