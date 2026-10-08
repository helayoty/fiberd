# The helper protocol

A [backend](../../docs/glossary.md#backend) whose mechanism is not reachable from Go plugs into fiberd through a **helper process**. Hyperlight has a Rust host API only, so it is one. fiberd starts one helper per [warm](../../docs/glossary.md#warm) [template](../../docs/glossary.md#template), inside the [grant](../../docs/glossary.md#grant)'s [cgroup](../../docs/glossary.md#cgroup), with a unix socketpair as the helper's fd 3, and speaks this line protocol on it. It is the [zygote](../../docs/glossary.md#zygote) protocol of `zygote/libfiberzygote.h` extended with [park](../../docs/glossary.md#park) and resume, and with [fibers](../../docs/glossary.md#fiber) named by [fence](../../docs/glossary.md#fence) rather than pid, because the helper's fibers are sandboxes inside one process, not processes of their own.

![Runtime/helper sequence: PARKED acknowledges snapshot writing, the host fsyncs before KILL, and Park returns after manifest writing and exit cleanup. A later RESUME restores state under a new fence.](../../docs/images/hyperlight-helper-protocol.svg)

The diagram shows what the host does, not a complete durability guarantee. The host syncs top-level files and their directory before teardown, but the manifest is written afterward without another sync, and nested snapshot files are not synced.

Every message is one line. Fields are separated by single spaces, and no field contains a space. Paths are absolute host paths. One operation per fence is outstanding at a time.

## helper -> fiberd

| line | meaning |
| --- | --- |
| `READY <helper> <hyperlight> <hypervisor> <cpu>` | The template is warm. The guest is loaded, its init ran, and the warm snapshot is taken. The four facts are what its snapshots depend on (the helper's version, the hyperlight_host crate, the hypervisor in use, the CPU vendor), and fiberd records them as the platform of every park |
| `CLONED <fence>` | The fiber serves on the endpoint it was given |
| `PARKED <fence> <bytes>` | Snapshot creation completed in the directory it was given, and `bytes` is what it costs to move. Host-side sync is separate, with the durability limits described above |
| `ERROR <fence> <text...>` | The operation on that fence failed. The text may contain spaces |
| `EXITED <fence> exit:<n>\|signal:<name>\|oom` | The fiber is gone. Sent for every end, asked for or not |
| `W <fence> <bytes>` | The fiber's working set changed. `bytes` is what it dirtied since the warm snapshot |

Before any of this, `helper --version` prints the same four facts on one line and exits. fiberd reads them at open and refuses a READY that disagrees.

## fiberd -> helper

| line | meaning |
| --- | --- |
| `CLONE <fence> <endpoint> <deadline_ms> <payload-hex\|->` | Make a fiber from the warm snapshot and serve on `endpoint` (a unix socket path) within the deadline. The payload is delivered to the guest as data |
| `PARK <fence> <dir> <0\|1>` | Close the endpoint and write the fiber's state into `dir`. With `1` (sync) keep the fiber alive afterwards until `KILL`, with `0` end it |
| `RESUME <fence> <dir> <endpoint> <deadline_ms>` | Make a fiber from the state in `dir` and serve on `endpoint` under the new fence |
| `KILL <fence>` | End the fiber |

## What fiberd guarantees the helper

- The helper runs inside the grant's cgroup, so every sandbox's memory is charged to the grant and the grant's ceiling applies.
- `dir` for `PARK` exists and is empty. `dir` for `RESUME` holds what a `PARK` wrote plus fiberd's own `manifest.json`, which the helper ignores.
- Endpoints live in the grant's run directory and are removed by fiberd after `EXITED`.
- The helper's stdout and stderr go to `<run dir>/<grant>/zygote.log`.

## What the helper guarantees fiberd

- `W` is honest. It is what the guest dirtied, not the sandbox's fixed footprint, and it is reported at least once after `CLONED`.
- A `PARK` ends serving before the state is written, and the snapshot is complete when `PARKED` is sent. For `sync=true`, fiberd then fsyncs the host-side state before replying to the caller.
- An `EXITED` follows every end, including one fiberd asked for.

## Implementations

- `hack/hyperlight/fakehelper` (Go). Sandboxes are goroutines serving the reference workload's line protocol, and state is a JSON file. It exists so the backend, the host runtime and the conformance suite run without a hypervisor.
- `hack/hyperlight/helper` (Rust, `hyperlight_host`). Sandboxes are Hyperlight micro-VMs restored from the warm snapshot. `PARK` is `Snapshot::save` (an OCI image layout), and `RESUME` builds a sandbox from it. Needs KVM, MSHV or Windows Hypervisor Platform.
