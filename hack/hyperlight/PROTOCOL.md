# The helper protocol

A backend whose mechanism is not reachable from Go (Hyperlight has a Rust
host API only) plugs into fiberd through a **helper process**. fiberd
starts one helper per warm template, inside the grant's cgroup, with a
unix socketpair as the helper's fd 3, and speaks this line protocol on
it. It is the zygote protocol of `hack/zygote/libfiberzygote.h` extended
with park and resume, and with fibers named by fence rather than pid,
because the helper's fibers are sandboxes inside one process, not
processes of their own.

Every message is one line, fields separated by single spaces, no field
contains a space. Paths are absolute host paths. One operation per fence
is outstanding at a time.

## helper -> fiberd

| line | meaning |
| --- | --- |
| `READY <version>` | the template is warm: the guest is loaded, its init ran, and the warm snapshot is taken |
| `CLONED <fence>` | the fiber serves on the endpoint it was given |
| `PARKED <fence> <bytes>` | the fiber's state is durable in the directory it was given; `bytes` is what it costs to move |
| `ERROR <fence> <text...>` | the operation on that fence failed (text may contain spaces) |
| `EXITED <fence> exit:<n>\|signal:<name>\|oom` | the fiber is gone; sent for every end, asked for or not |
| `W <fence> <bytes>` | the fiber's working set changed: bytes dirtied since the warm snapshot |

## fiberd -> helper

| line | meaning |
| --- | --- |
| `CLONE <fence> <endpoint> <deadline_ms> <payload-hex\|->` | make a fiber from the warm snapshot and serve on `endpoint` (a unix socket path) within the deadline; the payload is delivered to the guest as data |
| `PARK <fence> <dir> <0\|1>` | close the endpoint and write the fiber's state into `dir`; with `1` (sync) keep the fiber alive afterwards until `KILL`, with `0` end it |
| `RESUME <fence> <dir> <endpoint> <deadline_ms>` | make a fiber from the state in `dir` and serve on `endpoint` under the new fence |
| `KILL <fence>` | end the fiber |

## What fiberd guarantees the helper

- the helper runs inside the grant's cgroup, so every sandbox's memory is
  charged to the grant and the grant's ceiling applies;
- `dir` for `PARK` is empty and exists; `dir` for `RESUME` holds what a
  `PARK` wrote plus fiberd's own `manifest.json`, which the helper ignores;
- endpoints live in the grant's run directory and are removed by fiberd
  after `EXITED`;
- the helper's stdout and stderr go to `<run dir>/<grant>/zygote.log`.

## What the helper guarantees fiberd

- `W` is honest: it is what the guest dirtied, not the sandbox's fixed
  footprint, and it is reported at least once after `CLONED`;
- a `PARK` with sync ends serving before the state is written and the
  state is complete when `PARKED` is sent;
- an `EXITED` follows every end, including one fiberd asked for.

## Implementations

- `hack/hyperlight/fakehelper` (Go): sandboxes are goroutines serving the
  reference workload's line protocol; state is a JSON file. It exists so
  the backend, the host runtime and the conformance suite run without a
  hypervisor.
- `hack/hyperlight/helper` (Rust, `hyperlight_host`): sandboxes are
  Hyperlight micro-VMs restored from the warm snapshot; `PARK` is
  `Snapshot::save` (an OCI image layout), `RESUME` builds a sandbox from
  it. Needs KVM, MSHV or Windows Hypervisor Platform.
