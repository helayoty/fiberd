# Design: per-grant user namespaces

> **Status:** Option 2 is implemented on the runc backend and always on
> (`pkg/backend/runc`, tests in `tests/runc`). Both prototypes ran in the
> dev container (kernel 6.12, runc 1.1.5, CRIU 4.1.1, cgroup v2, no Yama).
> For what fiberd does today, see [Security](../security.md).

## Purpose

Every zygote and fiber of the `proc` and `runc` backends runs as host root,
and the deny-list patches (read-only `/proc/sys` and `/sys`, masked paths,
dropped capabilities) are all that stands between a fiber and the host. This
design maps each grant's root to an unprivileged host uid range, so the
kernel refuses host resources by default and the deny list becomes a second
line of defense.

## The problem with CRIU restore

A restore creates the fiber's user namespace and a mount namespace copied
from the agent's, and the kernel marks every copied mount `MNT_LOCKED`
together with its children. CRIU re-creates a mount inherited from the host
(an "external" mount such as `/dev`) with a non-recursive bind, which the
kernel refuses for a source with locked children, so the restore fails with
`EINVAL` (`mnt-v2: Failed to open_tree /dev/`). The first prototype got past
it by launching and restoring in a pruned, flattened mount tree. That depends
on the host's mount layout and is a workaround, not a fix.

## Option 1, fix CRIU

- **What.** Inside a user namespace, bind an external mount that has
  children recursively and treat the mounts under it as already restored.
- **Where.** `criu/mount-v2.c`, `__do_bind_mount_v2` calls `open_tree` with
  `OPEN_TREE_CLONE` and no `AT_RECURSIVE`, reached from `do_bind_mount_v2`
  for external mounts. `criu/mount.c`, `do_bind_mount`, does the same with
  `MS_BIND` and no `MS_REC`.
- **How carried.** A second patch in `hack/dev`, applied by
  `install-criu.sh` like the passcred one, and proposed upstream.
- **Pros.** The proc backend keeps its shape and needs no root filesystem.
- **Cons.** The fiber still inherits host mounts, so the deny list must keep
  hiding them, and every home runs a privately patched CRIU mount engine
  until upstream ships the fix.

## Option 2, own root filesystem via the runc backend

- **What.** The zygote is already the init of a grant's OCI container. The
  container adds a `user` namespace with `uidMappings` and `gidMappings`.
  runc makes every mount the fiber sees from inside that namespace, so none
  is locked, and CRIU restores with `--root` and plain external binds.
- **How.** `pkg/backend/runc` adds the namespace and maps to its config,
  chowns a rootfs copy and the work directory to the range, drops `sysfs`
  (a userns without a network namespace cannot mount it), and lists runc's
  six device binds (`/dev/null`, `zero`, `full`, `random`, `urandom`, `tty`)
  as external mounts in `DumpExtra` and `RestoreExtra`. The agent delegates
  only `cgroup.procs` of the grant cgroup and of each leaf.
- **Pros.** No CRIU change, standard OCI, a fiber cannot see the home, and
  the container's capabilities become capabilities inside the namespace.
- **Cons.** A rootfs copy per grant, runc on every home, more agent
  capabilities, and the proc backend stays host root.

## Prototype results

First prototype, proc backend with a hand-made namespace. Mapped root was
denied `core_pattern`, `subtree_control` and root-owned files and still made
pidns and mntns children (P1). Delegating only `cgroup.procs` kept the
limits root-owned while `CLONE_INTO_CGROUP` worked (P2). The plain restore
failed with `open_tree /dev: EINVAL` and only the flattened tree restored
(P3). Seven agent capabilities could not connect to a fiber's 0755 socket,
`DAC_OVERRIDE` fixed it (P4). `PTRACE_ATTACH` from host root worked (P5).

Second prototype, runc backend with the namespace in the OCI config.

- **R1 proven.** The zygote ran as init, uid 100000 host-side and 0 inside,
  all 19 mounts made by runc. Mapped root got `EACCES` on `core_pattern`
  and `sysrq-trigger`, `EPERM` on `mknod`, could not write `memory.max`,
  `pids.max` or `subtree_control`, and could write `cgroup.procs`.
- **R2 proven.** `clone3` into an agent-made leaf with only the grant's and
  the leaf's `cgroup.procs` chowned landed the fiber in `0::/g1/f1`.
- **R3 proven, the key result.** `criu dump` of a pidns fiber with
  `--external mnt[/host]:host` plus the six device binds wrote
  `userns-13.img`. The image restored three times, twice on the same rootfs
  and once onto a rootfs copy standing in for another home. Each restore got
  a fresh namespace with the same map, answered `get` with the parked
  counter and `incr` with the next value, re-bound its socket in the new
  `/host`, and still got `EACCES` on `core_pattern`. No workaround.
- **R3 limit.** A fiber with its own mount namespace does not dump in a
  container at all (`Can't lookup mount for /bin/refzygote`). The runc
  backend never asks for one.
- **R4 proven.** `runc run` needs the seven plus `SETUID`, `SETGID`,
  `CHOWN` (`fchown` of `exec.fifo`) and `DAC_OVERRIDE` (`exec.fifo` is 0622
  owned by the mapped root, runc hangs without it). `criu dump` needs
  `SETUID`, `SETGID` and `DAC_READ_SEARCH` (`map_files`), `criu restore`
  needs `SETUID` and `SETGID`.
- **R5.** Idmapped mounts are unavailable here (runc 1.1.5 advertises none,
  util-linux 2.38 ignores `X-mount.idmap`), so the rootfs is chowned.
  `chown -R` of a 629 MB, 5461-file tree took 21 ms, `cp -a` of it 7.9 s.
  Overlayfs and nested user namespaces are allowed inside the namespace.

## Recommendation

Option 2. It restored userns fibers on the runc backend with no CRIU change
and no mount workaround, and the backend already exists. Option 1 is still
worth proposing upstream, because it would let the proc backend follow, but
fiberd should not rest its security floor on a carried CRIU patch.

## Phased plan for Option 2

1. **`-userns` on the runc backend.** The config gains the namespace and
   maps, the launcher chowns a per-grant rootfs copy and the work directory,
   the agent delegates `cgroup.procs` and keeps `SETUID`, `SETGID`, `CHOWN`,
   `DAC_OVERRIDE` and `DAC_READ_SEARCH`, and the dump and restore extras add
   the device binds. Park and resume ship with it, since R3 proved them.
2. **Deterministic maps.** The range derives from the grant UID over
   `-userns-pool`, admission refuses a collision, and a home test resumes a
   parked fiber on a second agent with its own rootfs copy. The pool
   defaults to `1073741824:49151`, above every `/etc/subuid` convention
   (the prototype's uid 100000 was the old default), and the agent refuses
   to start when an `/etc/subuid` or `/etc/subgid` entry overlaps it. A
   grant holds its slot for as long as its zygote or any fiber restored on
   the home maps the range, and a second grant hashing to a held slot is
   refused with an error that names the slot and asks for a larger pool.
3. **Hardening and default on.** The zygote caps nested namespaces, the
   container's capability list shrinks to what `clone3` needs, the flag
   inverts to `-no-userns`, and `docs/security.md` describes the model.
4. **Proc backend, later.** Carry or upstream the Option 1 patch and reuse
   the first prototype's launcher for homes without runc.

## Risks and open questions

- **Rootfs per grant.** A chowned copy per range costs disk and time. One
  range for every grant of a home avoids the copies but no longer separates
  grants from each other. Idmapped mounts (runc 1.2, util-linux 2.39) remove
  the trade-off and should be checked first.
- **Kernel surface.** The zygote holds nine capabilities inside its
  namespace, and the kernel allows it overlayfs and nested namespaces. The
  nested cap and trusted-grant admission bound it, a seccomp profile is next.
- **runc coupling.** The device list and the `exec.fifo` behaviour are runc
  1.1's and need a check on each bump.
- **Untested.** Yama `ptrace_scope` 1, a Pod with `hostUsers: false` whose
  65536-id range would force small per-grant ranges, and the gVisor and
  Hyperlight backends, which own their isolation.
