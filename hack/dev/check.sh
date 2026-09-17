#!/usr/bin/env bash
# Probe the Linux environment for what Phase 3 needs. Exit non-zero if a
# hard requirement is missing; print WARN for soft ones.
set -u
fail=0
ok()   { printf 'ok    %s\n' "$*"; }
warn() { printf 'WARN  %s\n' "$*"; }
bad()  { printf 'FAIL  %s\n' "$*"; fail=1; }

CG=${FIBERD_CGROUP_ROOT:-/sys/fs/cgroup/fiberd}

uname -r | grep -qE '^([6-9]|5\.(1[4-9]|[2-9][0-9]))\.' && ok "kernel $(uname -r) (>= 5.14: cgroup.kill, clone3 into cgroup)" || bad "kernel $(uname -r) is older than 5.14"
[ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" = cgroup2fs ] && ok "cgroup v2 mounted" || bad "cgroup v2 not mounted at /sys/fs/cgroup"
[ -w /sys/fs/cgroup/cgroup.subtree_control ] && ok "cgroup root writable (delegation possible)" || bad "cgroup root is read-only"
[ -d "$CG" ] && ok "delegated subtree $CG exists" || bad "delegated subtree $CG missing (entrypoint did not run?)"
grep -qw memory "$CG/cgroup.controllers" 2>/dev/null && ok "memory controller available in $CG" || bad "memory controller not available in $CG"
grep -qw memory "$CG/cgroup.subtree_control" 2>/dev/null && ok "memory controller enabled for children of $CG" || bad "memory controller not enabled for children of $CG"
if mkdir -p "$CG/probe" 2>/dev/null; then
  [ -f "$CG/probe/memory.max" ] && ok "child cgroup gets memory.max" || bad "child cgroup lacks memory.max"
  [ -f "$CG/probe/memory.oom.group" ] && ok "memory.oom.group present" || bad "memory.oom.group missing"
  [ -f "$CG/probe/memory.pressure" ] && ok "PSI memory.pressure present" || warn "PSI memory.pressure missing (kernel without CONFIG_PSI?)"
  [ -f "$CG/probe/cgroup.kill" ] && ok "cgroup.kill present" || warn "cgroup.kill missing"
  rmdir "$CG/probe" 2>/dev/null
else
  bad "cannot create a child cgroup under $CG"
fi
[ -r /proc/pressure/memory ] && ok "system PSI at /proc/pressure/memory" || warn "no /proc/pressure/memory"
command -v criu >/dev/null && ok "criu $(criu --version 2>/dev/null | head -1)" || bad "criu not installed"
if command -v criu >/dev/null; then
  if criu check --no-default-config >/tmp/criu-check.log 2>&1; then ok "criu check passes"; else warn "criu check reported issues (see /tmp/criu-check.log): $(tail -1 /tmp/criu-check.log)"; fi
fi
command -v gcc >/dev/null && ok "gcc $(gcc -dumpversion)" || bad "gcc missing"
go version >/dev/null 2>&1 && ok "$(go version)" || bad "go missing"
exit $fail
