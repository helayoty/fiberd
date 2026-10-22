#!/usr/bin/env bash
# The facts of one GPU VM that the GPU PoC depends on (docs/proposals/gpu-poc.md).
# Run it on VM A and on VM B, then diff the two files. A line that differs is
# a fact the cross-GPU move must tolerate or refuse.
#
#   bash hack/gpu/facts.sh | tee facts-$(hostname).txt
#   diff facts-vm-a.txt facts-vm-b.txt
#
# It only reads. Every line is "<key> <value>", in a fixed order, so two runs
# diff cleanly. A missing tool prints "<key> absent" and the script goes on.
# A few probes need root (criu check, bpftool, the uid 65534 opens). They run
# through "sudo -n", and say so when sudo would ask for a password.
set -u
export LC_ALL=C

kv() { printf '%s %s\n' "$1" "${2:-}"; }
have() { command -v "$1" >/dev/null 2>&1; }
# One line. Newlines become " | " so a multi-line answer stays one fact.
one() { awk 'NR > 1 { printf " | " } { printf "%s", $0 } END { print "" }'; }

# asroot runs a command as root. It prints nothing and fails when it cannot.
if [ "$(id -u)" = 0 ]; then
  asroot() { "$@"; }
  ROOT=yes
elif have sudo && sudo -n true 2>/dev/null; then
  asroot() { sudo -n "$@"; }
  ROOT=sudo
else
  asroot() { return 1; }
  ROOT=no
fi
kv facts.version 1
kv facts.root "$ROOT"

# The host.
kv kernel.release "$(uname -r)"
kv kernel.machine "$(uname -m)"
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  kv os.id "${ID:-unknown}"
  kv os.version "${VERSION_ID:-unknown}"
  kv os.pretty "${PRETTY_NAME:-unknown}"
else
  kv os.release absent
fi

# The CPU. CRIU's CPU check compares these between the two hosts.
cpuinfo() { sed -n "s/^$1[[:space:]]*: //p" /proc/cpuinfo | head -1; }
kv cpu.vendor "$(cpuinfo vendor_id)"
kv cpu.model_name "$(cpuinfo 'model name')"
kv cpu.family "$(cpuinfo 'cpu family')"
kv cpu.model "$(cpuinfo model)"
kv cpu.stepping "$(cpuinfo stepping)"
kv cpu.microcode "$(cpuinfo microcode)"
kv cpu.count "$(nproc 2>/dev/null)"
kv cpu.flags "$(cpuinfo flags | tr ' ' '\n' | sed '/^$/d' | sort -u | tr '\n' ' ' | sed 's/ $//')"

# CRIU.
if have criu; then
  kv criu.version "$(criu --version 2>&1 | one)"
  if out=$(asroot criu check 2>&1); then
    kv criu.check "ok $(printf '%s' "$out" | one)"
  elif [ "$ROOT" = no ]; then
    kv criu.check "needs root (sudo -n not available)"
  else
    kv criu.check "failed $(printf '%s' "$out" | one)"
  fi
else
  kv criu.version absent
  kv criu.check absent
fi

# Docker and the NVIDIA container toolkit.
if have docker; then
  v=$(docker version --format '{{.Server.Version}}' 2>/dev/null) || v=$(asroot docker version --format '{{.Server.Version}}' 2>/dev/null) || v=""
  kv docker.server "${v:-unreachable}"
  kv docker.client "$(docker --version 2>&1 | one)"
else
  kv docker.server absent
  kv docker.client absent
fi
if have nvidia-ctk; then kv nvidia.ctk "$(nvidia-ctk --version 2>&1 | head -1)"; else kv nvidia.ctk absent; fi
if have nvidia-container-cli; then
  kv nvidia.container_cli "$(nvidia-container-cli --version 2>&1 | head -1)"
else
  kv nvidia.container_cli absent
fi

# The driver and the GPUs. nvidia-smi -L lists every GPU and MIG UUID.
if have nvidia-smi; then
  q() { nvidia-smi --query-gpu="$1" --format=csv,noheader 2>&1 | one; }
  kv nvidia.driver "$(q driver_version)"
  kv nvidia.gpu "$(q index,name,uuid)"
  kv nvidia.compute_cap "$(q compute_cap)"
  kv nvidia.mig_mode "$(q mig.mode.current,mig.mode.pending)"
  kv nvidia.memory "$(q memory.total)"
  nvidia-smi -L 2>&1 | while IFS= read -r line; do kv nvidia.list "$(printf '%s' "$line" | sed 's/^[[:space:]]*//')"; done
else
  for k in driver gpu compute_cap mig_mode memory list; do kv "nvidia.$k" absent; done
fi

# KVM, for the Hyperlight and Cloud Hypervisor rows.
if [ -e /dev/kvm ]; then
  kv kvm.node "$(ls -l /dev/kvm 2>&1)"
  if { : <>/dev/kvm; } 2>/dev/null; then kv kvm.open_rw "ok as $(id -un)"; else kv kvm.open_rw "denied as $(id -un)"; fi
else
  kv kvm.node absent
  kv kvm.open_rw absent
fi

# The cgroup device programs already attached. fiberd's device program
# attaches with BPF_F_ALLOW_MULTI, which an ancestor's single program breaks.
kv cgroup.type "$(stat -f -c %T /sys/fs/cgroup 2>/dev/null)"
if have bpftool || asroot sh -c 'command -v bpftool' >/dev/null 2>&1; then
  if out=$(asroot bpftool cgroup tree 2>&1); then
    if [ -z "$out" ]; then kv bpftool.cgroup_tree none; fi
    printf '%s\n' "$out" | sed '/^$/d' | while IFS= read -r line; do kv bpftool.cgroup_tree "$line"; done
  elif [ "$ROOT" = no ]; then
    kv bpftool.cgroup_tree "needs root (sudo -n not available)"
  else
    kv bpftool.cgroup_tree "failed $(printf '%s' "$out" | one)"
  fi
else
  kv bpftool.cgroup_tree absent
fi

# The NVIDIA device nodes, their numbers, and their owners. The fiber guard
# denies these majors, so both VMs should agree on them.
nodes=$(ls -d /dev/nvidia* /dev/nvidia-caps/* 2>/dev/null | grep -v '^/dev/nvidia-caps$')
if [ -z "$nodes" ]; then
  kv dev.node absent
else
  for f in $nodes; do
    kv dev.node "$(stat -c '%n %F %Hr:%Lr %A %U:%G' "$f" 2>&1)"
  done
fi
if grep -qi nvidia /proc/devices 2>/dev/null; then
  grep -i nvidia /proc/devices | while read -r major name; do kv proc.devices "$major $name"; done
else
  kv proc.devices absent
fi

# Whether uid 65534 can open each node. A proc fiber's uid sees what this
# sees until the device program lands, so "ok" here is the gap it closes.
# shellcheck disable=SC2016  # "$1" expands in the child shell
nobody_open() { # <mode: ro|rw> <path>
  local redir='exec 3<"$1"'
  [ "$1" = rw ] && redir='exec 3<>"$1"'
  shift
  asroot setpriv --reuid 65534 --regid 65534 --clear-groups -- sh -c "$redir" sh "$1" 2>&1
}
if [ -z "$nodes" ]; then
  kv uid65534.open absent
elif ! have setpriv; then
  kv uid65534.open "absent (no setpriv)"
elif [ "$ROOT" = no ]; then
  kv uid65534.open "needs root (sudo -n not available)"
else
  for f in $nodes; do
    for m in ro rw; do
      if out=$(nobody_open "$m" "$f"); then
        kv uid65534.open "$f $m ok"
      else
        kv uid65534.open "$f $m denied $(printf '%s' "$out" | sed 's/^sh: [0-9]*: //' | one)"
      fi
    done
  done
fi
