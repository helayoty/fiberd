# The pins every Cloud Hypervisor spike uses. Sourced by lib.sh, never run.
# Every value here is read by lib.sh and the spikes, not by this file.
# shellcheck shell=bash disable=SC2034
#
# The sha256 values are the digests GitHub records for each release asset
# (api.github.com/repos/<repo>/releases/tags/<tag>, the "digest" field),
# read on 2026-10-22. A download that does not match is refused.

# Cloud Hypervisor v53.0, released 2026-07-12. The static x86_64 binary.
CH_VERSION=v53.0
CH_URL=https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/$CH_VERSION/cloud-hypervisor-static
CH_SHA256=${CH_SHA256:-448af3d4e59b22c2987f7df94c213ad40fb53a10d437e42b5ee6c4fce7c29ecc}

# The guest kernel v53.0's own integration tests download
# (scripts/test-util.sh, download_linux). Built from ch_defconfig, which has
# virtio-vsock, virtio-blk, virtio-console and initramfs support built in.
KERNEL_TAG=ch-release-v6.16.9-20260508
KERNEL_URL=https://github.com/cloud-hypervisor/linux/releases/download/$KERNEL_TAG/vmlinux-x86_64
KERNEL_SHA256=${KERNEL_SHA256:-9d3570b47d5abb069ca00edfbfcef4c68306a9c3d078a01f10082b258f1001b8}

# Where everything lands. Setup is idempotent inside it.
SPIKE_DIR=${SPIKE_DIR:-/var/tmp/cloudhv-spike}
# Guest memory per VM, in MiB. 64 restores of a full copy cost 64 times this.
SPIKE_MEM_MB=${SPIKE_MEM_MB:-128}
# How much the warm guest dirties before its snapshot, and each clone after.
SPIKE_WARM_MB=${SPIKE_WARM_MB:-32}
SPIKE_DIRTY_MB=${SPIKE_DIRTY_MB:-4}
# The guest's kernel command line. ttyS0 goes to the serial log file.
SPIKE_CMDLINE=${SPIKE_CMDLINE:-console=ttyS0 panic=-1 quiet}
# The cgroup v2 parent the spikes create their leaves under.
SPIKE_CGROUP=${SPIKE_CGROUP:-/sys/fs/cgroup/cloudhv-spike}
