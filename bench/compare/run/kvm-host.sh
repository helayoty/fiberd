#!/usr/bin/env bash
# Sets up the KVM host for phase 4 of docs/design/compare.md. Ubuntu 24.04,
# x86_64, 16 vCPU, 64 GB, nested virtualization on. Run as a sudoer. It
# installs Docker, kind, kubectl, Go, Firecracker and the fiberd dev image
# prerequisites, then proves /dev/kvm works. Nothing here runs on the Mac.
#
#   Azure:  az vm create -n compare --size Standard_D16s_v5 --image Ubuntu2404 --os-disk-size-gb 200 ...
#   GCP:    gcloud compute instances create compare --machine-type n2-standard-16 \
#             --enable-nested-virtualization --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
#             --boot-disk-size 200GB --boot-disk-type pd-ssd
set -euo pipefail
FC_VERSION=${FC_VERSION:-v1.17.0}
ARCH=$(uname -m)

echo "== kvm"; test -e /dev/kvm || { echo "no /dev/kvm: enable nested virtualization or pick a metal instance" >&2; exit 1; }
sudo apt-get update -q
sudo apt-get install -y -q docker.io curl git make gcc libssl-dev jq
sudo usermod -aG docker "$USER"
sudo apt-get install -y -q cpu-checker && sudo kvm-ok

# kind, kubectl, Go
KIND_VERSION=${KIND_VERSION:-v0.29.0}
sudo curl -fsSLo /usr/local/bin/kind "https://kind.sigs.k8s.io/dl/$KIND_VERSION/kind-linux-amd64" && sudo chmod +x /usr/local/bin/kind
KUBE_VERSION=$(curl -fsSL https://dl.k8s.io/release/stable.txt)
sudo curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/$KUBE_VERSION/bin/linux/amd64/kubectl" && sudo chmod +x /usr/local/bin/kubectl
GO_VERSION=${GO_VERSION:-1.26.7}
curl -fsSLo /tmp/go.tgz "https://go.dev/dl/go$GO_VERSION.linux-amd64.tar.gz" && sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tgz
export PATH=$PATH:/usr/local/go/bin

# Firecracker, with the matching jailer, and a guest kernel from the CI artifacts
mkdir -p "$HOME/fc" && cd "$HOME/fc"
# Pinned from the release's .sha256.txt files, so a changed tarball fails.
case "$ARCH" in
  x86_64) FC_SHA256=06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558 ;;
  aarch64) FC_SHA256=e351ebe4f7a16b5873bbd51005d2e6767103cff4d5ebc829df2d3f95a93e2256 ;;
  *) echo "no pinned Firecracker for $ARCH" >&2; exit 1 ;;
esac
curl -fsSLo fc.tgz "https://github.com/firecracker-microvm/firecracker/releases/download/$FC_VERSION/firecracker-$FC_VERSION-$ARCH.tgz"
echo "$FC_SHA256  fc.tgz" | sha256sum -c -
tar xzf fc.tgz && sudo install -m 0755 "release-$FC_VERSION-$ARCH/firecracker-$FC_VERSION-$ARCH" /usr/local/bin/firecracker
firecracker --version
# A 6.1 guest kernel from Firecracker's CI bucket. It has no published
# checksum, so use it only on a throwaway benchmark host. The rootfs is
# built by the harness from counter.c.
curl -fsSLo vmlinux "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.12/$ARCH/vmlinux-6.1.102" || echo "fetch a guest kernel by hand (docs/getting-started.md)"
sudo setfacl -m "u:$USER:rw" /dev/kvm

# fiberd: the dev image has runsc, criu, Rust and cargo-hyperlight. The
# Hyperlight helper needs /dev/kvm only at run time.
echo "== next, in the fiberd checkout"
echo "  make hyperlight-helper && make linux-hyperlight-check   # proves the helper on this KVM"
echo "  make conform-hyperlight                                 # the backend end to end"
echo "  make compare-phase4                                     # every comparator on this host"
