# Development image for the parts of fiberd that need a Linux kernel, such
# as the fork zygote, cgroup v2, PSI and CRIU. hack/dev/run.sh builds and
# runs it for `make linux-shell`, `make linux-test` and `make conform-proc`.
#
# This is a workbench, not a runtime image. It runs --privileged with a
# private cgroup namespace so the agent can carve a delegated cgroup subtree
# and CRIU can dump and restore process trees. It stays root on purpose for
# the same reason.
#
# The base is Debian 12 (bookworm) because its arm64 userland is built
# without pointer authentication (PAC). Trixie turns PAC on for arm64. A
# process restored from a checkpoint (CRIU or gVisor) keeps stale PAC keys
# and dies with SIGILL on CPUs with FEAT_FPAC (Apple silicon), so every park
# and resume would fail. Bookworm's own criu 3.17 cannot read the 6.17
# kernel on GitHub's runners, so criu is built from source below.
#
# The base image is pinned by digest. Refresh it with
# `docker buildx imagetools inspect golang:1.26-bookworm`. Every download
# below is checked against a pinned sha256 or sha512. Debian packages come
# from the base's snapshot of the archive, so a newer base digest is the
# upgrade and `apt-get upgrade` is not run.
FROM golang:1.26-bookworm@sha256:dc9ad6c05acc7a88e5b71bde60a5fe3bd4b9f0db209011711b464107438a8107

LABEL org.opencontainers.image.source="https://github.com/helayoty/fiberd" \
      org.opencontainers.image.description="fiberd Linux development workbench: Go, criu, runsc, Rust and cargo-hyperlight" \
      org.opencontainers.image.licenses="Apache-2.0"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      gcc make pkg-config patch libssl-dev clang lld \
      runc \
      curl ca-certificates jq procps iproute2 strace \
      libprotobuf-c-dev protobuf-c-compiler libprotobuf-dev python3-protobuf \
      libnl-3-dev libnet1-dev libcap-dev libbsd-dev uuid-dev libaio-dev \
    && rm -rf /var/lib/apt/lists/*

# criu 4.1.1 from source (binary only) plus upstream commit 4b7398595 from
# 4.2. On Linux 6.16 and later, 4.1.1 cannot park a fiber with a tcp
# endpoint because it reads SO_PASSCRED and SO_PASSSEC on every socket. The
# commit limits those reads to the families that have them. 4.2.1 is not
# used because its restore segfaults with these images on arm64 and amd64.
# install-criu.sh pins the tarball's sha256.
ARG CRIU_VERSION=4.1.1
COPY hack/dev/install-criu.sh hack/dev/criu-4b7398595-passcred-families.patch /tmp/fiberd-criu/
RUN CRIU_VERSION="${CRIU_VERSION}" sh /tmp/fiberd-criu/install-criu.sh \
    && rm -rf /tmp/fiberd-criu

# gVisor's runsc for the gvisor backend. Its systrap platform gives
# FIBER_SNAPSHOT inside a privileged container without KVM. The release is
# the newest with both aarch64 and x86_64 binaries. Each binary's sha512 is
# copied here from gVisor's runsc.sha512, so the download is checked
# against this file and not against the server.
ARG RUNSC_RELEASE=20260817.0
ARG RUNSC_SHA512_X86_64=84936438d583ec976800f464e75a83e1515f0890b451b9b4db219c4472b54ca9b106a6772ee683f1e64cce2128871d7637b14d800591f8451b8137f6c39fb2ef
ARG RUNSC_SHA512_AARCH64=6394fd161a4af0dc9a2c29f75c3016d05275a55744f124e12023fa7666a9f161c68d6ce3803ad49205c6a7b5bee0ad2ccf48edff340db344fdafec678c788aa4
RUN set -eu; arch=$(uname -m); \
    case "$arch" in \
      x86_64)  sum=$RUNSC_SHA512_X86_64 ;; \
      aarch64) sum=$RUNSC_SHA512_AARCH64 ;; \
      *) echo "no pinned runsc for $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://storage.googleapis.com/gvisor/releases/release/${RUNSC_RELEASE}/${arch}/runsc" -o /usr/local/bin/runsc; \
    echo "$sum  /usr/local/bin/runsc" | sha512sum -c - >/dev/null; \
    chmod 0755 /usr/local/bin/runsc; \
    runsc --version

# Rust, cargo-hyperlight and clang build the Hyperlight helper and guest
# (hack/hyperlight). Building needs no hypervisor. Running the helper needs
# /dev/kvm passed into the container. rustup-init is a pinned release
# checked against its published sha256. rustup then checks the toolchains
# it installs against the signed channel manifests.
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo PATH=/usr/local/cargo/bin:$PATH
ARG RUSTUP_VERSION=1.29.1
ARG RUSTUP_SHA256_X86_64=dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71
ARG RUSTUP_SHA256_AARCH64=15f6e4ce9f583b929c996c91562bad6d4454f3281de858b02cdfdef615fac433
ARG CARGO_HYPERLIGHT_VERSION=0.1.14
RUN set -eu; arch=$(uname -m); \
    case "$arch" in \
      x86_64)  sum=$RUSTUP_SHA256_X86_64 ;; \
      aarch64) sum=$RUSTUP_SHA256_AARCH64 ;; \
      *) echo "no pinned rustup-init for $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${arch}-unknown-linux-gnu/rustup-init" -o /tmp/rustup-init; \
    echo "$sum  /tmp/rustup-init" | sha256sum -c - >/dev/null; \
    chmod 0755 /tmp/rustup-init; \
    /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain stable; \
    rm -f /tmp/rustup-init; \
    cargo install --locked cargo-hyperlight --version "${CARGO_HYPERLIGHT_VERSION}"; \
    rm -rf /usr/local/cargo/registry/cache /usr/local/cargo/git
# Stable Rust rejects the guests' custom target since 1.95, so the guest
# crate pins 1.94.0 (hack/hyperlight/guest/rust-toolchain.toml).
RUN rustup toolchain install 1.94.0 --profile minimal --component rust-src

# OpenSSL for the rootfs zygote (hack/gvisor/rootfs.sh), built without
# pointer authentication. Debian's libcrypto signs the link register in
# its arm64 assembly (78 paciasp/autiasp in a static refzygote), and a
# fiber checkpointed inside one of those routines traps on restore on a
# FEAT_FPAC CPU. The 3.0 line hard-codes those instructions in its
# perlasm (`.inst 0xd503233f`), so no compiler flag removes them, and on
# aarch64 the C implementations are built instead (no-asm) with the flag
# keeping the compiler's own output clean. Static libraries and headers
# only, no shared objects, engines or tests. The tarball is pinned by
# sha256.
ARG OPENSSL_VERSION=3.0.18
ARG OPENSSL_SHA256=d80c34f5cf902dccf1f1b5df5ebb86d0392e37049e5d73df1b3abae72e4ffe8b
RUN set -eu; cd /tmp; \
    curl -fsSL "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" -o openssl.tar.gz; \
    echo "${OPENSSL_SHA256}  openssl.tar.gz" | sha256sum -c - >/dev/null; \
    tar xzf openssl.tar.gz; cd "openssl-${OPENSSL_VERSION}"; \
    flags=""; [ "$(uname -m)" != aarch64 ] || flags="no-asm -mbranch-protection=none"; \
    ./Configure --prefix=/usr/local/openssl-nopac --libdir=lib no-shared no-dso no-engine no-tests $flags >/dev/null; \
    make -j"$(nproc)" build_libs >/dev/null; \
    make install_dev >/dev/null; \
    cd /; rm -rf /tmp/openssl.tar.gz "/tmp/openssl-${OPENSSL_VERSION}"

# GOTOOLCHAIN=auto lets the go.mod toolchain line fetch the exact version.
ENV GOTOOLCHAIN=auto \
    GOFLAGS=-buildvcs=false \
    CGO_ENABLED=1 \
    FIBERD_CGROUP_ROOT=/sys/fs/cgroup/fiberd

WORKDIR /src
COPY --chmod=0755 hack/dev/entrypoint.sh /usr/local/bin/fiberd-dev-entrypoint
ENTRYPOINT ["/usr/local/bin/fiberd-dev-entrypoint"]
CMD ["bash"]
