# Linux development container for the parts of fiberd that need a kernel:
# the fork zygote, cgroup v2, PSI, CRIU. Built and run by hack/dev/run.sh;
# `make linux-shell` / `make linux-test` / `make conform-proc` use it.
#
# The image is not a runtime image for fiberd; it is a workbench. It runs
# --privileged with a private cgroup namespace so the agent can carve a
# delegated cgroup subtree and CRIU can dump and restore process trees.
# Debian 12 (bookworm) on purpose: its arm64 userland is built without
# pointer authentication. Trixie's glibc, musl and gcc default to PAC
# branch protection on arm64, and a process restored from a checkpoint
# (CRIU or gVisor) keeps stale PAC keys, so its first authenticated return
# traps with SIGILL on a CPU with FEAT_FPAC (Apple silicon): every
# park/resume would fail on this workbench. Bookworm's criu 3.17 cannot
# read the 6.17 kernel of GitHub's runners ("Could not initialize kernel
# features detection"), so criu is built from source below.
FROM golang:1.26-bookworm

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      gcc make pkg-config \
      runc \
      curl ca-certificates jq procps iproute2 strace \
      libprotobuf-c-dev protobuf-c-compiler libprotobuf-dev python3-protobuf \
      libnl-3-dev libnet1-dev libcap-dev libbsd-dev uuid-dev libaio-dev \
    && rm -rf /var/lib/apt/lists/*

# criu 4.1.1 from source (the binary only; no docs, no python bindings).
ARG CRIU_VERSION=4.1.1
RUN set -eu; curl -fsSL "https://github.com/checkpoint-restore/criu/archive/refs/tags/v${CRIU_VERSION}.tar.gz" | tar -xz -C /tmp; \
    cd "/tmp/criu-${CRIU_VERSION}"; make -j"$(nproc)" criu >/tmp/criu-build.log 2>&1 || (tail -40 /tmp/criu-build.log; exit 1); \
    install -m 0755 criu/criu /usr/local/sbin/criu; cd /; rm -rf "/tmp/criu-${CRIU_VERSION}"; criu --version

# gVisor's runsc for the gvisor backend (FIBER_SNAPSHOT without KVM: the
# systrap platform works inside a privileged container). Pinned to the
# newest release that publishes an aarch64 binary as well as x86_64; the
# checksum file beside the binary is verified.
ARG RUNSC_RELEASE=20260817.0
RUN set -eu; arch=$(uname -m); \
    url="https://storage.googleapis.com/gvisor/releases/release/${RUNSC_RELEASE}/${arch}"; \
    curl -fsSL "$url/runsc" -o /usr/local/bin/runsc; \
    curl -fsSL "$url/runsc.sha512" -o /tmp/runsc.sha512; \
    (cd /usr/local/bin && sed 's| .*runsc$| runsc|' /tmp/runsc.sha512 | sha512sum -c -); \
    chmod +x /usr/local/bin/runsc; rm -f /tmp/runsc.sha512; \
    runsc --version

# Rust, cargo-hyperlight and clang for the Hyperlight helper and guest
# (hack/hyperlight). Compiling them needs no hypervisor; running the
# helper does (pass /dev/kvm into the container).
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo PATH=/usr/local/cargo/bin:$PATH
RUN apt-get update && apt-get install -y --no-install-recommends clang lld \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable \
    && cargo install --locked cargo-hyperlight \
    && rm -rf /usr/local/cargo/registry/cache /usr/local/cargo/git
# Guests build for a custom target, which stable Rust rejects since 1.95:
# the guest crate pins 1.94.0 (hack/hyperlight/guest/rust-toolchain.toml).
RUN rustup toolchain install 1.94.0 --profile minimal --component rust-src

# GOTOOLCHAIN=auto lets the go.mod toolchain line fetch the exact version.
ENV GOTOOLCHAIN=auto \
    GOFLAGS=-buildvcs=false \
    CGO_ENABLED=1 \
    FIBERD_CGROUP_ROOT=/sys/fs/cgroup/fiberd

WORKDIR /src
COPY hack/dev/entrypoint.sh /usr/local/bin/fiberd-dev-entrypoint
RUN chmod +x /usr/local/bin/fiberd-dev-entrypoint
ENTRYPOINT ["/usr/local/bin/fiberd-dev-entrypoint"]
CMD ["bash"]
