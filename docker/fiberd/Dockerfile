# The fiberd images, the ones the release publishes. One build stage holds
# fiberd, criu for FIBER_CHECKPOINT, and the zygote library (header and
# static archive) so a template image can build its zygote from this one.
#
#   fiberd         fiberd, criu and the zygote library.
#   fiberd-runc    fiberd with the runc fiberd was built and tested against.
#   fiberd-gvisor  fiberd with the runsc fiberd was built and tested against.
#
# The two variants are built on the plain image, so they share every layer
# of it. Name the target, since the last stage is not the plain image.
#
#   docker build --target fiberd -t fiberd -f docker/fiberd/Dockerfile .   (from the repo root)
#
# The licenses and notices are under /usr/share/doc. The release passes
# --build-arg VERSION=<tag>, which fiberd -version prints.
#
# The base images are pinned by digest. Refresh them with
# `docker buildx imagetools inspect <image:tag>`.
ARG RUNTIME_BASE=debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
ARG DEV_IMAGE=golang:1.26-bookworm@sha256:dc9ad6c05acc7a88e5b71bde60a5fe3bd4b9f0db209011711b464107438a8107
FROM ${DEV_IMAGE} AS build
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
USER root
ARG DEBIAN_FRONTEND=noninteractive
ARG CRIU_VERSION=4.2.1
# The dev image already has criu. The plain Go image builds it here.
COPY hack/dev/install-criu.sh /tmp/fiberd-criu/
RUN if ! command -v criu >/dev/null 2>&1; then \
      apt-get update && apt-get install -y --no-install-recommends \
        gcc make pkg-config curl ca-certificates \
        libprotobuf-c-dev protobuf-c-compiler protobuf-compiler libprotobuf-dev python3-protobuf \
        libnl-3-dev libnet1-dev libcap-dev libbsd-dev uuid-dev libaio-dev \
      && rm -rf /var/lib/apt/lists/* \
      && CRIU_VERSION="${CRIU_VERSION}" sh /tmp/fiberd-criu/install-criu.sh; \
    fi \
    && rm -rf /tmp/fiberd-criu
# Rust for the zygote library (sdk/c/template/core), with the pins
# of docker/dev/Dockerfile. rustup-init is a pinned release checked
# against its published sha256, and rustup checks the toolchain against
# the signed channel manifest. The toolchain is the one the crate's
# rust-toolchain.toml pins. The dev image already has it.
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo PATH=/usr/local/cargo/bin:$PATH
ARG RUSTUP_VERSION=1.29.1
ARG RUSTUP_SHA256_X86_64=dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71
ARG RUSTUP_SHA256_AARCH64=15f6e4ce9f583b929c996c91562bad6d4454f3281de858b02cdfdef615fac433
ARG RUST_TOOLCHAIN=1.99.0
RUN set -eu; if ! command -v cargo >/dev/null 2>&1; then \
      arch=$(uname -m); \
      case "$arch" in \
        x86_64)  sum=$RUSTUP_SHA256_X86_64 ;; \
        aarch64) sum=$RUSTUP_SHA256_AARCH64 ;; \
        *) echo "no pinned rustup-init for $arch" >&2; exit 1 ;; \
      esac; \
      curl -fsSL "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${arch}-unknown-linux-gnu/rustup-init" -o /tmp/rustup-init; \
      echo "$sum  /tmp/rustup-init" | sha256sum -c - >/dev/null; \
      chmod 0755 /tmp/rustup-init; \
      /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain "${RUST_TOOLCHAIN}" -c clippy -c rustfmt; \
      rm -f /tmp/rustup-init; \
    fi; cargo --version
WORKDIR /src
COPY . .
# fiberd is static and reproducible. The zygote library is cargo's
# archive of its Rust crate, with no C in it. Rust emits no pointer
# authentication unless asked, which a process restored from a checkpoint
# cannot use (see docker/dev/Dockerfile), and its objects are PIC, so the
# archive links into PIE templates and shared objects alike. The source
# paths are remapped.
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
ARG VERSION=""
RUN set -eu; mkdir -p /out/bin /out/lib /out/doc; \
    go build -ldflags "-s -w -buildid= -X main.version=${VERSION}" -o /out/bin/fiberd ./cmd/fiberd; \
    hack/release/third-party-notices.sh ./cmd/fiberd > /out/doc/THIRD_PARTY_NOTICES; \
    cp LICENSE NOTICE /out/doc/; \
    (cd sdk/c/template/core && RUSTFLAGS="--remap-path-prefix=/src=. --remap-path-prefix=$CARGO_HOME=/cargo" \
      cargo build --release --locked --target-dir /tmp/core); \
    cp /tmp/core/release/libfiberzygote_core.a /out/lib/libfiberzygote.a

FROM ${RUNTIME_BASE} AS fiberd
# Labels for local builds. The release workflow adds the rest.
LABEL org.opencontainers.image.source="https://github.com/helayoty/fiberd" \
      org.opencontainers.image.description="fiberd with criu and the zygote library" \
      org.opencontainers.image.licenses="Apache-2.0"
ARG DEBIAN_FRONTEND=noninteractive
# The libraries criu links against, and tini.
RUN apt-get update && apt-get install -y --no-install-recommends \
      libbsd0 libmd0 libnet1 libnl-3-200 libprotobuf-c1 libuuid1 ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build --chmod=0755 /usr/local/sbin/criu /usr/local/sbin/criu
COPY --from=build --chmod=0755 /out/bin/fiberd /usr/local/bin/fiberd
COPY --from=build --chmod=0644 /out/lib/libfiberzygote.a /usr/local/lib/libfiberzygote.a
COPY --chmod=0644 sdk/c/template/libfiberzygote.h /usr/local/include/libfiberzygote.h
COPY --from=build /usr/share/doc/criu /usr/share/doc/criu
COPY --from=build /out/doc /usr/share/doc/fiberd
# No USER on purpose. fiberd creates namespaces and cgroups and runs criu,
# so it starts as root and drops the capabilities it does not need
# (pkg/sys/caps).
# tini is PID 1 and reaps the orphans a fiber or sandbox leaves.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/fiberd"]

# The mount points of a sandbox rootfs, as hack/gvisor/rootfs.sh makes them
# plus the two every rootfs copy carries (docs/design/backends.md). Empty
# directories owned by root. The deployment adds its workload binary.
FROM ${RUNTIME_BASE} AS rootfs
RUN install -d -m 0755 -o root -g root \
      /skeleton /skeleton/bin /skeleton/proc /skeleton/dev /skeleton/tmp \
      /skeleton/host /skeleton/workspace /skeleton/fiberd \
      /skeleton/fiberd/channel /skeleton/fiberd/template

# runsc, pinned in docker/pins/runsc.env and checked against its sha512.
# curl and ca-certificates stay in this stage and never reach an image.
FROM ${RUNTIME_BASE} AS runsc
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY docker/pins/runsc.env /tmp/fiberd-pins/runsc.env
RUN set -eu; . /tmp/fiberd-pins/runsc.env; arch=$(uname -m); \
    case "$arch" in \
      x86_64)  sum=$RUNSC_SHA512_X86_64 ;; \
      aarch64) sum=$RUNSC_SHA512_AARCH64 ;; \
      *) echo "no pinned runsc for $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://storage.googleapis.com/gvisor/releases/release/${RUNSC_RELEASE}/${arch}/runsc" -o /usr/local/bin/runsc; \
    echo "$sum  /usr/local/bin/runsc" | sha512sum -c - >/dev/null; \
    chmod 0755 /usr/local/bin/runsc; \
    rm -rf /tmp/fiberd-pins; runsc --version

# fiberd and the runc it was built and tested against. The entrypoint, tini
# and the absence of a USER come from the fiberd stage.
FROM fiberd AS fiberd-runc
LABEL org.opencontainers.image.description="fiberd with runc for the runc runtime"
ARG DEBIAN_FRONTEND=noninteractive
RUN set -eu; apt-get update; \
    apt-get install -y --no-install-recommends runc util-linux mount; \
    rm -rf /var/lib/apt/lists/*; \
    runc --version | grep -Eq '^runc version 1\.1\.' || { echo "runc must be the 1.1 series" >&2; runc --version >&2; exit 1; }
COPY --from=rootfs /skeleton /usr/share/fiberd/rootfs

# fiberd and the runsc it was built and tested against.
FROM fiberd AS fiberd-gvisor
LABEL org.opencontainers.image.description="fiberd with runsc for the gVisor runtime"
COPY --from=runsc --chmod=0755 /usr/local/bin/runsc /usr/local/bin/runsc
COPY --from=rootfs /skeleton /usr/share/fiberd/rootfs
