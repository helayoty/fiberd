# The Kubernetes example image (examples/kubernetes). It holds fiberd-k8s
# (PID 1 of a grant Pod), the grant-controller, the reference zygote as the
# template, criu for FIBER_CHECKPOINT, runsc and a gVisor rootfs for
# UNTRUSTED grants, and the conformance, storm and sessioncheck binaries
# so an acceptance run can exec them inside the cluster. It is built
# locally and never released. The release publishes the plain agent image
# from docker/fiberd/Dockerfile. Local builds can start from
# fiberd-dev:local. Without it the build starts from the plain Go image and
# installs the same patched criu and the same pinned runsc.
#
#   docker build -t fiberd:kind -f docker/kubernetes/Dockerfile .   (from the repo root)
#
# Both base images are pinned by digest. Refresh them with
# `docker buildx imagetools inspect <image:tag>`. The criu tarball is checked
# against the sha256 in hack/dev/install-criu.sh, and Go modules against the
# Go sum database. Debian packages come from the base's snapshot of the
# archive, so a newer base digest is the upgrade and `apt-get upgrade` is not
# run.
ARG DEV_IMAGE=golang:1.26-bookworm@sha256:dc9ad6c05acc7a88e5b71bde60a5fe3bd4b9f0db209011711b464107438a8107
FROM ${DEV_IMAGE} AS build
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
USER root
ARG DEBIAN_FRONTEND=noninteractive
ARG CRIU_VERSION=4.1.1
# The dev image already has criu and these build dependencies. The plain Go
# image gets them here.
COPY hack/dev/install-criu.sh hack/dev/criu-4b7398595-passcred-families.patch /tmp/fiberd-criu/
RUN if ! command -v criu >/dev/null 2>&1; then \
      apt-get update && apt-get install -y --no-install-recommends \
        gcc make pkg-config patch libssl-dev curl ca-certificates \
        libprotobuf-c-dev protobuf-c-compiler libprotobuf-dev python3-protobuf \
        libnl-3-dev libnet1-dev libcap-dev libbsd-dev uuid-dev libaio-dev \
      && rm -rf /var/lib/apt/lists/* \
      && CRIU_VERSION="${CRIU_VERSION}" sh /tmp/fiberd-criu/install-criu.sh; \
    fi \
    && rm -rf /tmp/fiberd-criu
# gVisor's runsc for the gvisor runtime, as docker/criu/Dockerfile installs
# it: the same pinned release, each binary checked against the sha512 from
# gVisor's runsc.sha512. The dev image already has it.
ARG RUNSC_RELEASE=20260817.0
ARG RUNSC_SHA512_X86_64=84936438d583ec976800f464e75a83e1515f0890b451b9b4db219c4472b54ca9b106a6772ee683f1e64cce2128871d7637b14d800591f8451b8137f6c39fb2ef
ARG RUNSC_SHA512_AARCH64=6394fd161a4af0dc9a2c29f75c3016d05275a55744f124e12023fa7666a9f161c68d6ce3803ad49205c6a7b5bee0ad2ccf48edff340db344fdafec678c788aa4
RUN set -eu; if ! command -v runsc >/dev/null 2>&1; then \
      arch=$(uname -m); \
      case "$arch" in \
        x86_64)  sum=$RUNSC_SHA512_X86_64 ;; \
        aarch64) sum=$RUNSC_SHA512_AARCH64 ;; \
        *) echo "no pinned runsc for $arch" >&2; exit 1 ;; \
      esac; \
      curl -fsSL "https://storage.googleapis.com/gvisor/releases/release/${RUNSC_RELEASE}/${arch}/runsc" -o /usr/local/bin/runsc; \
      echo "$sum  /usr/local/bin/runsc" | sha512sum -c - >/dev/null; \
      chmod 0755 /usr/local/bin/runsc; \
    fi; runsc --version
WORKDIR /src
COPY . .
# Go binaries are static and reproducible. The reference zygote is built
# with TLS (-DFZ_TLS) because handoff fibers must serve the TLS identity
# they receive, with ZYGOTE_CFLAGS and ZYGOTE_LDFLAGS from the Makefile. On
# aarch64 it is built without PAC branch protection, because a process
# restored from a checkpoint keeps stale PAC keys (see
# docker/criu/Dockerfile).
# The agent is built with the fiberd_testhooks tag, since kind conformance
# drives the test-only admin controls (-admin-unsafe). The release image
# (docker/fiberd) is built without it.
# The gVisor rootfs is what every sandbox of a gvisor grant Pod runs in: a
# static refzygote built by hack/gvisor/rootfs.sh with the same flags,
# PAC-free on aarch64 (the PAC-free OpenSSL comes from the dev image; a
# plain Go image build on aarch64 fails there, see the script).
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
RUN set -eu; mkdir -p /out; \
    ldflags="-s -w -buildid="; \
    go build -ldflags "$ldflags" -o /out/ ./hack/storm ./hack/fibctl ./hack/sessioncheck; \
    hack/gvisor/rootfs.sh /out/rootfs >/dev/null; \
    go test -c -ldflags "$ldflags" -o /out/grant-conform ./tests/conform; \
    (cd examples/kubernetes && go build -tags fiberd_testhooks -ldflags "$ldflags" -o /out/ ./cmd/...); \
    flags=""; if [ "$(uname -m)" = aarch64 ]; then flags="-mbranch-protection=none"; fi; \
    gcc -D_FORTIFY_SOURCE=3 -O2 -fstack-protector-strong -fstack-clash-protection -fPIE -Wformat=2 -Werror=format-security \
      -pie -Wl,-z,relro,-z,now -Wall -Wextra -pthread $flags -DFZ_TLS -o /out/refzygote \
      zygote/refzygote.c zygote/libfiberzygote.c -lssl -lcrypto

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
# The release workflow adds version, revision, created and title labels.
# These static ones cover local builds.
LABEL org.opencontainers.image.source="https://github.com/helayoty/fiberd" \
      org.opencontainers.image.description="fiberd for Kubernetes: the grant Pod agent (fiberd-k8s), the issuer controller (grant-controller), the reference zygote, criu, runc, runsc, and the conformance and storm binaries" \
      org.opencontainers.image.licenses="Apache-2.0"
ARG DEBIAN_FRONTEND=noninteractive
# Runtime packages only. The libraries serve criu and the zygote's TLS.
# runc serves the runc runtime (a grant Pod with runtime: runc runs each
# zygote as an OCI container's init), from Debian's package as the dev
# image has it. curl and procps serve the conformance hooks that run in
# the Pod through kubectl exec (examples/kubernetes/kind/conform.sh). The
# grant Pod's probes do not need them, since they run `fiberd-k8s -healthz`.
RUN apt-get update && apt-get install -y --no-install-recommends \
      libbsd0 libmd0 libnet1 libnl-3-200 libprotobuf-c1 libuuid1 libssl3 \
      runc curl ca-certificates procps \
    && rm -rf /var/lib/apt/lists/* \
    && runc --version
COPY --from=build --chmod=0755 /usr/local/sbin/criu /usr/local/sbin/criu
COPY --from=build --chmod=0755 /usr/local/bin/runsc /usr/local/bin/runsc
COPY --from=build --chmod=0755 /out/storm /out/fibctl /out/sessioncheck /out/grant-conform /out/refzygote /out/fiberd-k8s /out/grant-controller /usr/local/bin/
# The rootfs a gvisor grant Pod's sandboxes run in (-gvisor-rootfs). The
# runc runtime can use it as well (-runc-rootfs). It is not under
# /var/lib/fiberd, which the grant Pod covers with its state volume.
COPY --from=build /out/rootfs /usr/share/fiberd/gvisor-rootfs
# No USER on purpose. fiberd-k8s creates namespaces and cgroups and runs
# criu, so it starts as root. Its privilege is narrowed at runtime instead.
# The Pod spec drops ALL capabilities and adds back only the runtime's list
# (examples/kubernetes/controller/pod.go), and the agent drops what it does
# not need (pkg/sys/caps). grant-controller needs none of this, so its
# Deployment runs it as non-root with a read-only root filesystem
# (examples/kubernetes/kind/manifests/20-issuer.yaml).
# No HEALTHCHECK, because the kubelet probes the Pod.
ENTRYPOINT ["/usr/local/bin/fiberd-k8s"]
