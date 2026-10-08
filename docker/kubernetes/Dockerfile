# The Kubernetes example image (examples/kubernetes). It holds fiberd-k8s
# (PID 1 of a grant Pod), the grant-controller, the reference zygote as the
# template, criu for FIBER_CHECKPOINT, and the conformance and storm
# binaries so an acceptance run can exec them inside the cluster. It is
# built locally and never released. The release publishes the plain agent
# image from docker/fiberd/Dockerfile. Local builds can start from
# fiberd-dev:local. Without it the build starts from the plain Go image and
# installs the same patched criu.
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
WORKDIR /src
COPY . .
# Go binaries are static and reproducible. The reference zygote is built
# with TLS (-DFZ_TLS) because handoff fibers must serve the TLS identity
# they receive. On aarch64 it is built without PAC branch protection,
# because a process restored from a checkpoint keeps stale PAC keys (see
# docker/criu/Dockerfile).
# The agent is built with the fiberd_testhooks tag, since kind conformance
# drives the test-only admin controls (-admin-unsafe). The release image
# (docker/fiberd) is built without it.
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
RUN set -eu; mkdir -p /out; \
    ldflags="-s -w -buildid="; \
    go build -ldflags "$ldflags" -o /out/ ./hack/storm ./hack/fibctl; \
    go test -c -ldflags "$ldflags" -o /out/grant-conform ./tests/conform; \
    (cd examples/kubernetes && go build -tags fiberd_testhooks -ldflags "$ldflags" -o /out/ ./cmd/...); \
    flags=""; if [ "$(uname -m)" = aarch64 ]; then flags="-mbranch-protection=none"; fi; \
    gcc -O2 -Wall -Wextra -pthread $flags -DFZ_TLS -o /out/refzygote \
      zygote/refzygote.c zygote/libfiberzygote.c -lssl -lcrypto

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
# The release workflow adds version, revision, created and title labels.
# These static ones cover local builds.
LABEL org.opencontainers.image.source="https://github.com/helayoty/fiberd" \
      org.opencontainers.image.description="fiberd for Kubernetes: the grant Pod agent (fiberd-k8s), the issuer controller (grant-controller), the reference zygote, criu, and the conformance and storm binaries" \
      org.opencontainers.image.licenses="Apache-2.0"
ARG DEBIAN_FRONTEND=noninteractive
# Runtime packages only. The libraries serve criu and the zygote's TLS.
# curl and procps serve the conformance hooks that
# run in the Pod through kubectl exec (examples/kubernetes/kind/conform.sh).
RUN apt-get update && apt-get install -y --no-install-recommends \
      libbsd0 libmd0 libnet1 libnl-3-200 libprotobuf-c1 libuuid1 libssl3 \
      curl ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build --chmod=0755 /usr/local/sbin/criu /usr/local/sbin/criu
COPY --from=build --chmod=0755 /out/ /usr/local/bin/
# No USER on purpose. fiberd-k8s creates namespaces and cgroups and runs
# criu, so it starts as root. Its privilege is narrowed at runtime instead.
# The Pod spec drops ALL capabilities and adds back only the runtime's list
# (examples/kubernetes/controller/pod.go), and the agent drops what it does
# not need (pkg/sys/caps). grant-controller needs none of this, so its
# Deployment runs it as non-root with a read-only root filesystem
# (examples/kubernetes/kind/manifests/20-issuer.yaml).
# No HEALTHCHECK, because the kubelet probes the Pod.
ENTRYPOINT ["/usr/local/bin/fiberd-k8s"]
