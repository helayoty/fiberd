# The fiberd agent image, the one the release publishes. It holds fiberd,
# criu for FIBER_CHECKPOINT, and the zygote library (header and static
# archive) so a template image can build its zygote from this one.
#
#   docker build -t fiberd -f docker/fiberd/Dockerfile .   (from the repo root)
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
# The dev image already has criu. The plain Go image builds it here.
COPY hack/dev/install-criu.sh hack/dev/criu-4b7398595-passcred-families.patch /tmp/fiberd-criu/
RUN if ! command -v criu >/dev/null 2>&1; then \
      apt-get update && apt-get install -y --no-install-recommends \
        gcc make pkg-config patch curl ca-certificates \
        libprotobuf-c-dev protobuf-c-compiler libprotobuf-dev python3-protobuf \
        libnl-3-dev libnet1-dev libcap-dev libbsd-dev uuid-dev libaio-dev \
      && rm -rf /var/lib/apt/lists/* \
      && CRIU_VERSION="${CRIU_VERSION}" sh /tmp/fiberd-criu/install-criu.sh; \
    fi \
    && rm -rf /tmp/fiberd-criu
WORKDIR /src
COPY . .
# fiberd is static and reproducible. The zygote library takes ZYGOTE_CFLAGS
# from the Makefile with -fPIC in place of -fPIE, since the archive links
# into PIE templates and shared objects alike, and no link flags, since an
# archive is not linked. On aarch64 it is built without PAC branch
# protection, because a process restored from a checkpoint keeps stale PAC
# keys (see docker/criu/Dockerfile).
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
RUN set -eu; mkdir -p /out/bin /out/lib; \
    go build -ldflags "-s -w -buildid=" -o /out/bin/fiberd ./cmd/fiberd; \
    flags=""; if [ "$(uname -m)" = aarch64 ]; then flags="-mbranch-protection=none"; fi; \
    gcc -D_FORTIFY_SOURCE=3 -O2 -fstack-protector-strong -fstack-clash-protection -fPIC -Wformat=2 -Werror=format-security \
      -Wall -Wextra -pthread $flags -ffile-prefix-map="$PWD"=. \
      -c zygote/libfiberzygote.c -o /tmp/libfiberzygote.o; \
    ar rcsD /out/lib/libfiberzygote.a /tmp/libfiberzygote.o

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
# The release workflow adds version, revision, created and title labels.
# These static ones cover local builds.
LABEL org.opencontainers.image.source="https://github.com/helayoty/fiberd" \
      org.opencontainers.image.description="fiberd, the fiber agent, with criu and the zygote library" \
      org.opencontainers.image.licenses="Apache-2.0"
ARG DEBIAN_FRONTEND=noninteractive
# The libraries criu links against, and nothing else.
RUN apt-get update && apt-get install -y --no-install-recommends \
      libbsd0 libmd0 libnet1 libnl-3-200 libprotobuf-c1 libuuid1 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build --chmod=0755 /usr/local/sbin/criu /usr/local/sbin/criu
COPY --from=build --chmod=0755 /out/bin/fiberd /usr/local/bin/fiberd
COPY --from=build --chmod=0644 /out/lib/libfiberzygote.a /usr/local/lib/libfiberzygote.a
COPY --chmod=0644 zygote/libfiberzygote.h /usr/local/include/libfiberzygote.h
# No USER on purpose. fiberd creates namespaces and cgroups and runs criu,
# so it starts as root and drops the capabilities it does not need
# (pkg/sys/caps).
ENTRYPOINT ["/usr/local/bin/fiberd"]
