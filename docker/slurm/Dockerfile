# A one-node Slurm cluster with fiberd inside. It holds Debian's slurm-wlm,
# munge, criu, fiberd-slurm, and fiberd's reference issuer, zygote,
# conformance and storm binaries. It builds from fiberd's dev image
# (docker/criu), which has the toolchain and criu 4.1.1. The runtime layer
# is bookworm-slim.
#
#   docker build -t fiberd:slurm -f docker/slurm/Dockerfile .   (from the repo root)
#
# The runtime base is pinned by digest. Refresh it with
# `docker buildx imagetools inspect debian:bookworm-slim`. The build base is
# the local dev image, which starts from a digest-pinned golang image. A
# newer base digest is the upgrade, so `apt-get upgrade` is not run.
ARG DEV_IMAGE=fiberd-dev:local
FROM ${DEV_IMAGE} AS build
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
WORKDIR /src
COPY . .
# Go binaries are static and reproducible. The reference zygote is built
# with TLS (-DFZ_TLS) so it can serve handoff grants, with ZYGOTE_CFLAGS and
# ZYGOTE_LDFLAGS from the Makefile. On aarch64 it is built without PAC
# branch protection (see docker/criu/Dockerfile).
# The agent is built with the fiberd_testhooks tag, since the conformance run
# drives the test-only admin controls (-admin-unsafe). The release image
# (docker/fiberd) is built without it.
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
RUN set -eu; mkdir -p /out; \
    ldflags="-s -w -buildid="; \
    go build -ldflags "$ldflags" -o /out/ ./cmd/grant-issuer ./hack/storm ./hack/fibctl; \
    go test -c -ldflags "$ldflags" -o /out/grant-conform ./tests/conform; \
    (cd examples/slurm && go build -tags fiberd_testhooks -ldflags "$ldflags" -o /out/ ./cmd/...); \
    flags=""; if [ "$(uname -m)" = aarch64 ]; then flags="-mbranch-protection=none"; fi; \
    gcc -D_FORTIFY_SOURCE=3 -O2 -fstack-protector-strong -fstack-clash-protection -fPIE -Wformat=2 -Werror=format-security \
      -pie -Wl,-z,relro,-z,now -Wall -Wextra -pthread $flags -DFZ_TLS -o /out/refzygote \
      zygote/refzygote.c zygote/libfiberzygote.c -lssl -lcrypto

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
LABEL org.opencontainers.image.source="https://github.com/helayoty/fiberd" \
      org.opencontainers.image.description="fiberd's Slurm example: a one-node Slurm cluster with fiberd-slurm, the reference issuer and zygote, criu, and the conformance and storm binaries" \
      org.opencontainers.image.licenses="Apache-2.0"
ARG DEBIAN_FRONTEND=noninteractive
# Runtime packages only. Besides Slurm and munge, the libraries serve criu
# and the zygote's TLS. curl and procps serve the conformance hooks.
RUN apt-get update && apt-get install -y --no-install-recommends \
      slurm-wlm munge \
      libbsd0 libmd0 libnet1 libnl-3-200 libprotobuf-c1 libuuid1 libssl3 \
      curl ca-certificates procps \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/spool/slurmctld /var/spool/slurmd /var/run/slurm /var/log/slurm /var/spool/fiberd /run/fiberd /var/lib/fiberd
COPY --from=build --chmod=0755 /usr/local/sbin/criu /usr/local/sbin/criu
COPY --from=build --chmod=0755 /out/ /usr/local/bin/
COPY examples/slurm/docker/slurm.conf.in /etc/slurm/slurm.conf.in
COPY examples/slurm/docker/cgroup.conf /etc/slurm/cgroup.conf
COPY --chmod=0755 examples/slurm/docker/entrypoint.sh /usr/local/bin/slurm-entrypoint
COPY --chmod=0755 examples/slurm/prolog/fiberd-prolog.sh /usr/local/bin/fiberd-prolog.sh
COPY --chmod=0755 examples/slurm/prolog/fiberd-job.sh /usr/local/bin/fiberd-job.sh
# No USER on purpose. The entrypoint starts the Slurm daemons and carves
# cgroups, and the agent runs criu, so all of it needs root.
# examples/slurm/conform.sh runs the container --privileged. There is no
# HEALTHCHECK because conform.sh waits on sinfo.
ENTRYPOINT ["/usr/local/bin/slurm-entrypoint"]
