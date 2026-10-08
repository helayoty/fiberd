# The worker image a Substrate WorkerPool runs. It holds ateom-fiberd,
# runsc, and the rootfs every actor's sandbox runs in, with the reference
# workload in HTTP mode as the actor. It builds from fiberd's dev image
# (docker/criu), which has the toolchain, runsc and the PAC-free OpenSSL
# the rootfs needs. The runtime layer is bookworm-slim.
#
#   docker build -t ateom-fiberd:dev -f docker/substrate/Dockerfile .   (from the repo root)
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
# Go binaries are static and reproducible. The rootfs is what every gVisor
# sandbox runs in: a static refzygote built with ZYGOTE_CFLAGS and
# ZYGOTE_LDFLAGS from the Makefile, TLS included, and on aarch64 without
# PAC branch protection, checked instruction by instruction, since a
# restored sandbox keeps stale PAC keys (hack/gvisor/rootfs.sh).
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
RUN set -eu; mkdir -p /out; \
    ldflags="-s -w -buildid="; \
    (cd examples/substrate && go build -ldflags "$ldflags" -o /out/ ./cmd/ateom-fiberd); \
    hack/gvisor/rootfs.sh /out/rootfs

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
LABEL org.opencontainers.image.source="https://github.com/helayoty/fiberd" \
      org.opencontainers.image.description="fiberd's Agent Substrate example: the ateom-fiberd worker, runsc, and a gVisor rootfs with the reference workload as the actor" \
      org.opencontainers.image.licenses="Apache-2.0"
ARG DEBIAN_FRONTEND=noninteractive
# Every binary here is static. curl and procps help debug a worker through
# kubectl exec.
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build --chmod=0755 /usr/local/bin/runsc /usr/local/bin/runsc
COPY --from=build --chmod=0755 /out/ateom-fiberd /usr/local/bin/ateom-fiberd
# The rootfs every sandbox runs in. The agent keeps its state (sandbox
# roots, template and park images) under /var/lib/fiberd.
COPY --from=build /out/rootfs /var/lib/fiberd/gvisor-rootfs
ENV ATEOM_FIBERD_RUNTIME=gvisor
ENV ATEOM_FIBERD_GVISOR_ROOTFS=/var/lib/fiberd/gvisor-rootfs
# Every ActorTemplate runs the reference workload as its sandbox's init,
# in HTTP mode, unless ATEOM_FIBERD_TEMPLATE names something else. The
# path is inside the rootfs.
ENV ATEOM_FIBERD_TEMPLATE="default=/bin/refzygote --heap-mb 16 --gvisor --http"
# Each actor has a sandbox kernel between it and the worker, so grants
# are untrusted, which is the home's default.
# Every worker shares the delta keys, so a golden snapshot taken on one
# worker restores on the others. The image holds no keys. The deploy mounts
# them from a Secret at /etc/fiberd (examples/substrate/kind/run.sh), and a
# worker without them refuses to start.
ENV ATEOM_FIBERD_DELTA_KEY=/etc/fiberd/delta-key.json
ENV ATEOM_FIBERD_DELTA_SEAL_KEY=/etc/fiberd/delta-seal-key.json
# No USER on purpose. The agent creates cgroups and runs runsc, which
# makes namespaces and mounts, for every actor. Substrate's worker spec
# grants the capabilities its own gVisor class needs, and this worker
# needs no more. There is no HEALTHCHECK because the WorkerPool probes
# the worker.
ENTRYPOINT ["/usr/local/bin/ateom-fiberd"]
