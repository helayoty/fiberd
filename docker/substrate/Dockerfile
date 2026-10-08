# The worker image a Substrate WorkerPool runs. It holds ateom-fiberd, the
# reference workload in HTTP mode as the actor, and criu for park and
# resume. It builds from fiberd's dev image (docker/criu), which has the
# toolchain and criu 4.1.1. The runtime layer is bookworm-slim.
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
# Go binaries are static and reproducible. The reference zygote is built
# with TLS (-DFZ_TLS) so it can serve handoff grants. On aarch64 it is built
# without PAC branch protection (see docker/criu/Dockerfile).
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
RUN set -eu; mkdir -p /out; \
    ldflags="-s -w -buildid="; \
    (cd examples/substrate && go build -ldflags "$ldflags" -o /out/ ./cmd/ateom-fiberd); \
    flags=""; if [ "$(uname -m)" = aarch64 ]; then flags="-mbranch-protection=none"; fi; \
    gcc -O2 -Wall -Wextra -pthread $flags -DFZ_TLS -o /out/refzygote \
      zygote/refzygote.c zygote/libfiberzygote.c -lssl -lcrypto; \
    mkdir -p /key && go run ./cmd/grant-issuer keygen -alg EdDSA -out /key/delta-key.json >/dev/null; \
    go run ./cmd/grant-issuer keygen -alg A256GCM -out /key/delta-seal-key.json >/dev/null

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
LABEL org.opencontainers.image.source="https://github.com/helayoty/fiberd" \
      org.opencontainers.image.description="fiberd's Agent Substrate example: the ateom-fiberd worker with the reference workload as the actor and criu for park and resume" \
      org.opencontainers.image.licenses="Apache-2.0"
ARG DEBIAN_FRONTEND=noninteractive
# Runtime packages only. The libraries serve criu and the zygote's TLS.
# curl and procps help debug a worker through kubectl exec.
RUN apt-get update && apt-get install -y --no-install-recommends \
      libbsd0 libmd0 libnet1 libnl-3-200 libprotobuf-c1 libuuid1 libssl3 \
      curl ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build --chmod=0755 /usr/local/sbin/criu /usr/local/sbin/criu
COPY --from=build --chmod=0755 /out/ /usr/local/bin/
# Every ActorTemplate runs the reference workload in HTTP mode unless
# ATEOM_FIBERD_TEMPLATE names it.
ENV ATEOM_FIBERD_TEMPLATE="default=/usr/local/bin/refzygote --heap-mb 16 --http"
# The proc backend shares the worker's kernel, so its grants must be trusted.
ENV ATEOM_FIBERD_ISOLATION=TRUSTED
# Every worker shares these delta keys, so a golden snapshot taken on one
# worker restores on the others. They are generated once per image build,
# never copied from the host. This is a demo shortcut, because anyone who
# can pull the image can sign and open deltas. A real pool mounts the keys
# from a Secret instead.
COPY --from=build --chmod=0600 /key/delta-key.json /key/delta-seal-key.json /etc/fiberd/
ENV ATEOM_FIBERD_DELTA_KEY=/etc/fiberd/delta-key.json
ENV ATEOM_FIBERD_DELTA_SEAL_KEY=/etc/fiberd/delta-seal-key.json
# No USER on purpose. The agent creates namespaces and cgroups and runs
# criu for every actor. There is no HEALTHCHECK because the WorkerPool
# probes the worker.
ENTRYPOINT ["/usr/local/bin/ateom-fiberd"]
