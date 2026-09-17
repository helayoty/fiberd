# The worker image a Substrate WorkerPool runs: ateom-fiberd (the herder,
# the ingress, fiberd's agent with the substrate home, the proc backend),
# fiberd's reference workload in HTTP mode as the actor, and criu for the
# park and resume behind checkpoint and restore. Built from fiberd's dev
# image (hack/dev), which carries the toolchain and criu 4.1.1; the
# runtime layer is bookworm-slim plus criu's shared libraries.
#
#   docker build -t ateom-fiberd:dev -f examples/substrate/kind/Dockerfile .   (from the repo root)
ARG DEV_IMAGE=fiberd-dev:local
FROM ${DEV_IMAGE} AS build
WORKDIR /src
COPY . .
RUN set -eu; mkdir -p /out; \
    (cd examples/substrate && go build -o /out/ ./cmd/ateom-fiberd); \
    flags=""; if [ "$(uname -m)" = aarch64 ]; then flags="-mbranch-protection=none"; fi; \
    gcc -O2 -Wall -pthread $flags -o /out/refzygote hack/zygote/refzygote.c hack/zygote/libfiberzygote.c

FROM debian:bookworm-slim
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      libbsd0 libmd0 libnet1 libnl-3-200 libprotobuf-c1 libuuid1 \
      curl ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/sbin/criu /usr/local/sbin/criu
COPY --from=build /out/ /usr/local/bin/
# What fiberd runs inside the worker: every ActorTemplate is served by the
# reference workload in HTTP mode unless ATEOM_FIBERD_TEMPLATE names it.
ENV ATEOM_FIBERD_TEMPLATE="default=/usr/local/bin/refzygote --heap-mb 16 --http"
ENTRYPOINT ["ateom-fiberd"]
