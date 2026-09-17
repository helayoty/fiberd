# The image the Kubernetes example runs: fiberd-k8s (the agent library
# plus the Kubernetes home, PID 1 of a grant Pod), grant-controller (the
# issuer as a controller), fiberd's reference zygote as the template, criu
# for FIBER_CHECKPOINT, and fiberd's conformance and storm binaries so an
# acceptance run can exec them inside the cluster. Built from fiberd's dev
# image (hack/dev), which carries the toolchain and criu 4.1.1; the
# runtime layer is bookworm-slim plus criu's shared libraries.
#
#   docker build -t fiberd:kind -f examples/kubernetes/kind/Dockerfile .   (from the repo root)
ARG DEV_IMAGE=fiberd-dev:local
FROM ${DEV_IMAGE} AS build
WORKDIR /src
COPY . .
RUN set -eu; mkdir -p /out; \
    go build -o /out/ ./hack/storm ./hack/fibctl; \
    go test -c -o /out/grant-conform ./tests/conform; \
    (cd examples/kubernetes && go build -o /out/ ./cmd/...); \
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
ENTRYPOINT ["fiberd-k8s"]
