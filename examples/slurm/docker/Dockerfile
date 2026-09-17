# A one-node Slurm cluster with fiberd inside: slurmctld and slurmd from
# Debian's slurm-wlm, munge, criu, fiberd-slurm (the agent library plus
# the Slurm home), fiberd's reference issuer, zygote, conformance and
# storm binaries. Built from fiberd's dev image (hack/dev), which carries
# the toolchain and criu 4.1.1; the runtime layer is bookworm-slim.
#
#   docker build -t fiberd:slurm -f examples/slurm/docker/Dockerfile .   (from the repo root)
ARG DEV_IMAGE=fiberd-dev:local
FROM ${DEV_IMAGE} AS build
WORKDIR /src
COPY . .
RUN set -eu; mkdir -p /out; \
    go build -o /out/ ./cmd/grant-issuer ./hack/storm ./hack/fibctl; \
    go test -c -o /out/grant-conform ./tests/conform; \
    (cd examples/slurm && go build -o /out/ ./cmd/...); \
    flags=""; if [ "$(uname -m)" = aarch64 ]; then flags="-mbranch-protection=none"; fi; \
    gcc -O2 -Wall -pthread $flags -o /out/refzygote hack/zygote/refzygote.c hack/zygote/libfiberzygote.c

FROM debian:bookworm-slim
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      slurm-wlm munge \
      libbsd0 libmd0 libnet1 libnl-3-200 libprotobuf-c1 libuuid1 \
      curl ca-certificates procps \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/spool/slurmctld /var/spool/slurmd /var/run/slurm /var/log/slurm /var/spool/fiberd /run/fiberd /var/lib/fiberd
COPY --from=build /usr/local/sbin/criu /usr/local/sbin/criu
COPY --from=build /out/ /usr/local/bin/
COPY examples/slurm/docker/slurm.conf.in /etc/slurm/slurm.conf.in
COPY examples/slurm/docker/cgroup.conf /etc/slurm/cgroup.conf
COPY examples/slurm/docker/entrypoint.sh /usr/local/bin/slurm-entrypoint
COPY examples/slurm/prolog/fiberd-prolog.sh /usr/local/bin/fiberd-prolog.sh
COPY examples/slurm/prolog/fiberd-job.sh /usr/local/bin/fiberd-job.sh
RUN chmod +x /usr/local/bin/slurm-entrypoint /usr/local/bin/fiberd-prolog.sh /usr/local/bin/fiberd-job.sh
ENTRYPOINT ["/usr/local/bin/slurm-entrypoint"]
