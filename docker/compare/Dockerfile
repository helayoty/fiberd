# The activation comparison images (bench/compare). Every system in the
# comparison runs the same workload, the counter, so this file builds it
# once and ships it three ways. Built locally and never released.
#
#   docker build --target counter  -t localhost:5002/counter:latest -f docker/compare/Dockerfile .
#   docker build --target client   -t compare-client:local          -f docker/compare/Dockerfile .
#   docker build --target binaries -o bin/compare-bin               -f docker/compare/Dockerfile .
#
# counter is FROM scratch with one static counter, run by Pods and
# agent-sandbox with --plain. client is the compare client Pod in kind:
# the compare and summarize clients and crictl on the Kubernetes example
# image. binaries exports the counters and the clients to a directory,
# for the runs that need no image (the dev container and the KVM host).
# The fiberd homes themselves run stock fiberd:kind
# (docker/kubernetes/Dockerfile) and pull the static counter from the
# compare registry as a zygote artifact, the way a production home gets
# its templates (bench/compare/run/phase1.sh, standalone.sh). No image
# carries the counter as a template.
#
# The build stage is the dev image (make linux-check builds it). The
# counter takes ZYGOTE_CFLAGS and ZYGOTE_LDFLAGS from the Makefile, with
# -static-pie in place of -pie for the static build. On aarch64 it is built
# without PAC branch protection, since a restored process keeps stale PAC
# keys (see docker/criu/Dockerfile). crictl is checked against its
# published sha256.
ARG BUILD_IMAGE=fiberd-dev:local
ARG BASE_IMAGE=fiberd:kind

FROM ${BUILD_IMAGE} AS build
WORKDIR /src
COPY . .
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
RUN set -eu; mkdir -p /out; flags=""; \
    if [ "$(uname -m)" = aarch64 ]; then flags="-mbranch-protection=none"; fi; \
    cflags="-D_FORTIFY_SOURCE=3 -O2 -fstack-protector-strong -fstack-clash-protection -fPIE -Wformat=2 -Werror=format-security -Wall -Wextra -pthread $flags"; \
    src="bench/compare/workload/counter.c zygote/libfiberzygote.c"; \
    gcc $cflags -pie -Wl,-z,relro,-z,now -o /out/counter $src; \
    gcc $cflags -static-pie -Wl,-z,relro,-z,now -o /out/counter-static $src; \
    { /out/counter-static --help 2>&1 || true; } | grep -q usage; \
    /out/counter-static --heap-mb 16 --plain --port 18099 & p=$!; sleep 1; \
    rss=$(awk '/VmRSS/ {print $2}' /proc/$p/status); kill $p; \
    [ "$rss" -ge 16384 ] || { echo "counter keeps $rss kB, not its 16 MiB heap" >&2; exit 1; }; \
    (cd bench/compare && go build -ldflags "-s -w -buildid=" -o /out/ ./cmd/...)
# crictl lets the cold Pod case drop the image from the node through the
# containerd socket the client Pod mounts.
ARG CRICTL_VERSION=v1.34.0
ARG CRICTL_SHA256_AMD64=a8ff2a3edb37a98daf3aba7c3b284fe0aa5bff24166d896ab9ef64c8913c9f51
ARG CRICTL_SHA256_ARM64=c31d252e203df5f4cf37f314bd3092eb79087e791631c1e607087c74b6d0423f
RUN set -eu; \
    case "$(uname -m)" in \
      x86_64)  a=amd64; sum=$CRICTL_SHA256_AMD64 ;; \
      aarch64) a=arm64; sum=$CRICTL_SHA256_ARM64 ;; \
      *) echo "no pinned crictl for $(uname -m)" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/kubernetes-sigs/cri-tools/releases/download/${CRICTL_VERSION}/crictl-${CRICTL_VERSION}-linux-${a}.tar.gz" -o /tmp/crictl.tar.gz; \
    echo "$sum  /tmp/crictl.tar.gz" | sha256sum -c - >/dev/null; \
    tar -xzf /tmp/crictl.tar.gz -C /out crictl

FROM scratch AS counter
COPY --from=build /out/counter-static /counter
EXPOSE 8080
ENTRYPOINT ["/counter", "--plain", "--heap-mb", "32"]

FROM scratch AS binaries
COPY --from=build /out/counter /out/counter-static /out/compare /out/summarize /

FROM ${BASE_IMAGE} AS client
COPY --from=build --chmod=0755 /out/compare /out/summarize /out/crictl /usr/local/bin/
