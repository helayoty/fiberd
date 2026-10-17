# Development image for the parts of fiberd that need a Linux kernel, such
# as the fork zygote, cgroup v2, PSI and CRIU. hack/dev/run.sh builds and
# runs it for `make linux-shell`, `make linux-test` and `make conform-proc`.
#
# This is a workbench, not a runtime image. It runs --privileged with a
# private cgroup namespace so fiberd can carve a delegated cgroup subtree
# and CRIU can dump and restore process trees. It stays root for the same
# reason.
#
# The base is Debian 12 (bookworm) because its arm64 userland is built
# without pointer authentication (PAC). Trixie and sid turn PAC on for
# arm64. A process restored by gVisor keeps stale PAC keys and dies with
# SIGILL on CPUs with FEAT_FPAC (Apple silicon), so every park and resume
# in a sandbox would fail. CRIU puts the keys back (criu 4.2.1 restores
# NT_ARM_PACA_KEYS), so the proc and runc backends do not mind. Bookworm's
# own criu 3.17 cannot read the 6.17 kernel on GitHub's runners, so criu
# is built from source below.
#
# The Python SDK needs CPython 3.14, which bookworm lacks, so the
# interpreter and its packages come from a pinned snapshot of sid. That
# moves glibc and a few libraries to sid's PAC-signed builds. Before it
# does, a copy of bookworm's glibc and the libraries CPython needs is kept
# at /usr/local/sysroot-nopac, and a PAC-free CPython is built against it
# at /usr/local/python-nopac. The rootfs scripts build and run against
# those two, so what a sandbox restores stays free of PAC.
#
# The base image is pinned by digest. Refresh it with
# `docker buildx imagetools inspect golang:1.26-bookworm`. Every download
# below is checked against a pinned sha256 or sha512. Debian packages come
# from the base's snapshot of the archive or from the sid snapshot named
# below, so a newer base digest or snapshot is the upgrade and `apt-get
# upgrade` is not run.
FROM node:24-bookworm-slim@sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5 AS node
FROM golang:1.26-bookworm@sha256:dc9ad6c05acc7a88e5b71bde60a5fe3bd4b9f0db209011711b464107438a8107

LABEL org.opencontainers.image.source="https://github.com/helayoty/fiberd" \
      org.opencontainers.image.description="fiberd Linux development workbench: Go, criu, runsc, Rust, cargo-hyperlight, CPython 3.14 and Node.js 24" \
      org.opencontainers.image.licenses="Apache-2.0"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ARG DEBIAN_FRONTEND=noninteractive
# libclang-rt-14-dev holds libFuzzer's runtime for `make fuzz`. criu 4.2
# generates its image code through protoc (protobuf-compiler) with the
# protobuf-c plugin. The last line is what the PAC-free CPython below
# links (zlib1g-dev and uuid-dev are already in the base).
RUN apt-get update && apt-get install -y --no-install-recommends \
      gcc make pkg-config libssl-dev clang lld libclang-rt-14-dev \
      runc \
      curl ca-certificates jq procps iproute2 strace \
      libprotobuf-c-dev protobuf-c-compiler protobuf-compiler libprotobuf-dev python3-protobuf \
      libnl-3-dev libnet1-dev libcap-dev libbsd-dev uuid-dev libaio-dev \
      libbz2-dev liblzma-dev libffi-dev libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

# criu 4.2.1 from source (binary only). It reads SO_PASSCRED and
# SO_PASSSEC only on the socket families that have them, so a fiber with
# a tcp endpoint parks on Linux 6.16 and later. It leaves glibc's droppable
# getrandom state pages out of a dump and restores their mapping
# droppable, so a resumed fiber that forks does not share a keystream
# with its child. install-criu.sh pins the tarball's sha256.
ARG CRIU_VERSION=4.2.1
COPY hack/dev/install-criu.sh /tmp/fiberd-criu/
RUN CRIU_VERSION="${CRIU_VERSION}" sh /tmp/fiberd-criu/install-criu.sh \
    && rm -rf /tmp/fiberd-criu

# gVisor's runsc for the gvisor backend. Its systrap platform gives
# FIBER_SNAPSHOT inside a privileged container without KVM. The release is
# the newest with both aarch64 and x86_64 binaries. Each binary's sha512 is
# copied here from gVisor's runsc.sha512, so the download is checked
# against this file and not against the server.
ARG RUNSC_RELEASE=20260817.0
ARG RUNSC_SHA512_X86_64=84936438d583ec976800f464e75a83e1515f0890b451b9b4db219c4472b54ca9b106a6772ee683f1e64cce2128871d7637b14d800591f8451b8137f6c39fb2ef
ARG RUNSC_SHA512_AARCH64=6394fd161a4af0dc9a2c29f75c3016d05275a55744f124e12023fa7666a9f161c68d6ce3803ad49205c6a7b5bee0ad2ccf48edff340db344fdafec678c788aa4
RUN set -eu; arch=$(uname -m); \
    case "$arch" in \
      x86_64)  sum=$RUNSC_SHA512_X86_64 ;; \
      aarch64) sum=$RUNSC_SHA512_AARCH64 ;; \
      *) echo "no pinned runsc for $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://storage.googleapis.com/gvisor/releases/release/${RUNSC_RELEASE}/${arch}/runsc" -o /usr/local/bin/runsc; \
    echo "$sum  /usr/local/bin/runsc" | sha512sum -c - >/dev/null; \
    chmod 0755 /usr/local/bin/runsc; \
    runsc --version

# Rust, cargo-hyperlight and clang build the Hyperlight helper and guest
# (hack/hyperlight). Building needs no hypervisor. Running the helper needs
# /dev/kvm passed into the container. rustup-init is a pinned release
# checked against its published sha256. rustup then checks the toolchains
# it installs against the signed channel manifests.
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo PATH=/usr/local/cargo/bin:$PATH
ARG RUSTUP_VERSION=1.29.1
ARG RUSTUP_SHA256_X86_64=dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71
ARG RUSTUP_SHA256_AARCH64=15f6e4ce9f583b929c996c91562bad6d4454f3281de858b02cdfdef615fac433
ARG CARGO_HYPERLIGHT_VERSION=0.1.14
RUN set -eu; arch=$(uname -m); \
    case "$arch" in \
      x86_64)  sum=$RUSTUP_SHA256_X86_64 ;; \
      aarch64) sum=$RUSTUP_SHA256_AARCH64 ;; \
      *) echo "no pinned rustup-init for $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${arch}-unknown-linux-gnu/rustup-init" -o /tmp/rustup-init; \
    echo "$sum  /tmp/rustup-init" | sha256sum -c - >/dev/null; \
    chmod 0755 /tmp/rustup-init; \
    /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain stable; \
    rm -f /tmp/rustup-init; \
    cargo install --locked cargo-hyperlight --version "${CARGO_HYPERLIGHT_VERSION}"; \
    rm -rf /usr/local/cargo/registry/cache /usr/local/cargo/git
# Stable Rust rejects the guests' custom target since 1.95, so the guest
# crate pins 1.94.0 (hack/hyperlight/guest/rust-toolchain.toml).
RUN rustup toolchain install 1.94.0 --profile minimal --component rust-src

# OpenSSL for the rootfs zygote (hack/gvisor/rootfs.sh), built without
# pointer authentication. Debian's libcrypto signs the link register in
# its arm64 assembly, and a fiber checkpointed inside one of those
# routines traps on restore on a FEAT_FPAC CPU. The 3.0 line hard-codes
# those instructions in its perlasm (`.inst 0xd503233f`), so no compiler
# flag removes them. On aarch64 the C implementations are built instead
# (no-asm), with the flag keeping the compiler's own output clean. Static
# libraries and headers only. The tarball is pinned by sha256.
ARG OPENSSL_VERSION=3.0.18
ARG OPENSSL_SHA256=d80c34f5cf902dccf1f1b5df5ebb86d0392e37049e5d73df1b3abae72e4ffe8b
RUN set -eu; cd /tmp; \
    curl -fsSL "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" -o openssl.tar.gz; \
    echo "${OPENSSL_SHA256}  openssl.tar.gz" | sha256sum -c - >/dev/null; \
    tar xzf openssl.tar.gz; cd "openssl-${OPENSSL_VERSION}"; \
    flags=""; [ "$(uname -m)" != aarch64 ] || flags="no-asm -mbranch-protection=none"; \
    ./Configure --prefix=/usr/local/openssl-nopac --libdir=lib no-shared no-dso no-engine no-tests $flags >/dev/null; \
    make -j"$(nproc)" build_libs >/dev/null; \
    make install_dev >/dev/null; \
    cd /; rm -rf /tmp/openssl.tar.gz "/tmp/openssl-${OPENSSL_VERSION}"

# A PAC-free sysroot: bookworm's glibc, static and shared, with its
# headers, OpenSSL, and the libraries the CPython below links, copied as the
# packages lay them out (merged /usr, so /lib is a symlink here too). The
# sid snapshot below replaces the live copies with PAC-signed builds. The
# rootfs scripts compile against this one (gcc --sysroot) and the
# PAC-free CPython runs on it, so every object a sandbox restores comes
# from here. On aarch64 the build fails if the base ever carries PAC.
# Absolute links, such as amd64's /lib64/ld-linux-x86-64.so.2, are pointed
# into the sysroot, or they would pair the live loader with this libc.
RUN set -eu; sysroot=/usr/local/sysroot-nopac; triplet=$(gcc -print-multiarch); \
    mkdir -p "$sysroot/usr/lib" "$sysroot/usr/lib64"; ln -s usr/lib "$sysroot/lib"; ln -s usr/lib64 "$sysroot/lib64"; \
    for p in libc6 libc6-dev linux-libc-dev libcrypt1 libcrypt-dev libgcc-s1 \
             zlib1g zlib1g-dev libbz2-1.0 libbz2-dev liblzma5 liblzma-dev libffi8 libffi-dev \
             libsqlite3-0 libsqlite3-dev libuuid1 uuid-dev libssl3 libssl-dev; do dpkg -L "$p"; done \
      | while read -r f; do if [ -L "$f" ] || [ -f "$f" ]; then echo "$f"; fi; done \
      | tar -cf - --no-recursion -T - | tar -C "$sysroot" --keep-directory-symlink -xf -; \
    find "$sysroot" -type l -lname '/*' | while read -r l; do ln -sfn "$sysroot$(readlink "$l")" "$l"; done; \
    out=$(find "$sysroot" -type l -lname '/*' ! -lname "$sysroot/*"); \
    [ -z "$out" ] || { echo "links leave the sysroot: $out" >&2; exit 1; }; \
    if [ "$(uname -m)" = aarch64 ]; then \
      for f in "$sysroot/lib/$triplet/libc.so.6" "$sysroot/usr/lib/$triplet/libc.a"; do \
        n=$(objdump -d "$f" | awk '$3 ~ /^(pac|aut|reta|bra|blra)/ {n++} END{print n+0}'); \
        [ "$n" = 0 ] || { echo "$n PAC instructions in $f; the base is no longer PAC-free" >&2; exit 1; }; \
      done; \
    fi

# A PAC-free CPython for the rootfs the gvisor and runc backends run the
# Python reference template in (hack/python/rootfs.sh). Built from the
# python.org tarball, checked against the sha256 python.org publishes
# beside it, against the sysroot above with -mbranch-protection=none on
# aarch64, with its loader and library path pointing into the sysroot, so
# it runs on bookworm's glibc here and in a sandbox. Its _ssl links the
# PAC-free OpenSSL. The interpreter remembers its compiler, so an
# extension it builds (setup.py) is built against the sysroot too. The
# -B is needed as well as --sysroot, since Debian's gcc also searches
# its own install-relative paths, which lead back to the live libc. No
# pip, no tests, no debug info.
ARG PYTHON_VERSION=3.14.8
ARG PYTHON_SHA256=a65b20a728f169f4e66ae143f40b1bd3d33c38d770251663f627c9767b79b210
RUN set -eu; cd /tmp; \
    curl -fsSL "https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz" -o python.tgz; \
    echo "${PYTHON_SHA256}  python.tgz" | sha256sum -c - >/dev/null; \
    tar xzf python.tgz; cd "Python-${PYTHON_VERSION}"; \
    sysroot=/usr/local/sysroot-nopac; triplet=$(gcc -print-multiarch); ld=$(echo "$sysroot/lib/$triplet"/ld-linux-*.so.*); \
    flags=""; [ "$(uname -m)" != aarch64 ] || flags="-mbranch-protection=none"; \
    ./configure --prefix=/usr/local/python-nopac --with-openssl=/usr/local/openssl-nopac \
      --without-ensurepip --disable-test-modules \
      CC="gcc --sysroot=$sysroot -B$sysroot/usr/lib/$triplet" OPT="-DNDEBUG -O2 -Wall" CFLAGS="$flags" \
      LDFLAGS="-Wl,-rpath,$sysroot/lib/$triplet -Wl,--disable-new-dtags -Wl,--dynamic-linker=$ld" >/dev/null; \
    make -j"$(nproc)" >/dev/null; \
    make install >/dev/null; \
    cd /; rm -rf /tmp/python.tgz "/tmp/Python-${PYTHON_VERSION}"; \
    rm -rf /usr/local/python-nopac/lib/python3.14/config-*/libpython3.14.a; \
    /usr/local/python-nopac/bin/python3.14 -c 'import ssl, _ctypes, _socket, select, zlib; print(ssl.OPENSSL_VERSION)'

# Python for the SDK (sdk/python), from a snapshot of sid pinned by date,
# since bookworm stops at 3.11 and the SDK supports 3.14 and 3.15. sid is
# pinned below bookworm, so only what is asked for here, and what that
# needs, comes from it. The headers the template extension builds
# against, setuptools to build it, pytest for the unit tests, and for
# fiberd.client Debian's grpcio and protobuf, the protoc of the same
# protobuf release, which makes the client's messages (make
# python-proto), and cryptography for the test certificates. wheel, venv
# and pip's wheel build the sdist's wheel and install it offline (make
# python-dist). The snapshot's Release files are past their date, hence
# check-valid-until=no.
#
# The interpreter needs sid's libssl3t64, which replaces bookworm's
# libssl3 and depends on openssl-provider-legacy. That provider ships
# legacy.so, a file libssl3 still owns when dpkg unpacks it, and only
# libssl3t64 declares the replacement, so dpkg refuses. The provider goes
# first, allowed to take the file over, and libssl3 leaves with the rest.
ARG DEBIAN_SID_SNAPSHOT=20261013T203804Z
RUN set -eu; \
    echo "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${DEBIAN_SID_SNAPSHOT} sid main" > /etc/apt/sources.list.d/sid.list; \
    printf 'Package: *\nPin: release a=unstable\nPin-Priority: 100\n' > /etc/apt/preferences.d/sid; \
    apt-get update; \
    apt-get install -y --no-install-recommends -t sid -o Dpkg::Options::=--force-overwrite openssl-provider-legacy; \
    apt-get install -y --no-install-recommends -t sid \
      python3-dev python3-setuptools python3-pytest python3-wheel python3-venv python3-pip-whl \
      python3-grpcio python3-protobuf protobuf-compiler libprotobuf-dev python3-cryptography; \
    rm -rf /var/lib/apt/lists/*; \
    python3 -c 'import sys, grpc, google.protobuf, cryptography; print(sys.version)'

COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm

# Rust for the zygote library's core (sdk/c/template/core): the exact
# stable its rust-toolchain.toml pins, with clippy and rustfmt, and both
# Linux targets so `cargo check --target` covers the other arch here. The
# fuzz targets under core/fuzz need a nightly for the sanitizers and
# cargo-fuzz, so the one their rust-toolchain.toml pins is installed too,
# for `make fuzz` only. The product build stays on stable.
ARG CARGO_FUZZ_VERSION=0.13.2
RUN set -eu; \
    rustup toolchain install 1.99.0 --profile minimal -c clippy -c rustfmt; \
    rustup target add --toolchain 1.99.0 x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu; \
    rustup toolchain install nightly-2026-10-08 --profile minimal; \
    cargo +1.99.0 install --locked cargo-fuzz --version "${CARGO_FUZZ_VERSION}"; \
    rm -rf /usr/local/cargo/registry/cache /usr/local/cargo/git

# GOTOOLCHAIN=auto lets the go.mod toolchain line fetch the exact version.
ENV GOTOOLCHAIN=auto \
    GOFLAGS=-buildvcs=false \
    CGO_ENABLED=1 \
    FIBERD_CGROUP_ROOT=/sys/fs/cgroup/fiberd

WORKDIR /src
COPY --chmod=0755 hack/dev/entrypoint.sh /usr/local/bin/fiberd-dev-entrypoint
ENTRYPOINT ["/usr/local/bin/fiberd-dev-entrypoint"]
CMD ["bash"]
