# fiberd build entry points. Tools (buf, protoc plugins) are pinned in
# hack/tools/go.mod and run through `go tool`, so no global installs are
# needed beyond Go itself (and Docker for the Linux-only targets).

GO      ?= go
TOOLS   := $(GO) tool -modfile=$(CURDIR)/hack/tools/go.mod
BIN     ?= bin
PKGS    := ./...
# Integrations are their own modules; test and lint run in each. The
# activation comparison benchmark (bench/compare) is one more.
EXAMPLES := examples/kubernetes examples/slurm examples/knative examples/kata examples/substrate bench/compare

# Hardening for every build of the zygote, refzygote and the storm's
# baseline workload (storm-grower). The flags are
# defined here once. The Dockerfiles, hack/gvisor/rootfs.sh and the Go
# tests that build refzygote mirror these lines, each saying so. The
# library itself is Rust, and its archive takes rustc's hardening
# (docs/design/zygote.md, Build flags), so these flags cover the
# template's own C and the link. On aarch64 (arm64) every
# build also takes -mbranch-protection=none. A restored process keeps
# stale pointer-authentication keys, so a PAC instruction run after a
# restore traps on a FEAT_FPAC CPU. Some toolchains default to
# -mbranch-protection=standard, so the flag is always spelled out.
ZYGOTE_CFLAGS  := -D_FORTIFY_SOURCE=3 -O2 -fstack-protector-strong -fstack-clash-protection -fPIE -Wformat=2 -Werror=format-security
ZYGOTE_LDFLAGS := -pie -Wl,-z,relro,-z,now
ifneq ($(filter aarch64 arm64,$(shell uname -m)),)
ZYGOTE_CFLAGS += -mbranch-protection=none
endif
# The zygote library, a static archive cargo builds from its Rust crate,
# which every template links. cargo runs in the crate, so rustup takes
# the toolchain its rust-toolchain.toml pins.
CARGO    ?= cargo
CORE_DIR := sdk/c/template/core
CORE_LIB := $(CORE_DIR)/target/release/libfiberzygote_core.a
# Seconds per fuzz harness (make fuzz).
FUZZTIME ?= 120
# Extra flags for the unit tests (CI passes -cover to print coverage).
TESTFLAGS ?=
# The integration suites. Every file under tests/ builds only with the
# integration tag, so `make test` compiles none of them. The TypeScript
# suite needs the client built from sdk/typescript/node_modules, which CI
# installs. A checkout without them runs every other suite and says so.
ifneq ($(wildcard sdk/typescript/node_modules),)
INTEGRATION_PKGS := ./tests/integration/...
TS_DIST := typescript-build
else
INTEGRATION_PKGS := $(shell GOOS=linux $(GO) list -tags integration ./tests/integration/... | grep -v /typescript)
TS_DIST := typescript-skipped
endif
# Where the conformance targets that run in the dev container keep their
# state and logs. On macOS it is the named volume fiberd-conform, mounted
# at /conform by hack/dev/run.sh, because bin/ in the shared folder is slow
# enough to time tests out. The volume outlives the container, so
# `make conform-logs` reads it. Linux and CI keep bin/, where CI uploads
# the logs from.
ifeq ($(shell uname -s),Darwin)
CONFORM_DIR ?= /conform
else
CONFORM_DIR ?= $(BIN)
endif

.PHONY: all build test integration-tests vet lint proto proto-lint proto-check clean \
        bench zygote zygote-core zygote-test zygote-c-test zygote-check storm-grower storm-grower-test fuzz fuzz-core conform-stub conform-signed conform-logs conform-proc conform-proc-python conform-gvisor conform-gvisor-python conform-runc conform-runc-python conform-hyperlight-fake conform-hyperlight \
        python-build python-test python-dist python-proto python-proto-check \
        typescript-build typescript-skipped typescript-test typescript-proto typescript-proto-check \
        hyperlight-helper linux-hyperlight-check linux-hyperlight-test overcommit overcommit-baseline kind-up kind-down kind-image conform-kind slurm-up slurm-down conform-slurm example-knative example-knative-kvm example-kata example-kata-gpu example-substrate \
        registry-start mobility linux-shell linux-check linux-gvisor-check linux-test linux-lint bench-e2e \
        compare-phase0 compare-phase1 compare-phase2 compare-phase3 compare-phase4 compare-down

all: build

## TypeScript client (run npm ci --ignore-scripts --prefix sdk/typescript first)

typescript-build: ## compile the Node.js client and its type declarations
	npm --prefix sdk/typescript run build

typescript-skipped:
	@echo "sdk/typescript/node_modules is missing, so tests/integration/typescript is left out. npm ci --ignore-scripts --prefix sdk/typescript includes it."

typescript-test: ## compile and test the Node.js client against in-process servers
	npm --prefix sdk/typescript test

typescript-proto: ## generate the TypeScript client's messages and gRPC stubs
	$(TOOLS) buf generate --template sdk/typescript/buf.gen.yaml

typescript-proto-check: ## compare the TypeScript bindings with a freshly generated scratch copy
	@tmp=$$(mktemp -d) || exit 1; trap 'rm -rf "$$tmp"' EXIT; \
	  $(TOOLS) buf generate --template sdk/typescript/buf.gen.yaml --output "$$tmp" && \
	  diff -ru sdk/typescript/src/generated "$$tmp/sdk/typescript/src/generated"

## Go

build: ## build every binary under cmd/ into $(BIN)/
	@mkdir -p $(BIN)
	$(GO) build -o $(BIN)/ ./cmd/...

conform-stub: ## run C1-C10 against a stub-runtime fiberd (all hooks wired)
	hack/conform/stub.sh run

conform-signed: ## same, over real signed grants: grant-issuer serve + -verifier=jwks
	CONFORM_SIGNED=1 CONFORM_STATE=$(BIN)/conform-state-signed hack/conform/stub.sh run

conform-proc: ## C1-C10 against the fork runtime with real cgroups, warmed from an artifact with sealed images, C11 moving a session to a peer home and back, and C14 moving a device slice, inside the Linux dev container
	hack/dev/run.sh env CONFORM_RUNTIME=proc CONFORM_SIGNED=1 CONFORM_GPU=1 CONFORM_STATE=$(CONFORM_DIR)/conform-state-proc hack/conform/stub.sh run

conform-proc-python: ## C1-C10 against the fork runtime with the Python reference template (sdk/python), inside the Linux dev container
	hack/dev/run.sh sh -ec 'hack/python/build.sh; env CONFORM_RUNTIME=proc CONFORM_SIGNED=1 CONFORM_W_BUDGET=8388608 \
	  CONFORM_TEMPLATE="$$PWD/hack/python/template.sh --heap-mb 32" CONFORM_STATE=$(CONFORM_DIR)/conform-state-proc-python hack/conform/stub.sh run'

conform-gvisor: ## C1-C10 against the gvisor backend (a runsc sandbox per fiber), with a pool of 2 per grant, and C11 and C14 over a peer home, inside the Linux dev container
	hack/dev/run.sh env CONFORM_RUNTIME=gvisor CONFORM_SIGNED=1 CONFORM_WARM=2 CONFORM_GPU=1 CONFORM_STATE=$(CONFORM_DIR)/conform-state-gvisor hack/conform/stub.sh run

conform-gvisor-python: ## C1-C10 against the gvisor backend with the Python reference template in a rootfs with CPython (hack/python/rootfs.sh), pooled, inside the Linux dev container
	hack/dev/run.sh env CONFORM_RUNTIME=gvisor CONFORM_SIGNED=1 CONFORM_WARM=2 CONFORM_W_BUDGET=8388608 CONFORM_ROOTFS_SH=hack/python/rootfs.sh \
	  CONFORM_GVISOR_ROOTFS=/var/lib/fiberd/gvisor-rootfs-python CONFORM_TEMPLATE="/usr/bin/python3 -m fiberd.template.ref --heap-mb 32" \
	  CONFORM_STATE=$(CONFORM_DIR)/conform-state-gvisor-python hack/conform/stub.sh run

conform-runc: ## C1-C10 against the runc backend (the zygote as an OCI container's init), and C11 and C14 over a peer home, inside the Linux dev container
	hack/dev/run.sh env CONFORM_RUNTIME=runc CONFORM_SIGNED=1 CONFORM_GPU=1 CONFORM_STATE=$(CONFORM_DIR)/conform-state-runc hack/conform/stub.sh run

conform-runc-python: ## C1-C10 against the runc backend with the Python reference template in the same rootfs, inside the Linux dev container
	hack/dev/run.sh env CONFORM_RUNTIME=runc CONFORM_SIGNED=1 CONFORM_W_BUDGET=8388608 CONFORM_ROOTFS_SH=hack/python/rootfs.sh \
	  CONFORM_GVISOR_ROOTFS=/var/lib/fiberd/gvisor-rootfs-python CONFORM_TEMPLATE="/usr/bin/python3 -m fiberd.template.ref --heap-mb 32" \
	  CONFORM_STATE=$(CONFORM_DIR)/conform-state-runc-python hack/conform/stub.sh run

conform-hyperlight-fake: ## C1-C10 against the hyperlight backend over the fake helper (no hypervisor), and C11 and C14 over a peer home, inside the Linux dev container
	hack/dev/run.sh env CONFORM_RUNTIME=hyperlight CONFORM_SIGNED=1 CONFORM_GPU=1 CONFORM_STATE=$(CONFORM_DIR)/conform-state-hyperlight hack/conform/stub.sh run

conform-logs: ## list the logs the dev-container conformance targets left in $(CONFORM_DIR)
	hack/dev/run.sh find $(CONFORM_DIR) -path '*conform-state-*' -name '*.log'

hyperlight-helper: ## build the Hyperlight guest and helper (Rust) into bin/, inside the dev container
	hack/dev/run.sh hack/hyperlight/build.sh

linux-hyperlight-check: ## probe /dev/kvm and run the helper's self-test (needs a hypervisor on the host)
	FIBERD_DEV_DOCKER_ARGS="--device /dev/kvm" hack/dev/run.sh hack/hyperlight/check.sh

linux-hyperlight-test: ## the hyperlight integration rows that need the real helper (needs /dev/kvm on the host; make hyperlight-helper first)
	FIBERD_DEV_DOCKER_ARGS="--device /dev/kvm" hack/dev/run.sh env FIBERD_HL_HELPER=/src/bin/hyperlight-helper FIBERD_HL_GUEST=/src/bin/hyperlight-guest \
	  go test -tags integration -count=1 -v -run 'TestRandomPerIncarnation|TestSeedNeverLogged' ./tests/integration/hyperlight/

conform-hyperlight: ## C1-C10 against the hyperlight backend with the real helper (needs /dev/kvm on the host)
	FIBERD_DEV_DOCKER_ARGS="--device /dev/kvm" hack/dev/run.sh env CONFORM_RUNTIME=hyperlight CONFORM_SIGNED=1 \
	  CONFORM_HL_HELPER=/src/bin/hyperlight-helper CONFORM_HL_GUEST=/src/bin/hyperlight-guest \
	  CONFORM_STATE=$(CONFORM_DIR)/conform-state-hyperlight-kvm hack/conform/stub.sh run

## The cloudhv backend (pkg/backend/cloudhv): a Cloud Hypervisor micro-VM
## per fiber. The fake VMM runs it without KVM. The W budget is 8 MiB
## there, since the fake's leaf holds two Go runtimes besides the fiber.
.PHONY: cloudhv-images conform-cloudhv-fake conform-cloudhv

cloudhv-images: ## the pinned cloud-hypervisor, the guest kernel and the rootfs into bin/cloudhv, inside the dev container
	hack/dev/run.sh hack/cloudhv/build.sh

conform-cloudhv-fake: ## C1-C10 against the cloudhv backend over the fake VMM (no KVM), and C11 and C14 over a peer home, inside the Linux dev container
	hack/dev/run.sh env CONFORM_RUNTIME=cloudhv CONFORM_SIGNED=1 CONFORM_GPU=1 CONFORM_W_BUDGET=8388608 \
	  CONFORM_STATE=$(CONFORM_DIR)/conform-state-cloudhv hack/conform/stub.sh run

conform-cloudhv: ## C1-C10 against the cloudhv backend with the real VMM, and C11 and C14 over a peer home (needs /dev/kvm on the host; make cloudhv-images first)
	FIBERD_DEV_DOCKER_ARGS="--device /dev/kvm" hack/dev/run.sh env CONFORM_RUNTIME=cloudhv CONFORM_SIGNED=1 CONFORM_GPU=1 \
	  CONFORM_CH_DIR=/src/bin/cloudhv CONFORM_STATE=$(CONFORM_DIR)/conform-state-cloudhv-kvm hack/conform/stub.sh run

## The Kubernetes example (examples/kubernetes, its own module): the issuer
## as a controller, a grant Pod with fiberd as PID 1, conformance from
## the host, the storm inside. What fiberd needs for it is pkg/fiberd and
## pkg/home; everything Kubernetes lives in the example.

kind-up: ## create the kind cluster (examples/kubernetes/kind/kind.yaml)
	examples/kubernetes/kind/conform.sh up

kind-down: ## delete the kind cluster
	examples/kubernetes/kind/conform.sh down

kind-image: ## build fiberd:kind (fiberd-k8s, grant-controller, zygote, criu, runsc and a gVisor rootfs) and load it into the cluster
	examples/kubernetes/kind/conform.sh image

conform-kind: ## C1-C10, the overcommit storm and an UNTRUSTED gVisor session check against grant Pods in kind (needs docker, kind, kubectl, go)
	examples/kubernetes/kind/conform.sh run

## The Slurm example (examples/slurm, its own module): a one-node Slurm in
## Docker, fiberd as a job in its allocation's cgroup, conformance from
## the host, the storm inside.

slurm-up: ## build fiberd:slurm and start the one-node cluster container
	examples/slurm/conform.sh up

slurm-down: ## remove the Slurm container
	examples/slurm/conform.sh down

conform-slurm: ## C1-C10, the overcommit storm, and its baseline without fiberd in allocations of the same size, in Slurm-in-Docker (needs docker, go)
	examples/slurm/conform.sh run

## The Knative example (examples/knative, its own module): scale-from-zero
## with fibers on a Hyperlight home; a consumer of the protocol.

example-knative: ## the activator over a Hyperlight home with the fake helper (no hypervisor), inside the dev container
	hack/dev/run.sh examples/knative/run.sh

## The Kata-shaped example (examples/kata, its own module): a containerd
## shim whose containers are fibers, as a RuntimeClass in the kind cluster
## of the Kubernetes example.

example-kata: ## install the shim into the kind node and run Pods whose containers are fibers (needs docker, kind, kubectl, go)
	examples/kata/kind/run.sh run

example-kata-gpu: ## the GPU PoC's Kata row on VM A: Pods whose fibers use a host home's GPU engine, park and resume their slice (KATA_GPU_SIM=1 without a GPU)
	examples/kata/kind/run.sh gpu

## The Agent Substrate example (examples/substrate, its own module): a
## Substrate sandbox class whose actors are fibers, run under Substrate's
## own install in a kind cluster of its own.

example-substrate: ## Substrate in kind, a WorkerPool of fiberd workers, an actor suspended and resumed through Substrate (needs docker, kubectl, go, jq)
	examples/substrate/kind/run.sh run

example-knative-kvm: ## the same over the real Hyperlight helper (needs /dev/kvm on the host; make hyperlight-helper first)
	FIBERD_DEV_DOCKER_ARGS="--device /dev/kvm" hack/dev/run.sh env \
	  CONFORM_HL_HELPER=/src/bin/hyperlight-helper CONFORM_HL_GUEST=/src/bin/hyperlight-guest examples/knative/run.sh

# The storm's three phases share one 384 MiB container. The fiberd side
# passes or fails the run. The two baselines without fiberd (hack/storm
# -plain) only measure, and their OOM kills are expected.
overcommit: ## 2x overcommit storm under a 384 MiB container cap: park must fire before any OOM kill. Then the same storm without fiberd (shared and separate), measured only
	hack/dev/run.sh sh -c 'go build -o bin/ ./cmd/grant-issuer ./hack/storm && go build -tags fiberd_testhooks -o bin/fiberd-testhooks ./cmd/fiberd && make -s zygote storm-grower'
	FIBERD_DEV_DOCKER_ARGS="--memory=384m --memory-swap=384m" hack/dev/run.sh env STORM_PREBUILT=1 hack/test/overcommit.sh

overcommit-baseline: ## only the storm's baselines without fiberd, plain processes under the same 384 MiB cap (shared and separate), measured only
	hack/dev/run.sh sh -c 'go build -o bin/ ./hack/storm && make -s storm-grower'
	FIBERD_DEV_DOCKER_ARGS="--memory=384m --memory-swap=384m" hack/dev/run.sh env STORM_PREBUILT=1 STORM_PHASES="shared separate" hack/test/overcommit.sh

## OCI artifacts (zygote templates, parked deltas) through a local registry

registry-start: ## registry:2 at 127.0.0.1:5000 (fiberd-registry:5000 inside the dev container)
	hack/registry/run.sh start

mobility: ## a session moves home-a -> home-b -> home-a through the registry (needs registry-start)
	hack/dev/run.sh hack/test/mobility.sh

test: ## unit tests (host OS, non-root; nothing under tests/ is compiled), fiberd and the examples
	$(GO) test -race -count=1 $(TESTFLAGS) $(PKGS)
	@for m in $(EXAMPLES); do echo "--- $$m"; (cd $$m && $(GO) test -race -count=1 $(TESTFLAGS) ./...) || exit 1; done

integration-tests: $(TS_DIST) ## the integration suites (tests/integration and the examples' tests/) as root in the dev container, built with -tags integration
	hack/dev/run.sh sh -ec 'go test -tags integration -count=1 $(INTEGRATION_PKGS); \
	  for m in $(EXAMPLES); do [ -d $$m/tests ] || continue; echo "--- $$m"; (cd $$m && go test -tags integration -count=1 ./tests/...); done'

vet:
	$(GO) vet $(PKGS)
	@for m in $(EXAMPLES); do (cd $$m && $(GO) vet ./...) || exit 1; done

lint: vet ## golangci-lint (pinned in hack/tools), including depguard for pkg/core; fiberd and the examples
	$(TOOLS) golangci-lint run $(PKGS)
	@for m in $(EXAMPLES); do echo "--- $$m"; (cd $$m && $(TOOLS) golangci-lint run ./...) || exit 1; done

clean:
	rm -rf $(BIN)

## Protocol

proto: ## regenerate api/**/*.pb.go from api/**/*.proto
	$(TOOLS) buf generate

proto-lint:
	$(TOOLS) buf lint

proto-check: proto proto-lint ## fail if generated code is out of date (CI)
	@git diff --exit-code -- api/ || \
	  (echo "generated proto code is stale: run 'make proto' and commit" && exit 1)

# The Python messages (sdk/python/src/fiberd/client/_api) come from the
# same proto through protoc 3.21, the protobuf-compiler package of
# Debian 12 and Ubuntu 24.04, which the dev image and the CI runner
# share, since every generator version prints differently and CI
# compares the files.
PROTOC          ?= protoc
PYTHON_API_DIR  := sdk/python/src/fiberd/client/_api
PYTHON_PROTOC   := $(PROTOC) -I api/grant/v1 grant.proto

python-proto: ## regenerate the Python messages from api/grant/v1/grant.proto, inside the dev container
	hack/dev/run.sh $(PYTHON_PROTOC) --python_out=$(PYTHON_API_DIR) --pyi_out=$(PYTHON_API_DIR)

python-proto-check: ## fail if the Python messages are out of date (CI, with protobuf-compiler installed), generated to a scratch directory and compared
	@tmp=$$(mktemp -d) && $(PYTHON_PROTOC) --python_out=$$tmp --pyi_out=$$tmp && \
	  diff -u $(PYTHON_API_DIR)/grant_pb2.py $$tmp/grant_pb2.py && diff -u $(PYTHON_API_DIR)/grant_pb2.pyi $$tmp/grant_pb2.pyi; \
	  code=$$?; rm -rf $$tmp; \
	  [ $$code -eq 0 ] || (echo "the Python messages are stale: run 'make python-proto' and commit" && exit 1)

## The zygote library and the reference workload.
## Linux only (clone3, close_range); build them inside the dev container.

zygote: zygote-core ## build bin/refzygote, the reference zygote, with TLS for handoff grants
	@mkdir -p $(BIN)
	$(CC) $(ZYGOTE_CFLAGS) $(ZYGOTE_LDFLAGS) -Wall -Wextra -pthread -DFZ_TLS -o $(BIN)/refzygote sdk/c/template/refzygote.c $(CORE_LIB) -lssl -lcrypto

zygote-core: ## build the zygote library, $(CORE_LIB), from its Rust crate
	cd $(CORE_DIR) && $(CARGO) build --release --locked

ENGINE_DIR := sdk/c/template/engine
.PHONY: engine
engine: ## build bin/refengine, the reference device engine fiberd starts beside a grant's zygote, from its Rust crate
	@mkdir -p $(BIN)
	cd $(ENGINE_DIR) && $(CARGO) build --release --locked
	cp $(ENGINE_DIR)/target/release/refengine $(BIN)/refengine

zygote-test: ## the core's Rust unit tests, clippy and rustfmt (the fuzz targets too, with the core's stable rustfmt, since the fuzz crate's nightly has none)
	cd $(CORE_DIR) && $(CARGO) test --locked && $(CARGO) clippy --locked --all-targets -- -D warnings && \
	  $(CARGO) fmt --check && rustfmt --edition 2024 --check fuzz/fuzz_targets/*.rs

zygote-c-test: zygote-core ## the reference zygote's own C unit test (the tcp endpoint's bind, sdk/c/template/test), built as make zygote is but without TLS, then run
	@mkdir -p $(BIN)
	$(CC) $(ZYGOTE_CFLAGS) $(ZYGOTE_LDFLAGS) -Wall -Wextra -pthread -o $(BIN)/refzygote-test sdk/c/template/test/engine_test.c $(CORE_LIB)
	$(BIN)/refzygote-test

## The storm's baseline workload (hack/storm/grower), plain processes
## that grow as the storm's fibers do. Linux only.

storm-grower: ## build bin/storm-grower with the zygote's hardening flags
	@mkdir -p $(BIN)
	$(CC) $(ZYGOTE_CFLAGS) $(ZYGOTE_LDFLAGS) -Wall -Wextra -o $(BIN)/storm-grower hack/storm/grower/grower.c

storm-grower-test: ## storm-grower's own C unit test (hack/storm/grower/grower_test.c), built as make storm-grower is, then run
	@mkdir -p $(BIN)
	$(CC) $(ZYGOTE_CFLAGS) $(ZYGOTE_LDFLAGS) -Wall -Wextra -o $(BIN)/storm-grower-test hack/storm/grower/grower_test.c
	$(BIN)/storm-grower-test

## The fake CUDA driver the engine's CUDA path runs on in CI. Linux only.
## A shared library takes -fPIC and -shared where the zygote takes -pie.

fakecuda: ## build bin/fakecuda/libcuda.so.1 (sdk/c/template/fakecuda) with the zygote's hardening flags
	@mkdir -p $(BIN)/fakecuda
	$(CC) $(ZYGOTE_CFLAGS) -fPIC -fvisibility=hidden $(filter-out -pie,$(ZYGOTE_LDFLAGS)) -shared -Wl,-soname,libcuda.so.1 -Wall -Wextra -pthread -o $(BIN)/fakecuda/libcuda.so.1 sdk/c/template/fakecuda/fakecuda.c

zygote-check: zygote-core ## check the core archive's undefined symbols against the allowlist and count its PAC instructions
	$(CORE_DIR)/check.sh $(CORE_LIB)

fuzz: ## fuzz the zygote library (the core's cargo-fuzz targets), the reference workload's parsers (a C libFuzzer harness), the handoff parser and the workspace path and archive readers (go test -fuzz), FUZZTIME seconds each, in the dev container on macOS
ifeq ($(shell uname -s),Darwin)
	hack/dev/run.sh make fuzz FUZZTIME=$(FUZZTIME)
else
	FUZZTIME=$(FUZZTIME) FUZZ_OUT=$(BIN)/fuzz sdk/c/template/fuzz/run.sh
	$(MAKE) fuzz-core
	$(GO) test -run='^$$' -fuzz=FuzzServerName -fuzztime=$(FUZZTIME)s ./pkg/handoff/
	$(GO) test -run='^$$' -fuzz=FuzzClean -fuzztime=$(FUZZTIME)s ./pkg/runtime/host/wsfs/
	$(GO) test -run='^$$' -fuzz=FuzzArchive -fuzztime=$(FUZZTIME)s ./pkg/runtime/host/wsfs/
endif

# Every cargo-fuzz target of the core, on the nightly its fuzz crate pins,
# so cargo runs in core/fuzz. The targets build the core with its fuzzshim
# feature, so control and procfiles shim its mounts and clones. Inputs
# reach 70000 bytes, past the 64 KiB line and record buffers. New inputs
# land in $(BIN)/fuzz/corpus, never in the seeds (corpus/<target>, some of
# them links to sdk/c/template/fuzz/corpus), and a crash leaves its input
# under $(BIN)/fuzz/crashes/ as the C harness does.
fuzz-core:
	@out=$(CURDIR)/$(BIN)/fuzz; mkdir -p "$$out/crashes"; failed=""; \
	targets=$$(cd $(CORE_DIR)/fuzz && $(CARGO) fuzz list) || exit 1; \
	for t in $$targets; do \
	  echo "--- core $$t for $(FUZZTIME)s"; mkdir -p "$$out/corpus/core-$$t"; \
	  seeds=""; [ ! -d $(CORE_DIR)/fuzz/corpus/$$t ] || seeds=corpus/$$t; \
	  (cd $(CORE_DIR)/fuzz && $(CARGO) fuzz run "$$t" "$$out/corpus/core-$$t" $$seeds -- \
	    -max_total_time=$(FUZZTIME) -timeout=10 -rss_limit_mb=2048 -max_len=70000 -artifact_prefix="$$out/crashes/core-$$t-") \
	    > "$$out/core-$$t.log" 2>&1 || failed="$$failed $$t"; \
	  grep -E '^(#[0-9]+\s+(DONE|INITED)|==|SUMMARY|Test unit written)' "$$out/core-$$t.log" || true; \
	done; \
	[ -z "$$failed" ] || { echo "fuzz-core: crashes in$$failed; inputs under $$out/crashes/, logs under $$out/core-*.log" >&2; exit 1; }

## The Python SDK (sdk/python). Its extension needs Linux, so it is built
## and its unit tests run inside the dev container.

python-build: ## build the fiberd._zygote extension in place (sdk/python/src/fiberd), inside the dev container
	hack/dev/run.sh hack/python/build.sh

python-test: ## the Python unit tests (pytest, no process started), after the build, inside the dev container
	hack/dev/run.sh sh -ec 'hack/python/build.sh; cd sdk/python && PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider'

python-dist: ## build the sdist and, offline, a wheel from it, then run the unit tests against the installed wheel, in the dev container, keeping nothing
	hack/dev/run.sh hack/python/dist.sh

## Linux-only work runs in the dev container (hack/dev): privileged,
## private cgroup namespace, criu installed. Needs Docker.

linux-shell: ## interactive shell in the Linux dev container
	hack/dev/run.sh bash

linux-check: ## probe the container for cgroup v2, PSI, criu, gcc
	hack/dev/run.sh hack/dev/check.sh

linux-gvisor-check: ## probe runsc in the container: run, checkpoint/restore, host unix sockets, self-checkpoint
	hack/dev/run.sh hack/dev/gvisor-check.sh

linux-test: $(TS_DIST) ## unit tests as uid 1001 (the GitHub runner's uid, not nobody, so a chown to 65534 cannot pass by luck), then the integration suites as root, inside the container
	hack/dev/run.sh sh -ec 'go mod download; for m in $(EXAMPLES); do (cd $$m && go mod download); done; \
	  mkdir -p /tmp/nr && chmod 777 /tmp/nr; \
	  env -u FIBERD_CGROUP_ROOT setpriv --reuid=1001 --regid=1001 --clear-groups --inh-caps=-all \
	    env HOME=/tmp/nr GOCACHE=/tmp/nr/cache GOMODCACHE=/go/pkg/mod PATH=$$PATH make test'
	$(MAKE) integration-tests

linux-lint: ## golangci-lint inside the container, so the Linux-only files are analysed too (what CI runs)
	hack/dev/run.sh make lint

bench: ## the clone storm on the proc, runc and gvisor backends (tests/bench/storm), in the container
	hack/dev/run.sh env FIBERD_BENCH=1 go test -tags integration -count=1 -v -run TestStormNumbers ./tests/bench/storm/

bench-e2e: ## time Clone over gRPC end to end, per stage (tests/bench/clone), in the container
	FIBERD_DEV_DOCKER_ARGS="-v fiberd-bench:/bench" hack/dev/run.sh env FIBERD_BENCH=1 FIBERD_BENCH_STATE=/bench \
	  go test -tags integration -count=1 -v -run TestE2ECloneNumbers ./tests/bench/clone/

## The activation comparison (bench/compare, its own module): fiberd
## against Pods, agent-sandbox, Firecracker and Hyperlight, one phase per
## target as docs/design/compare.md lays them out. Results land in
## bin/compare-state/. Every phase refuses to run on a loaded host.

compare-phase0: ## host facts and load; exits 3 when load exceeds the core count
	bench/compare/run/phase0.sh

compare-phase1: ## kind cluster "compare": Pod warm and cold, fiberd proc and runc, agent-sandbox under runc, control-plane deltas
	bench/compare/run/phase1.sh

compare-phase2: ## dev container: fiberd proc, runc and gVisor standalone over loopback, with resume and density
	bench/compare/run/phase2.sh

compare-phase3: ## kind cluster "compare": Pod gVisor, agent-sandbox gVisor, fiberd gVisor through the relay
	bench/compare/run/phase3.sh

compare-phase4: ## a KVM host: phases 1 to 3 plus Firecracker and fiberd Hyperlight (COMPARE_GROUPS picks classes)
	bench/compare/run/phase4.sh

compare-down: ## delete the "compare" kind cluster and its registry
	bench/compare/kind/cluster.sh down

help:
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'
