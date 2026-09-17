# fiberd build entry points. Tools (buf, protoc plugins) are pinned in
# hack/tools/go.mod and run through `go tool`, so no global installs are
# needed beyond Go itself (and Docker for the Linux-only targets).

GO      ?= go
TOOLS   := $(GO) tool -modfile=hack/tools/go.mod
BIN     ?= bin
PKGS    := ./...

.PHONY: all build test vet lint proto proto-lint proto-check clean \
        bench zygote conform-bin conform-stub conform-signed conform-proc conform-gvisor conform-runc conform-hyperlight-fake conform-hyperlight \
        hyperlight-helper linux-hyperlight-check overcommit \
        registry-start registry-stop zygote-artifact mobility linux-shell linux-check linux-gvisor-check linux-test linux-lint

all: build

## Go

build: ## build every binary under cmd/ into $(BIN)/
	@mkdir -p $(BIN)
	$(GO) build -o $(BIN)/ ./cmd/...

conform-bin: ## build the conformance test binary
	@mkdir -p $(BIN)
	$(GO) test -c -o $(BIN)/grant-conform ./cmd/grant-conform

conform-stub: ## run C1-C7 against a stub-runtime fiberd (all hooks wired)
	hack/conform/stub.sh run

conform-signed: ## same, over real signed grants: grant-issuer serve + -verifier=jwks
	CONFORM_SIGNED=1 CONFORM_STATE=$(BIN)/conform-state-signed hack/conform/stub.sh run

conform-proc: ## C1-C7 against the fork runtime with real cgroups, inside the Linux dev container
	hack/dev/run.sh env CONFORM_RUNTIME=proc CONFORM_SIGNED=1 CONFORM_STATE=$(BIN)/conform-state-proc hack/conform/stub.sh run

conform-gvisor: ## C1-C7 against the gvisor backend (a runsc sandbox per fiber), inside the Linux dev container
	hack/dev/run.sh env CONFORM_RUNTIME=gvisor CONFORM_SIGNED=1 CONFORM_STATE=$(BIN)/conform-state-gvisor hack/conform/stub.sh run

conform-runc: ## C1-C7 against the runc backend (the zygote as an OCI container's init), inside the Linux dev container
	hack/dev/run.sh env CONFORM_RUNTIME=runc CONFORM_SIGNED=1 CONFORM_STATE=$(BIN)/conform-state-runc hack/conform/stub.sh run

conform-hyperlight-fake: ## C1-C7 against the hyperlight backend over the fake helper (no hypervisor), inside the Linux dev container
	hack/dev/run.sh env CONFORM_RUNTIME=hyperlight CONFORM_SIGNED=1 CONFORM_STATE=$(BIN)/conform-state-hyperlight hack/conform/stub.sh run

hyperlight-helper: ## build the Hyperlight guest and helper (Rust) into bin/, inside the dev container
	hack/dev/run.sh hack/hyperlight/build.sh

linux-hyperlight-check: ## probe /dev/kvm and run the helper's self-test (needs a hypervisor on the host)
	FIBERD_DEV_DOCKER_ARGS="--device /dev/kvm" hack/dev/run.sh hack/hyperlight/check.sh

conform-hyperlight: ## C1-C7 against the hyperlight backend with the real helper (needs /dev/kvm on the host)
	FIBERD_DEV_DOCKER_ARGS="--device /dev/kvm" hack/dev/run.sh env CONFORM_RUNTIME=hyperlight CONFORM_SIGNED=1 \
	  CONFORM_HL_HELPER=/src/bin/hyperlight-helper CONFORM_HL_GUEST=/src/bin/hyperlight-guest \
	  CONFORM_STATE=$(BIN)/conform-state-hyperlight-kvm hack/conform/stub.sh run

overcommit: ## 2x overcommit storm under a 384 MiB container cap: park must fire before any OOM kill
	hack/dev/run.sh sh -c 'go build -o bin/ ./cmd/fiberd ./cmd/grant-issuer ./hack/storm && make -s zygote'
	FIBERD_DEV_DOCKER_ARGS="--memory=384m --memory-swap=384m" hack/dev/run.sh env STORM_PREBUILT=1 hack/test/overcommit.sh

## OCI artifacts (zygote templates, parked deltas) through a local registry

registry-start: ## registry:2 at 127.0.0.1:5000 (fiberd-registry:5000 inside the dev container)
	hack/registry/run.sh start

registry-stop:
	hack/registry/run.sh stop

mobility: ## phase 6 acceptance: a session moves home-a -> home-b -> home-a through the registry (needs registry-start)
	hack/dev/run.sh hack/test/mobility.sh

zygote-artifact: ## build the reference zygote artifact (with CRIU images) in the dev container and push it
	hack/dev/run.sh sh -c 'make -s zygote && go build -o bin/ ./cmd/zygotectl && \
	  bin/zygotectl build -zygote bin/refzygote -args "--heap-mb 32" -out bin/zygote-artifact && \
	  bin/zygotectl push -dir bin/zygote-artifact -ref fiberd-registry:5000/zygotes/ref:latest -plain-http'

test: ## unit tests (host OS; Linux-only packages compile to stubs elsewhere)
	$(GO) test -race -count=1 $(PKGS)

vet:
	$(GO) vet $(PKGS)

lint: vet ## golangci-lint (pinned in hack/tools), including depguard for pkg/core
	$(TOOLS) golangci-lint run $(PKGS)

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

## C: the zygote library + reference workload, and the fork/CoW bench.
## Linux only (clone3, close_range); build them inside the dev container.

zygote: ## build bin/refzygote (the reference zygote; conformance template)
	@mkdir -p $(BIN)
	$(CC) -O2 -Wall -Wextra -o $(BIN)/refzygote hack/zygote/refzygote.c hack/zygote/libfiberzygote.c

bench: ## build the fork/CoW bench
	@mkdir -p $(BIN)
	$(CC) -O2 -o $(BIN)/zb zygote_bench.c

## Linux-only work runs in the dev container (hack/dev): privileged,
## private cgroup namespace, criu installed. Needs Docker.

linux-shell: ## interactive shell in the Linux dev container
	hack/dev/run.sh bash

linux-check: ## probe the container for cgroup v2, PSI, criu, gcc
	hack/dev/run.sh hack/dev/check.sh

linux-gvisor-check: ## probe runsc in the container: run, checkpoint/restore, host unix sockets, self-checkpoint
	hack/dev/run.sh hack/dev/gvisor-check.sh

linux-test: ## unit tests inside the container (Linux-only packages included)
	hack/dev/run.sh $(GO) test -race -count=1 $(PKGS)

linux-lint: ## golangci-lint inside the container, so the Linux-only files are analysed too (what CI runs)
	hack/dev/run.sh make lint

help:
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'
