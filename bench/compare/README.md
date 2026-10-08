# Activation comparison

This benchmark times fiberd against Pods, agent-sandbox and Firecracker, from the request that activates an instance to the first byte of its first `200`. Its comparators, workload and fairness rules are in [the design doc](../../docs/design/compare.md).

## Run it

Each phase is one make target. Phase 0 refuses to time anything when the load exceeds the core count.

```bash
make compare-phase0    # host facts and load
make compare-phase1    # kind: the shared-kernel class, with control-plane deltas
make compare-phase2    # dev container: fiberd proc, runc and gVisor over loopback
make compare-phase3    # kind: the sandboxed class
make compare-phase4    # a KVM host: everything, plus Firecracker and fiberd Hyperlight
make compare-down      # delete the compare cluster and its registry
```

Results are JSON lines under `bin/compare-state/<phase>/`, and `go run ./cmd/summarize bin/compare-state/*/*.jsonl` prints the tables. The phases use a kind cluster named `compare` with its own registry at `localhost:5002`, and touch no other cluster. Phase 1 writes the digests of the templates it pushed to `bin/compare-state/templates.env`. Phase 4 needs a host with `/dev/kvm`. `run/kvm-host.sh` sets one up, or use the manual `bench-compare` GitHub workflow.

## Layout

`adapter.go` is the interface every system implements, `run.go` the protocol, `ready.go` the first-byte probe. `adapters/` holds one package per system, `kind/` the cluster and manifests, `run/` the phase scripts, `summary/` the tables.
