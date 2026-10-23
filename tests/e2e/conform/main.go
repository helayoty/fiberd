//go:build integration

// Command grant-conform is the conformance suite for the grant protocol,
// packaged as a `go test` binary so its cases are ordinary subtests with
// -run, -v and -json available.
//
// Build:  go test -c -tags integration -o bin/grant-conform ./tests/e2e/conform
// Run:    bin/grant-conform -target host:port -node-id <audience> [hooks]
//
// Hooks are shell commands run with `sh -c`; positional arguments arrive
// as $1, $2:
//
//	-restart-cmd   restart the target in place; return when serving
//	-cp-health-cmd $1 is "up" or "down": make the issuer reachable or unreachable
//	-audit-cmd     $1 event, $2 fence "grant/epoch/seq": exit 0 if recorded
//	-audit-file    alternative to -audit-cmd: grep this JSONL spool locally
//	-engine-kill-cmd $1 grant uid: end the grant's warm template (engine) as a crash would
//	-scope-cmd     the home's scope is lost while it runs; it must revoke every fence
//	-seal-check-cmd exit non-zero if the shared registry holds template memory in the clear (C11)
//
// -peer-target and -peer-node-id name a second home that shares the
// target's delta registry and keys. C11 moves a session to it and back.
// -gpu runs C14, which moves a session's device slice to the peer and
// has a third home, -layout-target and -layout-node-id, whose engine
// declares another layout refuse it. -gpu-events records each step.
// -gpu-volatile, for a backend whose restore restarts the guest, checks
// the engine's sum under the new fence in place of gpucheck.
//
// Cases whose hook is missing are skipped, and say so.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "grant-conform is a test binary: build it with `go test -c -tags integration -o bin/grant-conform ./tests/e2e/conform` and run that.")
	os.Exit(2)
}
