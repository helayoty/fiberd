//go:build linux && integration

// Package hyperlighttest holds the integration tests of the hyperlight
// backend on the host runtime, driven against hack/hyperlight/fakehelper
// (the helper protocol without a hypervisor). It builds only with the
// integration tag and runs as root in the dev container
// (make integration-tests). The Rust helper is exercised by the KVM-gated
// conformance job.
package hyperlighttest
