//go:build linux && integration

// Package hyperlighttest holds the integration tests of the hyperlight
// backend on the host runtime, driven against hack/hyperlight/fakehelper
// (the helper protocol without a hypervisor). It builds only with the
// integration tag and runs as root in the dev container
// (make integration-tests). The rows that need a guest's own generator
// also run over the Rust helper where /dev/kvm and its build are present
// (make linux-hyperlight-test), as the KVM-gated conformance job does.
package hyperlighttest
