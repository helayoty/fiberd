// Package hyperlighttest holds the integration tests of the hyperlight
// backend on the host runtime, driven against hack/hyperlight/fakehelper
// (the helper protocol without a hypervisor). They run inside the Linux
// dev container (make linux-test) and skip elsewhere. The Rust helper is
// exercised by the KVM-gated CI job.
package hyperlighttest
