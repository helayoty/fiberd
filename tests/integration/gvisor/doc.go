//go:build linux && integration

// Package gvisortest holds the integration tests of the gvisor backend on
// the host runtime: real runsc sandboxes, cgroups and checkpoints. It
// builds only with the integration tag and runs as root in the dev
// container (make integration-tests).
package gvisortest
