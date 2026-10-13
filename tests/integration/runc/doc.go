//go:build linux && integration

// Package runctest holds the integration tests of the runc backend on the
// host runtime: the zygote as an OCI container's init, fibers forked
// inside it, checkpointed and restored across the container boundary.
// It builds only with the integration tag and runs as root in the dev
// container (make integration-tests).
package runctest
