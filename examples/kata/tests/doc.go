//go:build linux && integration

// Package katatest holds the Kata-shaped example's integration tests.
// They let Manager.Start exec this test binary as the shim daemon, the
// way containerd's shim would be started, and read back what the daemon
// saw. The suite needs root, because shim sockets live under
// containerd's state directory, so it builds only with the integration
// tag and skips itself when that directory is not writable.
package katatest
