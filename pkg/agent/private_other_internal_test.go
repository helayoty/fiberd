//go:build !linux

package agent

import "testing"

// readOnlyDir needs a Linux bind mount.
func readOnlyDir(t *testing.T, _ string) {
	t.Helper()
	t.Skip("read-only bind mounts are Linux only")
}
