//go:build !linux

package fiberd

import "testing"

// readOnlyDir needs a Linux bind mount.
func readOnlyDir(t *testing.T, _ string) {
	t.Helper()
	t.Skip("read-only bind mounts are Linux only")
}
