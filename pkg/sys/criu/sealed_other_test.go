//go:build !linux

package criu_test

import "testing"

// sealedFile needs a sealed memfd, which only Linux has. The cases that
// use it skip before calling it.
func sealedFile(t *testing.T, _ string, _ []byte) {
	t.Helper()
	t.Skip("needs Linux")
}
