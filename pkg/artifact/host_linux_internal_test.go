//go:build linux

package artifact

import (
	"os"
	"strings"
	"testing"
)

// TestUnameRelease checks the kernel release against what the kernel
// publishes under /proc, so the parity fact is the running kernel's.
func TestUnameRelease(t *testing.T) {
	cases := []struct {
		name string
		from string
	}{
		{name: "the release is the kernel's own", from: "/proc/sys/kernel/osrelease"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want, err := os.ReadFile(tc.from)
			if err != nil {
				t.Fatal(err)
			}
			if got := unameRelease(); got == "" || got != strings.TrimSpace(string(want)) {
				t.Fatalf("unameRelease = %q, want %q", got, want)
			}
		})
	}
}
