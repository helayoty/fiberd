//go:build linux

package caps_test

import (
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/helayoty/fiberd/pkg/sys/caps"
)

// selfSets reads this process's bounding, inheritable and ambient sets
// from /proc/self/status. A kernel without ambient capabilities has no
// CapAmb line, which reads as an empty set.
func selfSets(t *testing.T) map[string]uint64 {
	t.Helper()
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]uint64{}
	for _, line := range strings.Split(string(b), "\n") {
		key, val, ok := strings.Cut(line, ":")
		if ok && slices.Contains([]string{"CapBnd", "CapInh", "CapAmb"}, key) {
			v, err := strconv.ParseUint(strings.TrimSpace(val), 16, 64)
			if err != nil {
				t.Fatalf("%s in status: %v", key, err)
			}
			out[key] = v
		}
	}
	for _, n := range []string{"CapBnd", "CapInh"} {
		if _, ok := out[n]; !ok {
			t.Fatalf("no %s line in status", n)
		}
	}
	return out
}

// bits lists, ascending, the capabilities set in mask that keep does
// not name.
func bits(mask uint64, keep []int) []int {
	var out []int
	for c := range 64 {
		if mask&(1<<c) != 0 && !slices.Contains(keep, c) {
			out = append(out, c)
		}
	}
	return out
}

// TestExtra checks what this process holds beyond keep, as read from its
// bounding set and /proc/self/status, against the sets that file reports.
// It reads the kernel's view twice and changes nothing, so it needs no
// privilege.
func TestExtra(t *testing.T) {
	all := make([]int, 64)
	for i := range all {
		all[i] = i
	}
	sets := selfSets(t)
	held := sets["CapBnd"] | sets["CapInh"] | sets["CapAmb"]
	cases := []struct {
		name string
		keep []int
	}{
		{name: "nothing kept", keep: nil},
		{name: "the proc set", keep: caps.Proc},
		{name: "the runc set", keep: caps.Runc},
		{name: "everything kept", keep: all},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := caps.Extra(tc.keep)
			if want := bits(held, tc.keep); !slices.Equal(got, want) {
				t.Fatalf("Extra(%v) = %v, want %v (held %#x)", tc.keep, got, want, held)
			}
			for _, c := range got {
				if slices.Contains(tc.keep, c) {
					t.Fatalf("Extra reports kept capability %d", c)
				}
			}
		})
	}
}
