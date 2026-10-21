//go:build linux

package fiberd

import (
	"path/filepath"
	"testing"
)

// TestProcOptions checks that the fork backend gets the bind of the host's
// root a resume restores under, inside the private directory, and finds
// criu on PATH.
func TestProcOptions(t *testing.T) {
	cases := []struct {
		name, state string
	}{
		{name: "defaults", state: "/var/lib/fiberd"},
		{name: "another state dir", state: "/s"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{Node: Node{StateDir: tc.state}}
			o := c.procOptions()
			if want := filepath.Join(tc.state, "private", "root"); o.CRIU != "" || o.RootBind != want {
				t.Fatalf("procOptions = CRIU %q RootBind %q, want no binary and %q", o.CRIU, o.RootBind, want)
			}
		})
	}
}

// TestGvisorOptions checks that the gVisor backend keeps its state under
// the home's state directory and gets -gvisor-templates-on-disk.
func TestGvisorOptions(t *testing.T) {
	cases := []struct {
		name   string
		onDisk bool
	}{
		{name: "templates on a tmpfs, the default"},
		{name: "templates on disk", onDisk: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{Node: Node{StateDir: "/s"}}
			c.Runtime.Gvisor.Rootfs, c.Runtime.Gvisor.TemplatesOnDisk = "/r", tc.onDisk
			o := c.gvisorOptions()
			if o.Rootfs != "/r" || o.StateDir != "/s/gvisor" || o.TemplatesOnDisk != tc.onDisk {
				t.Fatalf("gvisorOptions = %+v, want rootfs /r, state /s/gvisor, on disk %v", o, tc.onDisk)
			}
		})
	}
}
