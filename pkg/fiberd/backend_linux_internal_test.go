//go:build linux

package fiberd

import (
	"path/filepath"
	"testing"
)

// TestProcOptions checks that the fork backend gets the bind of the host's
// root a resume restores under, inside the private directory, and the
// criu binary the config names, none by default.
func TestProcOptions(t *testing.T) {
	cases := []struct {
		name, state, criu string
	}{
		{name: "defaults", state: "/var/lib/fiberd"},
		{name: "another state dir", state: "/s"},
		{name: "a named criu", state: "/s", criu: "/opt/criu"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{Node: Node{StateDir: tc.state}}
			c.Runtime.Helpers.CRIU = tc.criu
			o := c.procOptions()
			if want := filepath.Join(tc.state, "private", "root"); o.CRIU != tc.criu || o.RootBind != want {
				t.Fatalf("procOptions = CRIU %q RootBind %q, want %q and %q", o.CRIU, o.RootBind, tc.criu, want)
			}
		})
	}
}

// TestGvisorOptions checks that the gVisor backend keeps its state under
// the home's state directory and gets -gvisor-templates-on-disk and the
// runsc binary the config names.
func TestGvisorOptions(t *testing.T) {
	cases := []struct {
		name   string
		onDisk bool
		runsc  string
	}{
		{name: "templates on a tmpfs, the default"},
		{name: "templates on disk", onDisk: true},
		{name: "a named runsc", runsc: "/opt/runsc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{Node: Node{StateDir: "/s"}}
			c.Runtime.Gvisor.Rootfs, c.Runtime.Gvisor.TemplatesOnDisk = "/r", tc.onDisk
			c.Runtime.Helpers.Runsc = tc.runsc
			o := c.gvisorOptions()
			if o.Rootfs != "/r" || o.StateDir != "/s/gvisor" || o.TemplatesOnDisk != tc.onDisk || o.Runsc != tc.runsc {
				t.Fatalf("gvisorOptions = %+v, want rootfs /r, state /s/gvisor, on disk %v, runsc %q", o, tc.onDisk, tc.runsc)
			}
		})
	}
}
