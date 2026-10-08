//go:build linux

package gvisortest

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// TestRootfsReadOnly: the rootfs is one host directory served to every
// sandbox of every grant by the gofer, which runs with the agent's
// credentials. A fiber is uid 0 in its sandbox, so the sandbox's root must
// be read-only or one tenant rewrites /bin/refzygote for every later
// sandbox. The grant's run directory at /host and the private /tmp stay
// writable. Checked on a fresh clone and again after a park and resume,
// which restores the sandbox from the park image under the same spec.
func TestRootfsReadOnly(t *testing.T) {
	rt := newRuntime(t)
	ctx := context.Background()
	g := core.Grant{UID: "ro1", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(work, name)
	// The refusal must be the filesystem's, so a sandbox that reports
	// something else (ok, ENOENT) is a hole.
	refused := map[string]bool{"EROFS": true, "EACCES": true}
	cases := []struct {
		name, line string
		want       func(string) bool
	}{
		{"open an executable for writing", "wopen /bin/refzygote", func(s string) bool { return refused[s] }},
		{"create a directory at the root", "mkdir /planted", func(s string) bool { return refused[s] }},
		{"create a directory under bin", "mkdir /bin/planted", func(s string) bool { return refused[s] }},
		{"the run directory stays writable", "mkdir /host/scratch", func(s string) bool { return s == "ok" }},
		{"tmp stays writable", "mkdir /tmp/scratch", func(s string) bool { return s == "ok" }},
	}
	check := func(t *testing.T, endpoint string) {
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if got := talk(t, endpoint, tc.line); !tc.want(got) {
					t.Fatalf("%s = %q", tc.line, got)
				}
			})
		}
		// A file actually written from inside the sandbox, so the host
		// side is checked too.
		t.Run("a file created at the root does not reach the host", func(t *testing.T) {
			got := probe(t, state, "write", "/planted")
			_, statErr := os.Stat(filepath.Join(rootfs, "planted"))
			if got == "ok" || statErr == nil {
				_ = os.Remove(filepath.Join(rootfs, "planted"))
				t.Fatalf("probe write /planted = %q, host rootfs has it: %v", got, statErr == nil)
			}
		})
	}
	h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "ro1", Epoch: 1, Seq: 1}, Deadline: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Run("fresh clone", func(t *testing.T) { check(t, h.Endpoint) })
	ref, err := rt.Park(ctx, h.ID, true)
	if err != nil {
		t.Fatalf("park: %v", err)
	}
	h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: "ro1", Epoch: 1, Seq: 2}, Deadline: 5 * time.Second})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	t.Cleanup(func() { _ = rt.Release(ctx, h2.ID, false) })
	// The parked sandbox's reaper deletes its runsc state in the
	// background, and probe wants the resumed one listed alone.
	deadline := time.Now().Add(5 * time.Second)
	for fiberSandboxes(t, state) != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	t.Run("after resume", func(t *testing.T) { check(t, h2.Endpoint) })
}

// fiberSandboxes counts the fiber sandboxes runsc lists in a home's root.
func fiberSandboxes(t *testing.T, state string) int {
	t.Helper()
	out, err := exec.Command("runsc", "--root="+filepath.Join(state, "root"), "list", "-quiet").Output()
	if err != nil {
		t.Fatalf("runsc list: %v", err)
	}
	n := 0
	for _, id := range strings.Fields(string(out)) {
		if strings.HasPrefix(id, "f-") {
			n++
		}
	}
	return n
}
