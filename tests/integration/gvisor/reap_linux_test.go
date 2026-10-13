//go:build linux && integration

package gvisortest

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// sandboxes lists the sandbox ids under the current runtime's runsc root.
func sandboxes(t *testing.T) map[string]bool {
	t.Helper()
	out, err := exec.Command("runsc", "--root="+filepath.Join(work, name, "root"), "list", "-quiet").Output()
	if err != nil {
		t.Fatalf("runsc list: %v", err)
	}
	ids := map[string]bool{}
	for _, id := range strings.Fields(string(out)) {
		ids[id] = true
	}
	return ids
}

// sandboxPID is the host pid of the sandbox cid, from `runsc state`.
func sandboxPID(t *testing.T, cid string) int {
	t.Helper()
	out, err := exec.Command("runsc", "--root="+filepath.Join(work, name, "root"), "state", cid).Output()
	if err != nil {
		t.Fatalf("runsc state %s: %v", cid, err)
	}
	var st struct {
		PID int `json:"pid"`
	}
	if err := json.Unmarshal(out, &st); err != nil || st.PID <= 0 {
		t.Fatalf("runsc state %s = %q (%v), want a pid", cid, out, err)
	}
	return st.PID
}

// TestReapThroughPidfd checks the backend's real reaper, which the unit
// tests replace with the fake runsc's in-process await. A fiber's
// sandbox killed from outside is waited for on a pidfd of the sandbox
// process and its end is reported for that fiber. fiberd is not the
// sandbox's parent, so the status is "exited", and the pidfd is the
// only hold it has on the process.
func TestReapThroughPidfd(t *testing.T) {
	cases := []struct {
		name   string
		signal syscall.Signal
	}{
		{name: "the sandbox process is killed", signal: syscall.SIGKILL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRuntime(t)
			ctx := context.Background()
			g := core.Grant{UID: "g-reap", TemplateDigest: "sha256:ref", FiberMax: 2, WBudgetBytes: 64 << 20}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			before := sandboxes(t)
			h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 10 * time.Second})
			if err != nil {
				t.Fatalf("clone: %v", err)
			}
			cid := ""
			for id := range sandboxes(t) {
				if !before[id] {
					cid = id
				}
			}
			if cid == "" {
				t.Fatal("the clone left no new sandbox")
			}
			if err := syscall.Kill(sandboxPID(t, cid), tc.signal); err != nil {
				t.Fatal(err)
			}
			select {
			case e := <-rt.Exits():
				if e.FiberID != h.ID || e.Reason != "exit" || e.Detail != "exited" {
					t.Fatalf("exit = %+v, want fiber %s reaped as exited", e, h.ID)
				}
			case <-time.After(15 * time.Second):
				t.Fatal("the sandbox's end was not reaped")
			}
		})
	}
}
