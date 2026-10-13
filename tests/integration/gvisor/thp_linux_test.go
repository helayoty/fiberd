//go:build linux && integration

package gvisortest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
	gvisorbackend "github.com/helayoty/fiberd/pkg/backend/gvisor"
	"github.com/helayoty/fiberd/pkg/core"
)

// thpEnabled is the THP_enabled field of /proc/<pid>/status, the inverse
// of the process's PR_SET_THP_DISABLE flag.
func thpEnabled(t *testing.T, pid int) string {
	t.Helper()
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		if v, ok := strings.CutPrefix(line, "THP_enabled:"); ok {
			return strings.TrimSpace(v)
		}
	}
	t.Fatalf("/proc/%d/status has no THP_enabled line", pid)
	return ""
}

// TestSandboxTHP checks that a fiber's processes, the sandbox and the
// gofer in its leaf, run with transparent huge pages off (THP_enabled 0),
// while the test process, standing for fiberd, keeps its own.
func TestSandboxTHP(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{name: "the sandbox and its gofer", want: "0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := filepath.Join(work, fmt.Sprintf("thp%d", time.Now().UnixNano()%1_000_000))
			b := gvisorbackend.New(gvisorbackend.Options{Rootfs: rootfs, StateDir: state}).(*gvisorbackend.Backend)
			if b.Tier() != core.TierSnapshot {
				t.Fatalf("gvisor backend not usable here: %v", b.ProbeErr())
			}
			t.Cleanup(b.Close)
			workDir := filepath.Join(t.TempDir(), "g")
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			w, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "thp", Template: backend.Template{Argv: []string{"/bin/refzygote", "--heap-mb", "16", "--gvisor"}},
				CgroupFD: -1, ProbeCgroupFD: -1, WorkDir: workDir})
			if err != nil {
				t.Fatalf("Warm: %v", err)
			}
			fd := cgroupLeaf(t)
			fb, err := b.Clone(ctx, w.ID, backend.FiberSpec{Fence: "thp/1-1", Endpoint: filepath.Join(workDir, "f.sock"), CgroupFD: fd, Deadline: 10 * time.Second})
			if err != nil {
				t.Fatalf("Clone: %v", err)
			}
			procs, err := os.ReadFile(fmt.Sprintf("/proc/self/fd/%d/cgroup.procs", fd))
			if err != nil {
				t.Fatal(err)
			}
			pids := strings.Fields(string(procs))
			sandbox := false
			for _, p := range pids {
				pid, _ := strconv.Atoi(p)
				sandbox = sandbox || pid == fb.PID
				if got := thpEnabled(t, pid); got != tc.want {
					t.Fatalf("pid %d THP_enabled = %s, want %s", pid, got, tc.want)
				}
			}
			if len(pids) < 2 || !sandbox {
				t.Fatalf("the leaf holds %q, want the sandbox %d and its gofer", procs, fb.PID)
			}
			if got := thpEnabled(t, os.Getpid()); got != "1" {
				t.Fatalf("the starting process's THP_enabled = %s, want 1", got)
			}
			if err := b.Kill(fb.ID); err != nil {
				t.Fatalf("Kill: %v", err)
			}
			select {
			case e := <-b.Exits():
				if e.FiberID != fb.ID {
					t.Fatalf("exit %+v, want %s", e, fb.ID)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("no exit after Kill")
			}
		})
	}
}
