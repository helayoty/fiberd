//go:build linux

package gvisortest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
	gvisorbackend "github.com/helayoty/fiberd/pkg/backend/gvisor"
	"github.com/helayoty/fiberd/pkg/core"
)

// cgroupLeaf makes an empty cgroup under the delegated root and opens
// it. The cleanup waits for the leaf to empty and removes it.
func cgroupLeaf(t *testing.T) int {
	t.Helper()
	dir := filepath.Join(cgRoot, fmt.Sprintf("gv-leaf-%d-%d", os.Getpid(), time.Now().UnixNano()%1_000_000))
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Close(fd)
		deadline := time.Now().Add(10 * time.Second)
		for os.Remove(dir) != nil {
			if time.Now().After(deadline) {
				procs, _ := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
				t.Errorf("the probe leaf %s cannot be removed, it holds %q", dir, procs)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	return fd
}

// TestProbeFootprintInLeaf measures a template's footprint as Warm does
// for the host, in a real cgroup leaf: the reading is what the kernel
// charges a sandbox, and the leaf is empty once Warm returns. Without a
// probe cgroup nothing is measured.
func TestProbeFootprintInLeaf(t *testing.T) {
	cases := []struct {
		name  string
		probe bool
	}{
		{name: "measured serving in a leaf of its own", probe: true},
		{name: "no probe cgroup", probe: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fd := -1
			if tc.probe {
				fd = cgroupLeaf(t)
			}
			state := filepath.Join(work, fmt.Sprintf("fp%d", time.Now().UnixNano()%1_000_000))
			b := gvisorbackend.New(gvisorbackend.Options{Rootfs: rootfs, StateDir: state}).(*gvisorbackend.Backend)
			if b.Tier() != core.TierSnapshot {
				t.Fatalf("gvisor backend not usable here: %v", b.ProbeErr())
			}
			t.Cleanup(b.Close)
			workDir := filepath.Join(t.TempDir(), "g")
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			t0 := time.Now()
			w, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "fp", Template: backend.Template{Argv: []string{"/bin/refzygote", "--heap-mb", "64", "--gvisor"}},
				CgroupFD: -1, ProbeCgroupFD: fd, WorkDir: workDir})
			if err != nil {
				t.Fatalf("Warm: %v", err)
			}
			t.Logf("warm with probe=%v in %s: shmem %d MiB of %d MiB", tc.probe, time.Since(t0).Round(time.Millisecond), w.Bytes>>20, w.TotalBytes>>20)
			if !tc.probe {
				if w.Bytes != 0 || w.TotalBytes != 0 {
					t.Fatalf("Warm measured %d/%d bytes without a probe cgroup", w.Bytes, w.TotalBytes)
				}
			} else if w.Bytes == 0 || w.Bytes > w.TotalBytes {
				t.Fatalf("Warm measured shmem %d of %d bytes, want a footprint", w.Bytes, w.TotalBytes)
			}
			// The probe is gone: not in runsc's root, nothing in the leaf,
			// nothing of it in the template directory or the run directory.
			out, err := exec.Command("runsc", "--root="+filepath.Join(state, "root"), "list", "-quiet").Output()
			if err != nil {
				t.Fatalf("runsc list: %v", err)
			}
			for _, id := range strings.Fields(string(out)) {
				if strings.HasSuffix(id, "-probe") {
					t.Fatalf("the probe sandbox %s is still in runsc's root", id)
				}
			}
			if tc.probe {
				procs, err := os.ReadFile(fmt.Sprintf("/proc/self/fd/%d/cgroup.procs", fd))
				if err != nil || strings.TrimSpace(string(procs)) != "" {
					t.Fatalf("the probe leaf holds %q (%v) after Warm", procs, err)
				}
			}
			if left, _ := filepath.Glob(filepath.Join(state, "templates", "*", "probe-bundle")); len(left) != 0 {
				t.Fatalf("%v left behind", left)
			}
			if _, err := os.Lstat(filepath.Join(workDir, "probe.sock")); err == nil {
				t.Fatal("probe.sock left behind")
			}
		})
	}
}
