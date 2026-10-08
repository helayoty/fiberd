//go:build linux

package agent_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/agent"
	"github.com/helayoty/fiberd/pkg/core"
)

// cgroupRoot is a fresh delegated cgroup for one Run, removed afterwards.
// It skips the test when this host cannot carve one (not root, or no
// writable cgroup v2).
func cgroupRoot(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to carve a cgroup (run it with hack/dev/run.sh)")
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		t.Skipf("no cgroup v2: %v", err)
	}
	root := fmt.Sprintf("/sys/fs/cgroup/fz-agent-%d-%d", os.Getpid(), time.Now().UnixNano()%1_000_000)
	t.Cleanup(func() {
		// cgroups go with rmdir, leaves first.
		var dirs []string
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				dirs = append(dirs, p)
			}
			return nil
		})
		slices.Reverse(dirs)
		for _, d := range dirs {
			_ = os.Remove(d)
		}
	})
	return root
}

// ceiling is the -grant-ceiling the proc case runs with, in bytes.
const ceiling = "268435456"

var (
	zygoteOnce sync.Once
	zygoteBin  string
	zygoteErr  error
)

// refzygote builds the reference zygote once, so a grant can be warmed.
// It skips the test when there is no C toolchain.
func refzygote(t *testing.T) string {
	t.Helper()
	zygoteOnce.Do(func() {
		dir, err := os.MkdirTemp("", "refzygote")
		if err != nil {
			zygoteErr = err
			return
		}
		zygoteBin = filepath.Join(dir, "refzygote")
		out, err := exec.Command("gcc", "-O2", "-pthread", "-DFZ_TLS", "-o", zygoteBin,
			"../../zygote/refzygote.c", "../../zygote/libfiberzygote.c", "-lssl", "-lcrypto").CombinedOutput()
		if err != nil {
			zygoteErr = fmt.Errorf("%w: %s", err, out)
		}
	})
	if zygoteErr != nil {
		t.Skipf("cannot build refzygote: %v", zygoteErr)
	}
	return zygoteBin
}

// TestRunHostRuntime starts the agent on the fork backends of the host
// runtime. It carves its cgroup, makes its directories under -state, and
// serves the handoff listener when asked, then stops cleanly. No fiber is
// cloned, since the backends' own tests do that. gVisor and Hyperlight
// without their tools offer no tier, and TestRunRefuses has them.
func TestRunHostRuntime(t *testing.T) {
	cases := []struct {
		name    string
		args    func(dir string) []string
		handoff bool
		// prune seeds a grant cgroup the snapshot re-admits and a stale
		// one it does not.
		prune bool
	}{
		{name: "proc with handoff, a grant ceiling, tcp endpoints and a stale grant", handoff: true, prune: true, args: func(dir string) []string {
			return []string{"-runtime", "proc", "-template", "default=" + refzygote(t) + " --heap-mb 16", "-handoff-listen", "127.0.0.1:0",
				"-grants-dir", dir, "-grant-ceiling", ceiling, "-endpoint-family", "inet4"}
		}},
		{name: "runc", args: func(dir string) []string {
			return []string{"-runtime", "runc", "-template", "default=/bin/true", "-runc-rootfs", dir, "-runc", "/nonexistent/runc"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cg := cgroupRoot(t)
			state := stateDir(t)
			args := append([]string{"-cgroup-root", cg, "-run-dir", filepath.Join(state, "run")}, tc.args(t.TempDir())...)
			if tc.prune {
				seedGrants(t, state, cg)
			}
			r := start(t, newConfig(t, state, args...), agent.Standalone)
			if tc.prune {
				if _, err := os.Stat(filepath.Join(cg, "stale")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("stale grant cgroup: %v, want it pruned", err)
				}
				// The re-admitted grant is warm, its cgroup kept and capped
				// at -grant-ceiling.
				high, err := os.ReadFile(filepath.Join(cg, "kept", "memory.high"))
				if err != nil {
					t.Fatalf("re-admitted grant cgroup: %v, want it kept", err)
				}
				if got := strings.TrimSpace(string(high)); got != ceiling {
					t.Fatalf("grant memory.high = %s, want -grant-ceiling %s", got, ceiling)
				}
			}
			for _, d := range []string{cg, filepath.Join(state, "run"), filepath.Join(state, "deltas"), filepath.Join(state, "templates")} {
				if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
					t.Fatalf("%s: %v, want a directory the runtime made", d, err)
				}
			}
			if _, ok := adminHealth(t, r)["tier"]; !ok {
				t.Fatal("admin healthz reports no tier")
			}
			if (r.handoff != nil) != tc.handoff {
				t.Fatalf("handoff listener %v, want one: %v", r.handoff, tc.handoff)
			}
			if tc.handoff {
				conn, err := net.Dial("tcp", r.handoff.String())
				if err != nil {
					t.Fatalf("handoff listener: %v", err)
				}
				_ = conn.Close()
				if got := mode(t, filepath.Join(state, "private", "handoff-key.json")); got != 0o600 {
					t.Fatalf("handoff key mode %v, want 0600", got)
				}
			}
			if err := r.stop(t); err != nil {
				t.Fatalf("Run after cancel = %v, want nil", err)
			}
			if tc.handoff {
				if conn, err := net.Dial("tcp", r.handoff.String()); err == nil {
					_ = conn.Close()
					t.Fatal("the handoff listener outlived Run")
				}
			}
			noRunGoroutines(t)
		})
	}
}

// seedGrants leaves what a previous run would: a snapshot holding grant
// "kept", and cgroups for it and for grant "stale".
func seedGrants(t *testing.T, state, cg string) {
	t.Helper()
	g := testGrant("kept")
	g.Policy.Isolation = core.Trusted // proc shares the host kernel
	g.Token = jsonGrant(t, g)
	b, err := json.Marshal(core.Snapshot{Grants: []core.Grant{g}})
	if err != nil {
		t.Fatal(err)
	}
	priv := filepath.Join(state, "private")
	if err := os.MkdirAll(priv, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(priv, "ledger.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"kept", "stale"} {
		if err := os.MkdirAll(filepath.Join(cg, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// TestRunHostRuntimeRefuses: what only the host runtime checks.
func TestRunHostRuntimeRefuses(t *testing.T) {
	cases := []struct {
		name, want string
		setup      func(t *testing.T) []string
	}{
		{name: "a relative -grants-dir with no working directory", want: "getwd",
			setup: func(t *testing.T) []string {
				gone := t.TempDir()
				t.Chdir(gone)
				if err := os.Remove(gone); err != nil {
					t.Fatal(err)
				}
				return []string{"-grants-dir", "grants"}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cg := cgroupRoot(t)
			state := stateDir(t)
			args := append([]string{"-runtime", "proc", "-template", "default=/bin/true", "-cgroup-root", cg,
				"-run-dir", filepath.Join(state, "run")}, tc.setup(t)...)
			r, err := launch(t, context.Background(), newConfig(t, state, args...), agent.Standalone)
			if r != nil {
				_ = r.stop(t)
				t.Fatal("Run started, want an error")
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Run = %v, want %q", err, tc.want)
			}
			noRunGoroutines(t)
		})
	}
}

func adminHealth(t *testing.T, r *running) map[string]any {
	t.Helper()
	_, h := adminDo(t, r.c, "GET", "/healthz", "")
	return h
}
