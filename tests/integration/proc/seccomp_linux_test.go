//go:build linux && integration

package proctest

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/tests/internal/testenv"
)

var (
	noSeccompOnce sync.Once
	noSeccompBin  string
	noSeccompErr  error
)

// noSeccomp builds the launcher in testdata/noseccomp.c once per test
// binary, beside refzygote, and returns its path.
func noSeccomp(t *testing.T) string {
	t.Helper()
	noSeccompOnce.Do(func() {
		noSeccompBin = filepath.Join(filepath.Dir(zygoteBin), "noseccomp")
		build := exec.Command("gcc", "-O2", "-o", noSeccompBin, "testdata/noseccomp.c")
		if out, err := build.CombinedOutput(); err != nil {
			noSeccompErr = fmt.Errorf("%w: %s", err, out)
		}
	})
	if noSeccompErr != nil {
		t.Skipf("cannot build noseccomp: %v", noSeccompErr)
	}
	return noSeccompBin
}

// TestFiberFilter pins the fiber filter on a real fiber. The zygote
// installs it before READY and every fiber inherits it, so a fiber
// answers each refused class with its errno, lets the neighbours
// through, and keeps all of it across a park and resume. The birth's
// clone3 passes the filter's gate straight into the leaf, and the fiber
// stacks its own clone3 refusal.
func TestFiberFilter(t *testing.T) {
	needRoot(t)
	rt := newRuntime(t)
	ctx := context.Background()
	g := core.Grant{UID: "gsc", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	status := []struct{ cmd, want string }{
		{cmd: "status Seccomp", want: "2"},
		{cmd: "status NoNewPrivs", want: "1"},
		{cmd: "status CapEff", want: "0000000000000000"},
	}
	check := func(when, ep string) {
		for _, s := range status {
			t.Run(when+"/"+s.cmd, func(t *testing.T) {
				if got := talk(t, ep, s.cmd); got != s.want {
					t.Errorf("%s = %q, want %q", s.cmd, got, s.want)
				}
			})
		}
		testenv.CheckFilter(t, when, func(t *testing.T, line string) string { return talk(t, ep, line) })
	}
	check("born", h.Endpoint)
	t.Run("born/in its leaf by clone3, under the zygote's filter", func(t *testing.T) {
		pid := peerPID(t, h.Endpoint)
		zygotePID := atoiOrFatal(t, "fiber's PPid", procStatus(t, pid, "PPid"))
		if got := procStatus(t, zygotePID, "Seccomp"); got != "2" {
			t.Errorf("zygote Seccomp = %q, want 2: the filter is the zygote's, installed before READY", got)
		}
		fiberCG, zygoteCG := cgroupOf(t, pid), cgroupOf(t, zygotePID)
		if filepath.Base(fiberCG) != "f-1-1" || filepath.Dir(fiberCG) != filepath.Dir(zygoteCG) {
			t.Errorf("fiber cgroup %q, zygote's %q, want <grant>/f-1-1 beside <grant>/zygote", fiberCG, zygoteCG)
		}
	})
	if got := talk(t, h.Endpoint, "incr"); got != "1" {
		t.Fatalf("incr = %q, want 1", got)
	}
	if rt.Tier() < core.TierCheckpoint {
		t.Skip("criu not usable here; park and resume not checked")
	}
	ref, err := rt.Park(ctx, h.ID, true)
	if err != nil {
		t.Fatalf("park: %v", err)
	}
	h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 2}, Deadline: 5 * time.Second})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	t.Cleanup(func() { _ = rt.Release(ctx, h2.ID, true) })
	if got := talk(t, h2.Endpoint, "get"); got != "1" {
		t.Fatalf("counter after resume = %q, want 1", got)
	}
	check("resumed", h2.Endpoint)
}

// TestFilterRefusedFailsWarm pins that a zygote that cannot install the
// fiber filter never says READY, so the warm fails with the reason and no
// fiber runs unfiltered. The noseccomp launcher refuses every filter the
// zygote asks for with one errno.
func TestFilterRefusedFailsWarm(t *testing.T) {
	needRoot(t)
	launcher := noSeccomp(t)
	cases := []struct {
		name  string
		errno syscall.Errno
		why   string // libc's text for errno, as the zygote says it
	}{
		{name: "refused", errno: syscall.EPERM, why: "Operation not permitted"},
		{name: "a kernel without seccomp", errno: syscall.ENOSYS, why: "Function not implemented"},
		{name: "a flag the kernel lacks", errno: syscall.EINVAL, why: "Invalid argument"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			argv := []string{launcher, strconv.Itoa(int(tc.errno)), zygoteBin, "--heap-mb", "16"}
			_, _, err := tryWarmArgv(t, dir, fmt.Sprintf("gns%d", i), argv, nil)
			want := "seccomp filter: " + tc.why
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("warm under a filter refused with %v = %v, want it failed with %q", tc.errno, err, want)
			}
		})
	}
}
