//go:build linux && integration

package stormtest

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
	gvisorbackend "github.com/helayoty/fiberd/pkg/backend/gvisor"
	procbackend "github.com/helayoty/fiberd/pkg/backend/proc"
	runcbackend "github.com/helayoty/fiberd/pkg/backend/runc"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/runtime/host"
	"github.com/helayoty/fiberd/tests/internal/testenv"
)

// work holds the rootfs and the sandboxed backends' state. It is not a
// tmpfs, because sandbox images would be memory there.
const work = "/var/lib/fiberd-test/storm"

func TestMain(m *testing.M) {
	code := m.Run()
	_ = os.RemoveAll(work)
	os.Exit(code)
}

// TestStormNumbers is the storm measurement, one subtest per backend, so
// -run TestStormNumbers/proc picks one.
func TestStormNumbers(t *testing.T) {
	cases := []struct {
		name string
		run  func(*testing.T)
	}{
		{name: "proc", run: stormProc},
		{name: "runc", run: stormRunc},
		{name: "gvisor", run: stormGvisor},
	}
	for _, tc := range cases {
		t.Run(tc.name, tc.run)
	}
}

// gate skips the measurement unless it was asked for and the dev
// container delegates a cgroup root, and returns that root.
func gate(t *testing.T) string {
	t.Helper()
	if os.Getenv("FIBERD_BENCH") == "" {
		t.Skip("set FIBERD_BENCH=1 to run the storm measurement")
	}
	root, err := testenv.WritableCgroupRoot()
	if err != nil {
		t.Skip(err)
	}
	return root
}

// The fixtures are built once per binary, on first use, so a skipped
// measurement builds nothing.
var (
	zygoteOnce sync.Once
	zygoteBin  string
	zygoteErr  error
	rootfsOnce sync.Once
	rootfsErr  error
)

// zygote is the hardened reference zygote built on the host.
func zygote(t *testing.T) string {
	t.Helper()
	zygoteOnce.Do(func() {
		if err := os.MkdirAll(work, 0o755); err != nil {
			zygoteErr = err
			return
		}
		zygoteBin, zygoteErr = testenv.BuildZygote(work)
	})
	if zygoteErr != nil {
		t.Fatal(zygoteErr)
	}
	return zygoteBin
}

// rootfs is the root the sandboxed backends run the zygote in.
func rootfs(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(work, "rootfs")
	rootfsOnce.Do(func() { rootfsErr = testenv.BuildRootfs(dir) })
	if rootfsErr != nil {
		t.Fatal(rootfsErr)
	}
	return dir
}

// newRuntime opens the host runtime over the backend be, named so its
// cgroup, state and run directory are its own, with mods applied last.
func newRuntime(t *testing.T, root, name, template string, be func(state string) (backend.Backend, error), mods ...func(*host.Config)) *host.Runtime {
	t.Helper()
	state := filepath.Join(work, name)
	b, err := be(state)
	if err != nil {
		t.Fatal(err)
	}
	cfg := host.Config{
		Backend:    b,
		Templates:  map[string]string{"default": template},
		CgroupRoot: filepath.Join(root, name),
		RunDir:     filepath.Join("/tmp", "fz-"+name),
		DeltaDir:   filepath.Join(state, "deltas"),
		// This suite's own store, not /var/lib/fiberd/templates, which
		// another suite running beside this one would share.
		TemplateCache: filepath.Join(work, "templates"),
	}
	for _, mod := range mods {
		mod(&cfg)
	}
	rt, err := host.New(cfg)
	if errors.Is(err, host.ErrNoTier) {
		t.Skipf("backend not usable here: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rt.Close)
	return rt
}

// unique is a name no earlier runtime of this binary used.
func unique(prefix string) string {
	return fmt.Sprintf("%s%d", prefix, time.Now().UnixNano()%1_000_000)
}

// procRuntime is the fork backend, as fiberd -runtime proc wires it.
func procRuntime(t *testing.T) *host.Runtime {
	t.Helper()
	root := gate(t)
	return newRuntime(t, root, unique("sp"), zygote(t)+" --heap-mb 32",
		func(string) (backend.Backend, error) { return procbackend.New(procbackend.Options{}), nil })
}

// runcRuntime is the runc backend over the rootfs, skipped where runc or
// criu is missing.
func runcRuntime(t *testing.T) *host.Runtime {
	t.Helper()
	root := gate(t)
	if _, err := exec.LookPath("runc"); err != nil {
		t.Skip("runc not installed")
	}
	fs := rootfs(t)
	rt := newRuntime(t, root, unique("sr"), "/bin/refzygote --heap-mb 32",
		func(state string) (backend.Backend, error) {
			return runcbackend.New(runcbackend.Options{Rootfs: fs, StateDir: state})
		})
	if rt.Tier() < core.TierCheckpoint {
		t.Skip("criu not usable here")
	}
	return rt
}

// gvisorRuntime is the gvisor backend over the rootfs, skipped where
// runsc is missing. mods apply to the host configuration last.
func gvisorRuntime(t *testing.T, mods ...func(*host.Config)) (*host.Runtime, string) {
	t.Helper()
	root := gate(t)
	if _, err := exec.LookPath("runsc"); err != nil {
		t.Skip("runsc not installed")
	}
	fs := rootfs(t)
	name := unique("sg")
	rt := newRuntime(t, root, name, "/bin/refzygote --heap-mb 64 --gvisor",
		func(state string) (backend.Backend, error) {
			return gvisorbackend.New(gvisorbackend.Options{Rootfs: fs, StateDir: state}), nil
		}, mods...)
	return rt, filepath.Join(work, name)
}
