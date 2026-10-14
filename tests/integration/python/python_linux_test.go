//go:build linux && integration

// Package pythontest runs fiberd's host runtime with the Python template
// SDK (sdk/python) on every backend that forks or restores a process: proc,
// runc and gVisor. It builds the fiberd._zygote extension in place, runs
// the reference template fiberd.template.ref as the zygote (proc) or as
// the container's or sandbox's init from a rootfs that holds CPython and
// the SDK (runc, gVisor), and drives clones through core.Runtime as the
// backends' own suites do with refzygote. It runs as root in the dev
// container (make integration-tests) and skips where python3 is missing.
// A backend whose tool is missing is left out.
package pythontest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	gvisorbackend "github.com/helayoty/fiberd/pkg/backend/gvisor"
	procbackend "github.com/helayoty/fiberd/pkg/backend/proc"
	runcbackend "github.com/helayoty/fiberd/pkg/backend/runc"
	"github.com/helayoty/fiberd/pkg/core"
	fiberendpoint "github.com/helayoty/fiberd/pkg/endpoint"
	"github.com/helayoty/fiberd/pkg/runtime/host"
	"github.com/helayoty/fiberd/tests/internal/testenv"
)

var (
	cgRoot string
	// runDirs is each runtime's run directory, where the zygote logs are.
	runDirs = map[core.Runtime]string{}
	// python runs the interpreter with the SDK on its path. fiberd gives a
	// zygote no environment but PATH, so the wrapper sets PYTHONPATH.
	python string
	// testdata holds the templates that break a rule each.
	testdata string
	// rootfs is the root filesystem with CPython and the SDK the runc and
	// gVisor backends run the template from, "" when neither is here.
	rootfs string
	// work is where the rootfs and the backends' state live. Not tmpfs,
	// since gVisor's images are memory there.
	work = "/var/lib/fiberd-test/python"
)

// backend is one way of running the Python reference template.
type backend struct {
	name string
	// template is the reference template's command line there.
	template string
	// pathEnv is what the fiber answers for "getenv PATH". A forked fiber
	// is scrubbed to its FIBERD_ entries, a sandbox keeps its spec's.
	pathEnv string
	// pooled says the backend restores sandboxes ahead of a clone.
	pooled bool
	// open opens the host runtime over the backend with the template.
	open func(t *testing.T, template string) core.Runtime
}

// backends is every backend this host can run, proc first.
var backends []backend

func TestMain(m *testing.M) {
	// A mount namespace of this suite's own, so the proc suite's restore
	// root never lands in a fiber forked here.
	testenv.OwnMountNamespace()
	cgRoot = testenv.RequireCgroupRoot("python")
	interp, err := exec.LookPath("python3")
	if err != nil {
		fmt.Fprintln(os.Stderr, "skipping python tests: no python3")
		os.Exit(0)
	}
	root := testenv.RepoRoot()
	dir, err := os.MkdirTemp("", "fzpy")
	if err != nil {
		panic(err)
	}
	build := exec.Command(filepath.Join(root, "hack", "python", "build.sh"))
	build.Env = append(os.Environ(), "FIBERD_PYTHON_BUILD="+filepath.Join(dir, "build"))
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "python tests: build the extension: %v\n", err)
		os.Exit(1)
	}
	python = filepath.Join(dir, "python.sh")
	wrapper := fmt.Sprintf("#!/bin/sh\nexec env PYTHONPATH=%s %s \"$@\"\n", filepath.Join(root, "sdk", "python", "src"), interp)
	if err := os.WriteFile(python, []byte(wrapper), 0o755); err != nil {
		panic(err)
	}
	testdata, _ = filepath.Abs("testdata")
	backends = []backend{{name: "proc", template: python + " -m fiberd.template.ref --heap-mb 8", pathEnv: "-", open: openProc}}
	_, haveRunc := exec.LookPath("runc")
	_, haveRunsc := exec.LookPath("runsc")
	if haveRunc == nil || haveRunsc == nil {
		_ = os.RemoveAll(work)
		rootfs = filepath.Join(work, "rootfs")
		if err := testenv.BuildPythonRootfs(rootfs); err != nil {
			fmt.Fprintf(os.Stderr, "python tests: %v\n", err)
			os.Exit(1)
		}
		const inRootfs = "/usr/bin/python3 -m fiberd.template.ref --heap-mb 8"
		if haveRunc == nil {
			backends = append(backends, backend{name: "runc", template: inRootfs, pathEnv: "-", open: openRunc})
		}
		if haveRunsc == nil {
			backends = append(backends, backend{name: "gvisor", template: inRootfs, pathEnv: "/bin:/usr/bin", pooled: true, open: openGvisor})
		}
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	_ = os.RemoveAll(work)
	os.Exit(code)
}

// newRuntime opens the host runtime over the fork backend with the given
// template command line, as the proc suite does.
func newRuntime(t *testing.T, template string) core.Runtime {
	t.Helper()
	return openProc(t, template)
}

// unique names a runtime's cgroup, state and run directory.
func unique(prefix string) string {
	return fmt.Sprintf("%s%d-%d", prefix, os.Getpid(), time.Now().UnixNano()%1_000_000)
}

func openProc(t *testing.T, template string) core.Runtime {
	t.Helper()
	name := unique("py")
	return open(t, name, host.Config{Backend: procbackend.New(procbackend.Options{}), Templates: map[string]string{"default": template},
		CgroupRoot: filepath.Join(cgRoot, name), RunDir: filepath.Join("/tmp", "fz-"+name)})
}

func openRunc(t *testing.T, template string) core.Runtime {
	t.Helper()
	name := unique("pyrc")
	be, err := runcbackend.New(runcbackend.Options{Rootfs: rootfs, StateDir: filepath.Join(work, name)})
	if err != nil {
		t.Fatal(err)
	}
	return open(t, name, host.Config{Backend: be, Templates: map[string]string{"default": template},
		CgroupRoot: filepath.Join(cgRoot, name), RunDir: filepath.Join("/tmp", "fz-"+name)})
}

func openGvisor(t *testing.T, template string) core.Runtime {
	t.Helper()
	name := unique("pygv")
	return open(t, name, host.Config{Backend: gvisorbackend.New(gvisorbackend.Options{Rootfs: rootfs, StateDir: filepath.Join(work, name)}),
		Templates:  map[string]string{"default": template},
		CgroupRoot: filepath.Join(cgRoot, name), RunDir: filepath.Join("/tmp", "fz-"+name)})
}

// open opens the host runtime over cfg with the deltas and the template
// cache under this suite's own work directory, never fiberd's defaults
// under /var/lib/fiberd, which another suite running beside this one
// would share.
func open(t *testing.T, name string, cfg host.Config) core.Runtime {
	t.Helper()
	cfg.DeltaDir = filepath.Join(work, name, "deltas")
	cfg.TemplateCache = filepath.Join(work, name, "templates")
	rt, err := host.New(cfg)
	if errors.Is(err, host.ErrNoTier) {
		t.Skipf("%s not usable here: %v", name, err)
	}
	if err != nil {
		t.Fatal(err)
	}
	runDirs[rt] = cfg.RunDir
	t.Cleanup(func() {
		rt.Close()
		if t.Failed() {
			t.Log(zygoteLogs(cfg.RunDir))
		}
		_ = os.RemoveAll(cfg.RunDir)
	})
	return rt
}

// zygoteLogs is every zygote.log under run, for a refusal's reason.
func zygoteLogs(run string) string {
	logs, _ := filepath.Glob(filepath.Join(run, "*", "zygote.log"))
	out := ""
	for _, l := range logs {
		if b, err := os.ReadFile(l); err == nil {
			out += l + ":\n" + string(b)
		}
	}
	return out
}

// prepare warms a grant on rt and returns it.
func prepare(t *testing.T, rt core.Runtime, uid string) core.Grant {
	t.Helper()
	g := core.Grant{UID: uid, TemplateDigest: "sha256:pyref", FiberMax: 4, WBudgetBytes: 64 << 20}
	if err := rt.PrepareTemplate(context.Background(), g); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	return g
}

// clone makes a fiber of g and releases it when the test ends.
func clone(t *testing.T, rt core.Runtime, g core.Grant, seq uint64, session string, payload []byte) core.FiberHandle {
	t.Helper()
	h, err := rt.Clone(context.Background(), core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: seq},
		Deadline: 20 * time.Second, Session: session, Payload: payload})
	if err != nil {
		t.Fatalf("clone %d: %v", seq, err)
	}
	t.Cleanup(func() { _ = rt.Release(context.Background(), h.ID, true) })
	return h
}

// talk sends one line to a fiber's endpoint and returns the reply.
func talk(t *testing.T, endpoint, line string) string {
	t.Helper()
	dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := fiberendpoint.Dial(dctx, endpoint)
	if err != nil {
		t.Fatalf("dial %s: %v", endpoint, err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(line + "\n")); err != nil {
		t.Fatalf("write %q: %v", line, err)
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read after %q: %v", line, err)
	}
	reply := string(buf[:n])
	if len(reply) > 0 && reply[len(reply)-1] == '\n' {
		reply = reply[:len(reply)-1]
	}
	return reply
}
