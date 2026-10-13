//go:build linux && integration

// Package pythontest runs fiberd's host runtime on the proc backend with
// the Python template SDK (sdk/python). It builds the fiberd._zygote
// extension in place, runs the reference template fiberd.template.ref as
// the zygote and drives clones through core.Runtime, as the proc suite
// does with refzygote. It runs as root in the dev container (make
// integration-tests) and skips where python3 is missing.
package pythontest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	procbackend "github.com/helayoty/fiberd/pkg/backend/proc"
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
)

func TestMain(m *testing.M) {
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
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// refTemplate is the reference template's command line.
func refTemplate() string {
	return python + " -m fiberd.template.ref --heap-mb 8"
}

// newRuntime opens the host runtime over the fork backend with the given
// template command line, as the proc suite does.
func newRuntime(t *testing.T, template string) core.Runtime {
	t.Helper()
	run := filepath.Join("/tmp", fmt.Sprintf("fzpy-%d-%d", os.Getpid(), time.Now().UnixNano()%1_000_000))
	rt, err := host.New(host.Config{
		Backend:    procbackend.New(procbackend.Options{}),
		Templates:  map[string]string{"default": template},
		CgroupRoot: filepath.Join(cgRoot, fmt.Sprintf("py%d-%d", os.Getpid(), time.Now().UnixNano()%1_000_000)),
		RunDir:     run,
	})
	if err != nil {
		t.Fatal(err)
	}
	runDirs[rt] = run
	t.Cleanup(func() {
		rt.Close()
		if t.Failed() {
			t.Log(zygoteLogs(run))
		}
		_ = os.RemoveAll(run)
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
	g := core.Grant{UID: uid, TemplateDigest: "sha256:pyref", WBudgetBytes: 64 << 20}
	if err := rt.PrepareTemplate(context.Background(), g); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	return g
}

// clone makes a fiber of g and releases it when the test ends.
func clone(t *testing.T, rt core.Runtime, g core.Grant, seq uint64, session string, payload []byte) core.FiberHandle {
	t.Helper()
	h, err := rt.Clone(context.Background(), core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: seq},
		Deadline: 5 * time.Second, Session: session, Payload: payload})
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
