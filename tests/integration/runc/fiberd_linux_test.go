//go:build linux && integration

package runctest

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/fiberd"
)

// fiberdConfig parses args the way cmd/fiberd does, after a base that
// starts a plaintext fiberd with the insecure-json verifier on loopback
// ":0" ports. Later flags win.
func fiberdConfig(t *testing.T, state string, args ...string) *fiberd.Config {
	t.Helper()
	fs := flag.NewFlagSet("fiberd", flag.ContinueOnError)
	var c fiberd.Config
	c.Bind(fs)
	base := []string{"-state", state, "-listen", "127.0.0.1:0", "-insecure-plaintext", "-verifier", "insecure-json",
		"-node-id", "node-a", "-status-interval", "10ms", "-pressure-interval", "10ms"}
	if err := fs.Parse(append(base, args...)); err != nil {
		t.Fatal(err)
	}
	c.Finish()
	return &c
}

// fiberdRun is one RunContext in the background.
type fiberdRun struct {
	c                   *fiberd.Config
	grpc, http, handoff net.Addr
	cancel              context.CancelFunc
	done                chan error
}

// startFiberd runs fiberd and returns once every listener is bound. It
// fails the test when Run returns first.
func startFiberd(t *testing.T, c *fiberd.Config) *fiberdRun {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &fiberdRun{c: c, cancel: cancel, done: make(chan error, 1)}
	ready := make(chan struct{})
	c.Ready = func(g, h, ho net.Addr) {
		r.grpc, r.http, r.handoff = g, h, ho
		close(ready)
	}
	go func() { r.done <- fiberd.RunContext(ctx, c, fiberd.Standalone) }()
	select {
	case <-ready:
		t.Cleanup(func() { cancel(); <-r.done })
		return r
	case err := <-r.done:
		cancel()
		t.Fatalf("Run: %v", err)
	case <-time.After(20 * time.Second):
		cancel()
		t.Fatal("Run neither became ready nor returned")
	}
	return nil
}

// stop cancels Run and returns what it returned.
func (r *fiberdRun) stop(t *testing.T) error {
	t.Helper()
	r.cancel()
	select {
	case err := <-r.done:
		r.done <- err // the cleanup reads it too
		return err
	case <-time.After(20 * time.Second):
		t.Fatal("Run did not return after its context ended")
		return nil
	}
}

// fiberdHealth is what the admin socket's /healthz reports.
func fiberdHealth(t *testing.T, c *fiberd.Config) map[string]any {
	t.Helper()
	cl := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", c.AdminSocket())
		},
	}}
	resp, err := cl.Get("http://admin/healthz")
	if err != nil {
		t.Fatalf("admin healthz: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

// noFiberdGoroutines waits until every goroutine RunContext started has
// returned, and fails when one outlives the deadline.
func noFiberdGoroutines(t *testing.T) {
	t.Helper()
	const mark = "created by github.com/helayoty/fiberd/pkg/fiberd.RunContext"
	deadline := time.Now().Add(10 * time.Second)
	for {
		buf := make([]byte, 8<<20)
		buf = buf[:runtime.Stack(buf, true)]
		if !bytes.Contains(buf, []byte(mark)) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutines Run started outlived it:\n%s", buf)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// fiberdCgroup is a fresh delegated cgroup under the suite's root for
// one Run, removed afterwards, leaves first.
func fiberdCgroup(t *testing.T) string {
	t.Helper()
	root := filepath.Join(cgRoot, fmt.Sprintf("fd%d-%d", os.Getpid(), time.Now().UnixNano()%1_000_000))
	t.Cleanup(func() {
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

// TestFiberdRunRunc starts fiberd on the runc backend of the host
// runtime, as cmd/fiberd -runtime runc does, over the suite's rootfs. It
// carves its cgroup, makes its directories under -state, including the
// backend's own, serves the handoff listener when asked, then stops
// cleanly. No fiber is cloned, since the suite's other tests do that.
func TestFiberdRunRunc(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		handoff bool
	}{
		{name: "runc alone"},
		{name: "runc with handoff", args: []string{"-handoff-listen", "127.0.0.1:0"}, handoff: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cg := fiberdCgroup(t)
			state, err := os.MkdirTemp("", "fz")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(state) })
			args := append([]string{"-runtime", "runc", "-runc-rootfs", rootfs, "-template", "default=/bin/refzygote --heap-mb 32",
				"-cgroup-root", cg, "-run-dir", filepath.Join(state, "run")}, tc.args...)
			r := startFiberd(t, fiberdConfig(t, state, args...))
			for _, d := range []string{cg, filepath.Join(state, "run"), filepath.Join(state, "deltas"), filepath.Join(state, "templates"),
				filepath.Join(state, "runc")} {
				if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
					t.Fatalf("%s: %v, want a directory the runtime made", d, err)
				}
			}
			if tier, _ := fiberdHealth(t, r.c)["tier"].(string); tier != core.TierCheckpoint.String() {
				t.Fatalf("admin healthz reports tier %q, want %s", tier, core.TierCheckpoint)
			}
			if (r.handoff != nil) != tc.handoff {
				t.Fatalf("handoff listener %v, want one: %v", r.handoff, tc.handoff)
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
			noFiberdGoroutines(t)
		})
	}
}
