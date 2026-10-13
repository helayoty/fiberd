//go:build linux && integration

package proctest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/fiberd"
	"github.com/helayoty/fiberd/pkg/grant"
)

// fiberdNode is the -node-id fiberd runs as here, and the audience of
// its grants.
const fiberdNode = "node-a"

// fiberdConfig parses args the way cmd/fiberd does, after a base that
// starts a plaintext fiberd with the insecure-json verifier on loopback
// ":0" ports, with its loops at 10ms. Later flags win.
func fiberdConfig(t *testing.T, state string, args ...string) *fiberd.Config {
	t.Helper()
	fs := flag.NewFlagSet("fiberd", flag.ContinueOnError)
	var c fiberd.Config
	c.Bind(fs)
	base := []string{"-state", state, "-listen", "127.0.0.1:0", "-insecure-plaintext", "-verifier", "insecure-json",
		"-node-id", fiberdNode}
	if err := fs.Parse(append(base, args...)); err != nil {
		t.Fatal(err)
	}
	c.Timing = fiberd.Timing{StatusEvery: 10 * time.Millisecond, PressureEvery: 10 * time.Millisecond}
	return &c
}

// fiberdState is a fresh -state directory, short because the admin
// socket lives under it.
func fiberdState(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "fz")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
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

// seedGrants leaves what a previous fiberd would, a snapshot holding
// grant "kept" and cgroups for it and for grant "stale".
func seedGrants(t *testing.T, state, cg string) {
	t.Helper()
	g := core.Grant{UID: "kept", Audience: fiberdNode, Tenant: "acme", FiberMax: 2, MinTier: core.TierBasic,
		LeaseExpiry: time.Now().Add(10 * time.Minute)}
	g.Policy.Isolation = core.Trusted // proc shares the host kernel
	tok, err := protojson.Marshal(grant.ToProto(g))
	if err != nil {
		t.Fatal(err)
	}
	g.Token = string(tok)
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

// fiberdCeiling is the -grant-ceiling the proc case runs with, in bytes.
const fiberdCeiling = "268435456"

// TestFiberdRunHostRuntime starts fiberd on the fork backend of the host
// runtime, as cmd/fiberd -runtime proc does. It carves its cgroup, makes
// its directories under -state, re-admits the snapshot's grant and
// prunes the stale one's cgroup, serves the handoff listener when asked,
// then stops cleanly. No fiber is cloned, since the suite's other tests
// do that.
func TestFiberdRunHostRuntime(t *testing.T) {
	cases := []struct {
		name    string
		args    func(grants string) []string
		handoff bool
		// prune seeds a grant cgroup the snapshot re-admits and a stale
		// one it does not.
		prune bool
	}{
		{name: "proc alone", args: func(string) []string { return nil }},
		{name: "proc with handoff, a grant ceiling, tcp endpoints and a stale grant", handoff: true, prune: true,
			args: func(grants string) []string {
				return []string{"-handoff-listen", "127.0.0.1:0", "-grants-dir", grants, "-grant-ceiling", fiberdCeiling,
					"-endpoint-family", "inet4"}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cg := fiberdCgroup(t)
			state := fiberdState(t)
			args := append([]string{"-runtime", "proc", "-template", "default=" + zygoteBin + " --heap-mb 16",
				"-cgroup-root", cg}, tc.args(t.TempDir())...)
			if tc.prune {
				seedGrants(t, state, cg)
			}
			r := startFiberd(t, fiberdConfig(t, state, args...))
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
				if got := strings.TrimSpace(string(high)); got != fiberdCeiling {
					t.Fatalf("grant memory.high = %s, want -grant-ceiling %s", got, fiberdCeiling)
				}
			}
			for _, d := range []string{cg, filepath.Join(state, "run"), filepath.Join(state, "deltas"), filepath.Join(state, "templates")} {
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
			if tc.handoff {
				conn, err := net.Dial("tcp", r.handoff.String())
				if err != nil {
					t.Fatalf("handoff listener: %v", err)
				}
				_ = conn.Close()
				fi, err := os.Lstat(filepath.Join(state, "private", "handoff-key.json"))
				if err != nil || fi.Mode().Perm() != 0o600 {
					t.Fatalf("handoff key: %v, %v; want mode 0600", fi, err)
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
			noFiberdGoroutines(t)
		})
	}
}
