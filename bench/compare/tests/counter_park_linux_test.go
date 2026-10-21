//go:build linux && integration

package comparetest

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/helayoty/fiberd/bench/compare"
	"github.com/helayoty/fiberd/bench/compare/adapters/fiberd"
	"github.com/helayoty/fiberd/pkg/endpoint"
)

// repoRoot is the checkout's root, from this package.
var repoRoot, _ = filepath.Abs(filepath.Join("..", "..", ".."))

// counterFlags mirrors ZYGOTE_CFLAGS and ZYGOTE_LDFLAGS in the Makefile.
func counterFlags() []string {
	f := []string{"-D_FORTIFY_SOURCE=3", "-O2", "-fstack-protector-strong", "-fstack-clash-protection", "-fPIE",
		"-Wformat=2", "-Werror=format-security"}
	if runtime.GOARCH == "arm64" {
		f = append(f, "-mbranch-protection=none")
	}
	return append(f, "-pie", "-Wl,-z,relro,-z,now")
}

func mustRun(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

func background(t *testing.T, logPath, name string, args ...string) {
	t.Helper()
	logf, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			b, _ := os.ReadFile(logPath)
			t.Logf("%s:\n%s", filepath.Base(logPath), b)
		}
		_ = logf.Close()
	})
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for range 100 {
		if ok() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("did not come up")
}

// TestCounterParkResume parks a proc fiber of the counter and resumes
// it, under both framings, the way the resume rows of bench-compare do.
// Parks are cooperative, so the counter must answer SIGUSR1 with
// fz_quiesce. Before it did, every park failed with "the fiber did not
// stop serving for the park". The count read after the resume shows the
// fiber kept its memory.
func TestCounterParkResume(t *testing.T) {
	cgroot := os.Getenv("FIBERD_CGROUP_ROOT")
	if cgroot == "" {
		t.Skip("FIBERD_CGROUP_ROOT is unset: run in the dev container (make integration-tests)")
	}
	bin := t.TempDir()
	mustRun(t, filepath.Join(repoRoot, "sdk", "c", "template", "core"), "cargo", "build", "--release", "--locked")
	counter := filepath.Join(bin, "counter")
	mustRun(t, repoRoot, "gcc", append(counterFlags(), "-o", counter, "bench/compare/workload/counter.c",
		"sdk/c/template/core/target/release/libfiberzygote_core.a")...)
	mustRun(t, repoRoot, "go", "build", "-o", bin, "./cmd/fiberd", "./cmd/grant-issuer")

	// Not t.TempDir: fiberd mounts under its state, and a mount left
	// behind would fail the cleanup. Removal is best effort.
	state, err := os.MkdirTemp("", "counter-park")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(state) })
	key := filepath.Join(state, "issuer-key.json")
	mustRun(t, repoRoot, filepath.Join(bin, "grant-issuer"), "keygen", "-alg", "EdDSA", "-out", key)
	const issuerAddr, homeAddr, node = "127.0.0.1:18798", "127.0.0.1:18598", "counter-park"
	issuerURL := "http://" + issuerAddr
	background(t, filepath.Join(state, "issuer.log"), filepath.Join(bin, "grant-issuer"),
		"serve", "-key", key, "-addr", issuerAddr, "-issuer", issuerURL)
	waitFor(t, func() bool {
		r, err := http.Get(issuerURL + "/openid/v1/jwks")
		return err == nil && r.Body.Close() == nil
	})
	background(t, filepath.Join(state, "fiberd.log"), filepath.Join(bin, "fiberd"),
		"-state", state, "-node-id", node, "-verifier", "jwks", "-issuer", issuerURL, "-insecure-plaintext",
		"-listen", homeAddr, "-runtime", "proc", "-cgroup-root", cgroot,
		"-template", "default="+counter+" --heap-mb 8", "-template", "sha256:line="+counter+" --heap-mb 8 --framing line")
	waitFor(t, func() bool { _, err := os.Stat(filepath.Join(state, "private", "admin.sock")); return err == nil })

	cases := []struct {
		name     string
		template string
		framing  compare.Framing
		incr     int // increments after the first, before the park
	}{
		{name: "HTTP, parked after the first increment", template: "sha256:http", framing: compare.HTTP},
		{name: "HTTP, parked after four increments", template: "sha256:http", framing: compare.HTTP, incr: 3},
		{name: "line protocol, parked after four increments", template: "sha256:line", framing: compare.Line, incr: 3},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			a, err := fiberd.New(ctx, fiberd.Options{
				Target: homeAddr, IssuerKey: key, IssuerURL: issuerURL, NodeID: node, TemplateDigest: tc.template,
				Isolation: "TRUSTED", WBudget: 64 << 20, FiberMax: 2, Framing: tc.framing,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = a.Close() }()
			h, err := a.Activate(ctx, "park-"+strconv.Itoa(i))
			if err != nil {
				t.Fatal(err)
			}
			if h, _, err = a.Ready(ctx, h); err != nil {
				t.Fatal(err)
			}
			probe := compare.Probe{Framing: tc.framing, Dial: func(ctx context.Context) (net.Conn, error) { return endpoint.Dial(ctx, h.Addr) }}
			for range tc.incr {
				if _, err := probe.Run(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if err := a.Park(ctx, h); err != nil {
				t.Fatalf("park: %v", err)
			}
			r, err := a.Resume(ctx, h)
			if err != nil {
				t.Fatalf("resume: %v", err)
			}
			defer func() { _ = a.Release(context.Background(), r) }()
			probe.Dial = func(ctx context.Context) (net.Conn, error) { return endpoint.Dial(ctx, r.Addr) }
			got, err := probe.Run(ctx)
			if err != nil {
				t.Fatal(err)
			}
			// Ready counted once, then tc.incr, then this probe.
			if want := strconv.Itoa(tc.incr + 2); got.Body != want {
				t.Fatalf("count after resume %q, want %q: the fiber lost its state", got.Body, want)
			}
		})
	}
}
