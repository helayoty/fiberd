package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/fiberd"
	"github.com/helayoty/fiberd/pkg/grant"

	"github.com/helayoty/fiberd/examples/slurm/home"
)

// config is fiberd's config as main builds it, from args.
func config(t *testing.T, args ...string) *fiberd.Config {
	t.Helper()
	var c fiberd.Config
	fs := flag.NewFlagSet("fiberd-slurm", flag.ContinueOnError)
	c.Bind(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	c.Finish()
	return &c
}

func jobEnv(over map[string]string) func(string) string {
	base := map[string]string{"SLURM_JOB_ID": "4242", "SLURMD_NODENAME": "127.0.0.1", "SLURM_CPUS_ON_NODE": "4"}
	for k, v := range over {
		base[k] = v
	}
	return func(k string) string { return base[k] }
}

func fakeCgroup(t *testing.T) string {
	cg := t.TempDir()
	if err := os.WriteFile(filepath.Join(cg, "cgroup.subtree_control"), []byte("memory pids\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return cg
}

// shortDir is a temporary directory with a short path. fiberd's admin
// socket lives under it, and unix socket paths are limited to about 100
// bytes, more than the test temp dir leaves on macOS.
func shortDir(t *testing.T) string {
	d, err := os.MkdirTemp("/tmp", "fs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// issuer serves an issuer's discovery and keys, and mints grants with it.
func issuer(t *testing.T) *grant.Issuer {
	key, err := grant.GenerateKey("EdDSA")
	if err != nil {
		t.Fatal(err)
	}
	iss := &grant.Issuer{Key: key}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { iss.Handler().ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	iss.URL = srv.URL
	return iss
}

func mint(t *testing.T, iss *grant.Issuer, audience string, lease time.Duration) string {
	tok, err := iss.Mint(core.Grant{UID: "g1", Audience: audience, FiberMax: 1, LeaseExpiry: time.Now().Add(lease).Truncate(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestStage checks that a grant is verified before it is staged, and
// staged where the home's grant directory reads it.
func TestStage(t *testing.T) {
	iss := issuer(t)
	valid := mint(t, iss, "node-a", time.Hour)
	cases := []struct {
		name     string
		args     []string // flags, before -grants-dir
		grant    func(t *testing.T) string
		grantDir func(t *testing.T) string // nil is a fresh directory
		staged   string                    // the token staged, or empty when stage must fail
		err      string
		is       error
	}{
		{name: "insecure-json stages the grant unverified", args: []string{"-verifier", "insecure-json"},
			grant: func(*testing.T) string { return "not-a-jwt" }, staged: "not-a-jwt"},
		{name: "@file reads the grant from a file", args: []string{"-verifier", "insecure-json"},
			grant: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "grant")
				if err := os.WriteFile(p, []byte("  from-file\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				return "@" + p
			}, staged: "from-file"},
		{name: "@file that does not exist", args: []string{"-verifier", "insecure-json"},
			grant: func(*testing.T) string { return "@/nonexistent/grant" }, err: "-grant", is: fs.ErrNotExist},
		{name: "jwks stages a grant that verifies for this node", args: []string{"-verifier", "jwks", "-issuer", iss.URL, "-node-id", "node-a"},
			grant: func(*testing.T) string { return valid }, staged: valid},
		{name: "jwks without an issuer cannot verify", args: []string{"-verifier", "jwks"},
			grant: func(*testing.T) string { return valid }, err: "needs -issuer"},
		{name: "jwks refuses a grant for another node", args: []string{"-verifier", "jwks", "-issuer", iss.URL, "-node-id", "node-b"},
			grant: func(*testing.T) string { return valid }, err: "does not verify for node node-b", is: grant.ErrWrongAudience},
		{name: "jwks refuses an expired grant", args: []string{"-verifier", "jwks", "-issuer", iss.URL, "-node-id", "node-a"},
			grant: func(t *testing.T) string { return mint(t, iss, "node-a", -time.Hour) }, err: "expired"},
		{name: "no verifier", grant: func(*testing.T) string { return valid }, err: `-verifier ""`},
		{name: "a grants dir that cannot be made", args: []string{"-verifier", "insecure-json"},
			grant: func(*testing.T) string { return "tok" },
			grantDir: func(t *testing.T) string {
				f := filepath.Join(t.TempDir(), "file")
				if err := os.WriteFile(f, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				return filepath.Join(f, "grants")
			}, is: syscall.ENOTDIR},
		{name: "a grant file that cannot be written", args: []string{"-verifier", "insecure-json"},
			grant: func(*testing.T) string { return "tok" },
			grantDir: func(t *testing.T) string {
				d := t.TempDir()
				if err := os.Mkdir(filepath.Join(d, "job.jwt"), 0o700); err != nil {
					t.Fatal(err)
				}
				return d
			}, is: syscall.EISDIR},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "grants")
			if tc.grantDir != nil {
				dir = tc.grantDir(t)
			}
			c := config(t, append(tc.args, "-grants-dir", dir)...)
			err := stage(c, tc.grant(t))
			if tc.staged == "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("stage = %v, want an error naming %q", err, tc.err)
				}
				if tc.is != nil && !errors.Is(err, tc.is) {
					t.Fatalf("stage = %v, want it to wrap %v", err, tc.is)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "job.jwt")
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.staged+"\n" {
				t.Fatalf("staged %q, want %q", got, tc.staged+"\n")
			}
			for p, want := range map[string]os.FileMode{dir: 0o700, path: 0o600} {
				if st, err := os.Stat(p); err != nil || st.Mode().Perm() != want {
					t.Fatalf("%s: mode %v (%v), want %v", p, st.Mode().Perm(), err, want)
				}
			}
		})
	}
}

// TestProbeCommand checks how -slurm-probe is read.
func TestProbeCommand(t *testing.T) {
	cases := []struct {
		name  string
		probe string
		want  []string
	}{
		{"empty is the home's default (scontrol)", "", nil},
		{"none is no probe: liveness from a timer", "none", []string{}},
		{"a command is split into its arguments", " /usr/bin/scontrol  show job ", []string{"/usr/bin/scontrol", "show", "job"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := probeCommand(tc.probe)
			if (got == nil) != (tc.want == nil) || !slices.Equal(got, tc.want) {
				t.Fatalf("probe = %#v, want %#v", got, tc.want)
			}
		})
	}
}

// TestRunRefuses checks what stops fiberd before it serves.
func TestRunRefuses(t *testing.T) {
	cases := []struct {
		name  string
		env   map[string]string
		args  []string
		grant string
		mount func(t *testing.T) string // nil is a fake cgroup mount
		err   string
		is    error
		check func(t *testing.T, c *fiberd.Config)
	}{
		{name: "outside an allocation", env: map[string]string{"SLURM_JOB_ID": ""}, err: "SLURM_JOB_ID",
			check: func(t *testing.T, c *fiberd.Config) {
				if c.GrantsDir != "" {
					t.Fatalf("grants dir = %q, want it left alone", c.GrantsDir)
				}
			}},
		{name: "the grants dir defaults to the job's, then fiberd needs a verifier", err: "-verifier is required",
			check: func(t *testing.T, c *fiberd.Config) {
				if c.GrantsDir != "/run/fiberd/job-4242/grants" {
					t.Fatalf("grants dir = %q, want the job's", c.GrantsDir)
				}
			}},
		{name: "a grant that cannot be staged", args: []string{"-verifier", "insecure-json"}, grant: "@/nonexistent/grant",
			err: "-grant", is: fs.ErrNotExist},
		{name: "an endpoint family that does not exist", args: []string{"-verifier", "insecure-json", "-endpoint-family", "ipx"},
			err: "ipx"},
		{name: "a listen address without a port", args: []string{"-verifier", "insecure-json", "-listen", "localhost"},
			err: "-listen"},
		{name: "a cgroup mount without the job step's cgroup", args: []string{"-verifier", "insecure-json"},
			mount: func(t *testing.T) string { return t.TempDir() }, err: "slurm: cgroup", is: fs.ErrNotExist},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"-state", shortDir(t), "-listen", "127.0.0.1:0", "-insecure-plaintext"}, tc.args...)
			if !slices.Contains(tc.args, "-grants-dir") && tc.check == nil {
				args = append(args, "-grants-dir", filepath.Join(t.TempDir(), "grants"))
			}
			c := config(t, args...)
			mount := fakeCgroup(t)
			if tc.mount != nil {
				mount = tc.mount(t)
			}
			err := run(context.Background(), c, tc.grant, "none", jobEnv(tc.env), home.Config{CgroupMount: mount})
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("run = %v, want an error naming %q", err, tc.err)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("run = %v, want it to wrap %v", err, tc.is)
			}
			if tc.check != nil {
				tc.check(t, c)
			}
		})
	}
}

// logTail collects the standard logger's output while a test runs.
type logTail struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logTail) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logTail) find(re *regexp.Regexp) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return re.FindStringSubmatch(l.buf.String())
}

// fakeProbe answers the job's state in process. The test flips it.
type fakeProbe struct {
	mu    sync.Mutex
	state string
}

func (p *fakeProbe) run(context.Context, []string) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return []byte("JobId=4242 JobState=" + p.state + "\n"), nil
}

func (p *fakeProbe) set(state string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state = state
}

// TestRunLeavesWithTheJob runs fiberd in an allocation until the job
// ends. fiberd stages its grant, serves, and on the job's end bumps
// its epoch and stops on its own, without an error. The job's end
// stops it through the context here, as the home's default SIGTERM
// does in the binary (tests/ TestFiberdLeavesWithTheJob).
func TestRunLeavesWithTheJob(t *testing.T) {
	cases := []struct {
		name  string
		state string // the job's terminal state
		epoch string // the epoch on disk once fiberd left
	}{
		{"COMPLETED", "COMPLETED", "2"},
		{"CANCELLED", "CANCELLED", "2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := &logTail{}
			log.SetOutput(logs)
			t.Cleanup(func() { log.SetOutput(os.Stderr) })

			probe := &fakeProbe{state: "RUNNING"}
			state, grants := shortDir(t), filepath.Join(t.TempDir(), "grants")
			c := config(t, "-state", state, "-listen", "127.0.0.1:0", "-insecure-plaintext", "-verifier", "insecure-json", "-runtime", "stub",
				"-grants-dir", grants, "-endpoint-host", "127.0.0.1", "-stale-ttl", "200ms")
			ready := make(chan net.Addr, 1)
			c.Ready = func(grpc, _, _ net.Addr) { ready <- grpc }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ended := make(chan struct{}, 1)
			base := home.Config{CgroupMount: fakeCgroup(t), RunProbe: probe.run, OnJobEnd: func() { ended <- struct{}{}; cancel() }}

			done := make(chan error, 1)
			go func() { done <- run(ctx, c, "staged-token", "/usr/bin/scontrol show job", jobEnv(nil), base) }()

			var addr net.Addr
			select {
			case addr = <-ready:
			case err := <-done:
				t.Fatalf("run returned before serving: %v", err)
			case <-time.After(20 * time.Second):
				t.Fatal("fiberd never served")
			}
			conn, err := grpc.NewClient(addr.String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			client := grantv1.NewFibersClient(conn)
			for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(10 * time.Millisecond) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				// A deadline already past is refused by the serving fiberd.
				_, err := client.Clone(ctx, &grantv1.CloneRequest{Deadline: timestamppb.New(time.Unix(1, 0))})
				cancel()
				if status.Code(err) == codes.InvalidArgument {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("fiberd does not answer: %v", err)
				}
			}
			if got, err := os.ReadFile(filepath.Join(grants, "job.jwt")); err != nil || string(got) != "staged-token\n" {
				t.Fatalf("staged grant = %q (%v), want the -grant token", got, err)
			}

			probe.set(tc.state)
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("run = %v, want a clean stop when the job ends", err)
				}
			case <-time.After(20 * time.Second):
				t.Fatal("the job ended but fiberd kept running")
			}
			select {
			case <-ended:
			default:
				t.Fatal("fiberd stopped without the job's end")
			}
			got, err := os.ReadFile(filepath.Join(state, "private", "epoch"))
			if err != nil || strings.TrimSpace(string(got)) != tc.epoch {
				t.Fatalf("epoch = %q (%v), want %s: the job's end bumps it", got, err, tc.epoch)
			}
			if m := logs.find(regexp.MustCompile(`slurm: scope lost: (job 4242 is \w+)`)); m == nil || m[1] != fmt.Sprintf("job 4242 is %s", tc.state) {
				t.Fatalf("scope loss logged as %q, want job 4242 is %s", m, tc.state)
			}
		})
	}
}

// TestExitCode checks the exit status main gives each outcome. The
// statuses of the binary itself are checked in tests/ TestSlurmMainExit.
func TestExitCode(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"a clean stop exits 0", nil, 0},
		{"-h exits 0", usageError{flag.ErrHelp}, 0},
		{"a bad command line exits 2", usageError{errors.New("flag provided but not defined: -nope")}, 2},
		{"any other failure exits 1", errors.New("slurm: not inside an allocation (SLURM_JOB_ID unset)"), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := exitCode(tc.err); got != tc.want {
				t.Fatalf("exitCode(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}
