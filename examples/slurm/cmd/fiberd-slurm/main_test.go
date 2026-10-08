package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
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
	"github.com/helayoty/fiberd/pkg/agent"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
)

// config is the agent's config as main builds it, from args.
func config(t *testing.T, args ...string) *agent.Config {
	t.Helper()
	var c agent.Config
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

// shortDir is a temporary directory with a short path. The agent's admin
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
// staged where the home's lane reads it.
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

// TestRunRefuses checks what stops the agent before it serves.
func TestRunRefuses(t *testing.T) {
	cases := []struct {
		name  string
		env   map[string]string
		args  []string
		grant string
		mount func(t *testing.T) string // nil is a fake cgroup mount
		err   string
		is    error
		check func(t *testing.T, c *agent.Config)
	}{
		{name: "outside an allocation", env: map[string]string{"SLURM_JOB_ID": ""}, err: "SLURM_JOB_ID",
			check: func(t *testing.T, c *agent.Config) {
				if c.GrantsDir != "" {
					t.Fatalf("grants dir = %q, want it left alone", c.GrantsDir)
				}
			}},
		{name: "the grants dir defaults to the job's, then the agent needs a verifier", err: "-verifier is required",
			check: func(t *testing.T, c *agent.Config) {
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
			err := run(c, tc.grant, "none", jobEnv(tc.env), mount)
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

// TestRunLeavesWithTheJob runs the agent in an allocation until the job
// ends. The agent stages its grant, serves, and on the job's end bumps
// its epoch and stops on its own, without an error.
func TestRunLeavesWithTheJob(t *testing.T) {
	cases := []struct {
		name  string
		state string // the job's terminal state
		epoch string // the epoch on disk once the agent left
	}{
		{"COMPLETED", "COMPLETED", "2"},
		{"CANCELLED", "CANCELLED", "2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := &logTail{}
			log.SetOutput(logs)
			t.Cleanup(func() { log.SetOutput(os.Stderr) })

			dir := t.TempDir()
			stateFile := filepath.Join(dir, "state")
			if err := os.WriteFile(stateFile, []byte("RUNNING"), 0o600); err != nil {
				t.Fatal(err)
			}
			probe := filepath.Join(dir, "probe.sh")
			if err := os.WriteFile(probe, []byte("#!/bin/sh\necho \"JobId=4242 JobState=$(cat "+stateFile+")\"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			state, grants := shortDir(t), filepath.Join(dir, "grants")
			c := config(t, "-state", state, "-listen", "127.0.0.1:0", "-insecure-plaintext", "-verifier", "insecure-json", "-runtime", "stub",
				"-grants-dir", grants, "-endpoint-host", "127.0.0.1", "-stale-ttl", "200ms")

			done := make(chan error, 1)
			go func() { done <- run(c, "staged-token", "/bin/sh "+probe, jobEnv(nil), fakeCgroup(t)) }()

			// Wait for the warm path, then for an answer from it.
			addrRE := regexp.MustCompile(`warm path on (\S+)`)
			var addr string
			for deadline := time.Now().Add(20 * time.Second); addr == ""; time.Sleep(10 * time.Millisecond) {
				if m := logs.find(addrRE); m != nil {
					addr = m[1]
				}
				select {
				case err := <-done:
					t.Fatalf("run returned before serving: %v", err)
				default:
				}
				if time.Now().After(deadline) {
					t.Fatal("the agent never served")
				}
			}
			conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			client := grantv1.NewFibersClient(conn)
			for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(10 * time.Millisecond) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				// A deadline already past is refused by the serving agent.
				_, err := client.Clone(ctx, &grantv1.CloneRequest{Deadline: timestamppb.New(time.Unix(1, 0))})
				cancel()
				if status.Code(err) == codes.InvalidArgument {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("the agent does not answer: %v", err)
				}
			}
			if got, err := os.ReadFile(filepath.Join(grants, "job.jwt")); err != nil || string(got) != "staged-token\n" {
				t.Fatalf("staged grant = %q (%v), want the -grant token", got, err)
			}

			if err := os.WriteFile(stateFile, []byte(tc.state), 0o600); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("run = %v, want a clean stop when the job ends", err)
				}
			case <-time.After(20 * time.Second):
				t.Fatal("the job ended but the agent kept running")
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

// TestMainExit runs main in a child process and checks its exit status.
// It is 0 for -h, 2 for a bad command line and 1 for any other failure.
func TestMainExit(t *testing.T) {
	if args, ok := os.LookupEnv("FIBERD_SLURM_TEST_ARGS"); ok {
		os.Args = append([]string{"fiberd-slurm"}, strings.Fields(args)...)
		main()
		os.Exit(0)
	}
	cases := []struct {
		name   string
		args   string
		code   int
		stderr string
	}{
		{name: "-h exits 0", args: "-h", code: 0, stderr: "-slurm-probe"},
		{name: "a bad flag exits 2", args: "-nope", code: 2, stderr: "flag provided but not defined: -nope"},
		{name: "outside an allocation exits 1", args: "-insecure-plaintext", code: 1, stderr: "SLURM_JOB_ID unset"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestMainExit$")
			cmd.Env = append(os.Environ(), "FIBERD_SLURM_TEST_ARGS="+tc.args, "SLURM_JOB_ID=", "FIBERD_GRANT=")
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			err := cmd.Run()
			code := 0
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				code = exit.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != tc.code || !strings.Contains(stderr.String(), tc.stderr) {
				t.Fatalf("exit %d with %q, want %d with %q", code, stderr.String(), tc.code, tc.stderr)
			}
		})
	}
}
