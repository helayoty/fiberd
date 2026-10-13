//go:build linux && integration

package slurmtest

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
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

	"github.com/helayoty/fiberd/examples/slurm/home"
)

// TestSlurmMainExit runs the binary and checks its exit status. It is 0
// for -h, 2 for a bad command line and 1 for any other failure.
func TestSlurmMainExit(t *testing.T) {
	cases := []struct {
		name   string
		args   []string
		code   int
		stderr string
	}{
		{name: "-h exits 0", args: []string{"-h"}, code: 0, stderr: "-slurm-probe"},
		{name: "a bad flag exits 2", args: []string{"-nope"}, code: 2, stderr: "flag provided but not defined: -nope"},
		{name: "outside an allocation exits 1", args: []string{"-insecure-plaintext"}, code: 1, stderr: "SLURM_JOB_ID unset"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(fiberdSlurm, tc.args...)
			cmd.Env = append(os.Environ(), "SLURM_JOB_ID=", "FIBERD_GRANT=")
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

// tail collects a process's stderr while a test runs.
type tail struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *tail) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *tail) find(re *regexp.Regexp) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return re.FindStringSubmatch(l.buf.String())
}

func (l *tail) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// TestFiberdLeavesWithTheJob runs the binary in an allocation until the
// job ends, with a shell script as the probe and the job step's cgroup
// delegated from this container's own. fiberd stages its grant, serves,
// and on the job's end bumps its epoch and exits 0 on its own, through
// the home's default SIGTERM to itself.
func TestFiberdLeavesWithTheJob(t *testing.T) {
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
			dir := t.TempDir()
			probe, set := probeScript(t, dir)
			state, grants := shortDir(t), filepath.Join(dir, "grants")
			cmd := exec.Command(fiberdSlurm, "-state", state, "-listen", "127.0.0.1:0", "-insecure-plaintext",
				"-verifier", "insecure-json", "-runtime", "stub", "-grants-dir", grants, "-endpoint-host", "127.0.0.1",
				"-stale-ttl", "200ms", "-grant", "staged-token", "-slurm-probe", "/bin/sh "+probe)
			cmd.Env = append(os.Environ(), "SLURM_JOB_ID=4242", "SLURMD_NODENAME=127.0.0.1", "SLURM_CPUS_ON_NODE=4")
			logs := &tail{}
			cmd.Stderr = logs
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			t.Cleanup(func() {
				_ = cmd.Process.Kill()
				<-done
			})

			addrRE := regexp.MustCompile(`warm path on (\S+)`)
			var addr string
			waitFor(t, "fiberd to serve", 30*time.Second, func() bool {
				select {
				case err := <-done:
					done <- err
					t.Fatalf("fiberd-slurm exited before serving: %v\n%s", err, logs)
				default:
				}
				if m := logs.find(addrRE); m != nil {
					addr = m[1]
				}
				return addr != ""
			})
			conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			client := grantv1.NewFibersClient(conn)
			waitFor(t, "fiberd to answer", 20*time.Second, func() bool {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				// A deadline already past is refused by the serving fiberd.
				_, err := client.Clone(ctx, &grantv1.CloneRequest{Deadline: timestamppb.New(time.Unix(1, 0))})
				return status.Code(err) == codes.InvalidArgument
			})
			if got, err := os.ReadFile(filepath.Join(grants, "job.jwt")); err != nil || string(got) != "staged-token\n" {
				t.Fatalf("staged grant = %q (%v), want the -grant token", got, err)
			}

			set(tc.state)
			select {
			case err := <-done:
				done <- err
				if err != nil {
					t.Fatalf("fiberd-slurm = %v, want exit 0 when the job ends\n%s", err, logs)
				}
			case <-time.After(30 * time.Second):
				t.Fatalf("the job ended but fiberd kept running\n%s", logs)
			}
			got, err := os.ReadFile(filepath.Join(state, "private", "epoch"))
			if err != nil || strings.TrimSpace(string(got)) != tc.epoch {
				t.Fatalf("epoch = %q (%v), want %s: the job's end bumps it", got, err, tc.epoch)
			}
			if want := "slurm: scope lost: job 4242 is " + tc.state; !strings.Contains(logs.String(), want) {
				t.Fatalf("scope loss not logged as %q\n%s", want, logs)
			}
		})
	}
}

// TestSlurmHomeSIGTERMOnJobEnd checks the home's defaults in place. The
// probe is run as a command, and the end of the job is SIGTERM to this
// process. The job is seen RUNNING first, so the exec answer counted as
// liveness before the state flips.
func TestSlurmHomeSIGTERMOnJobEnd(t *testing.T) {
	cases := []struct {
		name  string
		state string
	}{
		{"CANCELLED sends SIGTERM", "CANCELLED"},
		{"COMPLETED sends SIGTERM", "COMPLETED"},
	}
	env := func(k string) string {
		return map[string]string{"SLURM_JOB_ID": "4242", "SLURMD_NODENAME": "localhost"}[k]
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGTERM)
			defer signal.Stop(sig)
			probe, set := probeScript(t, t.TempDir())
			const stale = time.Second
			h, err := home.New(home.Config{Env: env, CgroupMount: fakeCgroup(t), StaleTTL: stale, Probe: []string{"/bin/sh", probe}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			start := time.Now()
			go h.Run(ctx)
			// Reachable a quarter TTL ahead means a sync within the last
			// quarter, close enough to clear the hysteresis. Once a whole
			// TTL has passed since New the boot sync is stale, so only the
			// script's RUNNING answer does that.
			waitFor(t, "the probe to report RUNNING", 10*time.Second, func() bool {
				return time.Since(start) > stale && h.Health().Healthy(time.Now().Add(stale/4))
			})
			set(tc.state)
			select {
			case <-sig:
			case <-time.After(10 * time.Second):
				t.Fatal("the job ended but fiberd got no SIGTERM")
			}
		})
	}
}
