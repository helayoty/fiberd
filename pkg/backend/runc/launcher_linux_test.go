//go:build linux

package runc

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
)

// TestExited checks the /proc reading waitPID relies on. A zombie counts
// as exited, because nobody reaps `runc run` until the channel is up.
func TestExited(t *testing.T) {
	cases := []struct {
		name  string
		start func(t *testing.T) int
		want  bool
	}{
		{name: "a running process is not exited", start: func(t *testing.T) int {
			cmd := exec.Command("sleep", "10")
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
			return cmd.Process.Pid
		}},
		{name: "an unreaped zombie is exited", want: true, start: func(t *testing.T) int {
			cmd := exec.Command("true")
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Wait() })
			pid := cmd.Process.Pid
			for deadline := time.Now().Add(2 * time.Second); !zombie(pid); time.Sleep(5 * time.Millisecond) {
				if time.Now().After(deadline) {
					t.Fatal("the child never became a zombie")
				}
			}
			return pid
		}},
		{name: "a reaped process is exited", want: true, start: func(t *testing.T) int {
			cmd := exec.Command("true")
			if err := cmd.Run(); err != nil {
				t.Fatal(err)
			}
			return cmd.Process.Pid
		}},
		{name: "a pid that never existed is exited", want: true, start: func(*testing.T) int { return 1<<31 - 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := exited(tc.start(t)); got != tc.want {
				t.Fatalf("exited = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestWaitPIDEnds checks that waitPID returns once `runc run` is gone,
// even when the context has no deadline. It once spun forever, because
// nothing had waited on the command to set its ProcessState.
func TestWaitPIDEnds(t *testing.T) {
	cases := []struct {
		name    string
		run     string // the stand-in for `runc run`
		reap    bool   // wait on it before asking, so ProcessState is set
		runc    string // the fake runc's body. "" fails `runc state` as for a container that never came up
		cancel  bool   // cancel the context after a moment
		wantPID bool   // the init is reported
		wantErr string
	}{
		{name: "runc run exits early", run: "true", wantErr: "exited before the container was up"},
		{name: "runc run was reaped already", run: "true", reap: true, wantErr: "exited before the container was up"},
		{name: "runc run lives and the caller gives up", run: "sleep", cancel: true, wantErr: "context canceled"},
		{name: "runc reports the init", run: "sleep", runc: stateBody(4242), wantPID: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := &launcher{opt: Options{Runc: "false", StateDir: t.TempDir()}}
			if tc.runc != "" {
				l.opt.Runc, _ = fakeRunc(t, tc.runc)
			}
			args := []string{}
			if tc.run == "sleep" {
				args = append(args, "10")
			}
			cmd := exec.Command(tc.run, args...)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
			if tc.reap {
				_ = cmd.Wait()
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				time.AfterFunc(50*time.Millisecond, cancel)
			}
			type result struct {
				pid int
				err error
			}
			done := make(chan result, 1)
			go func() {
				pid, err := l.waitPID(ctx, backend.WarmSpec{GrantUID: "g"}, cmd)
				done <- result{pid, err}
			}()
			select {
			case r := <-done:
				if tc.wantPID {
					if r.err != nil || r.pid != 4242 {
						t.Fatalf("waitPID = %d, %v, want 4242", r.pid, r.err)
					}
					return
				}
				if r.err == nil || !strings.Contains(r.err.Error(), tc.wantErr) {
					t.Fatalf("waitPID = %v, want an error containing %q", r.err, tc.wantErr)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("waitPID did not return")
			}
		})
	}
}

// zombie reports whether pid is in state Z.
func zombie(pid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	return i >= 0 && i+2 < len(s) && s[i+2] == 'Z'
}
