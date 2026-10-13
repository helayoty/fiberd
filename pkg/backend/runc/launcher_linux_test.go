//go:build linux

package runc

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
)

// TestExitedIn checks the /proc reading waitPID relies on. A zombie counts
// as exited, because nobody reaps `runc run` until the channel is up.
func TestExitedIn(t *testing.T) {
	cases := []struct {
		name string
		stat string // /proc/<pid>/stat, "" for no entry
		want bool
	}{
		{name: "a running process is not exited", stat: "7 (runc) S 1 7 7 0 -1 4194560 0\n"},
		{name: "a sleeping process with a parenthesis in its name", stat: "7 (runc (init)) S 1 7 7 0\n"},
		{name: "an unreaped zombie is exited", stat: "7 (runc) Z 1 7 7 0\n", want: true},
		{name: "a dead process is exited", stat: "7 (runc) X 1 7 7 0\n", want: true},
		{name: "a pid that is gone is exited", want: true},
		{name: "a stat without a state is exited", stat: "7 (runc)", want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			procRoot := t.TempDir()
			if tc.stat != "" {
				if err := os.MkdirAll(filepath.Join(procRoot, "7"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(procRoot, "7", "stat"), []byte(tc.stat), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if got := exitedIn(procRoot, 7); got != tc.want {
				t.Fatalf("exitedIn = %v, want %v", got, tc.want)
			}
		})
	}
	t.Run("under the real /proc", func(t *testing.T) {
		if exited(os.Getpid()) {
			t.Fatal("this process reads as exited")
		}
		if !exited(1<<22 + 1) {
			t.Fatal("a pid past pid_max reads as alive")
		}
	})
}

// TestWaitPIDEnds checks that waitPID returns once `runc run` is gone,
// even when the context has no deadline. It once spun forever, because
// nothing had waited on the command to set its ProcessState. An error
// about a container that never came up quotes runc's log and the zygote's.
func TestWaitPIDEnds(t *testing.T) {
	cases := []struct {
		name    string
		gone    string // "" alive, "exited" gone unreaped, else the reaped status
		asks    int    // `runc state` answers after this many refusals, 0 for never
		cancel  bool   // cancel the context once runc has been asked
		logs    bool   // runc's log and the zygote's hold a line each
		wantPID bool   // the init is reported
		wantErr string
		wantIn  []string // what else the error must quote
	}{
		{name: "runc run exits early", gone: "exited", wantErr: "exited before the container was up:"},
		{name: "runc run was reaped already", gone: "exit status 0", wantErr: "exited before the container was up (exit status 0)"},
		{name: "runc run lives and the caller gives up", cancel: true, wantErr: "context canceled"},
		{name: "runc reports the init", asks: 1, wantPID: true},
		{name: "runc reports the init after a refusal", asks: 2, wantPID: true},
		// The logs are the only evidence once runc has torn its state down.
		{name: "an early exit quotes runc's log and the zygote's", gone: "exited", logs: true, wantErr: "exited before the container was up",
			wantIn: []string{"runc log ", "(last 36 bytes):\nlevel=error msg=\"mount proc: EPERM\"", "zygote log ", "(last 11 bytes):\nzygote: hi"}},
		{name: "an early exit says which logs are missing", gone: "exited", wantErr: "exited before the container was up",
			wantIn: []string{"runc log ", ".runc.log: empty or missing", "zygote log ", "zygote.log: empty or missing"}},
		{name: "a reaped exit carries the exit status and the logs", gone: "exit status 1", logs: true, wantErr: "exited before the container was up (exit status 1)",
			wantIn: []string{"mount proc: EPERM", "zygote: hi"}},
		{name: "giving up quotes the logs too", cancel: true, logs: true, wantErr: "context canceled",
			wantIn: []string{"mount proc: EPERM", "zygote: hi"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var asked atomic.Int64
			l, _ := newLauncher(t, func(sub string, _ []string) ([]byte, error) {
				if sub == "state" && int(asked.Add(1)) >= tc.asks && tc.asks > 0 {
					return []byte(`{"pid": 4242}`), nil
				}
				return []byte("container does not exist"), os.ErrNotExist
			})
			spec := backend.WarmSpec{GrantUID: "g", WorkDir: filepath.Join(t.TempDir(), "g")}
			if tc.logs {
				for path, line := range map[string]string{
					l.runcLog(spec): "level=error msg=\"mount proc: EPERM\"\n",
					filepath.Join(spec.WorkDir, "zygote.log"): "zygote: hi\n",
				} {
					if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte(line), 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			gone := func() (string, bool) {
				if tc.cancel {
					cancel()
				}
				switch tc.gone {
				case "":
					return "", false
				case "exited":
					return "", true
				default:
					return tc.gone, true
				}
			}
			type result struct {
				pid int
				err error
			}
			done := make(chan result, 1)
			go func() {
				pid, err := l.waitPID(ctx, spec, gone)
				done <- result{pid, err}
			}()
			select {
			case r := <-done:
				if tc.wantPID {
					if r.err != nil || r.pid != 4242 {
						t.Fatalf("waitPID = %d, %v, want 4242", r.pid, r.err)
					}
					if int(asked.Load()) != tc.asks {
						t.Fatalf("runc state asked %d times, want %d", asked.Load(), tc.asks)
					}
					return
				}
				if r.err == nil || !strings.Contains(r.err.Error(), tc.wantErr) {
					t.Fatalf("waitPID = %v, want an error containing %q", r.err, tc.wantErr)
				}
				for _, want := range tc.wantIn {
					if !strings.Contains(r.err.Error(), want) {
						t.Errorf("waitPID = %v, want it to quote %q", r.err, want)
					}
				}
			case <-time.After(5 * time.Second):
				t.Fatal("waitPID did not return")
			}
		})
	}
}
