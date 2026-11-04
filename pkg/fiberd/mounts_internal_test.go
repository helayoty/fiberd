package fiberd

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/Azure/fiberd/pkg/sys/mounts"
)

// TestPrepareMounts checks that fiberd prepares the container's mounts
// for every runtime but the stub, starts on with a warning when only the
// CRIU sysctls stayed read-only, and stops on any other failure.
func TestPrepareMounts(t *testing.T) {
	errCgroup := errors.New("mounts: remount /sys/fs/cgroup read-write: operation not permitted")
	errSysctls := fmt.Errorf("%w: bind /proc/sys/kernel/ns_last_pid onto itself: operation not permitted", mounts.ErrSysctlsReadOnly)
	cases := []struct {
		name     string
		runtime  string
		prepare  error // what the replaced Prepare returns
		wantCall bool
		wantErr  error
		wantLog  []string // substrings of the one warning, none for silence
	}{
		{name: "stub prepares nothing", runtime: "stub", prepare: errCgroup},
		{name: "proc prepares", runtime: "proc", wantCall: true},
		{name: "gvisor prepares", runtime: "gvisor", wantCall: true},
		{name: "runc prepares", runtime: "runc", wantCall: true},
		{name: "hyperlight prepares", runtime: "hyperlight", wantCall: true},
		{
			name:     "read-only sysctls are a warning",
			runtime:  "proc",
			prepare:  errSysctls,
			wantCall: true,
			wantLog:  []string{"WARNING", "the CRIU sysctls stayed read-only", "warm tier only", "/proc/sys/kernel/ns_last_pid"},
		},
		{
			name:     "a cgroup failure stops fiberd",
			runtime:  "proc",
			prepare:  errCgroup,
			wantCall: true,
			wantErr:  errCgroup,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := prepareMounts
			t.Cleanup(func() { prepareMounts = old })
			called := false
			prepareMounts = func() error {
				called = true
				return tc.prepare
			}
			var logs bytes.Buffer
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(os.Stderr) })

			c := &Config{}
			c.Runtime.Name = tc.runtime
			err := c.PrepareMounts()
			if called != tc.wantCall {
				t.Fatalf("Prepare called = %v, want %v", called, tc.wantCall)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("PrepareMounts = %v, want %v", err, tc.wantErr)
			}
			if len(tc.wantLog) == 0 && logs.Len() != 0 {
				t.Fatalf("logged %q, want nothing", logs.String())
			}
			for _, want := range tc.wantLog {
				if !strings.Contains(logs.String(), want) {
					t.Fatalf("log %q lacks %q", logs.String(), want)
				}
			}
		})
	}
}
