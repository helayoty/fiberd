//go:build linux

package proctest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// TestExitWakesZygote pins that a fiber's exit wakes the zygote's loop at
// once. The loop takes SIGCHLD from a signalfd in its poll set, so the
// EXITED line, and with it Release, follows the kill within a few
// milliseconds. Without it the loop learnt of the exit at its next 100ms
// timeout, and Release of a lone fiber took about 100ms every time. The
// bound is generous and taken on the median of several releases, so a
// loaded host does not fail it. The fiber must start with the signal
// unblocked and without the descriptor, on the clone3 birth and on the
// legacy clone alike.
func TestExitWakesZygote(t *testing.T) {
	const releases = 7
	const bound = 30 * time.Millisecond
	cases := []struct {
		name     string
		template func(t *testing.T) string
	}{
		{name: "clone3 birth", template: func(*testing.T) string { return zygoteBin + " --heap-mb 16" }},
		{name: "legacy clone without clone3", template: func(t *testing.T) string { return noClone3(t) + " " + zygoteBin + " --heap-mb 16" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRuntimeFrom(t, nil, tc.template(t))
			ctx := context.Background()
			g := core.Grant{UID: "wake", TemplateDigest: "sha256:ref"}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			var took []time.Duration
			for i := 1; i <= releases; i++ {
				fence := core.Fence{GrantUID: "wake", Epoch: 1, Seq: uint64(i)}
				h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: fence, Deadline: 2 * time.Second})
				if err != nil {
					t.Fatalf("clone %d: %v", i, err)
				}
				if i == 1 {
					// The zygote's block and its descriptor are its own.
					if got := talk(t, h.Endpoint, "status SigBlk"); got != "0000000000000000" {
						t.Fatalf("fiber SigBlk = %q, want none blocked", got)
					}
					if fd := signalfdOf(t, peerPID(t, h.Endpoint)); fd != "" {
						t.Fatalf("fiber holds the zygote's signalfd at fd %s", fd)
					}
				}
				t0 := time.Now()
				if err := rt.Release(ctx, h.ID, false); err != nil {
					t.Fatalf("release %d: %v", i, err)
				}
				took = append(took, time.Since(t0))
			}
			sort.Slice(took, func(i, j int) bool { return took[i] < took[j] })
			median := took[len(took)/2]
			t.Logf("release of a lone fiber: p50=%s min=%s max=%s", median.Round(10*time.Microsecond), took[0].Round(10*time.Microsecond), took[len(took)-1].Round(10*time.Microsecond))
			if median > bound {
				t.Fatalf("release p50 = %s, want under %s: the fiber's exit did not wake the zygote's loop", median, bound)
			}
		})
	}
}

// signalfdOf is the number of a signalfd among pid's descriptors, or "".
func signalfdOf(t *testing.T, pid int) string {
	t.Helper()
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("descriptors of %d: %v", pid, err)
	}
	for _, e := range ents {
		target, err := os.Readlink(filepath.Join(dir, e.Name()))
		if err == nil && strings.Contains(target, "signalfd") {
			return e.Name()
		}
	}
	return ""
}
