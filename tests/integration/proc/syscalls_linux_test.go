//go:build linux && integration

package proctest

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// TestCloneSyscallBudget pins how many system calls a fiber makes on its
// way to ready in the two stretches its record and its channel added:
// from its fork to the read of its record off fd 4, and from that read
// to the first thing after it, opening /dev/null, where it makes its
// own pair. Every call there is a cost on every clone, so the budget is
// what the stretch needs and nothing more. The zygote runs under strace
// -f, and the fiber's lines alone are counted.
func TestCloneSyscallBudget(t *testing.T) {
	if _, err := exec.LookPath("strace"); err != nil {
		t.Skip("strace is not installed")
	}
	cases := []struct {
		name   string
		from   *regexp.Regexp // the stretch starts after the line matching this, nil for the fiber's first line
		to     *regexp.Regexp // and ends before the line matching this
		budget int
	}{
		// close the ready pipe's read end, close the zygote's SIGCHLD
		// descriptor, dup the ready pipe to 3 and the channel to 4,
		// close_range
		{name: "fork to record", to: regexp.MustCompile(`^recvmsg\(4,`), budget: 5},
		// socketpair, dup2 to 4, dup2 to 5, close the end left over
		{name: "record to own pair", from: regexp.MustCompile(`^recvmsg\(4,`), to: regexp.MustCompile(`^openat\(AT_FDCWD, "/dev/null"`), budget: 4},
	}
	out := filepath.Join(t.TempDir(), "zygote.strace")
	rt := newRuntimeFrom(t, nil, "strace -f -o "+out+" "+zygoteBin+" --heap-mb 32")
	ctx := context.Background()
	g := core.Grant{UID: "gsys", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 5 * time.Second})
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	t.Cleanup(func() { _ = rt.Release(ctx, h.ID, true) })
	if got := talk(t, h.Endpoint, "fence"); got != h.ID {
		t.Fatalf("fence = %q, want %q", got, h.ID)
	}
	calls := fiberCalls(t, out)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stretch []string
			in := tc.from == nil
			for _, c := range calls {
				if !in {
					in = tc.from.MatchString(c)
					continue
				}
				if tc.to.MatchString(c) {
					break
				}
				stretch = append(stretch, c)
			}
			if len(stretch) > tc.budget {
				t.Fatalf("%d system calls, budget %d:\n%s", len(stretch), tc.budget, strings.Join(stretch, "\n"))
			}
		})
	}
}

// fiberCalls is every system call the fiber made, in order, from the
// strace -f output at path: the lines of the one pid that wrote the
// ready byte on fd 3, each with its pid stripped and a call that was
// interrupted counted where it began.
func fiberCalls(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	byPID := map[string][]string{}
	var fiber string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		pid, rest, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if !ok {
			continue
		}
		rest = strings.TrimSpace(rest)
		if strings.HasPrefix(rest, "<... ") {
			continue // the end of a call counted at its start
		}
		byPID[pid] = append(byPID[pid], rest)
		if strings.HasPrefix(rest, `write(3, "r", 1`) {
			fiber = pid
		}
	}
	if fiber == "" {
		t.Fatalf("no ready byte in %s", path)
	}
	return byPID[fiber]
}
