//go:build linux

package proctest

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
	procbackend "github.com/helayoty/fiberd/pkg/backend/proc"
)

// capSysAdmin is CAP_SYS_ADMIN's bit in the Cap* fields of /proc/<pid>/status.
const capSysAdmin = 21

// warmArgv opens the fork backend on its own and warms one zygote from
// the given argv, which may wrap the zygote in a launcher (strace,
// setpriv, noclone3), with dir as the grant's run directory. Fibers are
// forked into the cgroup each Clone names, or none when the caller passes
// -1. The zygote itself runs in the test's cgroup.
func warmArgv(t *testing.T, dir, grant string, argv []string, hide []string) (*procbackend.Backend, backend.Warm) {
	t.Helper()
	be := procbackend.NewBackend(procbackend.Options{})
	t.Cleanup(be.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	w, err := be.Warm(ctx, backend.WarmSpec{
		GrantUID:      grant,
		Template:      backend.Template{Argv: argv},
		CgroupFD:      -1,
		ProbeCgroupFD: -1,
		WorkDir:       dir,
		Hide:          hide,
	})
	if err != nil {
		t.Fatalf("warm %v: %v", argv, err)
	}
	return be, w
}

// procStatus is one field of /proc/<pid>/status, "" when absent.
func procStatus(t *testing.T, pid int, key string) string {
	t.Helper()
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatalf("status of %d: %v", pid, err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), key+":"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// hasCap reports whether the capability bit is set in a Cap* field's
// hex value as /proc/<pid>/status prints it.
func hasCap(t *testing.T, hexMask string, bit uint) bool {
	t.Helper()
	v, err := strconv.ParseUint(hexMask, 16, 64)
	if err != nil {
		t.Fatalf("capability mask %q: %v", hexMask, err)
	}
	return v&(1<<bit) != 0
}

// cgroupOf is the cgroup v2 path of pid, relative to the cgroup
// namespace root (the second field of the "0::" line of /proc/<pid>/cgroup).
func cgroupOf(t *testing.T, pid int) string {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		t.Fatalf("cgroup of %d: %v", pid, err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			return p
		}
	}
	t.Fatalf("no cgroup v2 line for %d in %q", pid, b)
	return ""
}

// atoiOrFatal parses a pid a fiber reported about itself.
func atoiOrFatal(t *testing.T, what, s string) int {
	t.Helper()
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 {
		t.Fatalf("%s = %q, want a pid", what, s)
	}
	return n
}

// birthLine matches one clone3 or legacy clone call in strace -f output,
// capturing the call's name and then its flags. A call that another
// tracee's event interleaved ends in "<unfinished ...>", and the
// "<... resumed>" line that follows is not a second call.
var birthLine = regexp.MustCompile(`^\d+\s+(clone3?)\((?:\{flags=|child_stack=[^,]*, flags=)([^,}]*)`)

// births counts the clone3 and legacy clone calls in an strace -f trace
// file, leaving out thread creation (CLONE_THREAD), which is a
// library's, not birth's.
func births(t *testing.T, trace string) (clone3, legacy int) {
	t.Helper()
	b, err := os.ReadFile(trace)
	if err != nil {
		t.Fatalf("read %s: %v", trace, err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		m := birthLine.FindStringSubmatch(line)
		if m == nil || strings.Contains(m[2], "CLONE_THREAD") {
			continue
		}
		if m[1] == "clone3" {
			clone3++
		} else {
			legacy++
		}
	}
	return clone3, legacy
}

// TestRefusedNamespacesRefuseClone pins that a zygote without
// CAP_SYS_ADMIN serves no fiber short of its namespaces, and that the
// zygote serves on after each refusal. setpriv takes the capability out
// of the bounding set, so the zygote has lost it after exec, and strace
// -f records the clone calls to count.
//
// Two refusals meet here. The kernel refuses CLONE_NEWPID with EPERM, and
// birth asks once, never retrying with fewer namespaces or falling back
// to the legacy clone (a property the old code had too). And the zygote,
// refused its own mount namespace in fz_init, refuses every mntns CLONE
// before any birth, so no clone3 is even asked for. The old code asked
// the kernel, which refused CLONE_NEWNS the same way, so this case is
// new in where the refusal lands and the same in that no fiber runs.
func TestRefusedNamespacesRefuseClone(t *testing.T) {
	for _, tool := range []string{"strace", "setpriv"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available: %v", tool, err)
		}
	}
	if !hasCap(t, procStatus(t, os.Getpid(), "CapEff"), capSysAdmin) {
		t.Skip("the test itself lacks CAP_SYS_ADMIN; a refusal would say nothing about the zygote's")
	}
	unprivileged := func(trace string) []string {
		return []string{
			"strace", "-f", "-qq", "-e", "trace=clone,clone3", "-o", trace,
			"setpriv", "--bounding-set", "-sys_admin", "--inh-caps", "-sys_admin",
		}
	}
	cases := []struct {
		name string
		// opts are the CLONE options sent on the raw channel after
		// PREPARE none (the kernel's refusal) or PREPARE mntns (the
		// zygote's).
		setup, opts string
		// wantErr is what the ERROR line must contain, and births how
		// many clone3 calls each CLONE costs.
		wantErr string
		births  int
	}{
		{name: "the kernel refuses the pid namespace once per CLONE", setup: "PREPARE mntns\n", opts: "pidns", wantErr: "clone: Operation not permitted", births: 1},
		{name: "the zygote without a namespace of its own refuses a mntns CLONE before any birth", setup: "PREPARE mntns\n", opts: "pidns,mntns",
			wantErr: "refused: the mount namespace cannot hide what the agent asked (the zygote could not take a mount namespace of its own: unshare: errno 1)", births: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			trace := filepath.Join(dir, "clone.strace")
			uc, rd := rawZygoteWith(t, dir, unprivileged(trace), tc.setup)
			// READY first, then the one line that says why no mntns
			// fiber will be born, which the agent logs.
			if got := readLine(t, uc, rd); !strings.HasPrefix(got, "ERROR ? the zygote could not take a mount namespace of its own: unshare: errno 1; every mntns CLONE is refused") {
				t.Fatalf("after READY the zygote said %q, want the reason it has no mount namespace of its own", got)
			}
			// The clones share the zygote on purpose and run in order,
			// each one more clone of it.
			seen := 0
			for _, fence := range []string{"gr/1-1", "gr/1-2"} {
				line := fmt.Sprintf("CLONE %s %s/%s.sock 2000 - %s", fence, dir, strings.ReplaceAll(fence, "/", "-"), tc.opts)
				if _, err := uc.Write([]byte(line + "\n")); err != nil {
					t.Fatal(err)
				}
				got := readLine(t, uc, rd)
				if !strings.HasPrefix(got, "ERROR "+fence+" ") || !strings.Contains(got, tc.wantErr) {
					t.Fatalf("reply to %s = %q, want it refused with an error mentioning %q", fence, got, tc.wantErr)
				}
				if _, err := os.Stat(filepath.Join(dir, strings.ReplaceAll(fence, "/", "-")+".sock")); err == nil {
					t.Fatalf("a fiber of %s serves although its clone was refused", fence)
				}
				// strace prints a call before the tracee runs on, so every
				// call of this birth is in the file before ERROR was sent.
				c3, legacy := births(t, trace)
				if c3-seen != tc.births || legacy != 0 {
					b, _ := os.ReadFile(trace)
					t.Fatalf("births for %s: clone3 %d, legacy clone %d, want %d clone3 and no legacy clone; trace so far:\n%s", fence, c3-seen, legacy, tc.births, b)
				}
				seen = c3
			}
		})
	}
}
