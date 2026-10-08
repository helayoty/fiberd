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
// forked into the cgroup each Clone names (none when the caller passes
// -1); the zygote itself runs in the test's.
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

// birthLine is one clone3 or legacy clone call in strace -f output: the
// call's name, then its flags. A call that another tracee's event
// interleaved ends in "<unfinished ...>", and the "<... resumed>" line
// that follows is not a second call.
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

// TestRefusedNamespacesRefuseClone: a zygote without CAP_SYS_ADMIN is
// refused CLONE_NEWNS and CLONE_NEWPID with EPERM. The clone is refused
// with that error, and no fiber runs without its namespaces. Birth asks
// once: it neither retries with fewer namespaces nor falls back to the
// legacy clone, which is for kernels without clone3. The zygote serves
// on and refuses the next clone the same way.
//
// The zygote is wrapped in setpriv, which takes CAP_SYS_ADMIN out of the
// bounding set so it is gone from the zygote's effective set after exec,
// and in strace -f, whose output file is the count.
func TestRefusedNamespacesRefuseClone(t *testing.T) {
	for _, tool := range []string{"strace", "setpriv"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available: %v", tool, err)
		}
	}
	if !hasCap(t, procStatus(t, os.Getpid(), "CapEff"), capSysAdmin) {
		t.Skip("the test itself lacks CAP_SYS_ADMIN; a refusal would say nothing about the zygote's")
	}
	dir := t.TempDir()
	trace := filepath.Join(dir, "clone.strace")
	be, w := warmArgv(t, dir, "gr", []string{
		"strace", "-f", "-qq", "-e", "trace=clone,clone3", "-o", trace,
		"setpriv", "--bounding-set", "-sys_admin", "--inh-caps", "-sys_admin",
		zygoteBin, "--heap-mb", "16",
	}, []string{hiddenDir})

	// The cases share the zygote on purpose and run in order: each is one
	// more clone of it.
	cases := []struct {
		name  string
		fence string
	}{
		{name: "first clone is refused", fence: "gr/1-1"},
		{name: "the zygote serves on and refuses the next", fence: "gr/1-2"},
	}
	seen := 0
	for _, tc := range cases {
		ok := t.Run(tc.name, func(t *testing.T) {
			_, err := cloneDirect(t, be, w, dir, tc.fence, "")
			if err == nil || !strings.Contains(err.Error(), "clone: Operation not permitted") {
				t.Fatalf("clone = %v, want it refused with clone: Operation not permitted", err)
			}
			if _, err := os.Stat(filepath.Join(dir, strings.ReplaceAll(tc.fence, "/", "-")+".sock")); err == nil {
				t.Fatalf("a fiber of %s serves although its clone was refused", tc.fence)
			}
			// strace prints a call before the tracee runs on, so every
			// call of this birth is in the file before ERROR was sent.
			c3, legacy := births(t, trace)
			if c3-seen != 1 || legacy != 0 {
				b, _ := os.ReadFile(trace)
				t.Fatalf("births for %s: clone3 %d, legacy clone %d, want one clone3 and no legacy clone; trace so far:\n%s", tc.fence, c3-seen, legacy, b)
			}
			seen = c3
		})
		if !ok {
			return
		}
	}
}
