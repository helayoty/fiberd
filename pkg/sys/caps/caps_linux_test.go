//go:build linux

package caps_test

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/helayoty/fiberd/pkg/sys/caps"
)

// all is every capability number a mask can hold.
var all = func() []int {
	out := make([]int, 64)
	for i := range out {
		out[i] = i
	}
	return out
}()

// capSets reads the named sets (CapBnd, CapInh, ...) of a status text.
func capSets(t *testing.T, status string, names ...string) map[string]uint64 {
	t.Helper()
	out := map[string]uint64{}
	for _, line := range strings.Split(status, "\n") {
		key, val, ok := strings.Cut(line, ":")
		if ok && slices.Contains(names, key) {
			v, err := strconv.ParseUint(strings.TrimSpace(val), 16, 64)
			if err != nil {
				t.Fatalf("%s in status: %v", key, err)
			}
			out[key] = v
		}
	}
	for _, n := range names {
		if _, ok := out[n]; !ok && n != "CapAmb" {
			t.Fatalf("no %s line in status", n)
		}
	}
	return out
}

// selfSets is this process's bounding, inheritable and ambient sets.
func selfSets(t *testing.T) map[string]uint64 {
	t.Helper()
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	return capSets(t, string(b), "CapBnd", "CapInh", "CapAmb", "CapEff")
}

// bits lists, ascending, the capabilities set in mask that keep does
// not name.
func bits(mask uint64, keep []int) []int {
	var out []int
	for c := range 64 {
		if mask&(1<<c) != 0 && !slices.Contains(keep, c) {
			out = append(out, c)
		}
	}
	return out
}

// TestExtra checks what this process holds beyond keep, in its bounding,
// inheritable or ambient set, as /proc/self/status reports those sets.
func TestExtra(t *testing.T) {
	sets := selfSets(t)
	held := sets["CapBnd"] | sets["CapInh"] | sets["CapAmb"]
	cases := []struct {
		name string
		keep []int
	}{
		{name: "nothing kept", keep: nil},
		{name: "the proc set", keep: caps.Proc},
		{name: "the runc set", keep: caps.Runc},
		{name: "everything kept", keep: all},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := caps.Extra(tc.keep)
			if want := bits(held, tc.keep); !slices.Equal(got, want) {
				t.Fatalf("Extra(%v) = %v, want %v (held %#x)", tc.keep, got, want, held)
			}
			for _, c := range got {
				if slices.Contains(tc.keep, c) {
					t.Fatalf("Extra reports kept capability %d", c)
				}
			}
		})
	}
}

// TestNarrowHelper is the process TestNarrow starts. It prints its
// sets, narrows to the keep list in FIBERD_CAPS_KEEP and prints what
// Narrow returned with its sets after, each with its generation (0
// before any re-exec, 1 after). Stdout is unbuffered, so what the first
// generation prints survives the exec.
func TestNarrowHelper(t *testing.T) {
	keepEnv, ok := os.LookupEnv("FIBERD_CAPS_KEEP")
	if !ok {
		return
	}
	var keep []int
	for _, f := range strings.Fields(keepEnv) {
		c, err := strconv.Atoi(f)
		if err != nil {
			t.Fatal(err)
		}
		keep = append(keep, c)
	}
	gen := os.Getenv("FIBERD_CAPS_GEN")
	if gen == "" {
		gen = "0"
		t.Setenv("FIBERD_CAPS_GEN", "1")
	}
	if os.Getenv("FIBERD_CAPS_BREAK_EXEC") != "" {
		// One environment string over the kernel's limit makes the
		// re-exec fail with E2BIG.
		t.Setenv("FIBERD_CAPS_HUGE", strings.Repeat("x", 256<<10))
	}
	sets := selfSets(t)
	fmt.Printf("helper before gen=%s bnd=%x inh=%x amb=%x\n", gen, sets["CapBnd"], sets["CapInh"], sets["CapAmb"])
	err := caps.Narrow(keep)
	sets = selfSets(t)
	fmt.Printf("helper after gen=%s bnd=%x inh=%x amb=%x err=%v\n", gen, sets["CapBnd"], sets["CapInh"], sets["CapAmb"], err)
}

// helperSets is one line TestNarrowHelper printed.
type helperSets struct {
	gen           int
	bnd, inh, amb uint64
	err           string // what Narrow returned, "<nil>" for nil
}

// parseHelper reads one helper line.
func parseHelper(t *testing.T, line string) helperSets {
	t.Helper()
	var r helperSets
	if i := strings.Index(line, " err="); i >= 0 {
		r.err, line = line[i+5:], line[:i]
	}
	for _, kv := range strings.Fields(line)[2:] {
		k, v, _ := strings.Cut(kv, "=")
		n, err := strconv.ParseUint(v, 16, 64)
		if err != nil {
			t.Fatalf("helper line %q: %v", line, err)
		}
		switch k {
		case "gen":
			r.gen = int(n)
		case "bnd":
			r.bnd = n
		case "inh":
			r.inh = n
		case "amb":
			r.amb = n
		}
	}
	return r
}

// helperRun is what one TestNarrowHelper process did. It holds the sets
// the first generation started with, those the last generation ended with
// (when it got that far), and how the process ended.
type helperRun struct {
	before, after helperSets
	ended         bool // an "after" line was printed
	exit          int
	stderr        string
}

// runHelper runs TestNarrowHelper in a fresh process, under wrapper (a
// command prefix such as setpriv) when given.
func runHelper(t *testing.T, keep []int, breakExec bool, wrapper ...string) helperRun {
	t.Helper()
	args := append(slices.Clone(wrapper), os.Args[0], "-test.run=^TestNarrowHelper$")
	if dir := flag.Lookup("test.gocoverdir"); dir != nil && dir.Value.String() != "" {
		// Count the helper's coverage with ours.
		args = append(args, "-test.gocoverdir="+dir.Value.String())
	}
	var keepStr []string
	for _, c := range keep {
		keepStr = append(keepStr, strconv.Itoa(c))
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = append(os.Environ(), "FIBERD_CAPS_KEEP="+strings.Join(keepStr, " "))
	if breakExec {
		cmd.Env = append(cmd.Env, "FIBERD_CAPS_BREAK_EXEC=1")
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	r := helperRun{stderr: stderr.String()}
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		r.exit = exit.ExitCode()
	default:
		t.Fatalf("helper: %v\n%s%s", err, out, r.stderr)
	}
	gotBefore := false
	for _, line := range strings.Split(string(out), "\n") {
		switch {
		case strings.HasPrefix(line, "helper before ") && !gotBefore:
			r.before, gotBefore = parseHelper(t, line), true
		case strings.HasPrefix(line, "helper after "):
			r.after, r.ended = parseHelper(t, line), true
		}
	}
	if !gotBefore {
		t.Fatalf("helper printed nothing:\n%s%s", out, r.stderr)
	}
	return r
}

// keepMask is keep as a capability mask.
func keepMask(keep []int) uint64 {
	var m uint64
	for _, c := range keep {
		m |= 1 << c
	}
	return m
}

// TestNarrow checks that a process with more than keep re-executes with its
// bounding set cut to keep, its inheritable set masked to keep and its
// ambient set empty. One with nothing beyond keep is left alone, one
// without CAP_SETPCAP is told it cannot narrow, and one whose re-exec
// fails exits rather than run half narrowed.
func TestNarrow(t *testing.T) {
	setpriv, _ := exec.LookPath("setpriv")
	// The effective set, not the bounding set, because a normal user keeps
	// a full bounding set but cannot use any of it.
	if selfSets(t)["CapEff"]&(1<<caps.SetPCAP) == 0 {
		t.Skip("this process lacks CAP_SETPCAP")
	}
	cases := []struct {
		name       string
		keep       []int
		wrapper    []string // run the helper under this (setpriv)
		breakExec  bool
		wantGen    int
		wantErr    error
		startsWith uint64 // capabilities the helper must start with, inheritable and ambient
		wantExit   int
		wantStderr string
	}{
		{name: "down to the proc set", keep: caps.Proc, wantGen: 1},
		{name: "down to the runc set", keep: caps.Runc, wantGen: 1},
		{name: "nothing beyond keep, no re-exec", keep: all, wantGen: 0},
		{name: "an inheritable and ambient capability outside keep is dropped", keep: caps.Proc, wantGen: 1,
			wrapper: []string{setpriv, "--inh-caps=+chown", "--ambient-caps=+chown"}, startsWith: 1 << caps.Chown},
		{name: "without CAP_SETPCAP", keep: caps.Proc, wantGen: 0,
			wrapper: []string{setpriv, "--bounding-set=-setpcap"}, wantErr: caps.ErrCannotNarrow},
		{name: "a failed re-exec exits", keep: caps.Proc, breakExec: true,
			wantExit: 1, wantStderr: "caps: re-exec with narrowed capabilities: argument list too long"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.wrapper) > 0 && setpriv == "" {
				t.Skip("setpriv not installed")
			}
			run := runHelper(t, tc.keep, tc.breakExec, tc.wrapper...)
			before, after := run.before, run.after
			if before.gen != 0 || before.inh&tc.startsWith != tc.startsWith || before.amb&tc.startsWith != tc.startsWith {
				t.Fatalf("helper started as %+v, want generation 0 holding %#x inheritable and ambient", before, tc.startsWith)
			}
			if run.exit != tc.wantExit || !strings.Contains(run.stderr, tc.wantStderr) {
				t.Fatalf("helper exited %d with stderr %q, want %d and %q", run.exit, run.stderr, tc.wantExit, tc.wantStderr)
			}
			if tc.wantExit != 0 {
				if run.ended {
					t.Fatalf("helper went on after the failed re-exec: %+v", after)
				}
				return
			}
			if !run.ended || after.gen != tc.wantGen {
				t.Fatalf("helper ended in generation %d (ended %v), want %d (%+v)", after.gen, run.ended, tc.wantGen, after)
			}
			if tc.wantErr != nil {
				if after.err != tc.wantErr.Error() {
					t.Fatalf("Narrow = %q, want %q", after.err, tc.wantErr)
				}
				if before.bnd&(1<<caps.SetPCAP) != 0 || after.bnd != before.bnd {
					t.Fatalf("bounding set %#x before, %#x after, want it without CAP_SETPCAP and unchanged", before.bnd, after.bnd)
				}
				return
			}
			if after.err != "<nil>" {
				t.Fatalf("Narrow = %q, want nil", after.err)
			}
			if want := before.bnd & keepMask(tc.keep); after.bnd != want {
				t.Fatalf("bounding set after = %#x, want %#x", after.bnd, want)
			}
			if after.inh&^keepMask(tc.keep) != 0 || after.amb != 0 {
				t.Fatalf("inheritable %#x ambient %#x after, want nothing outside keep and no ambient set", after.inh, after.amb)
			}
		})
	}
}
