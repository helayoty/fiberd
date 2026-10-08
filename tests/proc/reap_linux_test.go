//go:build linux

package proctest

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestWaitBoundedNeverBlocks pins that wait_bounded gives up after its
// bound and reaps a gone child well within it. A child the kernel holds in
// uninterruptible sleep after SIGKILL must not hold the zygote's loop, and
// with it every grant's clones.
func TestWaitBoundedNeverBlocks(t *testing.T) {
	bin := filepath.Join(filepath.Dir(zygoteBin), "waitbounded")
	// The probe includes the library source, so it is built with the
	// Makefile's ZYGOTE_CFLAGS and ZYGOTE_LDFLAGS, as the zygote is.
	build := exec.Command("gcc", append(zygoteBuildFlags(runtime.GOARCH), "-pthread", "-o", bin, "testdata/waitbounded.c")...)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build waitbounded: %v: %s", err, out)
	}
	cases := []struct {
		name string
		arg  string
		want string
		// minMS and maxMS bound the milliseconds the wait may take.
		minMS, maxMS int
	}{
		{name: "a live child is given up on at the bound", arg: "alive", want: "alive", minMS: 100, maxMS: 1500},
		{name: "a dead child is reaped before the bound", arg: "killed", want: "reaped", minMS: 0, maxMS: 99},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := exec.Command(bin, tc.arg).CombinedOutput()
			if err != nil {
				t.Fatalf("waitbounded %s: %v: %s", tc.arg, err, out)
			}
			fields := strings.Fields(string(out))
			if len(fields) != 2 || fields[0] != tc.want {
				t.Fatalf("waitbounded %s = %q, want %q and a duration", tc.arg, out, tc.want)
			}
			took, err := strconv.Atoi(fields[1])
			if err != nil {
				t.Fatal(err)
			}
			if took < tc.minMS || took > tc.maxMS {
				t.Fatalf("waitbounded %s took %dms, want %s", tc.arg, took, fmt.Sprintf("%d..%d", tc.minMS, tc.maxMS))
			}
		})
	}
}

// TestReadyThenExitInsideBoundedWait pins that a fiber which reports
// ready and exits while the zygote's loop sits in a bounded wait on
// another child (settle_pending gives a closed readiness pipe 200ms) is
// answered CLONED then EXITED, as it is when the loop is polling. The
// old reap took every pending child it reaped for a birth that failed
// and answered its CLONE with ERROR, so the agent's Clone failed for a
// fiber that had run. Child b is forked first and reports after a
// delay, child a closes its pipe at once and keeps running, and b's
// report and exit land inside a's wait.
func TestReadyThenExitInsideBoundedWait(t *testing.T) {
	cases := []struct {
		name    string
		delayMS int
	}{
		{name: "ready and gone inside the other child's wait", delayMS: 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			uc, rd := rawZygote(t, dir)
			hex := func(s string) string { return fmt.Sprintf("%x", s) }
			lines := "CLONE b " + filepath.Join(dir, "b.sock") + " 3000 " + hex(fmt.Sprintf(`{"ready_delay_ms": %d, "exit_after_ready": 1}`, tc.delayMS)) + "\n" +
				"CLONE a " + filepath.Join(dir, "a.sock") + " 3000 " + hex(`{"ready_misuse": 2}`) + "\n"
			if _, err := uc.Write([]byte(lines)); err != nil {
				t.Fatal(err)
			}
			var got []string
			pid := ""
			for len(got) < 3 {
				line := readLine(t, uc, rd)
				if line == "" {
					break
				}
				got = append(got, line)
				if rest, ok := strings.CutPrefix(line, "CLONED b "); ok {
					pid = rest
				}
			}
			if pid == "" || !slices.Contains(got, "EXITED "+pid+" exit:0") {
				t.Fatalf("zygote said %q, want CLONED b <pid> and EXITED <pid> exit:0", got)
			}
			if !slices.Contains(got, "ERROR a closed the readiness pipe without reporting ready; killed") {
				t.Fatalf("zygote said %q, want a's ERROR as well", got)
			}
		})
	}
}
