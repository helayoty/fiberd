//go:build linux

package proctest

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
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
