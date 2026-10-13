//go:build linux && integration

package clonetest

import (
	"os"
	"testing"

	"github.com/helayoty/fiberd/tests/internal/testenv"
)

// work holds the zygote the measurement forks.
var work string

func TestMain(m *testing.M) {
	code := m.Run()
	if work != "" {
		_ = os.RemoveAll(work)
	}
	os.Exit(code)
}

// gate skips the measurement unless it was asked for and the dev
// container delegates a cgroup root, then builds the zygote. It returns
// the cgroup root and the zygote's path.
func gate(t *testing.T) (cgRoot, zygoteBin string) {
	t.Helper()
	if os.Getenv("FIBERD_BENCH") == "" {
		t.Skip("set FIBERD_BENCH=1 to run the end-to-end clone measurement")
	}
	root, err := testenv.WritableCgroupRoot()
	if err != nil {
		t.Skip(err)
	}
	if work == "" {
		if work, err = os.MkdirTemp("", "refzygote"); err != nil {
			t.Fatal(err)
		}
	}
	bin, err := testenv.BuildZygote(work)
	if err != nil {
		t.Fatal(err)
	}
	return root, bin
}
