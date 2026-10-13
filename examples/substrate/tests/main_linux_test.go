//go:build linux && integration

package substratetest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// cgRoot is the cgroup subtree the dev container delegates to the tests.
var cgRoot = os.Getenv("FIBERD_CGROUP_ROOT")

// ateomFiberd is the binary TestMain builds from ../cmd/ateom-fiberd.
var ateomFiberd string

func TestMain(m *testing.M) {
	if cgRoot == "" {
		cgRoot = "/sys/fs/cgroup/fiberd"
	}
	if f, err := os.OpenFile(filepath.Join(cgRoot, "cgroup.subtree_control"), os.O_WRONLY, 0); err != nil {
		fmt.Fprintf(os.Stderr, "skipping substrate tests: %s not writable (run under hack/dev/run.sh)\n", cgRoot)
		os.Exit(0)
	} else {
		_ = f.Close()
	}
	dir, err := os.MkdirTemp("", "ateom-fiberd-bin")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ateomFiberd = filepath.Join(dir, "ateom-fiberd")
	build := exec.Command("go", "build", "-o", ateomFiberd, "../cmd/ateom-fiberd")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "build ateom-fiberd: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
