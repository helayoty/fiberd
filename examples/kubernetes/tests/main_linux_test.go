//go:build linux && integration

package kubernetestest

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	cgRoot := os.Getenv("FIBERD_CGROUP_ROOT")
	if cgRoot == "" {
		cgRoot = "/sys/fs/cgroup/fiberd"
	}
	if f, err := os.OpenFile(filepath.Join(cgRoot, "cgroup.subtree_control"), os.O_WRONLY, 0); err != nil {
		fmt.Fprintf(os.Stderr, "skipping kubernetes tests: %s not writable (run under hack/dev/run.sh)\n", cgRoot)
		os.Exit(0)
	} else {
		_ = f.Close()
	}
	os.Exit(m.Run())
}
