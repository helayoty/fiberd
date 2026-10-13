//go:build linux && integration

package systest

import (
	"os"
	"testing"
	"time"

	"github.com/helayoty/fiberd/tests/internal/testenv"
)

// cgRoot is the cgroup subtree the dev container delegates to the tests.
var cgRoot string

func TestMain(m *testing.M) {
	cgRoot = testenv.RequireCgroupRoot("sys")
	os.Exit(m.Run())
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func mustWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}
