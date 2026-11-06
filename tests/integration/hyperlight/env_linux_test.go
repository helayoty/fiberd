//go:build linux && integration

package hyperlighttest

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Azure/fiberd/pkg/backend"
	hlbackend "github.com/Azure/fiberd/pkg/backend/hyperlight"
)

// TestHelperKeepsEnvironment checks that both of the helper's starts see
// the container's environment. The fake writes what it was started with,
// and exits, so the Warm that starts it fails.
func TestHelperKeepsEnvironment(t *testing.T) {
	const own = "FIBERD_TEST_OWN_NAME=1"
	cases := []struct {
		name string
		seen string // the file the fake writes on this start
	}{
		{name: "its version", seen: "version"},
		{name: "a warm start", seen: "start"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("FIBERD_TEST_OWN_NAME", "1")
			dir := t.TempDir()
			bin := filepath.Join(dir, "helper")
			script := "#!/bin/sh\n" +
				"if [ \"$1\" = --version ]; then\n" +
				"  cat /proc/$$/environ > '" + filepath.Join(dir, "version") + "'\n" +
				"  echo 'fake/1 none none none'\n" +
				"else\n" +
				"  cat /proc/$$/environ > '" + filepath.Join(dir, "start") + "'\n" +
				"fi\n"
			if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			be := hlbackend.New(hlbackend.Options{Helper: bin})
			t.Cleanup(be.Close)
			sp := backend.WarmSpec{GrantUID: "g1", WorkDir: filepath.Join(dir, "run", "g1"), CgroupFD: -1, ProbeCgroupFD: -1}
			_, _ = be.Warm(warmCtx(t), sp)
			b, err := os.ReadFile(filepath.Join(dir, tc.seen))
			if err != nil {
				t.Fatalf("the fake did not run: %v", err)
			}
			if got := strings.Split(string(b), "\x00"); !slices.Contains(got, own) {
				t.Fatalf("the helper saw %q, want it to hold %q", got, own)
			}
		})
	}
}
