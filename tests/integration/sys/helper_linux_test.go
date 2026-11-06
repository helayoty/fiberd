//go:build linux && integration

package systest

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Azure/fiberd/pkg/artifact"
	"github.com/Azure/fiberd/pkg/sys/criu"
	"github.com/Azure/fiberd/pkg/sys/helper"
)

// TestHelperEnvironment checks what a helper sees while fiberd's own
// environment holds other names. Its environment is the fixed one and
// nothing more, however it is started. The fake reads the environment it
// was started with, since a shell adds names of its own afterwards.
func TestHelperEnvironment(t *testing.T) {
	cases := []struct {
		name string
		run  func(ctx context.Context, bin string) // its result does not matter
	}{
		{name: "a command", run: func(ctx context.Context, bin string) { _ = helper.Command(ctx, bin).Run() }},
		{name: "criu's check", run: func(ctx context.Context, bin string) { _ = criu.Options{Bin: bin}.Available(ctx) }},
		{name: "ldd", run: func(_ context.Context, bin string) { _ = artifact.LibcVersion(bin) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("FIBERD_TEST_OWN_NAME", "1")
			dir := t.TempDir()
			seen := filepath.Join(dir, "environ")
			bin := filepath.Join(dir, "helper")
			execFile(t, bin, "#!/bin/sh\ncat /proc/$$/environ > '"+seen+"'\n")
			tc.run(context.Background(), bin)
			b, err := os.ReadFile(seen)
			if err != nil {
				t.Fatalf("the fake did not run: %v", err)
			}
			if got := strings.Split(strings.TrimSuffix(string(b), "\x00"), "\x00"); !slices.Equal(got, []string{helper.PathEnv}) {
				t.Fatalf("the helper saw %q, want only %q", got, helper.PathEnv)
			}
		})
	}
}
