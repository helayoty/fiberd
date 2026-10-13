//go:build linux && integration

package substratetest

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestAteomFiberdMainExit runs the binary and checks its exit status. It
// is 0 for -h, 2 for a bad command line and 1 for any other failure.
func TestAteomFiberdMainExit(t *testing.T) {
	cases := []struct {
		name   string
		args   []string
		env    []string
		code   int
		stderr string
	}{
		{name: "-h exits 0", args: []string{"-h"}, code: 0, stderr: "-pod-uid"},
		{name: "a bad flag exits 2", args: []string{"-nope"}, code: 2, stderr: "flag provided but not defined: -nope"},
		{name: "no pod uid exits 1", env: []string{"POD_UID="}, code: 1, stderr: "-pod-uid (or POD_UID) is required"},
		{name: "a run that fails exits 1", args: []string{"-pod-uid", "p-1"}, env: []string{"ATEOM_FIBERD_ISOLATION=SOMEWHAT"}, code: 1,
			stderr: "ateom-fiberd: ATEOM_FIBERD_ISOLATION"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(ateomFiberd, tc.args...)
			cmd.Env = append(os.Environ(), tc.env...)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			err := cmd.Run()
			code := 0
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				code = exit.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != tc.code || !strings.Contains(stderr.String(), tc.stderr) {
				t.Fatalf("exit %d with %q, want %d with %q", code, stderr.String(), tc.code, tc.stderr)
			}
		})
	}
}
