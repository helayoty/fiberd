//go:build linux && integration

package knativetest

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// activator is the binary TestMain builds from ../cmd/fiberd-activator.
var activator string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "fiberd-activator-bin")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	activator = filepath.Join(dir, "fiberd-activator")
	build := exec.Command("go", "build", "-o", activator, "../cmd/fiberd-activator")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "build fiberd-activator: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// TestActivatorMainExit runs the binary and checks its exit status. It
// is 0 for -h, 2 for a bad command line and 1 for any other failure.
func TestActivatorMainExit(t *testing.T) {
	cases := []struct {
		name   string
		args   []string
		code   int
		stderr string
	}{
		{name: "-h exits 0", args: []string{"-h"}, code: 0, stderr: "Usage of fiberd-activator"},
		{name: "a bad flag exits 2", args: []string{"-nope"}, code: 2, stderr: "flag provided but not defined: -nope"},
		{name: "a failure exits 1", args: []string{"-home", "%zz", "-revision", "a=t"}, code: 1, stderr: "invalid URL escape"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(activator, tc.args...)
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
