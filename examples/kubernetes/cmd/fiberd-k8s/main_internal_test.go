package main

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRun checks the agent command up to where it needs a cluster: its
// flags, the agent's own checks, and the Kubernetes home factory reading
// the agent's configuration.
func TestRun(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "an unknown flag is an error", args: []string{"-nope"}, wantErr: "flag provided but not defined: -nope"},
		{name: "the agent's own checks run first: a verifier is required", wantErr: "-verifier is required"},
		{name: "the home factory refuses an unknown endpoint family",
			args: []string{"-verifier", "insecure-json", "-endpoint-family", "carrier-pigeon"}, wantErr: `endpoint family "carrier-pigeon"`},
		{name: "the home factory refuses a listen address without a port",
			args: []string{"-verifier", "insecure-json", "-listen", "nowhere"}, wantErr: `-listen "nowhere"`},
		{name: "a valid configuration reaches the Kubernetes home, which needs a cluster",
			args: []string{"-verifier", "insecure-json", "-endpoint-family", "inet4", "-devices", "/dev/a,/dev/b"}, wantErr: "not in a cluster"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KUBERNETES_SERVICE_HOST", "")
			state := t.TempDir()
			fs := flag.NewFlagSet("fiberd-k8s", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			args := append([]string{"-state", state, "-insecure-plaintext"}, tc.args...)
			err := run(fs, args)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("run = %v, want %q", err, tc.wantErr)
			}
			// The flags were parsed into the agent: its private state
			// directory is made under -state before the verifier check.
			if tc.wantErr != "flag provided but not defined: -nope" {
				if st, err := os.Stat(filepath.Join(state, "private")); err != nil || st.Mode().Perm() != 0o700 {
					t.Fatalf("private state dir: %v (%v), want mode 0700 under -state", st, err)
				}
			}
		})
	}
}
