package main

import (
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRun checks the agent command up to where it needs a cluster. That
// covers its flags, the agent's own checks, and the Kubernetes home factory
// reading the agent's configuration.
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
			// The agent makes its private state directory under -state
			// before the verifier check, so finding it proves the flags
			// reached the agent.
			if tc.wantErr != "flag provided but not defined: -nope" {
				if st, err := os.Stat(filepath.Join(state, "private")); err != nil || st.Mode().Perm() != 0o700 {
					t.Fatalf("private state dir: %v (%v), want mode 0700 under -state", st, err)
				}
			}
		})
	}
}

// TestRunHealthz checks -healthz, the grant Pod's liveness and startup
// probe. It succeeds only when the admin socket under -state answers 200.
// The 503 of a poisoned audit spool and a socket not up yet both fail,
// and the agent itself is never started.
func TestRunHealthz(t *testing.T) {
	cases := []struct {
		name    string
		status  int // 0 means nothing listens
		wantErr string
	}{
		{name: "a healthy agent passes", status: http.StatusOK},
		{name: "a poisoned audit spool fails", status: http.StatusServiceUnavailable, wantErr: `503 Service Unavailable: {"audit":"poisoned"}`},
		{name: "no admin socket yet fails", wantErr: "healthz:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A short path, since a unix socket path is limited to about
			// 100 bytes.
			state, err := os.MkdirTemp("", "hz")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(state) })
			if tc.status != 0 {
				if err := os.Mkdir(filepath.Join(state, "private"), 0o700); err != nil {
					t.Fatal(err)
				}
				l, err := net.Listen("unix", filepath.Join(state, "private", "admin.sock"))
				if err != nil {
					t.Fatal(err)
				}
				srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/healthz" {
						http.NotFound(w, r)
						return
					}
					w.WriteHeader(tc.status)
					_, _ = io.WriteString(w, `{"audit":"poisoned"}`)
				})}
				go func() { _ = srv.Serve(l) }()
				t.Cleanup(func() { _ = srv.Close() })
			}
			fs := flag.NewFlagSet("fiberd-k8s", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			err = run(fs, []string{"-state", state, "-healthz"})
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("run -healthz = %v, want %q", err, tc.wantErr)
			}
		})
	}
}
