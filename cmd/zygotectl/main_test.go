package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/registry"

	"github.com/helayoty/fiberd/pkg/artifact"
)

// call runs the command with args and returns its exit code and output.
func call(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// newRegistry is an in-memory OCI registry in this process, as host:port.
func newRegistry(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// The command dispatches subcommands and maps outcomes to exit codes. It
// returns 0 for success and help, 2 for usage errors and 1 for failures.
// Each subcommand refuses to run without its required flags.
func TestRunDispatch(t *testing.T) {
	cases := []struct {
		name       string
		args       []string
		want       int
		wantStdout string
		wantStderr string
	}{
		{name: "no subcommand is a usage error", want: 2, wantStderr: "usage: zygotectl"},
		{name: "help prints usage", args: []string{"--help"}, want: 0, wantStderr: "usage: zygotectl"},
		{name: "an unknown subcommand fails", args: []string{"run"}, want: 1, wantStderr: `unknown subcommand "run"`},
		{name: "-h on a subcommand prints its flags", args: []string{"push", "-h"}, want: 0, wantStderr: "-plain-http"},
		{name: "an unknown flag is a usage error", args: []string{"pull", "-bogus"}, want: 2, wantStderr: "flag provided but not defined: -bogus"},
		{name: "build needs -zygote and -out", args: []string{"build", "-out", "x"}, want: 1, wantStderr: "-zygote and -out are required"},
		{name: "push needs -dir and -ref", args: []string{"push", "-dir", "x"}, want: 1, wantStderr: "-dir and -ref are required"},
		{name: "pull needs -ref and -out", args: []string{"pull", "-ref", "x"}, want: 1, wantStderr: "-ref and -out are required"},
		{name: "inspect needs -dir", args: []string{"inspect"}, want: 1, wantStderr: "-dir is required"},
		{name: "build rejects a bad flag", args: []string{"build", "-skip-images=maybe"}, want: 2, wantStderr: "invalid boolean value"},
		{name: "inspect rejects a bad flag", args: []string{"inspect", "-dir"}, want: 2, wantStderr: "flag needs an argument"},
		{name: "-version prints the version", args: []string{"-version"}, want: 0, wantStdout: "zygotectl "},
		{name: "--version prints the version", args: []string{"--version"}, want: 0, wantStdout: "zygotectl "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := call(tc.args...)
			if code != tc.want || !strings.HasPrefix(stdout, tc.wantStdout) || !strings.Contains(stderr, tc.wantStderr) {
				t.Fatalf("exit %d, stdout %q, stderr %q, want %d with %q and %q", code, stdout, stderr, tc.want, tc.wantStdout, tc.wantStderr)
			}
		})
	}
}

// An artifact goes through its life in order. It is built without
// images, inspected, pushed to a registry and pulled back, and the
// digest is the same at every step. Each step's failure cases follow it.
func TestBuildPushPullInspect(t *testing.T) {
	reg := newRegistry(t)
	dir := t.TempDir()
	zygote := filepath.Join(dir, "refzygote")
	if err := os.WriteFile(zygote, []byte("#!/bin/sh\necho READY\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	art := filepath.Join(dir, "art")
	pulled := filepath.Join(dir, "pulled")
	var digest string
	ref := reg + "/zygotes/ref"
	p, err := artifact.ParseParity("strict")
	if err != nil {
		t.Fatal(err)
	}
	strict := p.String()

	steps := []struct {
		name       string
		args       func() []string
		wantStderr string // on failure
		check      func(t *testing.T, stdout string)
	}{
		{name: "build without images prints the digest",
			args: func() []string {
				return []string{"build", "-zygote", zygote, "-args", "--heap-mb  32", "-out", art, "-skip-images"}
			},
			check: func(t *testing.T, stdout string) {
				digest = strings.TrimSpace(stdout)
				if !strings.HasPrefix(digest, "sha256:") {
					t.Fatalf("digest = %q, want sha256:...", digest)
				}
			}},
		{name: "build of a missing zygote fails",
			args: func() []string {
				return []string{"build", "-zygote", filepath.Join(dir, "nope"), "-out", filepath.Join(dir, "x"), "-skip-images"}
			},
			wantStderr: "no such file"},
		{name: "inspect reports the artifact and that it runs here",
			args: func() []string { return []string{"inspect", "-dir", art} },
			check: func(t *testing.T, stdout string) {
				var got struct {
					Digest string `json:"digest"`
					Config struct {
						Args      []string `json:"args"`
						Arch      string   `json:"arch"`
						HasImages bool     `json:"has_images"`
					} `json:"config"`
					Parity string `json:"parity"`
					Usable string `json:"usable_here"`
				}
				if err := json.Unmarshal([]byte(stdout), &got); err != nil {
					t.Fatalf("inspect output %q: %v", stdout, err)
				}
				if got.Digest != digest || got.Parity != strict || got.Usable != "ok" || got.Config.Arch != runtime.GOARCH ||
					strings.Join(got.Config.Args, " ") != "--heap-mb 32" {
					t.Fatalf("inspect = %+v, want digest %s, %s parity, usable, args --heap-mb 32", got, digest, strict)
				}
			}},
		{name: "inspect with an unknown parity level fails",
			args: func() []string { return []string{"inspect", "-dir", art, "-parity", "loose"} }, wantStderr: "loose"},
		{name: "inspect of a directory that is not an artifact fails",
			args: func() []string { return []string{"inspect", "-dir", dir} }, wantStderr: "config.json"},
		{name: "push prints the same digest",
			args: func() []string { return []string{"push", "-dir", art, "-ref", ref + ":v1", "-plain-http"} },
			check: func(t *testing.T, stdout string) {
				if got := strings.TrimSpace(stdout); got != digest {
					t.Fatalf("pushed digest = %q, want %q", got, digest)
				}
			}},
		{name: "push of a directory that is not an artifact fails",
			args: func() []string { return []string{"push", "-dir", dir, "-ref", ref + ":v2", "-plain-http"} }, wantStderr: "config.json"},
		{name: "pull by digest prints the config",
			args: func() []string { return []string{"pull", "-ref", ref + "@" + digest, "-out", pulled, "-plain-http"} },
			check: func(t *testing.T, stdout string) {
				var cfg struct {
					Args []string `json:"args"`
				}
				if err := json.Unmarshal([]byte(stdout), &cfg); err != nil || strings.Join(cfg.Args, " ") != "--heap-mb 32" {
					t.Fatalf("pulled config %q, %v, want args --heap-mb 32", stdout, err)
				}
				if _, err := os.Stat(filepath.Join(pulled, "zygote")); err != nil {
					t.Fatalf("the pull left no zygote: %v", err)
				}
			}},
		{name: "inspect of an artifact for another architecture says why it cannot run here",
			args: func() []string {
				path := filepath.Join(pulled, "config.json")
				b, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				b = bytes.Replace(b, []byte(`"arch": "`+runtime.GOARCH+`"`), []byte(`"arch": "s390x"`), 1)
				if err := os.WriteFile(path, b, 0o644); err != nil {
					t.Fatal(err)
				}
				return []string{"inspect", "-dir", pulled}
			},
			check: func(t *testing.T, stdout string) {
				var got struct {
					Usable string `json:"usable_here"`
				}
				if err := json.Unmarshal([]byte(stdout), &got); err != nil {
					t.Fatal(err)
				}
				if got.Usable == "ok" || !strings.Contains(got.Usable, "s390x") {
					t.Fatalf("usable_here = %q, want the architecture mismatch", got.Usable)
				}
			}},
		{name: "pull of a tag the registry lacks fails",
			args: func() []string {
				return []string{"pull", "-ref", ref + ":missing", "-out", filepath.Join(dir, "p2"), "-plain-http"}
			},
			wantStderr: "artifact: pull"},
	}
	for _, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			code, stdout, stderr := call(st.args()...)
			if st.wantStderr != "" {
				if code != 1 || !strings.Contains(stderr, st.wantStderr) {
					t.Fatalf("exit %d, stderr %q, want 1 with %q", code, stderr, st.wantStderr)
				}
				return
			}
			if code != 0 {
				t.Fatalf("exit %d: %s", code, stderr)
			}
			st.check(t, stdout)
		})
	}
}
