//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBuildSmoke checks that build -skip-images runs the zygote to READY
// by default, needing no criu, and that -no-smoke runs nothing. A zygote
// that never gets there fails the build, and the error names -no-smoke.
func TestBuildSmoke(t *testing.T) {
	cases := []struct {
		name       string
		zygote     string // a shell script standing in for the zygote
		flags      []string
		want       int
		wantRan    bool
		wantStderr string
	}{
		{name: "the zygote is run to READY", zygote: "read line <&3\necho READY >&3\nexec sleep 30\n",
			flags: []string{"-skip-images"}, wantRan: true},
		{name: "a zygote that never says READY fails the build", zygote: "read line <&3\necho NOPE >&3\nexec sleep 30\n",
			flags: []string{"-skip-images"}, want: 1, wantRan: true, wantStderr: "-no-smoke"},
		{name: "-no-smoke runs nothing", zygote: "exit 7\n", flags: []string{"-skip-images", "-no-smoke"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			marker := filepath.Join(dir, "ran")
			zygote := filepath.Join(dir, "z")
			if err := os.WriteFile(zygote, []byte("#!/bin/sh\n: > "+marker+"\n"+tc.zygote), 0o755); err != nil {
				t.Fatal(err)
			}
			args := append([]string{"build", "-zygote", zygote, "-out", filepath.Join(dir, "art"), "-criu", "/nonexistent/criu"}, tc.flags...)
			code, stdout, stderr := call(args...)
			if code != tc.want || !strings.Contains(stderr, tc.wantStderr) {
				t.Fatalf("exit %d, stdout %q, stderr %q, want %d with %q", code, stdout, stderr, tc.want, tc.wantStderr)
			}
			if code == 0 && !strings.HasPrefix(stdout, "sha256:") {
				t.Fatalf("stdout %q, want the digest", stdout)
			}
			if _, err := os.Stat(marker); (err == nil) != tc.wantRan {
				t.Fatalf("the zygote ran %v, want %v", err == nil, tc.wantRan)
			}
		})
	}
}
