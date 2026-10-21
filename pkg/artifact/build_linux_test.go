//go:build linux

package artifact_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/sys/criu"
)

// TestBuildSmoke checks that a build without images still runs the
// zygote to READY, the way a home starts it, and refuses one that does
// not get there. NoSmoke builds without running anything. No criu is
// involved either way. The smoke leaves no process and no directory.
func TestBuildSmoke(t *testing.T) {
	fakeHost(t)
	cases := []struct {
		name    string
		zygote  string // a shell script standing in for the zygote
		args    []string
		noSmoke bool
		timeout time.Duration
		want    string // substrings of the error, any of them split by "|", "" for success
	}{
		{name: "a zygote that answers PREPARE none with READY", args: []string{"--heap-mb", "8"},
			zygote: "read line <&3\n[ \"$line\" = 'PREPARE none' ] || exit 3\n[ \"$*\" = '--heap-mb 8' ] || exit 4\necho READY >&3\nexec sleep 30\n"},
		// Its exit, its closed channel or the reset of the unread PREPARE,
		// whichever the build sees first.
		{name: "a zygote that exits before READY", zygote: "exit 7\n", want: "exited before READY|did not become ready: "},
		{name: "a zygote that says something else", zygote: "read line <&3\necho NOPE >&3\nexec sleep 30\n", want: `zygote said "NOPE"`},
		{name: "a zygote that never answers", zygote: "exec sleep 30\n", timeout: 200 * time.Millisecond, want: "did not become ready in time"},
		{name: "no smoke: a zygote that cannot run is not run", zygote: "exit 7\n", noSmoke: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			t.Setenv("TMPDIR", tmp)
			root := t.TempDir()
			pidFile := filepath.Join(root, "pid")
			writeFile(t, filepath.Join(root, "z"), "#!/bin/sh\necho $$ > "+pidFile+"\n"+tc.zygote)
			out := filepath.Join(root, "out")
			digest, err := artifact.Build(context.Background(), artifact.BuildOptions{Zygote: filepath.Join(root, "z"), Args: tc.args, Out: out,
				SkipImages: true, NoSmoke: tc.noSmoke, ReadyTimeout: tc.timeout, CRIU: criu.Options{Bin: "/nonexistent/criu"}})
			if tc.want != "" {
				said := false
				for _, w := range strings.Split(tc.want, "|") {
					said = said || (err != nil && strings.Contains(err.Error(), w))
				}
				if !said || !strings.Contains(err.Error(), "-no-smoke") {
					t.Fatalf("Build = %s, %v; want an error about %q that names -no-smoke", digest, err, tc.want)
				}
			} else if err != nil || !strings.HasPrefix(digest, "sha256:") {
				t.Fatalf("Build = %s, %v", digest, err)
			}
			if tc.want == "" {
				cfg, err := artifact.ReadConfig(out)
				if err != nil || cfg.HasImages() {
					t.Fatalf("config = %+v (%v), want one without images", cfg, err)
				}
				if _, err := os.Stat(filepath.Join(out, "images")); !os.IsNotExist(err) {
					t.Fatalf("a build without images left images: %v", err)
				}
			}
			ran := false
			if b, err := os.ReadFile(pidFile); err == nil {
				ran = true
				var pid int
				if _, err := fmt.Sscan(strings.TrimSpace(string(b)), &pid); err == nil && syscall.Kill(pid, 0) == nil {
					t.Fatalf("the zygote %d outlived the build", pid)
				}
			}
			if ran == tc.noSmoke {
				t.Fatalf("the zygote ran %v, want %v", ran, !tc.noSmoke)
			}
			if ents, _ := os.ReadDir(tmp); len(ents) != 0 {
				t.Fatalf("the smoke left %v in TMPDIR", ents)
			}
		})
	}
}
