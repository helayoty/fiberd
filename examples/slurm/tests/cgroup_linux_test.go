//go:build linux && integration

package slurmtest

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestCgroupSetup runs docker/cgroup-setup.sh the way the entrypoint
// does, with a shell sitting in the root it is given, as the container's
// first process sits in the container's root cgroup. The script must
// move that shell into the init leaf before it enables the controllers,
// on the root and on system.slice, and make the slurmd leaf. A
// controller the kernel does not know, and a directory that is not a
// cgroup, end it with a message naming the controller and the error.
func TestCgroupSetup(t *testing.T) {
	script, err := filepath.Abs("../docker/cgroup-setup.sh")
	if err != nil {
		t.Fatal(err)
	}
	cgRoot := os.Getenv("FIBERD_CGROUP_ROOT")
	if cgRoot == "" {
		cgRoot = "/sys/fs/cgroup/fiberd"
	}
	for _, c := range []string{"memory", "pids"} {
		if !slices.Contains(controllers(t, filepath.Join(cgRoot, "cgroup.subtree_control")), c) {
			t.Skipf("%s is not delegated under %s", c, cgRoot)
		}
	}
	cases := []struct {
		name        string
		fake        bool // a plain directory holding the cgroup files as regular files
		controllers []string
		wantErr     []string // what stderr must say, none for success
	}{
		{name: "a root holding a process", controllers: []string{"memory", "pids"}},
		{name: "a controller the kernel does not know", controllers: []string{"memory", "nosuch"},
			wantErr: []string{"cannot enable nosuch in ", "Invalid argument"}},
		{name: "a directory that is not a cgroup", fake: true, controllers: []string{"memory"},
			wantErr: []string{"cannot enable memory in ", "not listed in"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var root string
			if tc.fake {
				root = t.TempDir()
				for _, f := range []string{"cgroup.procs", "cgroup.subtree_control"} {
					if err := os.WriteFile(filepath.Join(root, f), nil, 0o644); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				root = filepath.Join(cgRoot, "slurm-cgroup-test-"+strconv.Itoa(os.Getpid()))
				if err := os.Mkdir(root, 0o755); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { removeCgroup(t, root) })
			}
			// The shell enters the root, then becomes the script, so the
			// script's own process is what has to be moved out. The fake
			// root is no cgroup to enter, so the script runs as it is.
			cmd := exec.Command(script, append([]string{root}, tc.controllers...)...)
			if !tc.fake {
				args := append([]string{"-c", `echo $$ > "$1/cgroup.procs" && exec "$0" "$@"`, script, root}, tc.controllers...)
				cmd = exec.Command("bash", args...)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			err := cmd.Run()
			if len(tc.wantErr) > 0 {
				if err == nil {
					t.Fatalf("cgroup-setup succeeded, want it to fail with %q", tc.wantErr)
				}
				for _, want := range tc.wantErr {
					if !strings.Contains(stderr.String(), want) {
						t.Errorf("stderr %q, want it to contain %q", stderr.String(), want)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("cgroup-setup: %v, stderr %q", err, stderr.String())
			}
			for _, dir := range []string{root, filepath.Join(root, "system.slice")} {
				have := controllers(t, filepath.Join(dir, "cgroup.subtree_control"))
				for _, c := range tc.controllers {
					if !slices.Contains(have, c) {
						t.Errorf("%s is not enabled in %s, which has %q", c, dir, have)
					}
				}
			}
			if fi, err := os.Stat(filepath.Join(root, "system.slice", "slurmd")); err != nil || !fi.IsDir() {
				t.Errorf("no slurmd leaf under system.slice: %v", err)
			}
			if procs, _ := os.ReadFile(filepath.Join(root, "cgroup.procs")); len(bytes.TrimSpace(procs)) != 0 {
				t.Errorf("processes left in the root: %q", procs)
			}
		})
	}
}

// controllers lists the controllers a subtree_control file names.
func controllers(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(b))
}

// removeCgroup removes the tree cgroup-setup makes under root once its
// processes are gone, leaves first.
func removeCgroup(t *testing.T, root string) {
	t.Helper()
	for _, dir := range []string{"init", "system.slice/slurmd", "system.slice", ""} {
		path := filepath.Join(root, dir)
		for i := 0; i < 50; i++ {
			if err := os.Remove(path); err == nil || os.IsNotExist(err) {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}
