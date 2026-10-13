//go:build linux && integration

package slurmtest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// fiberdSlurm is the binary TestMain builds from ../cmd/fiberd-slurm.
var fiberdSlurm string

func TestMain(m *testing.M) {
	cgRoot := os.Getenv("FIBERD_CGROUP_ROOT")
	if cgRoot == "" {
		cgRoot = "/sys/fs/cgroup/fiberd"
	}
	if f, err := os.OpenFile(filepath.Join(cgRoot, "cgroup.subtree_control"), os.O_WRONLY, 0); err != nil {
		fmt.Fprintf(os.Stderr, "skipping slurm tests: %s not writable (run under hack/dev/run.sh)\n", cgRoot)
		os.Exit(0)
	} else {
		_ = f.Close()
	}
	dir, err := os.MkdirTemp("", "fiberd-slurm-bin")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fiberdSlurm = filepath.Join(dir, "fiberd-slurm")
	build := exec.Command("go", "build", "-o", fiberdSlurm, "../cmd/fiberd-slurm")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "build fiberd-slurm: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// shortDir is a temporary directory with a short path. fiberd's admin
// socket lives under it, and unix socket paths are limited to about 100
// bytes.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "fs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// fakeCgroup is a cgroup v2 mount with its controllers already delegated,
// so a home made in process touches no real cgroup.
func fakeCgroup(t *testing.T) string {
	t.Helper()
	cg := t.TempDir()
	if err := os.WriteFile(filepath.Join(cg, "cgroup.subtree_control"), []byte("memory pids\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return cg
}

// probeScript writes a shell script that reports the state a file names,
// so a test flips the job's state under a probe that really execs.
func probeScript(t *testing.T, dir string) (script string, set func(state string)) {
	t.Helper()
	stateFile := filepath.Join(dir, "state")
	set = func(s string) {
		if err := os.WriteFile(stateFile, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	set("RUNNING")
	script = filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho \"JobId=4242 JobName=x JobState=$(cat "+stateFile+") NodeList=localhost\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return script, set
}
