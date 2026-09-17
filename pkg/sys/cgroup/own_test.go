package cgroup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestScopeOf: the container's cgroup under the mount is the root of a
// private namespace or the scope the host namespace shows.
func TestScopeOf(t *testing.T) {
	cases := map[string]string{
		"0::/\n": "",
		"0::/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable-podX.slice/cri-containerd-abc.scope\n": "/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable-podX.slice/cri-containerd-abc.scope",
		"0::/system.slice/slurmstepd.scope/job_42/step_0/user/task_0\n":                                             "/system.slice/slurmstepd.scope/job_42/step_0/user/task_0",
		"1:name=systemd:/\n": "",
	}
	for in, want := range cases {
		if got := ScopeOf(in); got != want {
			t.Fatalf("ScopeOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestOwnFromStripsTheAgentLeaf: an agent restarted in the same
// allocation finds itself in the leaf its predecessor made; its root is
// the leaf's parent.
func TestOwnFromStripsTheAgentLeaf(t *testing.T) {
	mount := t.TempDir()
	step := filepath.Join(mount, "system.slice", "slurmstepd.scope", "job_2", "step_batch", "user", "task_0")
	_ = os.MkdirAll(filepath.Join(step, "agent"), 0o755)
	if got := ownFrom(mount, "0::/system.slice/slurmstepd.scope/job_2/step_batch/user/task_0/agent\n"); got.Path != step {
		t.Fatalf("own from the agent leaf = %s, want %s", got.Path, step)
	}
	if got := ownFrom(mount, "0::/system.slice/slurmstepd.scope/job_2/step_batch/user/task_0\n"); got.Path != step {
		t.Fatalf("own from the step = %s, want %s", got.Path, step)
	}
	if got := ownFrom(mount, "0::/agent\n"); got.Path != mount {
		t.Fatalf("own from /agent = %s, want the mount root", got.Path)
	}
	if got := ownFrom(mount, "0::/nowhere/such\n"); got.Path != mount {
		t.Fatalf("own from a missing scope = %s, want the mount root", got.Path)
	}
}

// TestDelegateSkipsControllersTheRootLacks: a root whose
// cgroup.controllers has no pids (a Slurm step) delegates memory alone;
// one without memory is refused.
func TestDelegateSkipsControllersTheRootLacks(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "cgroup.controllers"), []byte("cpuset cpu memory\n"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), []byte(""), 0o644)
	_ = os.WriteFile(filepath.Join(root, "cgroup.procs"), []byte("7\n"), 0o644)
	if _, err := Delegate(Root(root)); err != nil {
		t.Fatal(err)
	}
	sub, _ := os.ReadFile(filepath.Join(root, "cgroup.subtree_control"))
	if got := strings.TrimSpace(string(sub)); got != "+memory" {
		t.Fatalf("subtree_control = %q, want +memory only", got)
	}
	if err := Root(root).Child("fiberd").Ensure("memory", "pids"); err != nil {
		t.Fatalf("Ensure on a child of that root: %v", err)
	}
	none := t.TempDir()
	_ = os.WriteFile(filepath.Join(none, "cgroup.controllers"), []byte("cpu\n"), 0o644)
	_ = os.WriteFile(filepath.Join(none, "cgroup.subtree_control"), []byte(""), 0o644)
	_ = os.WriteFile(filepath.Join(none, "cgroup.procs"), []byte(""), 0o644)
	if _, err := Delegate(Root(none)); err == nil || !strings.Contains(err.Error(), "memory") {
		t.Fatalf("delegate without memory = %v, want a refusal", err)
	}
}

// TestDelegateMovesSelfThenEnablesControllers: on a fake cgroup root that
// has processes and no controllers delegated, the agent leaf is created,
// the processes are moved there, and memory and pids are enabled for the
// subtree. Plain file operations, so it runs on any OS.
func TestDelegateMovesSelfThenEnablesControllers(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), []byte(""), 0o644)
	_ = os.WriteFile(filepath.Join(root, "cgroup.procs"), []byte("1\n42\n"), 0o644)
	got, err := Delegate(Root(root))
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != filepath.Join(root, "fiberd") {
		t.Fatalf("subtree = %s", got.Path)
	}
	moved, _ := os.ReadFile(filepath.Join(root, "agent", "cgroup.procs"))
	if !strings.Contains(string(moved), "42") {
		t.Fatalf("agent leaf procs = %q, want the last pid written", moved)
	}
	sub, _ := os.ReadFile(filepath.Join(root, "cgroup.subtree_control"))
	if !strings.Contains(string(sub), "+") {
		t.Fatalf("subtree_control = %q, want controllers enabled", sub)
	}

	// Already delegated: nothing is touched.
	root2 := t.TempDir()
	_ = os.WriteFile(filepath.Join(root2, "cgroup.subtree_control"), []byte("cpu memory pids"), 0o644)
	_ = os.WriteFile(filepath.Join(root2, "cgroup.procs"), []byte("1\n"), 0o644)
	if _, err := Delegate(Root(root2)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root2, "agent")); err == nil {
		t.Fatal("agent leaf created although the root was already delegated")
	}
}
