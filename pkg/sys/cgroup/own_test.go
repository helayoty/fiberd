package cgroup

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestScopeOf: the container's cgroup under the mount is the root of a
// private namespace or the scope the host namespace shows.
func TestScopeOf(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{name: "the root of a private namespace", in: "0::/\n", want: ""},
		{name: "a kubelet container scope",
			in:   "0::/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable-podX.slice/cri-containerd-abc.scope\n",
			want: "/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable-podX.slice/cri-containerd-abc.scope"},
		{name: "a Slurm task scope", in: "0::/system.slice/slurmstepd.scope/job_42/step_0/user/task_0\n",
			want: "/system.slice/slurmstepd.scope/job_42/step_0/user/task_0"},
		{name: "no v2 line", in: "1:name=systemd:/\n", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ScopeOf(tc.in); got != tc.want {
				t.Fatalf("ScopeOf(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestOwnFromStripsTheAgentLeaf: an agent restarted in the same
// allocation finds itself in the leaf its predecessor made; its root is
// the leaf's parent.
func TestOwnFromStripsTheAgentLeaf(t *testing.T) {
	mount := t.TempDir()
	step := filepath.Join("system.slice", "slurmstepd.scope", "job_2", "step_batch", "user", "task_0")
	_ = os.MkdirAll(filepath.Join(mount, step, "agent"), 0o755)
	_ = os.WriteFile(filepath.Join(mount, step, "cgroup.procs"), nil, 0o644)
	cases := []struct {
		name, procSelf string
		want           string // relative to the mount, "" for the mount root
	}{
		{name: "from the agent leaf, the step", procSelf: "0::/system.slice/slurmstepd.scope/job_2/step_batch/user/task_0/agent\n", want: step},
		{name: "from the step, the step", procSelf: "0::/system.slice/slurmstepd.scope/job_2/step_batch/user/task_0\n", want: step},
		{name: "from /agent, the mount root", procSelf: "0::/agent\n"},
		{name: "from a missing scope, the mount root", procSelf: "0::/nowhere/such\n"},
		{name: "from the root of a private namespace, the mount root", procSelf: "0::/\n"},
		{name: "without a v2 line, the mount root", procSelf: "1:name=systemd:/\n"},
		{name: "from a scope that is a file, the mount root", procSelf: "0::/system.slice/slurmstepd.scope/job_2/step_batch/user/task_0/cgroup.procs\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := filepath.Join(mount, tc.want)
			if got := ownFrom(mount, tc.procSelf); got.Path != want {
				t.Fatalf("ownFrom(%q) = %s, want %s", tc.procSelf, got.Path, want)
			}
		})
	}
}

// TestDelegate uses a fake cgroup root with processes and missing
// controllers. Plain file operations let it run on any OS. The processes
// move to the agent leaf, and the missing controllers that the root's
// cgroup.controllers lists (all when it is absent) are enabled for the
// subtree. Memory is a must. A root already delegated is not touched.
func TestDelegate(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string // the root's files before the call
		// Each enable is a write that replaces a plain file's contents, so
		// subtree_control holds the last controller enabled.
		control    string
		agentProcs string // last pid moved into the agent leaf, "" for no leaf
		prepare    func(t *testing.T, root string)
		err        string // substring of the refusal, "" for success
	}{
		{name: "processes move to the agent leaf, then memory and pids are enabled",
			files:   map[string]string{"cgroup.subtree_control": "", "cgroup.procs": "1\n42\n"},
			control: "+pids", agentProcs: "42"},
		{name: "already delegated: nothing is touched",
			files:   map[string]string{"cgroup.subtree_control": "cpu memory pids", "cgroup.procs": "1\n"},
			control: "cpu memory pids"},
		{name: "a root without pids (a Slurm step) delegates memory alone",
			files:   map[string]string{"cgroup.controllers": "cpuset cpu memory\n", "cgroup.subtree_control": "", "cgroup.procs": "7\n"},
			control: "+memory", agentProcs: "7"},
		{name: "a root without memory is refused",
			files: map[string]string{"cgroup.controllers": "cpu\n", "cgroup.subtree_control": "", "cgroup.procs": ""},
			err:   "memory"},
		{name: "an empty root enables the controllers without an agent leaf",
			files:   map[string]string{"cgroup.subtree_control": "", "cgroup.procs": ""},
			control: "+pids"},
		{name: "a root with memory already enabled gains pids alone",
			files:   map[string]string{"cgroup.subtree_control": "memory", "cgroup.procs": ""},
			control: "+pids"},
		{name: "a root without subtree_control is not a cgroup",
			files: map[string]string{"cgroup.procs": "1\n"},
			err:   "cgroup: root"},
		{name: "a root whose processes cannot be listed",
			files: map[string]string{"cgroup.subtree_control": ""},
			err:   "cgroup.procs"},
		{name: "a process that cannot be moved",
			files: map[string]string{"cgroup.subtree_control": "", "cgroup.procs": "42\n"},
			prepare: func(t *testing.T, root string) {
				// A file where the agent leaf should be. Making it is
				// "already there", and moving a pid into it fails.
				if err := os.WriteFile(filepath.Join(root, "agent"), nil, 0o644); err != nil {
					t.Fatal(err)
				}
			},
			err: "move pid 42 into the agent leaf"},
		{name: "a controller that cannot be enabled",
			files: map[string]string{"cgroup.procs": ""},
			prepare: func(t *testing.T, root string) {
				// A file that reads but refuses every write, the way a
				// read-only cgroup mount does.
				if runtime.GOOS != "linux" {
					t.Skip("needs a /proc file")
				}
				if err := os.Symlink("/proc/self/status", filepath.Join(root, "cgroup.subtree_control")); err != nil {
					t.Fatal(err)
				}
			},
			err: "enable memory under"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for name, v := range tc.files {
				_ = os.WriteFile(filepath.Join(root, name), []byte(v), 0o644)
			}
			if tc.prepare != nil {
				tc.prepare(t, root)
			}
			got, err := Delegate(Root(root))
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("Delegate = %v, want a refusal mentioning %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Path != filepath.Join(root, "fiberd") {
				t.Fatalf("subtree = %s, want %s", got.Path, filepath.Join(root, "fiberd"))
			}
			sub, _ := os.ReadFile(filepath.Join(root, "cgroup.subtree_control"))
			if got := strings.TrimSpace(string(sub)); got != tc.control {
				t.Fatalf("subtree_control = %q, want %q", got, tc.control)
			}
			moved, err := os.ReadFile(filepath.Join(root, "agent", "cgroup.procs"))
			if tc.agentProcs == "" {
				if _, serr := os.Stat(filepath.Join(root, "agent")); serr == nil {
					t.Fatal("agent leaf created although the root was already delegated")
				}
			} else if err != nil || string(moved) != tc.agentProcs {
				t.Fatalf("agent leaf procs = %q %v, want the last pid written %q", moved, err, tc.agentProcs)
			}
			if err := Root(root).Child("fiberd").Ensure("memory", "pids"); err != nil {
				t.Fatalf("Ensure on a child of that root: %v", err)
			}
		})
	}
}

// TestPidsLimitAndEvents checks that pids.max is written only where the
// controller is present, and pids.events max reads as the refused-fork count.
func TestPidsLimitAndEvents(t *testing.T) {
	cases := []struct {
		name     string
		files    map[string]string // present before the call
		dirs     []string          // control files that are directories, so unusable
		asFile   bool              // the cgroup itself is a regular file
		max      uint64
		wantMax  string // "" = pids.max absent afterwards
		wantHits uint64
		setErr   string // substring of SetPidsMax's refusal
		hitsErr  bool
	}{
		{name: "limit set and hits read", files: map[string]string{"pids.max": "max\n", "pids.events": "max 3\n"},
			max: 256, wantMax: "256", wantHits: 3},
		{name: "zero leaves it unlimited", files: map[string]string{"pids.max": "max\n", "pids.events": "max 0\n"},
			max: 0, wantMax: "max\n"},
		{name: "no pids controller", files: map[string]string{}, max: 256},
		{name: "events without a max line read as zero", files: map[string]string{"pids.events": "other 5\n"}, max: 0},
		{name: "pids.max refused", dirs: []string{"pids.max"}, max: 256, setErr: "pids.max on"},
		{name: "pids.events unreadable", dirs: []string{"pids.events"}, max: 0, hitsErr: true},
		{name: "pids.events malformed", files: map[string]string{"pids.events": "max lots\n"}, max: 0, hitsErr: true},
		{name: "not a cgroup at all", asFile: true, max: 0, hitsErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := Root(t.TempDir())
			if tc.asFile {
				d = d.Child("file")
				_ = os.WriteFile(d.Path, nil, 0o644)
			}
			for name, v := range tc.files {
				_ = os.WriteFile(d.file(name), []byte(v), 0o644)
			}
			for _, name := range tc.dirs {
				_ = os.Mkdir(d.file(name), 0o755)
			}
			err := d.SetPidsMax(tc.max)
			if tc.setErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.setErr) {
					t.Fatalf("SetPidsMax = %v, want a refusal mentioning %q", err, tc.setErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(d.file("pids.max"))
			if tc.wantMax == "" {
				if err == nil {
					t.Fatalf("pids.max created without a pids controller: %q", got)
				}
			} else if string(got) != tc.wantMax {
				t.Fatalf("pids.max = %q, want %q", got, tc.wantMax)
			}
			hits, err := d.PidsMaxHits()
			if tc.hitsErr {
				if err == nil {
					t.Fatalf("PidsMaxHits = %d, nil, want an error", hits)
				}
				return
			}
			if err != nil || hits != tc.wantHits {
				t.Fatalf("PidsMaxHits = %d %v, want %d", hits, err, tc.wantHits)
			}
		})
	}
}
