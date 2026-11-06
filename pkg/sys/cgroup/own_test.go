package cgroup

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
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

// TestOwnFromStripsTheFiberdLeaf: a fiberd restarted in the same
// allocation finds itself in the leaf its predecessor made; its root is
// the leaf's parent.
func TestOwnFromStripsTheFiberdLeaf(t *testing.T) {
	mount := t.TempDir()
	step := filepath.Join("system.slice", "slurmstepd.scope", "job_2", "step_batch", "user", "task_0")
	_ = os.MkdirAll(filepath.Join(mount, step, "fiberd"), 0o755)
	_ = os.WriteFile(filepath.Join(mount, step, "cgroup.procs"), nil, 0o644)
	cases := []struct {
		name, procSelf string
		want           string // relative to the mount, "" for the mount root
	}{
		{name: "from the fiberd leaf, the step", procSelf: "0::/system.slice/slurmstepd.scope/job_2/step_batch/user/task_0/fiberd\n", want: step},
		{name: "from the step, the step", procSelf: "0::/system.slice/slurmstepd.scope/job_2/step_batch/user/task_0\n", want: step},
		{name: "from /fiberd, the mount root", procSelf: "0::/fiberd\n"},
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
// move to the fiberd leaf, and the missing controllers that the root's
// cgroup.controllers lists (all when it is absent) are enabled for the
// subtree. Memory is a must. A root already delegated is not touched. A
// row's fail answers Delegate's writes the way a live root does.
func TestDelegate(t *testing.T) {
	const subtree = "cgroup.subtree_control"
	leafProcs := filepath.Join(ownLeaf, "cgroup.procs")
	// arrival refuses the first enable as pids enter the root.
	arrival := func(pids string) func(root, file, v string) error {
		arrived := false
		return func(root, file, _ string) error {
			if file != subtree || arrived {
				return nil
			}
			arrived = true
			if err := os.WriteFile(filepath.Join(root, "cgroup.procs"), []byte(pids), 0o644); err != nil {
				return err
			}
			return syscall.EBUSY
		}
	}
	// onEnable gives every enable err.
	onEnable := func(err error) func(root, file, v string) error {
		return func(_, file, _ string) error {
			if file == subtree {
				return err
			}
			return nil
		}
	}
	// pidsRefusedOnce refuses +pids once, and refuses any controller that
	// comes a second time.
	pidsRefusedOnce := func() func(root, file, v string) error {
		written := map[string]bool{}
		refused := false
		return func(_, file, v string) error {
			switch {
			case file != subtree:
				return nil
			case v == "+pids" && !refused:
				refused = true
				return syscall.EBUSY
			case written[v]:
				return syscall.EINVAL
			}
			written[v] = true
			return nil
		}
	}
	cases := []struct {
		name  string
		files map[string]string // the root's files before the call
		// Each enable is a write that replaces a plain file's contents, so
		// subtree_control holds the last controller enabled.
		control  string
		ownProcs string // last pid moved into the fiberd leaf, "" for no leaf
		prepare  func(t *testing.T, root string)
		// fail answers a write to file, relative to root, before it lands.
		// nil lets it through to the plain file.
		fail   func(root, file, v string) error
		err    string // substring of the refusal, $ROOT for the root, "" for success
		notErr string // what the refusal must not say
	}{
		{name: "processes move to the fiberd leaf, then memory and pids are enabled",
			files:   map[string]string{"cgroup.subtree_control": "", "cgroup.procs": "1\n42\n"},
			control: "+pids", ownProcs: "42"},
		{name: "already delegated: nothing is touched",
			files:   map[string]string{"cgroup.subtree_control": "cpu memory pids", "cgroup.procs": "1\n"},
			control: "cpu memory pids"},
		{name: "a root without pids (a Slurm step) delegates memory alone",
			files:   map[string]string{"cgroup.controllers": "cpuset cpu memory\n", "cgroup.subtree_control": "", "cgroup.procs": "7\n"},
			control: "+memory", ownProcs: "7"},
		{name: "a root without memory is refused",
			files: map[string]string{"cgroup.controllers": "cpu\n", "cgroup.subtree_control": "", "cgroup.procs": ""},
			err:   "memory"},
		{name: "an empty root enables the controllers without a fiberd leaf",
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
				// A file where the fiberd leaf should be. Making it is
				// "already there", and moving a pid into it fails.
				if err := os.WriteFile(filepath.Join(root, "fiberd"), nil, 0o644); err != nil {
					t.Fatal(err)
				}
			},
			err: "move pid 42 into the fiberd leaf"},
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
		{name: "a pid that exited is skipped",
			files: map[string]string{subtree: "", "cgroup.procs": "1\n42\n"},
			fail: func(_, file, v string) error {
				if file == leafProcs && v == "42" {
					return syscall.ESRCH
				}
				return nil
			},
			control: "+pids", ownProcs: "1"},
		{name: "a process that arrives during the move is moved on the next pass",
			files: map[string]string{subtree: "", "cgroup.procs": "1\n"},
			fail:  arrival("1\n7\n"), control: "+pids", ownProcs: "7"},
		{name: "a process that arrives in an empty root gets the leaf then",
			files: map[string]string{subtree: "", "cgroup.procs": ""},
			fail:  arrival("7\n"), control: "+pids", ownProcs: "7"},
		{name: "a controller enabled before the arrival is not written again",
			files: map[string]string{subtree: "", "cgroup.procs": "1\n"},
			fail:  pidsRefusedOnce(), control: "+pids", ownProcs: "1"},
		{name: "a root that never empties is refused",
			files: map[string]string{subtree: "", "cgroup.procs": "1\n42\n"},
			fail:  onEnable(syscall.EBUSY), err: "enable memory under $ROOT: processes still in it: 1 42", notErr: "cgroup mount"},
		{name: "a busy root with no pid left to list says so",
			files: map[string]string{subtree: "", "cgroup.procs": ""},
			fail:  onEnable(syscall.EBUSY), err: "enable memory under $ROOT: processes still in it: none listed"},
		{name: "a read-only mount keeps its hint",
			files: map[string]string{subtree: "", "cgroup.procs": ""},
			fail:  onEnable(syscall.EROFS), err: "enable memory under $ROOT (is the cgroup mount writable?)"},
		{name: "a move a read-only mount refuses gets the hint too",
			files: map[string]string{subtree: "", "cgroup.procs": "1\n"},
			fail: func(_, file, _ string) error {
				if file == leafProcs {
					return syscall.EROFS
				}
				return nil
			},
			err: "move pid 1 into the fiberd leaf (is the cgroup mount writable?)"},
		{name: "any other refusal has no hint",
			files: map[string]string{subtree: "", "cgroup.procs": ""},
			fail:  onEnable(syscall.EPERM), err: "enable memory under", notErr: "cgroup mount"},
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
			if tc.fail != nil {
				delegateWrite = func(d Dir, name, v string) error {
					file, err := filepath.Rel(root, d.file(name))
					if err != nil {
						return err
					}
					if err := tc.fail(root, file, v); err != nil {
						return err
					}
					return d.write(name, v)
				}
				t.Cleanup(func() { delegateWrite = Dir.write })
			}
			got, err := Delegate(Root(root))
			if tc.err != "" {
				want := strings.ReplaceAll(tc.err, "$ROOT", root)
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("Delegate = %v, want a refusal mentioning %q", err, want)
				}
				if tc.notErr != "" && strings.Contains(err.Error(), tc.notErr) {
					t.Fatalf("Delegate = %v, want a refusal without %q", err, tc.notErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Path != filepath.Join(root, "grants") {
				t.Fatalf("subtree = %s, want %s", got.Path, filepath.Join(root, "grants"))
			}
			sub, _ := os.ReadFile(filepath.Join(root, "cgroup.subtree_control"))
			if got := strings.TrimSpace(string(sub)); got != tc.control {
				t.Fatalf("subtree_control = %q, want %q", got, tc.control)
			}
			moved, err := os.ReadFile(filepath.Join(root, "fiberd", "cgroup.procs"))
			if tc.ownProcs == "" {
				if _, serr := os.Stat(filepath.Join(root, "fiberd")); serr == nil {
					t.Fatal("fiberd leaf created although the root was already delegated")
				}
			} else if err != nil || string(moved) != tc.ownProcs {
				t.Fatalf("fiberd leaf procs = %q %v, want the last pid written %q", moved, err, tc.ownProcs)
			}
			if err := Root(root).Child("grants").Ensure("memory", "pids"); err != nil {
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
