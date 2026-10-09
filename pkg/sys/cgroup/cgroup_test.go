package cgroup_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/helayoty/fiberd/pkg/sys/cgroup"
)

// fakeDir is a plain directory standing in for a cgroup, with the
// files given. Every cgroup operation is a file operation, so the
// parsing and error handling run on any OS. The real kernel behaviour
// is in cgroup_linux_test.go.
func fakeDir(t *testing.T, files map[string]string) cgroup.Dir {
	t.Helper()
	d := cgroup.Root(t.TempDir())
	for name, v := range files {
		if err := os.WriteFile(filepath.Join(d.Path, name), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

// mkdirIn makes a directory named name under d, which turns a control
// file into something that cannot be read or written.
func mkdirIn(t *testing.T, d cgroup.Dir, name string) {
	t.Helper()
	if err := os.Mkdir(filepath.Join(d.Path, name), 0o755); err != nil {
		t.Fatal(err)
	}
}

func fileIn(t *testing.T, d cgroup.Dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(d.Path, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// TestDirPaths checks that a Dir is its path, a child is a path below it, and
// only a directory exists.
func TestDirPaths(t *testing.T) {
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "file"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		dir      cgroup.Dir
		wantPath string
		wantName string
		exists   bool
	}{
		{name: "the root", dir: cgroup.Root(base), wantPath: base, wantName: filepath.Base(base), exists: true},
		{name: "a child that is not there", dir: cgroup.Root(base).Child("leaf"), wantPath: filepath.Join(base, "leaf"), wantName: "leaf"},
		{name: "a regular file is not a cgroup", dir: cgroup.Root(base).Child("file"), wantPath: filepath.Join(base, "file"), wantName: "file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.dir.Path != tc.wantPath || tc.dir.Name() != tc.wantName || tc.dir.Exists() != tc.exists {
				t.Fatalf("Dir = path %s name %s exists %v, want %s %s %v", tc.dir.Path, tc.dir.Name(), tc.dir.Exists(), tc.wantPath, tc.wantName, tc.exists)
			}
		})
	}
}

// TestEnsure checks that the directory is made, the controllers the parent
// offers are enabled one by one, and a parent without memory or an unwritable
// subtree_control is an error.
func TestEnsure(t *testing.T) {
	cases := []struct {
		name        string
		files       map[string]string
		underFile   bool // the path has a regular file as parent
		blocked     bool // cgroup.subtree_control is a directory
		controllers []string
		wantControl string // the last enable written, "" for none
		wantErr     string
		wantIs      error
	}{
		{name: "every controller when the parent lists none", controllers: []string{"memory", "pids"}, wantControl: "+pids"},
		{name: "only what the parent offers", files: map[string]string{"cgroup.controllers": "cpu memory\n"},
			controllers: []string{"memory", "pids"}, wantControl: "+memory"},
		{name: "no controllers asked", controllers: nil},
		{name: "memory is a must", files: map[string]string{"cgroup.controllers": "cpu pids\n"},
			controllers: []string{"memory"}, wantErr: "offers no memory controller (has: cpu pids)"},
		{name: "the directory cannot be made", underFile: true, controllers: []string{"memory"}, wantIs: syscall.ENOTDIR},
		{name: "subtree_control cannot be written", blocked: true, controllers: []string{"memory"}, wantErr: "enable memory under"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := fakeDir(t, tc.files)
			if tc.blocked {
				mkdirIn(t, d, "cgroup.subtree_control")
			}
			if tc.underFile {
				f := filepath.Join(d.Path, "file")
				if err := os.WriteFile(f, nil, 0o644); err != nil {
					t.Fatal(err)
				}
				d = cgroup.Root(f).Child("leaf")
			}
			err := d.Ensure(tc.controllers...)
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("Ensure = %v, want %v", err, tc.wantIs)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("Ensure = %v, want an error containing %q", err, tc.wantErr)
			}
			if tc.wantIs != nil || tc.wantErr != "" {
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !d.Exists() {
				t.Fatal("Ensure did not make the directory")
			}
			got, err := os.ReadFile(filepath.Join(d.Path, "cgroup.subtree_control"))
			if tc.wantControl == "" {
				if err == nil {
					t.Fatalf("subtree_control written (%q) with nothing to enable", got)
				}
				return
			}
			if err != nil || string(got) != tc.wantControl {
				t.Fatalf("subtree_control = %q, %v, want %q", got, err, tc.wantControl)
			}
		})
	}
}

// TestCreate checks that a leaf gets a memory ceiling with swap closed, and
// group OOM when asked. Each setting that fails is named.
func TestCreate(t *testing.T) {
	cases := []struct {
		name     string
		exists   bool   // the leaf is there already
		noParent bool   // the leaf's parent is missing
		blocked  string // a control file that is a directory
		memMax   uint64
		oomGroup bool
		want     map[string]string // control files afterwards
		absent   []string
		wantErr  string
		wantIs   error
	}{
		{name: "no ceiling, no group OOM", absent: []string{"memory.max", "memory.swap.max", "memory.oom.group"}},
		{name: "ceiling closes swap", memMax: 1 << 30, want: map[string]string{"memory.max": "1073741824", "memory.swap.max": "0"}, absent: []string{"memory.oom.group"}},
		{name: "group OOM", oomGroup: true, want: map[string]string{"memory.oom.group": "1"}, absent: []string{"memory.max"}},
		{name: "an existing leaf is reused", exists: true, memMax: 4096, want: map[string]string{"memory.max": "4096"}},
		{name: "missing parent", noParent: true, wantIs: fs.ErrNotExist},
		{name: "memory.max refused", exists: true, blocked: "memory.max", memMax: 4096, wantErr: "memory.max on"},
		{name: "memory.oom.group refused", exists: true, blocked: "memory.oom.group", oomGroup: true, wantErr: "memory.oom.group on"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := cgroup.Root(t.TempDir()).Child("leaf")
			if tc.noParent {
				d = d.Child("deeper")
			}
			if tc.exists {
				if err := os.Mkdir(d.Path, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if tc.blocked != "" {
				mkdirIn(t, d, tc.blocked)
			}
			err := d.Create(tc.memMax, tc.oomGroup)
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("Create = %v, want %v", err, tc.wantIs)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("Create = %v, want an error containing %q", err, tc.wantErr)
			}
			if tc.wantIs != nil || tc.wantErr != "" {
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for name, v := range tc.want {
				if got := fileIn(t, d, name); got != v {
					t.Fatalf("%s = %q, want %q", name, got, v)
				}
			}
			for _, name := range tc.absent {
				if _, err := os.Stat(filepath.Join(d.Path, name)); err == nil {
					t.Fatalf("%s written although not asked", name)
				}
			}
		})
	}
}

// TestSetCeiling checks that memory.high is the throttle, memory.max the
// stop when given, and swap is always closed.
func TestSetCeiling(t *testing.T) {
	cases := []struct {
		name      string
		high, max uint64
		blocked   string
		want      map[string]string
		absent    []string
		wantErr   string
	}{
		{name: "throttle only", high: 1000, want: map[string]string{"memory.high": "1000", "memory.swap.max": "0"}, absent: []string{"memory.max"}},
		{name: "throttle and stop", high: 1000, max: 2000, want: map[string]string{"memory.high": "1000", "memory.max": "2000", "memory.swap.max": "0"}},
		{name: "memory.high refused", blocked: "memory.high", high: 1, wantErr: "memory.high on"},
		{name: "memory.max refused", blocked: "memory.max", high: 1, max: 2, wantErr: "memory.max on"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := fakeDir(t, nil)
			if tc.blocked != "" {
				mkdirIn(t, d, tc.blocked)
			}
			err := d.SetCeiling(tc.high, tc.max)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("SetCeiling = %v, want an error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for name, v := range tc.want {
				if got := fileIn(t, d, name); got != v {
					t.Fatalf("%s = %q, want %q", name, got, v)
				}
			}
			for _, name := range tc.absent {
				if _, err := os.Stat(filepath.Join(d.Path, name)); err == nil {
					t.Fatalf("%s written although not asked", name)
				}
			}
		})
	}
}

// TestCeiling reads the nearest limit above a directory: the smallest
// numeric value on the way up, stopping where the file ends, and 0 when
// every ancestor says max.
func TestCeiling(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string // path relative to the mount: content
		dir   string            // the directory asked, relative to the mount
		want  uint64
	}{
		{name: "the parent's limit", files: map[string]string{"memory.max": "max", "box/memory.max": "1000"}, dir: "box/fiberd", want: 1000},
		{name: "the smallest limit above", files: map[string]string{"memory.max": "500", "box/memory.max": "1000"}, dir: "box/fiberd", want: 500},
		{name: "max all the way up", files: map[string]string{"memory.max": "max", "box/memory.max": "max"}, dir: "box/fiberd", want: 0},
		{name: "the walk stops where the file ends", files: map[string]string{"memory.max": "500", "box/pids.max": "7"}, dir: "box/fiberd", want: 0},
		{name: "a limit on the mount's own root, as a private namespace shows", files: map[string]string{"memory.max": "4096"}, dir: "fiberd", want: 4096},
		{name: "nothing above", files: nil, dir: "fiberd", want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mount := t.TempDir()
			for name, v := range tc.files {
				p := filepath.Join(mount, name)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(v+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if got := cgroup.Root(filepath.Join(mount, tc.dir)).Ceiling("memory.max"); got != tc.want {
				t.Fatalf("Ceiling = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestSetMemoryMin checks that the protection is written, or its refusal
// named.
func TestSetMemoryMin(t *testing.T) {
	cases := []struct {
		name    string
		blocked bool
		b       uint64
		wantErr string
	}{
		{name: "written", b: 65536},
		{name: "zero clears it", b: 0},
		{name: "refused", blocked: true, b: 1, wantErr: "memory.min on"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := fakeDir(t, nil)
			if tc.blocked {
				mkdirIn(t, d, "memory.min")
			}
			err := d.SetMemoryMin(tc.b)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("SetMemoryMin = %v, want an error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got, want := fileIn(t, d, "memory.min"), strconv.FormatUint(tc.b, 10); got != want {
				t.Fatalf("memory.min = %q, want %q", got, want)
			}
		})
	}
}

// counterCases are the shapes a one-counter read takes. They are the
// value, a missing file, a file that is not readable and a value that is
// not a number.
type counterCase struct {
	name    string
	file    string // "" for a missing file
	blocked bool   // the file is a directory
	want    uint64
	wantIs  error
	wantErr bool
}

// readCounter runs one case against read, with file the control file's name.
func readCounter(t *testing.T, tc counterCase, file string, read func(cgroup.Dir) (uint64, error)) {
	t.Helper()
	files := map[string]string{}
	if tc.file != "" {
		files[file] = tc.file
	}
	d := fakeDir(t, files)
	if tc.blocked {
		mkdirIn(t, d, file)
	}
	got, err := read(d)
	if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
		t.Fatalf("read = %d, %v, want %v", got, err, tc.wantIs)
	}
	if tc.wantErr && err == nil {
		t.Fatalf("read = %d, nil, want an error", got)
	}
	if tc.wantIs != nil || tc.wantErr {
		return
	}
	if err != nil || got != tc.want {
		t.Fatalf("read = %d, %v, want %d", got, err, tc.want)
	}
}

// TestMemoryCurrent checks the charge, trimmed, or why it cannot be read.
func TestMemoryCurrent(t *testing.T) {
	cases := []counterCase{
		{name: "the charge", file: "123456\n", want: 123456},
		{name: "missing", wantIs: fs.ErrNotExist},
		{name: "unreadable", blocked: true, wantErr: true},
		{name: "not a number", file: "lots\n", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			readCounter(t, tc, "memory.current", cgroup.Dir.MemoryCurrent)
		})
	}
}

// TestStat checks reading one counter out of memory.stat, by key.
func TestStat(t *testing.T) {
	stat := "anon 4096\nfile 8192\nshmem 12288\nanon_thp 0\n"
	cases := []struct {
		counterCase
		key string
	}{
		{counterCase{name: "the first key", file: stat, want: 4096}, "anon"},
		{counterCase{name: "a key further down", file: stat, want: 12288}, "shmem"},
		{counterCase{name: "a key that is a prefix of another is not confused", file: "anon_thp 7\nanon 4096\n", want: 4096}, "anon"},
		{counterCase{name: "no such key", file: stat, wantErr: true}, "swap"},
		{counterCase{name: "missing", wantIs: fs.ErrNotExist}, "anon"},
		{counterCase{name: "unreadable", blocked: true, wantErr: true}, "anon"},
		{counterCase{name: "not a number", file: "anon lots\n", wantErr: true}, "anon"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			readCounter(t, tc.counterCase, "memory.stat", func(d cgroup.Dir) (uint64, error) { return d.Stat(tc.key) })
		})
	}
}

// TestOOMKills checks the oom_kill count of memory.events, 0 when the line
// is not there.
func TestOOMKills(t *testing.T) {
	cases := []counterCase{
		{name: "kills counted", file: "low 0\nhigh 3\nmax 9\noom 2\noom_kill 2\noom_group_kill 1\n", want: 2},
		{name: "no oom_kill line", file: "low 0\n", want: 0},
		{name: "missing", wantIs: fs.ErrNotExist},
		{name: "unreadable", blocked: true, wantErr: true},
		{name: "not a number", file: "oom_kill many\n", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			readCounter(t, tc, "memory.events", cgroup.Dir.OOMKills)
		})
	}
}

// TestPSI checks avg10 of the some and full lines, and nothing from lines
// that are neither.
func TestPSI(t *testing.T) {
	cases := []struct {
		name    string
		file    string
		blocked bool
		want    cgroup.PSI
		wantIs  error
		wantErr bool
	}{
		{name: "some and full", file: "some avg10=1.50 avg60=0.70 avg300=0.10 total=1234\nfull avg10=0.25 avg60=0.00 avg300=0.00 total=99\n",
			want: cgroup.PSI{SomeAvg10: 1.5, FullAvg10: 0.25}},
		{name: "a root cgroup reports some only", file: "some avg10=2.00 avg60=0.00 avg300=0.00 total=5\n", want: cgroup.PSI{SomeAvg10: 2}},
		{name: "short and unknown lines skipped", file: "\nnone\nother avg10=9.00\nfull avg10=0.50 total=1\n", want: cgroup.PSI{FullAvg10: 0.5}},
		{name: "avg10 missing reads as zero", file: "some avg60=1.00\n"},
		{name: "missing", wantIs: fs.ErrNotExist},
		{name: "unreadable", blocked: true, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{}
			if tc.file != "" {
				files["memory.pressure"] = tc.file
			}
			d := fakeDir(t, files)
			if tc.blocked {
				mkdirIn(t, d, "memory.pressure")
			}
			got, err := d.PSI()
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("PSI = %+v, %v, want %v", got, err, tc.wantIs)
			}
			if tc.wantErr && err == nil {
				t.Fatalf("PSI = %+v, nil, want an error", got)
			}
			if tc.wantIs != nil || tc.wantErr {
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("PSI = %+v, %v, want %+v", got, err, tc.want)
			}
		})
	}
}

// TestProcs checks the pids of cgroup.procs, with anything else on the
// lines skipped.
func TestProcs(t *testing.T) {
	cases := []struct {
		name   string
		file   string
		want   []int
		wantIs error
	}{
		{name: "pids", file: "1\n42\n4242\n", want: []int{1, 42, 4242}},
		{name: "empty leaf", file: "", want: nil},
		{name: "junk skipped", file: "7\nx\n", want: []int{7}},
		{name: "missing", wantIs: fs.ErrNotExist},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{}
			if tc.wantIs == nil {
				files["cgroup.procs"] = tc.file
			}
			got, err := fakeDir(t, files).Procs()
			if tc.wantIs != nil {
				if !errors.Is(err, tc.wantIs) {
					t.Fatalf("Procs = %v, %v, want %v", got, err, tc.wantIs)
				}
				return
			}
			if err != nil || !slices.Equal(got, tc.want) {
				t.Fatalf("Procs = %v, %v, want %v", got, err, tc.want)
			}
		})
	}
}

// TestKillWritesTheKnob checks that Kill is a 1 in cgroup.kill, or the
// refusal.
func TestKillWritesTheKnob(t *testing.T) {
	cases := []struct {
		name    string
		blocked bool
		wantErr bool
	}{
		{name: "written"},
		{name: "refused", blocked: true, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := fakeDir(t, nil)
			if tc.blocked {
				mkdirIn(t, d, "cgroup.kill")
			}
			err := d.Kill()
			if tc.wantErr {
				if err == nil {
					t.Fatal("Kill = nil, want an error")
				}
				return
			}
			if err != nil || fileIn(t, d, "cgroup.kill") != "1" {
				t.Fatalf("Kill = %v, cgroup.kill = %q, want 1", err, fileIn(t, d, "cgroup.kill"))
			}
		})
	}
}

// TestRemove checks that a leaf goes, one already gone is fine, and one
// with children stays.
func TestRemove(t *testing.T) {
	cases := []struct {
		name    string
		exists  bool
		child   bool
		wantErr bool
	}{
		{name: "an empty leaf", exists: true},
		{name: "already gone"},
		{name: "not empty", exists: true, child: true, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := cgroup.Root(t.TempDir()).Child("leaf")
			if tc.exists {
				if err := os.Mkdir(d.Path, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if tc.child {
				mkdirIn(t, d, "sub")
			}
			err := d.Remove()
			if tc.wantErr {
				if err == nil || !d.Exists() {
					t.Fatalf("Remove = %v, exists %v, want an error and the leaf kept", err, d.Exists())
				}
				return
			}
			if err != nil || d.Exists() {
				t.Fatalf("Remove = %v, exists %v, want nil and gone", err, d.Exists())
			}
		})
	}
}

// TestChildren checks the sub-cgroups with the prefix, with files skipped.
func TestChildren(t *testing.T) {
	cases := []struct {
		name    string
		dirs    []string
		files   []string
		prefix  string
		missing bool
		want    []string
		wantIs  error
	}{
		{name: "by prefix", dirs: []string{"fiber-1", "fiber-2", "agent"}, files: []string{"fiber-file"}, prefix: "fiber-", want: []string{"fiber-1", "fiber-2"}},
		{name: "everything", dirs: []string{"a", "b"}, prefix: "", want: []string{"a", "b"}},
		{name: "none match", dirs: []string{"a"}, prefix: "z"},
		{name: "missing", missing: true, wantIs: fs.ErrNotExist},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := cgroup.Root(t.TempDir())
			if tc.missing {
				d = d.Child("none")
			}
			for _, name := range tc.dirs {
				mkdirIn(t, d, name)
			}
			for _, name := range tc.files {
				if err := os.WriteFile(filepath.Join(d.Path, name), nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			got, err := d.Children(tc.prefix)
			if tc.wantIs != nil {
				if !errors.Is(err, tc.wantIs) {
					t.Fatalf("Children = %v, %v, want %v", got, err, tc.wantIs)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, c := range got {
				if filepath.Dir(c.Path) != d.Path {
					t.Fatalf("child %s is not under %s", c.Path, d.Path)
				}
				names = append(names, c.Name())
			}
			if !slices.Equal(names, tc.want) {
				t.Fatalf("Children = %v, want %v", names, tc.want)
			}
		})
	}
}

// TestOpen checks a directory descriptor on the leaf, or the missing-leaf
// error.
func TestOpen(t *testing.T) {
	cases := []struct {
		name   string
		exists bool
		wantIs error
	}{
		{name: "a leaf", exists: true},
		{name: "missing", wantIs: fs.ErrNotExist},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := cgroup.Root(t.TempDir()).Child("leaf")
			if tc.exists {
				if err := os.Mkdir(d.Path, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			f, err := d.Open()
			if tc.wantIs != nil {
				if !errors.Is(err, tc.wantIs) {
					t.Fatalf("Open = %v, want %v", err, tc.wantIs)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			if st, err := f.Stat(); err != nil || !st.IsDir() || f.Name() != d.Path {
				t.Fatalf("Open = %s (dir %v, %v), want a descriptor on %s", f.Name(), st != nil && st.IsDir(), err, d.Path)
			}
		})
	}
}

// TestOwn checks the cgroup this process runs in, under a mount of the
// caller's choosing. Without /proc/self/cgroup (not Linux) or in the
// root of a private namespace that is the mount itself. Otherwise it
// is the scope /proc/self/cgroup names, when it exists under the mount.
func TestOwn(t *testing.T) {
	pc, err := os.ReadFile("/proc/self/cgroup")
	scope := ""
	if err == nil {
		scope = cgroup.ScopeOf(string(pc))
	}
	if filepath.Base(scope) == "agent" {
		scope = filepath.Dir(scope)
	}
	cases := []struct {
		name    string
		mkScope bool // make the scope's directory under the mount
		want    string
	}{
		{name: "the scope exists under the mount", mkScope: true, want: scope},
		{name: "the scope is missing under the mount", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mount := t.TempDir()
			if tc.mkScope && scope != "" {
				if err := os.MkdirAll(filepath.Join(mount, scope), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			want := filepath.Join(mount, tc.want)
			if scope == "" {
				want = mount
			}
			if got := cgroup.Own(mount); got.Path != want {
				t.Fatalf("Own(%s) = %s, want %s (scope %q)", mount, got.Path, want, scope)
			}
		})
	}
}
