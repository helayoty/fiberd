package criu

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// fakeProc plants a process tree under a fake /proc. Each process has a
// status with its NSpid line, a task directory whose children files name
// its children, and a smaps with the mappings given, each flagged dp or
// not.
type fakeTask struct {
	pid      int
	nspid    []int // the NSpid line, pid first
	children []int
	smaps    string
}

func plantProc(t *testing.T, tasks []fakeTask) string {
	t.Helper()
	proc := t.TempDir()
	for _, task := range tasks {
		dir := filepath.Join(proc, strconv.Itoa(task.pid))
		if err := os.MkdirAll(filepath.Join(dir, "task", strconv.Itoa(task.pid)), 0o755); err != nil {
			t.Fatal(err)
		}
		ids := []string{strconv.Itoa(task.pid)}
		for _, id := range task.nspid {
			ids = append(ids, strconv.Itoa(id))
		}
		status := "Name:\tfiber\nNSpid:\t" + strings.Join(ids, "\t") + "\n"
		if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644); err != nil {
			t.Fatal(err)
		}
		var kids []string
		for _, k := range task.children {
			kids = append(kids, strconv.Itoa(k))
		}
		if err := os.WriteFile(filepath.Join(dir, "task", strconv.Itoa(task.pid), "children"), []byte(strings.Join(kids, " ")+" "), 0o644); err != nil {
			t.Fatal(err)
		}
		if task.smaps != "" {
			if err := os.WriteFile(filepath.Join(dir, "smaps"), []byte(task.smaps), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return proc
}

// mapping is one smaps entry, as the kernel prints it, with the flags
// given on its VmFlags line.
func mapping(start, end uint64, flags string) string {
	return strconv.FormatUint(start, 16) + "-" + strconv.FormatUint(end, 16) + " rw-p 00000000 00:00 0                          [anon:vdso]\n" +
		"Size:                  4 kB\nRss:                   4 kB\nVmFlags: " + flags + " \n"
}

// TestDroppableMappings checks that the dp mappings of every process of a
// tree are found, keyed by the pid criu names images with, which is the
// pid at the root's namespace depth. Processes without one are left out,
// one that is gone is skipped, and a root that is gone gives nothing.
func TestDroppableMappings(t *testing.T) {
	dp := mapping(0x1000, 0x2000, "rd wr mr mw me nr wf dd dp")
	plain := mapping(0x5000, 0x8000, "rd wr mr mw me ac")
	cases := []struct {
		name  string
		tasks []fakeTask
		root  int
		want  map[int][]droppable
		err   string
	}{
		{name: "one process in the host namespace", root: 7,
			tasks: []fakeTask{{pid: 7, smaps: plain + dp}},
			want:  map[int][]droppable{7: {{0x1000, 0x2000}}}},
		{name: "a root in its own namespace is named by its inner pid", root: 7,
			tasks: []fakeTask{{pid: 7, nspid: []int{1}, smaps: dp}},
			want:  map[int][]droppable{1: {{0x1000, 0x2000}}}},
		{name: "children are walked and named at the root's depth", root: 7,
			tasks: []fakeTask{
				{pid: 7, nspid: []int{1}, children: []int{8, 9}, smaps: plain},
				{pid: 8, nspid: []int{2}, smaps: dp},
				{pid: 9, nspid: []int{3}, children: []int{10}, smaps: plain},
				{pid: 10, nspid: []int{4, 1}, smaps: dp + mapping(0x9000, 0xa000, "rd wr dp")},
			},
			want: map[int][]droppable{2: {{0x1000, 0x2000}}, 4: {{0x1000, 0x2000}, {0x9000, 0xa000}}}},
		{name: "a child that exited is skipped", root: 7,
			tasks: []fakeTask{{pid: 7, children: []int{8}, smaps: dp}},
			want:  map[int][]droppable{7: {{0x1000, 0x2000}}}},
		{name: "a root that is gone", root: 7, want: nil},
		{name: "no droppable mappings", root: 7,
			tasks: []fakeTask{{pid: 7, smaps: plain}}, want: map[int][]droppable{}},
		{name: "a mangled mapping line", root: 7,
			tasks: []fakeTask{{pid: 7, smaps: "zzz\nVmFlags: dp\n"}}, err: `mapping "zzz"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proc := plantProc(t, tc.tasks)
			got, err := droppableMappings(proc, tc.root)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("err = %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("mappings = %v, want %v", got, tc.want)
			}
			for pid, want := range tc.want {
				if g := got[pid]; len(g) != len(want) || (len(want) > 0 && !equalDroppable(g, want)) {
					t.Fatalf("pid %d: mappings = %v, want %v", pid, g, want)
				}
			}
		})
	}
}

func equalDroppable(a, b []droppable) bool {
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestScrubDroppable checks that only the present pages inside a
// droppable mapping are zeroed, at their place in the pages file, and
// that pages the dump left out need nothing.
func TestScrubDroppable(t *testing.T) {
	ps := PageSize
	fill := func(b byte) []byte { return bytes.Repeat([]byte{b}, int(ps)) }
	type img struct {
		entries []PagemapEntry
		pages   []byte
	}
	cases := []struct {
		name     string
		imgs     map[int]img // pid -> image
		mappings map[int][]droppable
		want     map[int][]byte // pid -> pages file after
		zeroed   int
	}{
		{name: "the droppable page in the middle of a run",
			imgs: map[int]img{7: {
				entries: []PagemapEntry{{VAddr: 1 * ps, NrPages: 3, Flags: PEPresent}},
				pages:   bytes.Join([][]byte{fill(1), fill(2), fill(3)}, nil)}},
			mappings: map[int][]droppable{7: {{2 * ps, 3 * ps}}},
			want:     map[int][]byte{7: bytes.Join([][]byte{fill(1), fill(0), fill(3)}, nil)},
			zeroed:   1},
		{name: "a parent entry takes no room in the pages file",
			imgs: map[int]img{7: {
				entries: []PagemapEntry{{VAddr: 1 * ps, NrPages: 2, Flags: PEParent}, {VAddr: 3 * ps, NrPages: 2, Flags: PEPresent}},
				pages:   bytes.Join([][]byte{fill(1), fill(2)}, nil)}},
			mappings: map[int][]droppable{7: {{4 * ps, 5 * ps}}},
			want:     map[int][]byte{7: bytes.Join([][]byte{fill(1), fill(0)}, nil)},
			zeroed:   1},
		{name: "a mapping the dump left out",
			imgs: map[int]img{7: {
				entries: []PagemapEntry{{VAddr: 1 * ps, NrPages: 1, Flags: PEPresent}},
				pages:   fill(1)}},
			mappings: map[int][]droppable{7: {{9 * ps, 10 * ps}}},
			want:     map[int][]byte{7: fill(1)}},
		{name: "a pid criu did not dump",
			imgs:     map[int]img{7: {entries: []PagemapEntry{{VAddr: 1 * ps, NrPages: 1, Flags: PEPresent}}, pages: fill(1)}},
			mappings: map[int][]droppable{8: {{1 * ps, 2 * ps}}},
			want:     map[int][]byte{7: fill(1)}},
		{name: "two processes",
			imgs: map[int]img{
				7: {entries: []PagemapEntry{{VAddr: 1 * ps, NrPages: 1, Flags: PEPresent}}, pages: fill(1)},
				8: {entries: []PagemapEntry{{VAddr: 1 * ps, NrPages: 2, Flags: PEPresent}}, pages: bytes.Join([][]byte{fill(1), fill(2)}, nil)}},
			mappings: map[int][]droppable{7: {{1 * ps, 2 * ps}}, 8: {{1 * ps, 3 * ps}}},
			want:     map[int][]byte{7: fill(0), 8: bytes.Join([][]byte{fill(0), fill(0)}, nil)},
			zeroed:   3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for pid, im := range tc.imgs {
				pm := &Pagemap{Path: filepath.Join(dir, "pagemap-"+strconv.Itoa(pid)+".img"), Header: []byte{0x19, 0x43, 0x56, 0x54, 1, 0, 0, 0}, PagesID: uint32(pid), Entries: im.entries}
				if err := writePagemap(pm); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(pm.PagesFile(), im.pages, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			n, err := scrubDroppable(dir, tc.mappings)
			if err != nil {
				t.Fatal(err)
			}
			if n != tc.zeroed {
				t.Fatalf("zeroed %d pages, want %d", n, tc.zeroed)
			}
			for pid, want := range tc.want {
				got, err := os.ReadFile(filepath.Join(dir, "pages-"+strconv.Itoa(pid)+".img"))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("pid %d: pages file differs from the one wanted", pid)
				}
			}
		})
	}
	t.Run("a pagemap that cannot be read", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "pagemap-7.img"), []byte("xx"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := scrubDroppable(dir, map[int][]droppable{7: {{0x1000, 0x2000}}}); err == nil || !strings.Contains(err.Error(), "short header") {
			t.Fatalf("err = %v, want the pagemap's parse error", err)
		}
	})
}

// TestDumpWithScrubs checks that a dump zeroes the droppable pages of the
// tree in the images criu wrote, and that a dump that leaves the tree
// running reads the mappings again afterwards.
func TestDumpWithScrubs(t *testing.T) {
	ps := PageSize
	cases := []struct {
		name         string
		leaveRunning bool
		plantLate    bool // the dp mapping appears only after the dump
		wantZero     bool
	}{
		{name: "a kill dump zeroes what was mapped before it", wantZero: true},
		{name: "a leave-running dump reads the mappings after it", leaveRunning: true, plantLate: true, wantZero: true},
		{name: "a kill dump cannot see a mapping made after it", plantLate: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dp := mapping(0x1000, 0x2000, "rd wr nr wf dd dp")
			early := dp
			if tc.plantLate {
				early = ""
			}
			proc := plantProc(t, []fakeTask{{pid: 7, smaps: early}})
			dir := filepath.Join(t.TempDir(), "img")
			fake := &scrubbingCriu{dir: dir, pages: bytes.Repeat([]byte{0xab}, int(ps)), after: func() {
				if tc.plantLate {
					if err := os.WriteFile(filepath.Join(proc, "7", "smaps"), []byte(dp), 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}}
			if err := (Options{Commander: fake, Proc: proc}).DumpWith(t.Context(), 7, dir, tc.leaveRunning, nil); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(filepath.Join(dir, "pages-1.img"))
			if err != nil {
				t.Fatal(err)
			}
			if zero := bytes.Equal(got, make([]byte, ps)); zero != tc.wantZero {
				t.Fatalf("page zeroed = %v, want %v", zero, tc.wantZero)
			}
		})
	}
}

// scrubbingCriu is a Commander whose dump writes one image with one
// present page at 0x1000, then runs after.
type scrubbingCriu struct {
	dir   string
	pages []byte
	after func()
}

func (s *scrubbingCriu) Output(_ context.Context, _ []string) ([]byte, error) {
	pm := &Pagemap{Path: filepath.Join(s.dir, "pagemap-7.img"), Header: []byte{0x19, 0x43, 0x56, 0x54, 1, 0, 0, 0}, PagesID: 1,
		Entries: []PagemapEntry{{VAddr: 0x1000, NrPages: 1, Flags: PEPresent}}}
	if err := writePagemap(pm); err != nil {
		return nil, err
	}
	if err := os.WriteFile(pm.PagesFile(), s.pages, 0o600); err != nil {
		return nil, err
	}
	s.after()
	return nil, nil
}

func (s *scrubbingCriu) Start([]string, []*os.File, int) (Process, error) {
	return nil, errors.New("not a restore")
}
