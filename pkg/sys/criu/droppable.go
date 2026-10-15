package criu

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Droppable mappings hold kernel state a restored copy must not keep.
//
// A glibc of 2.41 or later answers getrandom(2) from the vDSO on a
// kernel of 6.11 or later. The vDSO keeps a ChaCha key and a batch of
// output per thread in user memory, in pages the libc maps with
// MAP_DROPPABLE, and only reseeds that state when the kernel's RNG
// generation counter moves on. A CRIU dump copies those pages like any
// other, and a restore puts them back under a kernel whose counter has
// not moved, so every process restored from one image continues the one
// keystream. That covers every getrandom caller, the template's own
// reseed, Python's os.urandom, secrets and uuid4 and OpenSSL's seeding
// among them. criu 4.2 skips the pages and restores the mapping as
// droppable. For an older criu the dump zeroes them here. A zeroed
// state carries generation 0, which the kernel never issues, so the
// first getrandom in each restored copy reseeds from the kernel.
//
// The mappings are read from /proc/<pid>/smaps of every process in the
// tree, where the kernel flags them "dp". The pages of each one are then
// zeroed in place in the images.

// droppable is one droppable mapping of a dumped process, [start, end).
type droppable struct {
	start, end uint64
}

// droppableMappings lists the droppable mappings of the tree rooted at
// pid, keyed by the pid criu names the process's images with (the one in
// the root's pid namespace). A process that exits during the walk is
// skipped. A root that is gone gives an empty map, and criu reports it.
func droppableMappings(proc string, pid int) (map[int][]droppable, error) {
	depth, err := nsDepth(proc, pid)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[int][]droppable{}
	todo := []int{pid}
	for len(todo) > 0 {
		p := todo[0]
		todo = todo[1:]
		kids, err := children(proc, p)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		todo = append(todo, kids...)
		dps, err := smapsDroppable(filepath.Join(proc, strconv.Itoa(p), "smaps"))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(dps) == 0 {
			continue
		}
		vpid, err := nsPID(proc, p, depth)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out[vpid] = append(out[vpid], dps...)
	}
	return out, nil
}

// nsPIDs is the NSpid line of a process: its pid in this /proc's
// namespace first, then in each nested one.
func nsPIDs(proc string, pid int) ([]int, error) {
	status, err := os.ReadFile(filepath.Join(proc, strconv.Itoa(pid), "status"))
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "NSpid:") {
			continue
		}
		var ids []int
		for _, f := range strings.Fields(line)[1:] {
			n, err := strconv.Atoi(f)
			if err != nil {
				return nil, fmt.Errorf("criu: pid %d: NSpid %q", pid, line)
			}
			ids = append(ids, n)
		}
		if len(ids) == 0 {
			break
		}
		return ids, nil
	}
	return nil, fmt.Errorf("criu: pid %d: no NSpid in its status", pid)
}

// nsDepth is how many pid namespaces deep the root task sits, counted
// from this /proc's. criu names images by the pid at that depth.
func nsDepth(proc string, pid int) (int, error) {
	ids, err := nsPIDs(proc, pid)
	if err != nil {
		return 0, err
	}
	return len(ids), nil
}

// nsPID is the pid of pid at depth, the namespace level of the dumped
// root, which every process of the tree is in or below.
func nsPID(proc string, pid, depth int) (int, error) {
	ids, err := nsPIDs(proc, pid)
	if err != nil {
		return 0, err
	}
	if len(ids) < depth {
		return 0, fmt.Errorf("criu: pid %d is above the dumped tree's pid namespace", pid)
	}
	return ids[depth-1], nil
}

// children lists the child processes of every thread of pid.
func children(proc string, pid int) ([]int, error) {
	tasks, err := os.ReadDir(filepath.Join(proc, strconv.Itoa(pid), "task"))
	if err != nil {
		return nil, err
	}
	var out []int
	for _, t := range tasks {
		b, err := os.ReadFile(filepath.Join(proc, strconv.Itoa(pid), "task", t.Name(), "children"))
		if errors.Is(err, fs.ErrNotExist) {
			continue // the thread is gone
		}
		if err != nil {
			return nil, err
		}
		for _, f := range strings.Fields(string(b)) {
			n, err := strconv.Atoi(f)
			if err != nil {
				return nil, fmt.Errorf("criu: pid %d: children %q", pid, b)
			}
			out = append(out, n)
		}
	}
	return out, nil
}

// smapsDroppable reads the mappings flagged dp (VM_DROPPABLE) in a smaps
// file. A mapping's header line is "start-end perms ...", and its
// "VmFlags:" line holds two-letter flags.
func smapsDroppable(path string) ([]droppable, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []droppable
	var cur droppable
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		switch {
		case len(fields) == 0:
		case fields[0] == "VmFlags:":
			if slices.Contains(fields[1:], "dp") && cur.end > cur.start {
				out = append(out, cur)
			}
		case !strings.HasSuffix(fields[0], ":"):
			// "start-end perms offset dev inode [path]"
			var start, end uint64
			if _, err := fmt.Sscanf(fields[0], "%x-%x", &start, &end); err != nil || start >= end {
				return nil, fmt.Errorf("criu: %s: mapping %q", path, line)
			}
			cur = droppable{start: start, end: end}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("criu: %s: %w", path, err)
	}
	return out, nil
}

// scrubDroppable zeroes, in the images in dir, every page of the
// mappings given, keyed by image pid. Pages the dump left out (criu 4.2
// and later skip droppable pages) need nothing. Returns the pages
// zeroed.
func scrubDroppable(dir string, mappings map[int][]droppable) (int, error) {
	zeroed := 0
	for pid, dps := range mappings {
		pm, err := ReadPagemap(filepath.Join(dir, fmt.Sprintf("pagemap-%d.img", pid)))
		if errors.Is(err, fs.ErrNotExist) {
			continue // not a process criu dumped
		}
		if err != nil {
			return zeroed, err
		}
		n, err := scrubPages(pm, dps)
		zeroed += n
		if err != nil {
			return zeroed, err
		}
	}
	return zeroed, nil
}

// scrubPages zeroes the present pages of pm that lie in dps. The pages
// file holds the present entries' pages back to back in pagemap order.
func scrubPages(pm *Pagemap, dps []droppable) (int, error) {
	zeroed := 0
	zero := make([]byte, PageSize)
	var pages *os.File
	off := uint64(0) // where the next present entry's pages start
	for _, e := range pm.Entries {
		if e.Flags&PEPresent == 0 {
			continue
		}
		for i := uint64(0); i < uint64(e.NrPages); i++ {
			if !inDroppable(e.VAddr+i*PageSize, dps) {
				continue
			}
			if pages == nil {
				var err error
				if pages, err = os.OpenFile(pm.PagesFile(), os.O_RDWR, 0); err != nil {
					return zeroed, err
				}
				defer func() { _ = pages.Close() }()
			}
			if _, err := pages.WriteAt(zero, int64(off+i*PageSize)); err != nil {
				return zeroed, fmt.Errorf("criu: %s: %w", pm.PagesFile(), err)
			}
			zeroed++
		}
		off += uint64(e.NrPages) * PageSize
	}
	if pages != nil {
		if err := pages.Sync(); err != nil {
			return zeroed, err
		}
	}
	return zeroed, nil
}

// inDroppable reports whether the page at va lies in one of dps.
func inDroppable(va uint64, dps []droppable) bool {
	for _, d := range dps {
		if va >= d.start && va < d.end {
			return true
		}
	}
	return false
}
