// Package cgroup is a thin view of a delegated cgroup v2 subtree: create
// leaves with a memory ceiling and group OOM, open them for clone3, read
// what they charge, and kill them. Plain file operations; nothing here is
// clever, which is the point.
package cgroup

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Dir is one cgroup directory.
type Dir struct{ Path string }

func Root(path string) Dir            { return Dir{Path: path} }
func (d Dir) Child(name string) Dir   { return Dir{Path: filepath.Join(d.Path, name)} }
func (d Dir) Name() string            { return filepath.Base(d.Path) }
func (d Dir) Exists() bool            { st, err := os.Stat(d.Path); return err == nil && st.IsDir() }
func (d Dir) file(name string) string { return filepath.Join(d.Path, name) }
func (d Dir) write(name, v string) error {
	return os.WriteFile(d.file(name), []byte(v), 0o644)
}

func (d Dir) read(name string) (string, error) {
	b, err := os.ReadFile(d.file(name))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// Ensure creates the directory (if needed) and enables controllers for
// its children, so leaves under it get memory.max and friends.
func (d Dir) Ensure(controllers ...string) error {
	if err := os.MkdirAll(d.Path, 0o755); err != nil {
		return err
	}
	for _, c := range controllers {
		if err := d.write("cgroup.subtree_control", "+"+c); err != nil {
			return fmt.Errorf("cgroup: enable %s under %s: %w", c, d.Path, err)
		}
	}
	return nil
}

// Create makes a leaf with a memory ceiling (0 = none) and, when oomGroup
// is set, makes the kernel kill the whole leaf at once when it is hit.
func (d Dir) Create(memMax uint64, oomGroup bool) error {
	if err := os.Mkdir(d.Path, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if memMax > 0 {
		if err := d.write("memory.max", strconv.FormatUint(memMax, 10)); err != nil {
			return fmt.Errorf("cgroup: memory.max on %s: %w", d.Path, err)
		}
		// No swap escape hatch: W is resident memory.
		_ = d.write("memory.swap.max", "0")
	}
	if oomGroup {
		if err := d.write("memory.oom.group", "1"); err != nil {
			return fmt.Errorf("cgroup: memory.oom.group on %s: %w", d.Path, err)
		}
	}
	return nil
}

// SetCeiling sets memory.high (throttle: the kernel reclaims and stalls
// the group, which PSI reports) and memory.max (the hard stop). max of 0
// leaves the hard limit unset.
func (d Dir) SetCeiling(high, max uint64) error {
	if err := d.write("memory.high", strconv.FormatUint(high, 10)); err != nil {
		return fmt.Errorf("cgroup: memory.high on %s: %w", d.Path, err)
	}
	if max > 0 {
		if err := d.write("memory.max", strconv.FormatUint(max, 10)); err != nil {
			return fmt.Errorf("cgroup: memory.max on %s: %w", d.Path, err)
		}
	}
	return nil
}

// MemoryHigh reads the throttle ceiling; 0 when "max".
func (d Dir) MemoryHigh() (uint64, error) {
	s, err := d.read("memory.high")
	if err != nil {
		return 0, err
	}
	if s == "max" {
		return 0, nil
	}
	return strconv.ParseUint(s, 10, 64)
}

// Open returns a directory descriptor suitable for clone3's cgroup field.
func (d Dir) Open() (*os.File, error) {
	return os.OpenFile(d.Path, os.O_RDONLY, 0)
}

// MemoryCurrent is what the leaf charges now: for a forked fiber, the
// pages it has made private since the fork, which is W.
func (d Dir) MemoryCurrent() (uint64, error) {
	s, err := d.read("memory.current")
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(s, 10, 64)
}

// Stat reads one counter of memory.stat (for example "shmem", "anon").
func (d Dir) Stat(key string) (uint64, error) {
	f, err := os.Open(d.file("memory.stat"))
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 2 && fields[0] == key {
			return strconv.ParseUint(fields[1], 10, 64)
		}
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("cgroup: memory.stat has no %q", key)
}

// OOMKills counts kernel OOM kills in the leaf (memory.events oom_kill).
func (d Dir) OOMKills() (uint64, error) {
	f, err := os.Open(d.file("memory.events"))
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 2 && fields[0] == "oom_kill" {
			return strconv.ParseUint(fields[1], 10, 64)
		}
	}
	return 0, sc.Err()
}

// PSI is the memory pressure of the cgroup, "some" and "full" avg10 in
// percent.
type PSI struct {
	SomeAvg10 float64
	FullAvg10 float64
}

func (d Dir) PSI() (PSI, error) {
	f, err := os.Open(d.file("memory.pressure"))
	if err != nil {
		return PSI{}, err
	}
	defer func() { _ = f.Close() }()
	var p PSI
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		var v float64
		for _, kv := range fields[1:] {
			if strings.HasPrefix(kv, "avg10=") {
				v, _ = strconv.ParseFloat(strings.TrimPrefix(kv, "avg10="), 64)
			}
		}
		switch fields[0] {
		case "some":
			p.SomeAvg10 = v
		case "full":
			p.FullAvg10 = v
		}
	}
	return p, sc.Err()
}

// Procs lists the PIDs in the leaf.
func (d Dir) Procs() ([]int, error) {
	s, err := d.read("cgroup.procs")
	if err != nil {
		return nil, err
	}
	var out []int
	for _, f := range strings.Fields(s) {
		if n, err := strconv.Atoi(f); err == nil {
			out = append(out, n)
		}
	}
	return out, nil
}

// Kill SIGKILLs every process in the leaf and its descendants.
func (d Dir) Kill() error {
	return d.write("cgroup.kill", "1")
}

// Remove deletes the leaf; it must be empty.
func (d Dir) Remove() error {
	err := os.Remove(d.Path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Children lists sub-cgroups whose names start with prefix.
func (d Dir) Children(prefix string) ([]Dir, error) {
	entries, err := os.ReadDir(d.Path)
	if err != nil {
		return nil, err
	}
	var out []Dir
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), prefix) {
			out = append(out, d.Child(e.Name()))
		}
	}
	return out, nil
}
