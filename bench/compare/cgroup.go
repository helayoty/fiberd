package compare

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// CgroupMemory reads memory.current of one cgroup v2 directory.
func CgroupMemory(dir string) (int64, error) {
	b, err := os.ReadFile(filepath.Join(dir, "memory.current"))
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s/memory.current: %w", dir, err)
	}
	return n, nil
}

// FindCgroup walks root for the cgroup of the Pod with the given uid.
// The kubelet's cgroup driver names it pod<uid> (cgroupfs) or
// <parent>-pod<uid>.slice with the uid's dashes as underscores
// (systemd). Only those exact names match, so one uid never finds
// another's directory or a slice above it. An empty uid is refused,
// since it would otherwise match the whole tree.
func FindCgroup(root, uid string) (string, error) {
	if uid == "" {
		return "", errors.New("no pod uid to find a cgroup for")
	}
	cgroupfs := "pod" + uid
	systemd := "-pod" + strings.ReplaceAll(uid, "-", "_") + ".slice"
	var found string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if n := d.Name(); n == cgroupfs || strings.HasSuffix(n, systemd) {
			found = p
			return fs.SkipAll
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("no cgroup under %s for %s", root, uid)
	}
	return found, nil
}

// SumCgroups adds memory.current over the given directories.
func SumCgroups(dirs []string) (int64, error) {
	var total int64
	for _, d := range dirs {
		n, err := CgroupMemory(d)
		if err != nil {
			return 0, err
		}
		total += n
	}
	return total, nil
}
