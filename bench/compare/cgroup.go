package compare

import (
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

// FindCgroup walks root for the first directory whose name contains
// needle. A Pod's cgroup is named after its uid, with the kubelet's
// cgroup driver deciding whether dashes became underscores, so both
// spellings are tried.
func FindCgroup(root, needle string) (string, error) {
	alt := strings.ReplaceAll(needle, "-", "_")
	var found string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if strings.Contains(d.Name(), needle) || strings.Contains(d.Name(), alt) {
			found = p
			return fs.SkipAll
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("no cgroup under %s for %s", root, needle)
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
