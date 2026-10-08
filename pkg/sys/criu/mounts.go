package criu

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// MountsFile, beside a dump's images, names the single-file mounts of a
// tree that has a mount namespace of its own. CRIU's automatic external
// mount detection (--external mnt[]) dumps them but cannot restore them,
// so each is dumped and restored by name.
const MountsFile = "fiberd-mounts.json"

type fileMount struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// OwnMountNS reports whether pid lives in a mount namespace other than
// the caller's.
func OwnMountNS(pid int) bool {
	theirs, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", pid))
	if err != nil {
		return false
	}
	ours, err := os.Readlink("/proc/self/ns/mnt")
	return err == nil && theirs != ours
}

// MountPoints lists the mount points of a mountinfo table, unescaped, in
// table order.
func MountPoints(mountinfo string) []string {
	var out []string
	for _, line := range strings.Split(mountinfo, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		out = append(out, unescapeMount(f[4]))
	}
	return out
}

// unescapeMount undoes the kernel's octal escapes (\040 for a space, ...).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// DumpMounts records, in dir, the single-file mounts of pid's mount
// namespace and returns the criu dump arguments for that namespace. It
// returns nil when pid shares the caller's.
func DumpMounts(pid int, dir string) ([]string, error) {
	if !OwnMountNS(pid) {
		return nil, nil
	}
	info, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		return nil, err
	}
	root := fmt.Sprintf("/proc/%d/root", pid)
	var files []fileMount
	args := []string{"--external", "mnt[]"}
	for _, mp := range MountPoints(string(info)) {
		st, err := os.Stat(filepath.Join(root, mp))
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		fm := fileMount{Name: fmt.Sprintf("fm%d", len(files)), Path: mp}
		files = append(files, fm)
		args = append(args, "--external", "mnt["+fm.Path+"]:"+fm.Name)
	}
	b, err := json.Marshal(files)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, MountsFile), b, 0o600); err != nil {
		return nil, err
	}
	return args, nil
}

// RestoreMounts returns the criu restore arguments for a dump DumpMounts
// recorded, with root as the new namespace's root (a mount point of the
// host's /), or nil when the dump has no mount namespace.
func RestoreMounts(dir, root string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(dir, MountsFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var files []fileMount
	if err := json.Unmarshal(b, &files); err != nil {
		return nil, fmt.Errorf("criu: %s: %w", MountsFile, err)
	}
	args := []string{"--root", root, "--external", "mnt[]"}
	for _, fm := range files {
		args = append(args, "--external", "mnt["+fm.Name+"]:"+fm.Path)
	}
	return args, nil
}
