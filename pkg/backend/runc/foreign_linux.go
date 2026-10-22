//go:build linux

package runc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/backend/proc"
	"github.com/helayoty/fiberd/pkg/sys/criu"
)

// A fiber with a workspace is born into a copy of the container's mount
// namespace. Every file it kept from before the birth stays on the
// container's own mount, whose id is in neither the fiber's table nor
// criu's, and criu refuses the dump ("Can't lookup mount"). That is the
// text and library mappings, the exe, the zygote log the fiber holds as
// stderr, and whatever the warm template left open, dozens of files for
// the Python one. criu checks --external file[<mnt_id hex>:<ino hex>]
// before that lookup, and at restore takes such a file from
// --inherit-fd fd[N]:file[...]. So the dump names each of them and
// records them in foreignFile beside the images, and the restore reopens
// each on this home and hands it over.
const foreignFile = "fiberd-foreign.json"

// foreignEntry is one file of that record.
type foreignEntry struct {
	// Key is criu's name for the file, file[<mnt_id hex>:<ino hex>].
	Key string `json:"key"`
	// Path is the file's path as the container sees it.
	Path string `json:"path"`
	// Mount is the container mount the path sits on, one of the mount
	// kinds below.
	Mount string `json:"mount"`
	// Type is typeFile, typeDir or typeDev.
	Type string `json:"type"`
	// Access is "r", "w" or "rw", the union of what the fiber's users of
	// the file need. Append keeps O_APPEND.
	Access string `json:"access"`
	Append bool   `json:"append,omitempty"`
}

// The container mounts a foreign file may sit on. Each has a base on
// this home the restore reopens beneath. A file on any other mount, the
// container's /proc, /sys, its /dev tmpfs, a masked or read-only path,
// refuses the park, since no resume could reopen it.
const (
	mountRootfs   = "rootfs"   // "/", the grant's root filesystem copy
	mountHost     = "host"     // "/host", the grant's run directory
	mountTemplate = "template" // backend.TemplateMount, the staged template
	mountDev      = "dev"      // "/dev/<name>", one of deviceBinds
)

// What a foreign file may be. Anything else, a fifo, a socket, a link,
// refuses the park. A dev is a character device, the node of a device
// bind.
const (
	typeFile = "file"
	typeDir  = "dir"
	typeDev  = "dev"
)

// entryInfo is what inspect learns about a map_files or fd entry.
type entryInfo struct {
	mntID int
	ino   uint64
	// mode is st_mode. Only its S_IFMT bits are read.
	mode uint32
}

// inspectEntry opens the entry as a path, reads its mount id from the
// open file's fdinfo, and stats it. A map_files entry needs root, which
// fiberd is.
func inspectEntry(p string) (entryInfo, error) {
	fd, err := unix.Open(p, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return entryInfo{}, err
	}
	defer unix.Close(fd)
	b, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", fd))
	if err != nil {
		return entryInfo{}, err
	}
	mnt := -1
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "mnt_id:"); ok {
			mnt, err = strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return entryInfo{}, fmt.Errorf("fdinfo mnt_id %q", v)
			}
		}
	}
	if mnt < 0 {
		return entryInfo{}, errors.New("fdinfo has no mnt_id")
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return entryInfo{}, err
	}
	return entryInfo{mntID: mnt, ino: st.Ino, mode: st.Mode}, nil
}

func (l *launcher) procDir() string {
	if l.procRoot == "" {
		return "/proc"
	}
	return l.procRoot
}

func (l *launcher) inspectOf(p string) (entryInfo, error) {
	if l.inspect == nil {
		return inspectEntry(p)
	}
	return l.inspect(p)
}

func (l *launcher) deviceDir() string {
	if l.devDir == "" {
		return "/dev"
	}
	return l.devDir
}

// foreignDump lists the files the tree rooted at d.PID holds through
// the container's own mounts, records them in dir and names each to
// criu. The tree lives in a copy of the container's namespace, so a
// file is foreign exactly when its mount id is in the container init's
// table. Mount ids are global, which makes that test exact. The fiber's
// own copies are not in that table, and neither are the internal mounts
// of pipes, sockets, memfds and anon inodes, which criu handles itself.
// The record is written even when empty, and the arguments are sorted
// by key.
func (l *launcher) foreignDump(d proc.Dumped, dir string) ([]string, error) {
	table, err := containerMounts(filepath.Join(l.procDir(), strconv.Itoa(d.Zygote), "mountinfo"))
	if err != nil {
		return nil, fmt.Errorf("runc: foreign files: container mounts: %w", err)
	}
	pids, err := treePIDs(l.procDir(), d.PID)
	if err != nil {
		return nil, err
	}
	files := map[string]*foreignEntry{}
	for _, pid := range pids {
		if err := l.foreignOf(pid, table, files); err != nil {
			return nil, err
		}
	}
	list := make([]foreignEntry, 0, len(files))
	for _, e := range files {
		list = append(list, *e)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Key < list[j].Key })
	b, err := json.Marshal(list)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, foreignFile), b, 0o600); err != nil {
		return nil, err
	}
	var args []string
	for _, e := range list {
		args = append(args, "--external", e.Key)
	}
	return args, nil
}

// containerMounts maps each mount id of a mountinfo table to its mount
// point, unescaped. criu.MountPoints does the unescaping, one line at
// a time here so the id stays beside its point.
func containerMounts(path string) (map[int]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	table := map[int]string{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		id, err := strconv.Atoi(f[0])
		if err != nil {
			continue
		}
		table[id] = criu.MountPoints(line)[0]
	}
	if len(table) == 0 {
		return nil, fmt.Errorf("%s lists no mount", path)
	}
	return table, nil
}

// treePIDs is every process of the tree rooted at pid, found through
// the children list of each task, without repeats. A process that is
// gone by the time it is reached is skipped, since criu will not see
// it either. The root must be there.
func treePIDs(procRoot string, pid int) ([]int, error) {
	seen := map[int]bool{pid: true}
	pids := []int{pid}
	for i := 0; i < len(pids); i++ {
		taskDir := filepath.Join(procRoot, strconv.Itoa(pids[i]), "task")
		tasks, err := os.ReadDir(taskDir)
		if err != nil {
			if i == 0 {
				return nil, fmt.Errorf("runc: foreign files of %d: %w", pid, err)
			}
			continue
		}
		for _, t := range tasks {
			b, err := os.ReadFile(filepath.Join(taskDir, t.Name(), "children"))
			if err != nil {
				// A task that exited meanwhile is fine. A task still
				// there without the list is a kernel without
				// CONFIG_PROC_CHILDREN, which criu needs as well.
				if _, still := os.Stat(filepath.Join(taskDir, t.Name())); still == nil {
					return nil, fmt.Errorf("runc: foreign files of %d: %w", pid, err)
				}
				continue
			}
			for _, f := range strings.Fields(string(b)) {
				c, err := strconv.Atoi(f)
				if err != nil || seen[c] {
					continue
				}
				seen[c] = true
				pids = append(pids, c)
			}
		}
	}
	return pids, nil
}

// gone says a /proc read failed because its process or descriptor is no
// longer there.
func gone(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ESRCH)
}

// foreignOf adds pid's foreign mappings and descriptors to files. Each
// entry is inspected first, so a pipe or a socket is set aside by its
// mount before its name is looked at.
func (l *launcher) foreignOf(pid int, table map[int]string, files map[string]*foreignEntry) error {
	pdir := filepath.Join(l.procDir(), strconv.Itoa(pid))
	maps, err := readMaps(filepath.Join(pdir, "maps"))
	if gone(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("runc: foreign files of %d: %w", pid, err)
	}
	for _, kind := range []string{"map_files", "fd"} {
		ents, err := os.ReadDir(filepath.Join(pdir, kind))
		if gone(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("runc: foreign files of %d: %w", pid, err)
		}
		for _, e := range ents {
			p := filepath.Join(pdir, kind, e.Name())
			info, err := l.inspectOf(p)
			if gone(err) {
				continue
			}
			if err != nil {
				return fmt.Errorf("runc: foreign files of %d: %s/%s: %w", pid, kind, e.Name(), err)
			}
			point, ok := table[info.mntID]
			if !ok {
				continue
			}
			path, err := os.Readlink(p)
			if gone(err) {
				continue
			}
			if err != nil {
				return fmt.Errorf("runc: foreign files of %d: %s/%s: %w", pid, kind, e.Name(), err)
			}
			access, app := "r", false
			if kind == "map_files" {
				access = maps.access(e.Name())
			} else {
				access, app, err = fdAccess(filepath.Join(pdir, "fdinfo", e.Name()))
				if gone(err) {
					continue
				}
				if err != nil {
					return fmt.Errorf("runc: foreign files of %d: fd/%s: %w", pid, e.Name(), err)
				}
			}
			if err := addForeign(files, pid, point, info, path, access, app); err != nil {
				return err
			}
		}
	}
	return nil
}

// mapping is one line of a process's maps, the fields read here.
type mapping struct {
	start, end uint64
	perms      string
}

type mappings []mapping

// readMaps parses a maps file. A line it cannot read is skipped.
func readMaps(path string) (mappings, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out mappings
	for _, line := range strings.Split(string(b), "\n") {
		// 00400000-0047e000 r-xp 00000000 00:78 19   /zyg
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		start, end, ok := parseRange(f[0])
		if !ok {
			continue
		}
		out = append(out, mapping{start: start, end: end, perms: f[1]})
	}
	return out, nil
}

// parseRange reads a "<start>-<end>" pair of hex addresses, the name of
// a map_files entry or the first field of a maps line.
func parseRange(s string) (start, end uint64, ok bool) {
	a, b, found := strings.Cut(s, "-")
	if !found {
		return 0, 0, false
	}
	start, err := strconv.ParseUint(a, 16, 64)
	if err != nil {
		return 0, 0, false
	}
	end, err = strconv.ParseUint(b, 16, 64)
	if err != nil {
		return 0, 0, false
	}
	return start, end, true
}

// access is what the mapping named by a map_files entry needs of its
// file. A mapping needs read, a shared writable one read and write,
// since criu maps the inherited file shared again. A mapping gone from
// the table meanwhile needs read, and its key is then unused.
func (m mappings) access(entry string) string {
	start, end, ok := parseRange(entry)
	if !ok {
		return "r"
	}
	for _, mp := range m {
		if mp.start == start && mp.end == end {
			if len(mp.perms) == 4 && mp.perms[1] == 'w' && mp.perms[3] == 's' {
				return "rw"
			}
			return "r"
		}
	}
	return "r"
}

// fdAccess is the access mode a descriptor was opened with, from its
// fdinfo, and whether it appends.
func fdAccess(fdinfo string) (access string, app bool, err error) {
	b, err := os.ReadFile(fdinfo)
	if err != nil {
		return "", false, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		v, ok := strings.CutPrefix(line, "flags:")
		if !ok {
			continue
		}
		flags, err := strconv.ParseUint(strings.TrimSpace(v), 8, 64)
		if err != nil {
			return "", false, fmt.Errorf("fdinfo flags %q", v)
		}
		switch flags & unix.O_ACCMODE {
		case unix.O_RDONLY:
			access = "r"
		case unix.O_WRONLY:
			access = "w"
		case unix.O_RDWR:
			access = "rw"
		default:
			return "", false, fmt.Errorf("fdinfo flags %q: no access mode", v)
		}
		return access, flags&unix.O_APPEND != 0, nil
	}
	return "", false, errors.New("fdinfo has no flags")
}

// addForeign puts one foreign file of pid into files, or unions its
// access with the entry its key already has. The park is refused for a
// file a resume could not reopen the same.
func addForeign(files map[string]*foreignEntry, pid int, point string, info entryInfo, path, access string, app bool) error {
	if strings.HasSuffix(path, " (deleted)") {
		return fmt.Errorf("runc: cannot park: process %d holds %s, which is deleted and would not be there at the resume", pid, path)
	}
	kind, ok := mountKind(point)
	if !ok {
		return fmt.Errorf("runc: cannot park: process %d holds %s on the container's %s mount, which a resume cannot reopen", pid, path, point)
	}
	if kind == mountDev && path != point {
		return fmt.Errorf("runc: cannot park: process %d holds %s on the device bind at %s", pid, path, point)
	}
	typ, ok := foreignType(info.mode, kind)
	if !ok {
		if kind == mountDev {
			return fmt.Errorf("runc: cannot park: process %d holds %s, which is %s, not a character device", pid, path, modeName(info.mode))
		}
		return fmt.Errorf("runc: cannot park: process %d holds %s, which is %s, not a regular file or directory", pid, path, modeName(info.mode))
	}
	e := foreignEntry{Key: fmt.Sprintf("file[%x:%x]", info.mntID, info.ino), Path: path, Mount: kind, Type: typ, Access: access, Append: app}
	if err := checkEntry(e); err != nil {
		return fmt.Errorf("runc: cannot park: process %d holds %s: %w", pid, path, err)
	}
	if have, ok := files[e.Key]; ok {
		have.Access = unionAccess(have.Access, access)
		have.Append = have.Append || app
		return nil
	}
	files[e.Key] = &e
	return nil
}

// mountKind names the container mount at point, or says it is one a
// foreign file may not sit on.
func mountKind(point string) (string, bool) {
	switch point {
	case "/":
		return mountRootfs, true
	case "/host":
		return mountHost, true
	case backend.TemplateMount:
		return mountTemplate, true
	}
	if name, ok := strings.CutPrefix(point, "/dev/"); ok {
		for _, d := range deviceBinds {
			if d == name {
				return mountDev, true
			}
		}
	}
	return "", false
}

// mountPointOf is the container path of a mount kind. A device bind's
// is the entry's own path.
func mountPointOf(e foreignEntry) string {
	switch e.Mount {
	case mountRootfs:
		return "/"
	case mountHost:
		return "/host"
	case mountTemplate:
		return backend.TemplateMount
	}
	return e.Path
}

// onMount says path lies on the mount at point.
func onMount(path, point string) bool {
	return point == "/" || path == point || strings.HasPrefix(path, point+"/")
}

// relOf is path relative to the mount at point, "" for the mount's root.
func relOf(path, point string) string {
	return strings.TrimPrefix(strings.TrimPrefix(path, point), "/")
}

// foreignType is the record's name for a file of mode on a mount of
// kind, or false for one the record cannot hold.
func foreignType(mode uint32, kind string) (string, bool) {
	switch mode & unix.S_IFMT {
	case unix.S_IFREG:
		if kind != mountDev {
			return typeFile, true
		}
	case unix.S_IFDIR:
		if kind != mountDev {
			return typeDir, true
		}
	case unix.S_IFCHR:
		if kind == mountDev {
			return typeDev, true
		}
	}
	return "", false
}

// modeName says what a mode is, for an error.
func modeName(mode uint32) string {
	switch mode & unix.S_IFMT {
	case unix.S_IFREG:
		return "a regular file"
	case unix.S_IFDIR:
		return "a directory"
	case unix.S_IFLNK:
		return "a symlink"
	case unix.S_IFIFO:
		return "a fifo"
	case unix.S_IFSOCK:
		return "a socket"
	case unix.S_IFCHR:
		return "a character device"
	case unix.S_IFBLK:
		return "a block device"
	}
	return fmt.Sprintf("of type %#o", mode&unix.S_IFMT)
}

func unionAccess(a, b string) string {
	r := strings.Contains(a, "r") || strings.Contains(b, "r")
	w := strings.Contains(a, "w") || strings.Contains(b, "w")
	switch {
	case r && w:
		return "rw"
	case w:
		return "w"
	}
	return "r"
}

// checkEntry refuses an entry the restore could not reopen as recorded.
// Both sides of the checkpoint apply it, the dump to what it found and
// the restore to what it read.
func checkEntry(e foreignEntry) error {
	if !filepath.IsAbs(e.Path) || filepath.Clean(e.Path) != e.Path {
		return fmt.Errorf("path %q is not absolute and clean", e.Path)
	}
	switch e.Mount {
	case mountRootfs, mountHost, mountTemplate:
		if !onMount(e.Path, mountPointOf(e)) {
			return fmt.Errorf("path %s is not under its mount %s", e.Path, mountPointOf(e))
		}
	case mountDev:
		if kind, ok := mountKind(e.Path); !ok || kind != mountDev {
			return fmt.Errorf("path %s is not a device bind", e.Path)
		}
	default:
		return fmt.Errorf("unknown mount %q", e.Mount)
	}
	switch e.Type {
	case typeFile, typeDir:
		if e.Mount == mountDev {
			return fmt.Errorf("a %s cannot be on a device bind", e.Type)
		}
	case typeDev:
		if e.Mount != mountDev {
			return fmt.Errorf("a device cannot be on the %s mount", e.Mount)
		}
	default:
		return fmt.Errorf("unknown type %q", e.Type)
	}
	switch e.Access {
	case "r", "w", "rw":
	default:
		return fmt.Errorf("unknown access %q", e.Access)
	}
	if e.Type == typeDir && e.Access != "r" {
		return errors.New("a directory opens read-only")
	}
	return nil
}

// validKey says k has the shape criu's external file keys have,
// file[<hex>:<hex>] in lower case, which is what the dump writes.
func validKey(k string) bool {
	s, ok := strings.CutPrefix(k, "file[")
	if !ok {
		return false
	}
	s, ok = strings.CutSuffix(s, "]")
	if !ok {
		return false
	}
	mnt, ino, ok := strings.Cut(s, ":")
	return ok && isHex(mnt) && isHex(ino)
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// decodeForeign reads a record strictly. An unknown field, a key of
// another shape, a repeated key, or an entry checkEntry refuses makes
// the record malformed, since the restore trusts it with opens on this
// home.
func decodeForeign(b []byte) ([]foreignEntry, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var list []foreignEntry
	if err := dec.Decode(&list); err != nil || list == nil {
		return nil, errors.New("malformed")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("malformed")
	}
	seen := map[string]bool{}
	for _, e := range list {
		if !validKey(e.Key) {
			return nil, fmt.Errorf("key %q is not file[<hex>:<hex>]", e.Key)
		}
		if seen[e.Key] {
			return nil, fmt.Errorf("key %s repeats", e.Key)
		}
		seen[e.Key] = true
		if err := checkEntry(e); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Key, err)
		}
	}
	return list, nil
}

// foreignInherit reopens on this home every file the dump in dir
// recorded, one Inherit per entry in the record's order, or nothing for
// a dump that recorded none. The root filesystem copy, the run
// directory and the staged template are trees the tenant can write and
// fiberd is root, so each path is resolved beneath its base with no way
// out, checked to be what the record says, and only then opened for
// access. A device bind's node comes from the host's /dev by its fixed
// name. Whatever was opened is closed again when a later entry fails.
func (l *launcher) foreignInherit(spec backend.WarmSpec, dir, rootfs string) ([]proc.Inherit, error) {
	b, err := os.ReadFile(filepath.Join(dir, foreignFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	list, err := decodeForeign(b)
	if err != nil {
		return nil, fmt.Errorf("runc: %s in %s: %w", foreignFile, dir, err)
	}
	var held []proc.Inherit
	closeHeld := func() {
		for _, h := range held {
			_ = h.File.Close()
		}
	}
	for _, e := range list {
		var f *os.File
		switch e.Mount {
		case mountRootfs:
			f, err = openUnder(rootfs, relOf(e.Path, "/"), e)
		case mountHost:
			f, err = openUnder(spec.WorkDir, relOf(e.Path, "/host"), e)
		case mountTemplate:
			staged := l.stagedFor(spec)
			if staged == "" {
				closeHeld()
				return nil, fmt.Errorf("runc: checkpoint holds %s of a registry template at %s, which warm instance %q does not have here", e.Path, backend.TemplateMount, spec.GrantUID)
			}
			f, err = openUnder(staged, relOf(e.Path, backend.TemplateMount), e)
		default:
			f, err = openDevice(l.deviceDir(), relOf(e.Path, "/dev"), e)
		}
		if err != nil {
			closeHeld()
			return nil, fmt.Errorf("runc: reopen %s for %s: %w", e.Path, e.Key, err)
		}
		held = append(held, proc.Inherit{Key: e.Key, File: f})
	}
	return held, nil
}

// errNoOpenat2 is the kernel lacking openat2, which the safe reopen
// needs.
var errNoOpenat2 = errors.New("openat2 is not supported on this kernel")

// openRetries bounds the retries after the kernel saw a rename during
// the walk and answered EAGAIN.
const openRetries = 32

// openUnder reopens rel beneath base, a tree the tenant can write, as e
// says. The walk stays in base whatever link it meets, crosses no mount
// and follows no magic link, and the final name may not be a link. The
// file found is checked against the record before it is opened for
// access, through its own path descriptor, so the open binds to that
// file and not to the name again.
func openUnder(base, rel string, e foreignEntry) (*os.File, error) {
	bfd, err := unix.Open(base, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", base, err)
	}
	defer unix.Close(bfd)
	if rel == "" {
		rel = "."
	}
	how := &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	}
	pfd := -1
	for try := 0; pfd < 0; try++ {
		pfd, err = unix.Openat2(bfd, rel, how)
		switch {
		case err == nil:
		case errors.Is(err, unix.EAGAIN) && try < openRetries:
			pfd = -1
		case errors.Is(err, unix.ENOSYS):
			return nil, errNoOpenat2
		default:
			return nil, fmt.Errorf("%s under %s: %w", rel, base, err)
		}
	}
	defer unix.Close(pfd)
	return reopen(pfd, e)
}

// openDevice reopens the node called name in devDir, which is the
// host's own and holds no link of the tenant's, so a plain path open
// without following the name does.
func openDevice(devDir, name string, e foreignEntry) (*os.File, error) {
	dfd, err := unix.Open(devDir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", devDir, err)
	}
	defer unix.Close(dfd)
	pfd, err := unix.Openat(dfd, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("%s in %s: %w", name, devDir, err)
	}
	defer unix.Close(pfd)
	return reopen(pfd, e)
}

// reopen opens the file behind the path descriptor pfd for the access
// e records, once it is the type e records. A link, a fifo or anything
// else at the name never gets this far, so no host file is reached. The
// open is non-blocking, since the tenant owns these files and may hold
// a lease on one, which would have a plain open wait out the lease
// break time. A lease refuses the restore at once instead. The flag is
// cleared after the open, so the file goes to criu as recorded.
func reopen(pfd int, e foreignEntry) (*os.File, error) {
	var st unix.Stat_t
	if err := unix.Fstat(pfd, &st); err != nil {
		return nil, err
	}
	flags := unix.O_CLOEXEC | unix.O_NOCTTY
	switch {
	case e.Type == typeFile && st.Mode&unix.S_IFMT == unix.S_IFREG:
	case e.Type == typeDir && st.Mode&unix.S_IFMT == unix.S_IFDIR:
		flags |= unix.O_DIRECTORY
	case e.Type == typeDev && st.Mode&unix.S_IFMT == unix.S_IFCHR:
	default:
		return nil, fmt.Errorf("%s is %s, not %s", e.Path, modeName(st.Mode), e.Type)
	}
	switch e.Access {
	case "r":
		flags |= unix.O_RDONLY
	case "w":
		flags |= unix.O_WRONLY
	default:
		flags |= unix.O_RDWR
	}
	if e.Append {
		flags |= unix.O_APPEND
	}
	fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", pfd), flags|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s for %s: %w", e.Path, e.Access, err)
	}
	fl, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err == nil {
		_, err = unix.FcntlInt(uintptr(fd), unix.F_SETFL, fl&^unix.O_NONBLOCK)
	}
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open %s for %s: %w", e.Path, e.Access, err)
	}
	return os.NewFile(uintptr(fd), e.Path), nil
}
