//go:build linux

package wsfs

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// rootName and stageName are the two directories under a workspace.
	// The fiber sees root and nothing else.
	rootName  = "root"
	stageName = ".stage"

	// resolve is how every name beneath the root is looked up. No
	// component may be a symlink or a magic link, the walk may not leave
	// the root, and it may not cross into another mount.
	resolve = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV

	// openFlags go on every open beneath the root.
	openFlags = unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NOCTTY

	// dirMode is what directories fiberd makes get. Files take the mode
	// the caller or the archive gives.
	dirMode = 0o755

	// eagainRetries is how often an open is retried after the kernel
	// saw a rename race during resolution and answered EAGAIN.
	eagainRetries = 32
)

// Workspace is one fiber's workspace on the home. Every method is safe
// for concurrent use, and Close waits for the operations in flight.
type Workspace struct {
	// mu is held shared by every operation and alone by Close, so a
	// descriptor is never closed under an open beneath it. The kernel
	// reuses descriptor numbers, and an open beneath a reused one would
	// resolve beneath whatever it became.
	mu    sync.RWMutex
	root  int
	stage int
	dev   uint64
	opts  Options
	seq   atomic.Uint64

	// owned maps the inodes fiberd wrote to the bytes it reserved for
	// them, so replacing one gives back exactly that and replacing a
	// file the fiber made gives back nothing. An inode the fiber unlinks
	// stays until its number comes back, which only happens once the
	// old file is gone. It holds at most one entry per file fiberd
	// wrote, under the entry ceiling, 32 bytes each.
	omu   sync.Mutex
	owned map[inode]int64
}

// Open opens the workspace at dir, making dir, its root and its staging
// directory when they are absent. The staging directory is 0700 and
// outside the root, so no fiber sees it. Staging files a crash left are
// removed. The root and the staging directory must be on one file
// system, since an upload is renamed between them. A kernel without
// openat2 gets ErrUnsupported and no workspace.
func Open(dir string, o Options) (*Workspace, error) {
	if o.Budget == nil {
		return nil, errors.New("wsfs: a budget is required")
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	dfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|openFlags, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", dir, err)
	}
	defer func() { _ = unix.Close(dfd) }()
	w := &Workspace{root: -1, stage: -1, opts: o, owned: map[inode]int64{}}
	ok := false
	defer func() {
		if !ok {
			w.Close()
		}
	}()
	if w.root, err = openSub(dfd, rootName, dirMode); err != nil {
		return nil, fmt.Errorf("%s: %w", path.Join(dir, rootName), err)
	}
	if w.stage, err = openSub(dfd, stageName, 0o700); err != nil {
		return nil, fmt.Errorf("%s: %w", path.Join(dir, stageName), err)
	}
	var rst, sst unix.Stat_t
	if err := unix.Fstat(w.root, &rst); err != nil {
		return nil, err
	}
	if err := unix.Fstat(w.stage, &sst); err != nil {
		return nil, err
	}
	if rst.Dev != sst.Dev {
		return nil, fmt.Errorf("wsfs: %s and %s are on different file systems", rootName, stageName)
	}
	w.dev = rst.Dev
	if o.Owner != nil {
		if err := unix.Fchown(w.root, o.Owner.UID, o.Owner.GID); err != nil {
			return nil, fmt.Errorf("chown %s: %w", path.Join(dir, rootName), err)
		}
	}
	if err := w.sweepStage(); err != nil {
		return nil, err
	}
	ok = true
	return w, nil
}

// openSub makes name under dfd when it is absent and opens it as a
// directory with no link resolution.
func openSub(dfd int, name string, mode uint32) (int, error) {
	if err := unix.Mkdirat(dfd, name, mode); err != nil && !errors.Is(err, unix.EEXIST) {
		return -1, err
	}
	fd, err := unix.Openat2(dfd, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | openFlags,
		Resolve: resolve,
	})
	if errors.Is(err, unix.ENOSYS) {
		return -1, ErrUnsupported
	}
	if err != nil {
		return -1, err
	}
	return fd, nil
}

// sweepStage removes every name in the staging directory.
func (w *Workspace) sweepStage() error {
	names, err := readNames(w.stage)
	if err != nil {
		return err
	}
	for _, n := range names {
		if err := unix.Unlinkat(w.stage, n, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("sweep %s: %w", n, err)
		}
	}
	return nil
}

// Close waits for the operations in flight and releases the
// descriptors. A File from Download keeps its own and outlives Close.
func (w *Workspace) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.root >= 0 {
		_ = unix.Close(w.root)
		w.root = -1
	}
	if w.stage >= 0 {
		_ = unix.Close(w.stage)
		w.stage = -1
	}
}

// openBeneath opens rel under dirfd with the workspace's resolution
// rules. A link, a magic link, a step outside or a crossing into another
// mount is refused with ErrPath. EAGAIN, which the kernel answers when a
// rename raced the resolution, is retried a bounded number of times.
func openBeneath(dirfd int, rel string, flags int) (int, error) {
	if rel == "" {
		rel = "."
	}
	flags |= unix.O_NOFOLLOW | unix.O_CLOEXEC
	if flags&unix.O_PATH == 0 {
		// O_PATH takes no other flag, and a path open touches no tty.
		flags |= unix.O_NOCTTY
	}
	how := &unix.OpenHow{Flags: uint64(flags), Resolve: resolve}
	for range eagainRetries {
		fd, err := unix.Openat2(dirfd, rel, how)
		switch {
		case err == nil:
			return fd, nil
		case errors.Is(err, unix.EAGAIN):
			continue
		case errors.Is(err, unix.ENOSYS):
			return -1, ErrUnsupported
		case errors.Is(err, unix.ELOOP), errors.Is(err, unix.EXDEV), errors.Is(err, unix.ENOTDIR):
			return -1, fmt.Errorf("%w: %s: %w", ErrPath, rel, err)
		case errors.Is(err, unix.EISDIR):
			return -1, fmt.Errorf("%w: %s is a directory", ErrNotRegular, rel)
		case errors.Is(err, unix.ENOENT):
			return -1, fmt.Errorf("%s: %w", rel, fs.ErrNotExist)
		default:
			return -1, fmt.Errorf("open %s: %w", rel, err)
		}
	}
	return -1, fmt.Errorf("%w: %s: renamed under the lookup %d times", ErrPath, rel, eagainRetries)
}

// openDir opens the directory rel beneath the root. With create set,
// every missing component is made on the way. A component that is a
// link or not a directory is refused at every step, since mkdirat does
// not follow a planted link and the open after it resolves none.
func (w *Workspace) openDir(rel string, create bool) (int, error) {
	if !create || rel == "" {
		return openBeneath(w.root, rel, unix.O_RDONLY|unix.O_DIRECTORY)
	}
	cur := w.root
	for {
		comp, rest, more := cutPath(rel)
		made := true
		if err := unix.Mkdirat(cur, comp, dirMode); err != nil && !errors.Is(err, unix.EEXIST) {
			if cur != w.root {
				_ = unix.Close(cur)
			}
			return -1, fmt.Errorf("mkdir %s: %w", comp, err)
		} else if err != nil {
			made = false
		}
		next, err := openBeneath(cur, comp, unix.O_RDONLY|unix.O_DIRECTORY)
		if cur != w.root {
			_ = unix.Close(cur)
		}
		if err != nil {
			return -1, err
		}
		if made && w.opts.Owner != nil {
			// By descriptor, so a name the fiber swapped in between the
			// mkdir and here is not what gets chowned.
			_ = unix.Fchown(next, w.opts.Owner.UID, w.opts.Owner.GID)
		}
		if !more {
			return next, nil
		}
		cur, rel = next, rest
	}
}

// cutPath splits the first component off a cleaned relative path.
func cutPath(rel string) (comp, rest string, more bool) {
	for i := 0; i < len(rel); i++ {
		if rel[i] == '/' {
			return rel[:i], rel[i+1:], true
		}
	}
	return rel, "", false
}

// readNames lists a directory open at dirfd, sorted. The directory is
// opened afresh beneath its own descriptor, so each listing has an
// offset of its own. A duplicate of dirfd would share the open file
// description, and two listings at once would split one offset between
// them and each miss names.
func readNames(dirfd int) ([]string, error) {
	fd, err := openBeneath(dirfd, "", unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "")
	defer func() { _ = f.Close() }()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	slices.Sort(names)
	return names, nil
}

// stageFile makes a new file in the staging directory and returns it
// with its name there. The caller renames it into place or unlinks it.
func (w *Workspace) stageFile(mode fs.FileMode) (*os.File, string, error) {
	name := fmt.Sprintf("%d.%d", os.Getpid(), w.seq.Add(1))
	fd, err := unix.Openat(w.stage, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|openFlags, uint32(mode&fs.ModePerm))
	if err != nil {
		return nil, "", fmt.Errorf("stage %s: %w", name, err)
	}
	f := os.NewFile(uintptr(fd), name)
	// The mode is exact, not what the umask left of it.
	if err := f.Chmod(mode & fs.ModePerm); err != nil {
		_ = f.Close()
		_ = unix.Unlinkat(w.stage, name, 0)
		return nil, "", err
	}
	return f, name, nil
}

// fillStaged copies exactly size bytes from r into f, checks sum when
// given, chowns, and syncs. A body shorter or longer than size is ErrSize.
func (w *Workspace) fillStaged(f *os.File, r io.Reader, size int64, sum []byte) ([]byte, error) {
	h := sha256.New()
	n, err := io.CopyN(io.MultiWriter(f, h), r, size)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("%w: %d bytes declared, %d received", ErrSize, size, n)
		}
		return nil, err
	}
	var extra [1]byte
	if m, err := io.ReadFull(r, extra[:]); m > 0 {
		return nil, fmt.Errorf("%w: %d bytes declared, more received", ErrSize, size)
	} else if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}
	got := h.Sum(nil)
	if sum != nil && !bytes.Equal(got, sum) {
		return nil, fmt.Errorf("%w: declared %x, got %x", ErrChecksum, sum, got)
	}
	if w.opts.Owner != nil {
		if err := f.Chown(w.opts.Owner.UID, w.opts.Owner.GID); err != nil {
			return nil, err
		}
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	return got, nil
}

// place renames the staged file name to base under the directory
// parent, from descriptors on both sides. A link, a FIFO, a socket or a
// device at the name is replaced, never followed. A directory at the
// name is refused. Whatever the name holds is pinned by a descriptor
// first and read again after the rename. When no name is left on it and
// fiberd wrote it, the bytes reserved for it come back as freed. A file
// the fiber made frees nothing, since nothing was reserved for it, and
// a file that keeps another name frees nothing until that goes too.
func (w *Workspace) place(parent int, name, base string) (replaced bool, freed int64, err error) {
	old, err := openBeneath(parent, base, unix.O_PATH)
	switch {
	case err == nil:
		replaced = true
		defer func() { _ = unix.Close(old) }()
		var st unix.Stat_t
		if err := unix.Fstat(old, &st); err != nil {
			return false, 0, err
		}
		if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			return false, 0, fmt.Errorf("%w: %s is a directory", ErrNotRegular, base)
		}
	case errors.Is(err, fs.ErrNotExist):
	default:
		return false, 0, err
	}
	if err := unix.Renameat(w.stage, name, parent, base); err != nil {
		if errors.Is(err, unix.EISDIR) || errors.Is(err, unix.ENOTEMPTY) || errors.Is(err, unix.EEXIST) {
			return false, 0, fmt.Errorf("%w: %s is a directory", ErrNotRegular, base)
		}
		return false, 0, fmt.Errorf("rename %s: %w", base, err)
	}
	_ = unix.Fsync(parent)
	if replaced {
		var st unix.Stat_t
		if err := unix.Fstat(old, &st); err == nil && st.Nlink == 0 {
			freed = w.disown(inode{st.Dev, st.Ino})
		}
	}
	return replaced, freed, nil
}

// own records that fiberd wrote the file f with size bytes reserved.
func (w *Workspace) own(f *os.File, size int64) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return
	}
	w.omu.Lock()
	defer w.omu.Unlock()
	w.owned[inode{st.Dev, st.Ino}] = size
}

// disown forgets an inode fiberd wrote and returns what was reserved
// for it, zero for one it never wrote.
func (w *Workspace) disown(k inode) int64 {
	w.omu.Lock()
	defer w.omu.Unlock()
	size := w.owned[k]
	delete(w.owned, k)
	return size
}

// exists reports whether rel names anything beneath the root, without
// following a link. It only guides the entry reservation, since the
// fiber can add or remove the name at any time. The bytes are exact,
// the entry count is best effort, and the kernel quota of a later stage
// holds the line.
func (w *Workspace) exists(rel string) bool {
	dir, base := split(rel)
	parent, err := w.openDir(dir, false)
	if err != nil {
		return false
	}
	defer w.closeDir(parent)
	var st unix.Stat_t
	return unix.Fstatat(parent, base, &st, unix.AT_SYMLINK_NOFOLLOW) == nil
}

// Upload writes size bytes from r to p. The path is checked, the
// budget is reserved for size bytes and, for a new name, one entry, the
// body is written to the staging directory, its length and optional
// sha256 are checked, and it is synced before it is renamed into place.
// Missing directories on the way are made. mode gives the permission
// bits, 0644 when zero. Nothing appears under the root until every
// check has passed, and a failed upload releases its reservation.
func (w *Workspace) Upload(p string, size int64, mode fs.FileMode, sum []byte, r io.Reader) (Info, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	rel, err := Clean(p, false)
	if err != nil {
		return Info{}, err
	}
	if size < 0 {
		return Info{}, fmt.Errorf("%w: negative size", ErrSize)
	}
	if sum != nil && len(sum) != sha256.Size {
		return Info{}, fmt.Errorf("%w: %d bytes of sha256", ErrChecksum, len(sum))
	}
	if mode&fs.ModePerm == 0 {
		mode = 0o644
	}
	mode &= fs.ModePerm
	var entries int64 = 1
	if w.exists(rel) {
		entries = 0
	}
	if err := w.opts.Budget.Reserve(size, entries); err != nil {
		return Info{}, err
	}
	info, err := w.write(rel, size, mode, sum, r, entries)
	if err != nil {
		w.opts.Budget.Release(size, entries)
		return Info{}, err
	}
	return info, nil
}

// write is Upload after the reservation of size bytes and entries.
func (w *Workspace) write(rel string, size int64, mode fs.FileMode, sum []byte, r io.Reader, entries int64) (Info, error) {
	f, name, err := w.stageFile(mode)
	if err != nil {
		return Info{}, err
	}
	placed := false
	defer func() {
		_ = f.Close()
		if !placed {
			_ = unix.Unlinkat(w.stage, name, 0)
		}
	}()
	got, err := w.fillStaged(f, r, size, sum)
	if err != nil {
		return Info{}, err
	}
	st, err := f.Stat()
	if err != nil {
		return Info{}, err
	}
	dir, base := split(rel)
	parent, err := w.openDir(dir, true)
	if err != nil {
		return Info{}, err
	}
	defer func() {
		if parent != w.root {
			_ = unix.Close(parent)
		}
	}()
	replaced, freed, err := w.place(parent, name, base)
	if err != nil {
		return Info{}, err
	}
	placed = true
	w.own(f, size)
	if replaced {
		w.opts.Budget.Release(freed, entries)
	}
	return Info{Path: rel, Size: size, Mode: mode, ModTime: st.ModTime(), SHA256: got}, nil
}

// openRegular opens the regular file rel beneath dirfd for reading. The
// name is opened as a path first, so a FIFO is never opened for reading
// and a device node is never opened at all, then checked to be a regular
// file, then reopened through its own descriptor and checked again to be
// the same inode. The reopen takes O_NONBLOCK too, so it could not hang
// even if the check were wrong.
func openRegular(dirfd int, rel string) (*os.File, unix.Stat_t, error) {
	var st unix.Stat_t
	pfd, err := openBeneath(dirfd, rel, unix.O_PATH)
	if err != nil {
		return nil, st, err
	}
	defer func() { _ = unix.Close(pfd) }()
	if err := unix.Fstat(pfd, &st); err != nil {
		return nil, st, err
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
	case unix.S_IFLNK:
		// O_PATH with O_NOFOLLOW opens the link itself. It is refused
		// like a link on the way.
		return nil, st, fmt.Errorf("%w: %s is a link", ErrPath, rel)
	default:
		return nil, st, fmt.Errorf("%w: %s (mode %#o)", ErrNotRegular, rel, st.Mode&unix.S_IFMT)
	}
	fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", pfd), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, st, fmt.Errorf("reopen %s: %w", rel, err)
	}
	var again unix.Stat_t
	if err := unix.Fstat(fd, &again); err != nil {
		_ = unix.Close(fd)
		return nil, st, err
	}
	if again.Mode&unix.S_IFMT != unix.S_IFREG || again.Dev != st.Dev || again.Ino != st.Ino {
		_ = unix.Close(fd)
		return nil, st, fmt.Errorf("%w: %s changed under the open", ErrNotRegular, rel)
	}
	return os.NewFile(uintptr(fd), rel), again, nil
}

// Download opens the regular file p for reading from offset. The reader
// is bounded by the size the file had at the open.
func (w *Workspace) Download(p string, offset int64) (*File, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	rel, err := Clean(p, false)
	if err != nil {
		return nil, err
	}
	if offset < 0 {
		return nil, fmt.Errorf("%w: negative offset", ErrSize)
	}
	f, st, err := openRegular(w.root, rel)
	if err != nil {
		return nil, err
	}
	return &File{
		f:         f,
		info:      infoOf(rel, &st),
		pos:       offset,
		remaining: max(st.Size-offset, 0),
	}, nil
}

// infoOf makes an Info from a stat.
func infoOf(rel string, st *unix.Stat_t) Info {
	i := Info{Path: rel, Mode: fs.FileMode(st.Mode) & fs.ModePerm, ModTime: time.Unix(st.Mtim.Sec, st.Mtim.Nsec)}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		i.Size = st.Size
	case unix.S_IFDIR:
		i.Mode |= fs.ModeDir
	}
	return i
}

// List returns the regular files and directories directly under the
// directory p, sorted by name. "" names the root. Links, FIFOs, sockets
// and devices are left out. More entries than the limit is ErrEntries.
func (w *Workspace) List(p string) ([]Info, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	rel, err := Clean(p, true)
	if err != nil {
		return nil, err
	}
	dfd, err := openBeneath(w.root, rel, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(dfd) }()
	names, err := readNames(dfd)
	if err != nil {
		return nil, err
	}
	if int64(len(names)) > w.opts.Limits.entries() {
		return nil, fmt.Errorf("%w: %d in %q, over %d", ErrEntries, len(names), rel, w.opts.Limits.entries())
	}
	out := make([]Info, 0, len(names))
	for _, n := range names {
		var st unix.Stat_t
		if err := unix.Fstatat(dfd, n, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			continue
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFREG, unix.S_IFDIR:
			out = append(out, infoOf(path.Join(rel, n), &st))
		}
	}
	return out, nil
}

// inode names one file across hard links.
type inode struct{ dev, ino uint64 }

// capture is one Capture in progress. The three maps hold only files
// with more than one link, so a tree without hard links costs nothing
// here. At worst, every entry a hard link with the longest path, they
// hold the entry ceiling times MaxPathBytes, 256 MiB, and a tree of
// that shape needs as many bytes of names on disk.
type capture struct {
	w       *Workspace
	tw      *tar.Writer
	entries int64
	bytes   int64
	first   map[inode]string
	names   map[inode]int64
	nlink   map[inode]int64
}

// Capture writes the tree under the root to out as a tar. Directories,
// regular files and symbolic links are carried, a link as its target
// string and never followed. A file with several names in the tree is
// written once and then as hard links to the first name. FIFOs, sockets
// and devices are skipped. Sparse files count by apparent size. A tree
// past the limits is refused, and so is a file with a name outside the
// tree, since fiberd must not seal host bytes into a delta. Every path
// is checked with the same rules Unpack applies, so a tree that parks
// can always resume.
func (w *Workspace) Capture(out io.Writer) error {
	w.mu.RLock()
	defer w.mu.RUnlock()
	c := &capture{
		w:     w,
		tw:    tar.NewWriter(out),
		first: map[inode]string{},
		names: map[inode]int64{},
		nlink: map[inode]int64{},
	}
	if err := c.dir(w.root, ""); err != nil {
		return err
	}
	for k, seen := range c.names {
		if c.nlink[k] > seen {
			return fmt.Errorf("%w: %s has %d names, %d in the workspace", ErrForeignLink, c.first[k], c.nlink[k], seen)
		}
	}
	return c.tw.Close()
}

// count admits one more entry of size bytes, before anything of it is
// written. The byte check subtracts, so an apparent size near the
// maximum cannot wrap the sum past the ceiling.
func (c *capture) count(size int64) error {
	if c.entries >= c.w.opts.Limits.entries() {
		return fmt.Errorf("%w: over %d", ErrEntries, c.w.opts.Limits.entries())
	}
	if size > c.w.opts.Limits.Bytes-c.bytes {
		return fmt.Errorf("%w: %d bytes with %d left of %d", ErrTooLarge, size, c.w.opts.Limits.Bytes-c.bytes, c.w.opts.Limits.Bytes)
	}
	c.entries++
	c.bytes += size
	return nil
}

// dir walks one directory open at dfd, at the relative path rel.
func (c *capture) dir(dfd int, rel string) error {
	names, err := readNames(dfd)
	if err != nil {
		return err
	}
	for _, n := range names {
		var st unix.Stat_t
		if err := unix.Fstatat(dfd, n, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return fmt.Errorf("stat %s: %w", path.Join(rel, n), err)
		}
		p := path.Join(rel, n)
		if _, err := Clean(p, false); err != nil {
			return err
		}
		hdr := &tar.Header{Name: p, Mode: int64(st.Mode & 0o777), ModTime: time.Unix(st.Mtim.Sec, st.Mtim.Nsec)}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			if err := c.count(0); err != nil {
				return err
			}
			hdr.Typeflag = tar.TypeDir
			hdr.Name += "/"
			if err := c.tw.WriteHeader(hdr); err != nil {
				return err
			}
			sub, err := openBeneath(dfd, n, unix.O_RDONLY|unix.O_DIRECTORY)
			if err != nil {
				return err
			}
			err = c.dir(sub, p)
			_ = unix.Close(sub)
			if err != nil {
				return err
			}
		case unix.S_IFLNK:
			target, err := readLink(dfd, n)
			if err != nil {
				return fmt.Errorf("readlink %s: %w", p, err)
			}
			if err := c.count(0); err != nil {
				return err
			}
			hdr.Typeflag = tar.TypeSymlink
			hdr.Linkname = target
			if err := c.tw.WriteHeader(hdr); err != nil {
				return err
			}
		case unix.S_IFREG:
			if err := c.file(dfd, n, p, hdr); err != nil {
				return err
			}
		}
	}
	return nil
}

// file writes one regular file, or a hard link to its first name.
func (c *capture) file(dfd int, n, p string, hdr *tar.Header) error {
	f, st, err := openRegular(dfd, n)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	defer func() { _ = f.Close() }()
	if st.Nlink > 1 {
		key := inode{st.Dev, st.Ino}
		c.names[key]++
		c.nlink[key] = max(c.nlink[key], int64(st.Nlink))
		if first, ok := c.first[key]; ok {
			if err := c.count(0); err != nil {
				return err
			}
			hdr.Typeflag = tar.TypeLink
			hdr.Linkname = first
			return c.tw.WriteHeader(hdr)
		}
		c.first[key] = p
	}
	if err := c.count(st.Size); err != nil {
		return err
	}
	hdr.Typeflag = tar.TypeReg
	hdr.Size = st.Size
	if err := c.tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := io.CopyN(c.tw, f, st.Size); err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%w: %s shrank under the capture", ErrSize, p)
		}
		return err
	}
	return nil
}

// readLink reads the target of the link n under dfd. A target longer
// than MaxPathBytes is refused.
func readLink(dfd int, n string) (string, error) {
	buf := make([]byte, MaxPathBytes+1)
	k, err := unix.Readlinkat(dfd, n, buf)
	if err != nil {
		return "", err
	}
	if k > MaxPathBytes {
		return "", fmt.Errorf("%w: link target over %d bytes", ErrPath, MaxPathBytes)
	}
	return string(buf[:k]), nil
}

// Unpack reads a workspace archive into an empty root. Every name and
// link target is checked with the path rules, entries and bytes are
// counted against the limits and reserved against the budget, regular
// files go through the staging directory and are renamed into place,
// and a symbolic link is made as a string that nothing here follows. A
// hard link may only name a regular file the same archive wrote. A root
// that already holds names is refused with ErrNotEmpty. On failure
// what is still reserved is released and the caller discards the tree.
func (w *Workspace) Unpack(in io.Reader) error {
	w.mu.RLock()
	defer w.mu.RUnlock()
	names, err := readNames(w.root)
	if err != nil {
		return err
	}
	if len(names) > 0 {
		return fmt.Errorf("%w: %d names", ErrNotEmpty, len(names))
	}
	// The net reservation, what Reserve took less what a replaced name
	// gave back, so a failure releases exactly what is still held.
	var bytes, entries int64
	err = readArchive(in, w.opts.Limits, func(e entry) error {
		size := e.Size
		if e.Type != tar.TypeReg {
			size = 0
		}
		if err := w.opts.Budget.Reserve(size, 1); err != nil {
			return err
		}
		bytes += size
		entries++
		freedBytes, freedEntries, err := w.unpackEntry(e)
		bytes -= freedBytes
		entries -= freedEntries
		return err
	})
	if err != nil {
		w.opts.Budget.Release(bytes, entries)
	}
	return err
}

// unpackEntry makes one archive entry under the root. It reports what a
// replaced name gave back to the budget.
func (w *Workspace) unpackEntry(e entry) (freedBytes, freedEntries int64, err error) {
	dir, base := split(e.Path)
	switch e.Type {
	case tar.TypeReg:
		f, name, err := w.stageFile(e.Mode)
		if err != nil {
			return 0, 0, err
		}
		placed := false
		defer func() {
			_ = f.Close()
			if !placed {
				_ = unix.Unlinkat(w.stage, name, 0)
			}
		}()
		if _, err := w.fillStaged(f, e.Body, e.Size, nil); err != nil {
			if errors.Is(err, ErrSize) {
				return 0, 0, fmt.Errorf("%w: %s: %w", ErrArchive, e.Path, err)
			}
			return 0, 0, err
		}
		parent, err := w.openDir(dir, true)
		if err != nil {
			return 0, 0, err
		}
		defer w.closeDir(parent)
		replaced, freed, err := w.place(parent, name, base)
		if err != nil {
			return 0, 0, err
		}
		placed = true
		w.own(f, e.Size)
		if replaced {
			w.opts.Budget.Release(freed, 1)
			return freed, 1, nil
		}
		return 0, 0, nil
	case tar.TypeDir:
		parent, err := w.openDir(dir, true)
		if err != nil {
			return 0, 0, err
		}
		defer w.closeDir(parent)
		// The owner keeps rwx so the rest of the archive can land inside.
		if err := unix.Mkdirat(parent, base, uint32(e.Mode|0o700)); err != nil {
			return 0, 0, fmt.Errorf("%w: mkdir %s: %w", ErrArchive, e.Path, err)
		}
		w.chownNew(parent, base, unix.S_IFDIR)
		return 0, 0, nil
	case tar.TypeSymlink:
		parent, err := w.openDir(dir, true)
		if err != nil {
			return 0, 0, err
		}
		defer w.closeDir(parent)
		if err := unix.Symlinkat(e.Linkname, parent, base); err != nil {
			return 0, 0, fmt.Errorf("%w: symlink %s: %w", ErrArchive, e.Path, err)
		}
		w.chownNew(parent, base, unix.S_IFLNK)
		return 0, 0, nil
	case tar.TypeLink:
		tdir, tbase := split(e.Linkname)
		tparent, err := w.openDir(tdir, false)
		if err != nil {
			return 0, 0, err
		}
		defer w.closeDir(tparent)
		var st unix.Stat_t
		if err := unix.Fstatat(tparent, tbase, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return 0, 0, fmt.Errorf("%w: link target %s: %w", ErrArchive, e.Linkname, err)
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			return 0, 0, fmt.Errorf("%w: link target %s is not a regular file", ErrArchive, e.Linkname)
		}
		parent, err := w.openDir(dir, true)
		if err != nil {
			return 0, 0, err
		}
		defer w.closeDir(parent)
		if err := unix.Linkat(tparent, tbase, parent, base, 0); err != nil {
			return 0, 0, fmt.Errorf("%w: link %s: %w", ErrArchive, e.Path, err)
		}
		return 0, 0, nil
	}
	return 0, 0, fmt.Errorf("%w: entry %s of type %q", ErrArchive, e.Path, e.Type)
}

// closeDir closes a directory openDir returned, unless it is the root.
func (w *Workspace) closeDir(fd int) {
	if fd != w.root {
		_ = unix.Close(fd)
	}
}

// chownNew gives a name fiberd just made to the owner. The name is
// pinned by a descriptor and checked to be of the type fiberd made, so
// a name the fiber swapped in meanwhile is left alone.
func (w *Workspace) chownNew(parent int, base string, want uint32) {
	if w.opts.Owner == nil {
		return
	}
	fd, err := openBeneath(parent, base, unix.O_PATH)
	if err != nil {
		return
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != want {
		return
	}
	_ = unix.Fchownat(fd, "", w.opts.Owner.UID, w.opts.Owner.GID, unix.AT_EMPTY_PATH)
}
