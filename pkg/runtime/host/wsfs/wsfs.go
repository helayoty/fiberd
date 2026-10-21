// Package wsfs is the file layer of a fiber's workspace. fiberd runs as
// root and the fiber owns every name under the workspace root, so each
// operation here treats the tree as hostile. The root is opened once and
// every path is resolved beneath that descriptor, never from a string.
// Uploads land in a staging directory the fiber cannot see and are
// renamed into place from descriptors. Downloads, listings and the park
// archive send regular files only.
//
// Only Linux has openat2, so only Linux gets a Workspace. The path rules
// and the archive reader are plain Go and are checked everywhere.
package wsfs

import (
	"archive/tar"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"sync"
	"time"
)

// Path limits from the design. A path is relative, at most MaxPathBytes
// long and MaxDepth components deep, with no NUL, "." or "..".
const (
	MaxPathBytes = 4096
	MaxDepth     = 64
)

// DefaultEntries is the entry ceiling a workspace gets when Limits names
// none.
const DefaultEntries = 65536

// Errors the layer returns. Callers match them with errors.Is.
var (
	// ErrPath is a path the rules refuse.
	ErrPath = errors.New("wsfs: bad path")
	// ErrNotRegular is a name that is not a regular file where one is
	// needed, such as a FIFO, a device, a socket, a link or a directory.
	ErrNotRegular = errors.New("wsfs: not a regular file")
	// ErrSize is a body that does not match its declared size.
	ErrSize = errors.New("wsfs: size mismatch")
	// ErrChecksum is a body whose sha256 does not match the declared one.
	ErrChecksum = errors.New("wsfs: sha256 mismatch")
	// ErrBudget is a reservation the budget refused.
	ErrBudget = errors.New("wsfs: over budget")
	// ErrEntries is a tree or an archive with more entries than allowed.
	ErrEntries = errors.New("wsfs: too many entries")
	// ErrTooLarge is a tree or an archive with more bytes than allowed.
	ErrTooLarge = errors.New("wsfs: too large")
	// ErrArchive is an archive entry the unpacker refuses.
	ErrArchive = errors.New("wsfs: bad archive")
	// ErrNotEmpty is an unpack into a root that already holds names.
	ErrNotEmpty = errors.New("wsfs: root not empty")
	// ErrForeignLink is a file in the tree with a hard link outside it.
	ErrForeignLink = errors.New("wsfs: hard link from outside the workspace")
	// ErrUnsupported is a platform without openat2.
	ErrUnsupported = errors.New("wsfs: unsupported on this platform")
)

// Info describes one entry of a workspace.
type Info struct {
	// Path is relative to the workspace root, with forward slashes.
	Path string
	// Size is the apparent size in bytes. A directory reports zero.
	Size int64
	// Mode holds the permission bits, and fs.ModeDir for a directory.
	Mode fs.FileMode
	// ModTime is the last modification time.
	ModTime time.Time
	// SHA256 is the content hash, set by Upload only.
	SHA256 []byte
}

// Limits bound what a workspace may hold. The park archive and the
// unpacker refuse a tree past either. Zero Bytes allows no file bytes
// at all, as a zero disk budget gives no workspace. Zero Entries means
// DefaultEntries.
type Limits struct {
	Bytes   int64
	Entries int64
}

// entries is the entry ceiling with the default applied.
func (l Limits) entries() int64 {
	if l.Entries <= 0 {
		return DefaultEntries
	}
	return l.Entries
}

// Budget accounts the bytes and entries a workspace holds. Upload and
// Unpack call Reserve before a byte lands and Release when the write
// fails, so a later stage can put a project quota behind it. A
// reservation is bytes and entries together, and Release takes back what
// one Reserve gave.
type Budget interface {
	Reserve(bytes, entries int64) error
	Release(bytes, entries int64)
}

// Counter is a Budget in memory. It is the default and what the tests
// use. The zero value refuses everything.
type Counter struct {
	mu      sync.Mutex
	limit   Limits
	bytes   int64
	entries int64
}

// NewCounter makes a Counter that allows up to l.Bytes bytes and
// l.Entries entries. Zero Bytes allows no bytes, as a zero disk budget
// gives no workspace.
func NewCounter(l Limits) *Counter {
	return &Counter{limit: Limits{Bytes: l.Bytes, Entries: l.entries()}}
}

// Reserve takes bytes and entries, or refuses with ErrBudget and takes
// nothing.
func (c *Counter) Reserve(bytes, entries int64) error {
	if bytes < 0 || entries < 0 {
		return fmt.Errorf("%w: negative reservation", ErrBudget)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Compared by subtraction. What is held never exceeds the limit, so
	// the remainder cannot overflow, while a sum with a huge request
	// would wrap negative and pass.
	if bytes > c.limit.Bytes-c.bytes || entries > c.limit.Entries-c.entries {
		return fmt.Errorf("%w: %d bytes and %d entries over %d bytes and %d entries, %d bytes and %d entries held",
			ErrBudget, bytes, entries, c.limit.Bytes, c.limit.Entries, c.bytes, c.entries)
	}
	c.bytes += bytes
	c.entries += entries
	return nil
}

// Release gives back a reservation. A release past zero is a bug in
// the caller and is left visible, not clamped.
func (c *Counter) Release(bytes, entries int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bytes -= bytes
	c.entries -= entries
}

// Held reports what the counter holds.
func (c *Counter) Held() (bytes, entries int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytes, c.entries
}

// Clean checks a caller's path against the rules and returns it with
// forward slashes and no trailing slash. The path is relative, at most
// MaxPathBytes long, at most MaxDepth components deep, and no component
// is empty, "." or "..". A NUL anywhere is refused. The empty path names
// the root and is allowed only when allowRoot is set.
func Clean(p string, allowRoot bool) (string, error) {
	if p == "" {
		if allowRoot {
			return "", nil
		}
		return "", fmt.Errorf("%w: empty", ErrPath)
	}
	if len(p) > MaxPathBytes {
		return "", fmt.Errorf("%w: %d bytes, over %d", ErrPath, len(p), MaxPathBytes)
	}
	if strings.IndexByte(p, 0) >= 0 {
		return "", fmt.Errorf("%w: NUL byte", ErrPath)
	}
	if p[0] == '/' {
		return "", fmt.Errorf("%w: absolute", ErrPath)
	}
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return "", fmt.Errorf("%w: only slashes", ErrPath)
	}
	depth := 0
	for comp := range strings.SplitSeq(p, "/") {
		switch comp {
		case "":
			return "", fmt.Errorf("%w: empty component", ErrPath)
		case ".", "..":
			return "", fmt.Errorf("%w: %q component", ErrPath, comp)
		}
		depth++
		if depth > MaxDepth {
			return "", fmt.Errorf("%w: deeper than %d", ErrPath, MaxDepth)
		}
	}
	return p, nil
}

// split returns the directory and the base of a cleaned path. The
// directory is "" for a name at the root.
func split(p string) (dir, base string) {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[:i], p[i+1:]
	}
	return "", p
}

// entry is one archive entry the reader accepted. Body is set for a
// regular file and reads exactly Size bytes.
type entry struct {
	Path     string
	Type     byte
	Mode     fs.FileMode
	Size     int64
	Linkname string
	ModTime  time.Time
	Body     io.Reader
}

// readArchive reads a tar stream and hands every accepted entry to sink,
// in order. It applies the path rules to every name and link name,
// counts entries against the limits, and sums the apparent size of the
// regular files against l.Bytes, by subtraction so a declared size
// near the maximum cannot wrap the sum. Only directories, regular
// files, symbolic links and hard links pass. Everything else is
// refused, since a workspace archive never holds anything else. A hard
// link's target must have been a regular file earlier in the same
// archive, so the unpacker never links to a name the archive did not
// make. The names seen are kept as hashes, 32 bytes each, so the
// reader holds at most 2 MiB for them at the entry ceiling.
func readArchive(r io.Reader, l Limits, sink func(entry) error) error {
	tr := tar.NewReader(r)
	var entries, bytes int64
	files := map[[sha256.Size]byte]bool{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: %w", ErrArchive, err)
		}
		entries++
		if entries > l.entries() {
			return fmt.Errorf("%w: over %d", ErrEntries, l.entries())
		}
		name, err := Clean(hdr.Name, false)
		if err != nil {
			return fmt.Errorf("%w: entry %d: %w", ErrArchive, entries, err)
		}
		e := entry{Path: name, Type: hdr.Typeflag, Mode: fs.FileMode(hdr.Mode) & fs.ModePerm, ModTime: hdr.ModTime}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if hdr.Size != 0 {
				return fmt.Errorf("%w: directory %s with a body", ErrArchive, name)
			}
		case tar.TypeReg:
			if hdr.Size < 0 {
				return fmt.Errorf("%w: file %s with a negative size", ErrArchive, name)
			}
			if hdr.Size > l.Bytes-bytes {
				return fmt.Errorf("%w: %s of %d bytes, %d left of %d", ErrTooLarge, name, hdr.Size, l.Bytes-bytes, l.Bytes)
			}
			bytes += hdr.Size
			e.Size = hdr.Size
			e.Body = io.LimitReader(tr, hdr.Size)
			files[sha256.Sum256([]byte(name))] = true
		case tar.TypeSymlink:
			if hdr.Linkname == "" || strings.IndexByte(hdr.Linkname, 0) >= 0 || len(hdr.Linkname) > MaxPathBytes {
				return fmt.Errorf("%w: symlink %s with a bad target", ErrArchive, name)
			}
			e.Linkname = hdr.Linkname
		case tar.TypeLink:
			target, err := Clean(hdr.Linkname, false)
			if err != nil {
				return fmt.Errorf("%w: hard link %s: %w", ErrArchive, name, err)
			}
			if !files[sha256.Sum256([]byte(target))] {
				return fmt.Errorf("%w: hard link %s to %s, not a file of this archive", ErrArchive, name, target)
			}
			e.Linkname = target
		default:
			return fmt.Errorf("%w: entry %s of type %q", ErrArchive, name, hdr.Typeflag)
		}
		if err := sink(e); err != nil {
			return err
		}
		if e.Body != nil {
			// The sink may stop short. Drain so the next header is read
			// from the right place, and so a short body is seen here.
			if _, err := io.Copy(io.Discard, e.Body); err != nil {
				return fmt.Errorf("%w: %s: %w", ErrArchive, name, err)
			}
		}
	}
}
