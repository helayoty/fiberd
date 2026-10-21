package wsfs

import (
	"errors"
	"io"
	"os"
)

// Owner is who owns what fiberd writes into a workspace. A backend whose
// fibers run as another id sets it, so the fiber can use the files.
type Owner struct {
	UID int
	GID int
}

// Options configure a workspace.
type Options struct {
	// Budget is required. Upload and Unpack reserve against it.
	Budget Budget
	// Limits bound the tree for List, Capture and Unpack.
	Limits Limits
	// Owner, when set, owns the root and everything fiberd writes. Nil
	// leaves fiberd's own ids.
	Owner *Owner
}

// File is an open download. It reads at most the bytes the file held
// when it was opened, from the offset asked for, so a fiber that grows
// the file after the open cannot keep the stream going.
type File struct {
	f         *os.File
	info      Info
	pos       int64
	remaining int64
}

// Info describes the file as it was when opened.
func (f *File) Info() Info { return f.info }

// Read reads the next bytes and ends with io.EOF at the bound.
func (f *File) Read(p []byte) (int, error) {
	if f.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > f.remaining {
		p = p[:f.remaining]
	}
	n, err := f.f.ReadAt(p, f.pos)
	f.pos += int64(n)
	f.remaining -= int64(n)
	if errors.Is(err, io.EOF) {
		if f.remaining > 0 {
			// The fiber truncated the file after the open. The stream
			// ends short rather than padding bytes the file never held.
			return n, io.ErrUnexpectedEOF
		}
		err = nil
	}
	return n, err
}

// Close closes the file.
func (f *File) Close() error { return f.f.Close() }
