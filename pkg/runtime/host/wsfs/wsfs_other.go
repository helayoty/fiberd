//go:build !linux

package wsfs

import (
	"io"
	"io/fs"
)

// Workspace is a placeholder so callers build on platforms without
// openat2. Open never returns one here.
type Workspace struct{}

// Open fails on platforms without openat2. Only Linux runs fibers.
func Open(string, Options) (*Workspace, error) { return nil, ErrUnsupported }

func (*Workspace) Close() {}
func (*Workspace) Upload(string, int64, fs.FileMode, []byte, io.Reader) (Info, error) {
	return Info{}, ErrUnsupported
}
func (*Workspace) Download(string, int64) (*File, error) { return nil, ErrUnsupported }
func (*Workspace) List(string) ([]Info, error)           { return nil, ErrUnsupported }
func (*Workspace) Capture(io.Writer) error               { return ErrUnsupported }
func (*Workspace) Unpack(io.Reader) error                { return ErrUnsupported }
