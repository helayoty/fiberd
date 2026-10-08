//go:build unix

package runc

import (
	"bytes"
	"io"
	"os"
	"syscall"
)

// tailLimit bounds what logTails quotes of each log in an error.
const tailLimit = 2048

// tailFile is the end of the file at path for an error message: at most
// limit bytes, and from the start of a line when the file is longer than
// that. A missing, empty or unreadable file reads as "". The path is
// opened without following a link, since the zygote log sits in a
// directory the mapped root can write.
func tailFile(path string, limit int64) string {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return ""
	}
	cut := false
	if st.Size() > limit {
		if _, err := f.Seek(st.Size()-limit, io.SeekStart); err != nil {
			return ""
		}
		cut = true
	}
	b, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return ""
	}
	if cut {
		// Drop the partial first line, unless it is all there is.
		if i := bytes.IndexByte(b, '\n'); i >= 0 && i+1 < len(b) {
			b = b[i+1:]
		}
	}
	return string(b)
}
