package artifact

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// A Hyperlight snapshot artifact (ImagesFormatHyperlight) carries the
// guest's snapshot as its images: a tree of directories and regular
// files, sealed like CRIU images, that a helper restores the warm
// template from. Its tar keeps the tree's directories, where a CRIU
// images tar is flat (tarDir), and every component of every name is a
// plain name (checkEntryName).

// snapshotMaxDepth bounds how deep a snapshot tree may nest, so a tar
// cannot make a home walk or create paths without end.
const snapshotMaxDepth = 16

// TarSnapshot writes the tree at src into the tar at dst, directories
// and regular files only, in a stable order with fixed times and owners,
// so one tree always tars to the same bytes. Anything else in the tree
// (a symlink, a device, a FIFO) refuses the tar rather than be dropped,
// and so do a src that is itself a symlink, which would tar as nothing,
// and a tree that holds no file.
func TarSnapshot(src, dst string) error {
	if st, err := os.Lstat(src); err != nil {
		return err
	} else if !st.IsDir() {
		return fmt.Errorf("artifact: snapshot %s is not a directory (a symlink to one is refused)", src)
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	tw := tar.NewWriter(out)
	files := 0
	err = filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil || rel == "." {
			return err
		}
		name := filepath.ToSlash(rel)
		if err := checkSnapshotName(name); err != nil {
			return err
		}
		hdr := &tar.Header{Name: name, ModTime: time.Unix(0, 0), Format: tar.FormatPAX}
		switch {
		case d.IsDir():
			hdr.Typeflag, hdr.Name, hdr.Mode = tar.TypeDir, name+"/", 0o700
		case d.Type().IsRegular():
			info, err := d.Info()
			if err != nil {
				return err
			}
			hdr.Typeflag, hdr.Mode, hdr.Size = tar.TypeReg, 0o600, info.Size()
			files++
		default:
			return fmt.Errorf("artifact: snapshot %s is neither a directory nor a regular file", name)
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		n, err := io.Copy(tw, f)
		_ = f.Close()
		if err == nil && n != hdr.Size {
			err = fmt.Errorf("artifact: snapshot %s changed size while it was read", name)
		}
		return err
	})
	if err != nil {
		return err
	}
	if files == 0 {
		return fmt.Errorf("artifact: snapshot %s holds no file", src)
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return out.Close()
}

// checkSnapshotName accepts a slash-separated relative name whose every
// component is a plain name (checkEntryName), at most snapshotMaxDepth
// deep.
func checkSnapshotName(name string) error {
	parts := strings.Split(name, "/")
	if len(parts) > snapshotMaxDepth || path.Clean(name) != name {
		return fmt.Errorf("%w: %q", ErrEntryName, name)
	}
	for _, p := range parts {
		if err := checkEntryName(p); err != nil {
			return fmt.Errorf("%w: %q", ErrEntryName, name)
		}
	}
	return nil
}

// untarSnapshot unpacks the tar at src into dst, an empty directory its
// caller made, owner-only: directories 0700, files 0600. A directory must come before
// what it holds, as TarSnapshot writes them, and a name may appear once.
// Any other entry type, a name checkSnapshotName refuses, or a sparse
// entry fails the unpack. What it writes is never more than the tar
// itself holds, so a small tar cannot fill the disk.
func untarSnapshot(src, dst string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	budget := st.Size()
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := strings.TrimSuffix(hdr.Name, "/")
		if err := checkSnapshotName(name); err != nil {
			return err
		}
		// archive/tar expands a PAX GNU sparse entry into a regular one
		// as large as it says, which TarSnapshot never writes.
		for k := range hdr.PAXRecords {
			if strings.HasPrefix(k, "GNU.sparse.") {
				return fmt.Errorf("artifact: snapshot entry %q is sparse", hdr.Name)
			}
		}
		to := filepath.Join(dst, filepath.FromSlash(name))
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(to, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if hdr.Size > budget {
				return fmt.Errorf("artifact: snapshot entry %q is %d bytes, more than the tar holds", hdr.Name, hdr.Size)
			}
			out, err := os.OpenFile(to, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			n, err := io.Copy(out, io.LimitReader(tr, budget+1))
			budget -= n
			if err == nil && budget < 0 {
				err = fmt.Errorf("artifact: snapshot unpacks to more than the tar holds")
			}
			if cerr := out.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("artifact: snapshot entry %q is neither a directory nor a regular file", hdr.Name)
		}
	}
}

// OpenSnapshot opens the sealed Hyperlight snapshot of the verified
// artifact in dir with the fleet key derived from k, checks it hashes to
// what cfg names, and unpacks it into dst for one warm alone, which must
// not exist. A copy of its own, so nothing another warm or a later
// resolve does reaches it, and read-only once made: files 0400 and
// directories 0500, fiberd's alone. The plaintext tar is made beside dst
// and is gone when it returns. On any error dst is removed.
// RemoveSnapshot removes it.
//
// Read-only is by mode. It keeps a process without CAP_DAC_OVERRIDE from
// writing the template by mistake, and is no boundary: one running as
// fiberd's user could make it writable, and anything else that user can
// write besides.
func OpenSnapshot(dir string, cfg Config, k *SealKey, dst string) error {
	if cfg.Images == nil || cfg.ImagesFormat != ImagesFormatHyperlight {
		return errors.New("artifact: no Hyperlight snapshot to open")
	}
	if k == nil {
		return fmt.Errorf("artifact: snapshot sealed to fleet key %q, and this home has no seal key (-delta-seal-key)", cfg.Images.KeyID)
	}
	// The plaintext tar beside dst must not be there either: opening it
	// would write through whatever stood at its name.
	open := dst + ".tar.open"
	if _, err := os.Lstat(open); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("artifact: snapshot destination %s is already there", open)
	}
	// dst is made here, alone, so an error below removes this open's own
	// tree and never one that was there.
	if err := os.Mkdir(dst, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("artifact: snapshot destination %s is already there", dst)
		}
		return err
	}
	defer func() { _ = os.Remove(open) }()
	if err := OpenImages(filepath.Join(dir, fileImages), open, k, *cfg.Images); err != nil {
		_ = RemoveSnapshot(dst)
		return err
	}
	if err := untarSnapshot(open, dst); err != nil {
		_ = RemoveSnapshot(dst)
		return fmt.Errorf("artifact: unpack snapshot: %w", err)
	}
	if err := readOnlyTree(dst); err != nil {
		_ = RemoveSnapshot(dst)
		return err
	}
	return nil
}

// readOnlyTree makes every file under dir 0400 and every directory 0500,
// the deepest first, so each directory is still writable while what it
// holds is made read-only.
func readOnlyTree(dir string) error {
	var dirs []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir():
			dirs = append(dirs, p)
			return nil
		default:
			return os.Chmod(p, 0o400)
		}
	})
	if err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := os.Chmod(dirs[i], 0o500); err != nil {
			return err
		}
	}
	return nil
}

// RemoveSnapshot removes a snapshot OpenSnapshot opened, giving its
// directories back the write bit a removal needs first, and any plaintext
// tar an open left beside it. A missing dst is no error.
func RemoveSnapshot(dst string) error {
	_ = os.Remove(dst + ".tar.open")
	if _, err := os.Lstat(dst); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	_ = filepath.WalkDir(dst, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(p, 0o700)
		}
		return nil
	})
	return os.RemoveAll(dst)
}
