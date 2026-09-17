package criu

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// CRIU memory images, enough of them to express one checkpoint as a delta
// over another:
//
//	pagemap-<pid>.img  8-byte header (two magics), then size-prefixed
//	                   protobuf messages: a head {pages_id} followed by
//	                   entries {vaddr, nr_pages, flags}
//	pages-<id>.img     the pages of every PRESENT entry, back to back, in
//	                   pagemap order
//
// A fiber forked from the zygote shares its address layout, so a fiber
// page is redundant when the zygote's checkpoint holds the same bytes at
// the same address. Dropping those leaves the dirtied working set: W.
//
// Everything here streams. Parents are memory-mapped (page cache, which
// the kernel may reclaim) and checkpoints are read and written a page at
// a time, so computing a delta under memory pressure does not itself
// consume memory: that is exactly when parks happen.

const (
	// Page flags in pagemap entries.
	PEParent  = 1 << 0
	PELazy    = 1 << 1
	PEPresent = 1 << 2
)

// PagemapEntry is one run of pages.
type PagemapEntry struct {
	VAddr   uint64
	NrPages uint32
	Flags   uint32
}

// Pagemap is one task's memory map.
type Pagemap struct {
	Path    string
	Header  []byte // the 8 magic bytes, preserved verbatim
	PagesID uint32
	Entries []PagemapEntry
}

// PagesFile is the pages image the pagemap refers to.
func (p *Pagemap) PagesFile() string {
	return filepath.Join(filepath.Dir(p.Path), fmt.Sprintf("pages-%d.img", p.PagesID))
}

// ReadPagemap parses pagemap-<pid>.img.
func ReadPagemap(path string) (*Pagemap, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) < 8 {
		return nil, fmt.Errorf("criu: %s: short header", path)
	}
	pm := &Pagemap{Path: path, Header: append([]byte{}, b[:8]...)}
	rest := b[8:]
	first := true
	for len(rest) > 0 {
		if len(rest) < 4 {
			return nil, fmt.Errorf("criu: %s: truncated entry size", path)
		}
		n := binary.LittleEndian.Uint32(rest[:4])
		rest = rest[4:]
		if uint32(len(rest)) < n {
			return nil, fmt.Errorf("criu: %s: truncated entry", path)
		}
		msg := rest[:n]
		rest = rest[n:]
		fields, err := parseVarintFields(msg)
		if err != nil {
			return nil, fmt.Errorf("criu: %s: %w", path, err)
		}
		if first {
			pm.PagesID = uint32(fields[1])
			first = false
			continue
		}
		pm.Entries = append(pm.Entries, PagemapEntry{VAddr: fields[1], NrPages: uint32(fields[2]), Flags: uint32(fields[4])})
	}
	return pm, nil
}

// parseVarintFields decodes a protobuf message whose fields are all
// varints (the only kind these messages have) into number -> value.
func parseVarintFields(msg []byte) (map[int]uint64, error) {
	out := map[int]uint64{}
	for len(msg) > 0 {
		key, n := binary.Uvarint(msg)
		if n <= 0 {
			return nil, errors.New("bad protobuf key")
		}
		msg = msg[n:]
		field, wire := int(key>>3), key&7
		switch wire {
		case 0:
			v, n := binary.Uvarint(msg)
			if n <= 0 {
				return nil, errors.New("bad varint")
			}
			msg = msg[n:]
			out[field] = v
		case 2:
			l, n := binary.Uvarint(msg)
			if n <= 0 || uint64(len(msg)-n) < l {
				return nil, errors.New("bad length-delimited field")
			}
			msg = msg[n+int(l):]
		case 1:
			if len(msg) < 8 {
				return nil, errors.New("bad fixed64")
			}
			msg = msg[8:]
		case 5:
			if len(msg) < 4 {
				return nil, errors.New("bad fixed32")
			}
			msg = msg[4:]
		default:
			return nil, fmt.Errorf("unsupported wire type %d", wire)
		}
	}
	return out, nil
}

func writePagemap(pm *Pagemap) error {
	var out bytes.Buffer
	out.Write(pm.Header)
	writeMsg := func(fields ...[2]uint64) {
		var msg []byte
		for _, f := range fields {
			msg = binary.AppendUvarint(msg, f[0]<<3) // wire type 0
			msg = binary.AppendUvarint(msg, f[1])
		}
		var sz [4]byte
		binary.LittleEndian.PutUint32(sz[:], uint32(len(msg)))
		out.Write(sz[:])
		out.Write(msg)
	}
	writeMsg([2]uint64{1, uint64(pm.PagesID)})
	for _, e := range pm.Entries {
		writeMsg([2]uint64{1, e.VAddr}, [2]uint64{2, uint64(e.NrPages)}, [2]uint64{4, uint64(e.Flags)})
	}
	return os.WriteFile(pm.Path, out.Bytes(), 0o600)
}

// FindPagemaps lists the pagemap images in a dump directory.
func FindPagemaps(dir string) ([]string, error) {
	return filepath.Glob(filepath.Join(dir, "pagemap-*.img"))
}

// PageSize is the page granularity of the images (host page size).
var PageSize = uint64(os.Getpagesize())

// Parent is a loaded zygote checkpoint: its pages files memory-mapped and
// every present page indexed by address, plus a hash of the pages files
// that identifies it. Load once per checkpoint and reuse; Close unmaps.
type Parent struct {
	Dir   string
	maps  [][]byte           // one mmap per pages file
	index map[uint64]pageRef // vaddr -> where the page is
	sha   string
}

type pageRef struct {
	file int
	off  uint64
}

// SHA256 identifies the checkpoint by the content of its pages files. A
// delta only merges against a parent with the same hash.
func (p *Parent) SHA256() string { return p.sha }

func (p *Parent) page(va uint64) ([]byte, bool) {
	r, ok := p.index[va]
	if !ok {
		return nil, false
	}
	return p.maps[r.file][r.off : r.off+PageSize], true
}

// Close releases the mappings.
func (p *Parent) Close() {
	for _, m := range p.maps {
		_ = syscall.Munmap(m)
	}
	p.maps = nil
}

// LoadParent maps a checkpoint directory. Memory cost is the index (a few
// tens of bytes per page); the pages stay in the page cache.
func LoadParent(dir string) (*Parent, error) {
	maps, err := FindPagemaps(dir)
	if err != nil || len(maps) == 0 {
		return nil, fmt.Errorf("criu: no pagemap in parent %s", dir)
	}
	sort.Strings(maps)
	p := &Parent{Dir: dir, index: map[uint64]pageRef{}}
	h := sha256.New()
	for fi, m := range maps {
		pm, err := ReadPagemap(m)
		if err != nil {
			p.Close()
			return nil, err
		}
		f, err := os.Open(pm.PagesFile())
		if err != nil {
			p.Close()
			return nil, err
		}
		st, err := f.Stat()
		if err != nil {
			_ = f.Close()
			p.Close()
			return nil, err
		}
		var data []byte
		if st.Size() > 0 {
			data, err = syscall.Mmap(int(f.Fd()), 0, int(st.Size()), syscall.PROT_READ, syscall.MAP_SHARED)
		}
		_ = f.Close()
		if err != nil {
			p.Close()
			return nil, fmt.Errorf("criu: mmap %s: %w", pm.PagesFile(), err)
		}
		p.maps = append(p.maps, data)
		h.Write(data)
		off := uint64(0)
		for _, e := range pm.Entries {
			if e.Flags&PEPresent == 0 {
				continue
			}
			for i := uint64(0); i < uint64(e.NrPages); i++ {
				if off+PageSize > uint64(len(data)) {
					p.Close()
					return nil, fmt.Errorf("criu: parent pages file %s shorter than its pagemap", pm.PagesFile())
				}
				p.index[e.VAddr+i*PageSize] = pageRef{file: fi, off: off}
				off += PageSize
			}
		}
	}
	p.sha = hex.EncodeToString(h.Sum(nil))
	return p, nil
}

// DeltaInfo is written beside a delta as delta.json.
type DeltaInfo struct {
	PageSize     uint64   `json:"page_size"`
	ParentSHA256 string   `json:"parent_sha256"`
	TotalPages   uint64   `json:"total_pages"`
	KeptPages    uint64   `json:"kept_pages"`
	Files        []string `json:"files"` // pagemap images the delta covers
}

// DeltaBytes is the size of the retained pages.
func (d DeltaInfo) DeltaBytes() uint64 { return d.KeptPages * d.PageSize }

const deltaFile = "delta.json"

// HasDelta reports whether dir holds a delta (pages stripped) rather than
// a full checkpoint.
func HasDelta(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, deltaFile))
	return err == nil
}

// ReadDeltaInfo loads delta.json.
func ReadDeltaInfo(dir string) (DeltaInfo, error) {
	b, err := os.ReadFile(filepath.Join(dir, deltaFile))
	if err != nil {
		return DeltaInfo{}, err
	}
	var d DeltaInfo
	return d, json.Unmarshal(b, &d)
}

var ErrParentMismatch = errors.New("criu: delta was taken over a checkpoint this home does not hold")

// ComputeDelta rewrites the checkpoint in dir as a delta over the parent:
// every page whose bytes equal the parent's page at the same address is
// dropped from the pages file and marked PE_PARENT in the pagemap. Runs
// are split and re-merged so the pagemap stays compact. Streams.
func ComputeDelta(dir string, parent *Parent) (DeltaInfo, error) {
	maps, err := FindPagemaps(dir)
	if err != nil || len(maps) == 0 {
		return DeltaInfo{}, fmt.Errorf("criu: no pagemap in %s", dir)
	}
	info := DeltaInfo{PageSize: PageSize, ParentSHA256: parent.sha}
	page := make([]byte, PageSize)
	for _, m := range maps {
		pm, err := ReadPagemap(m)
		if err != nil {
			return DeltaInfo{}, err
		}
		in, err := os.Open(pm.PagesFile())
		if err != nil {
			return DeltaInfo{}, err
		}
		rd := bufio.NewReaderSize(in, 1<<20)
		tmp := pm.PagesFile() + ".tmp"
		out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			_ = in.Close()
			return DeltaInfo{}, err
		}
		wr := bufio.NewWriterSize(out, 1<<20)
		var entries []PagemapEntry
		fail := func(err error) (DeltaInfo, error) {
			_ = in.Close()
			_ = out.Close()
			_ = os.Remove(tmp)
			return DeltaInfo{}, err
		}
		for _, e := range pm.Entries {
			if e.Flags&PEPresent == 0 {
				entries = append(entries, e)
				continue
			}
			for i := uint64(0); i < uint64(e.NrPages); i++ {
				va := e.VAddr + i*PageSize
				if _, err := io.ReadFull(rd, page); err != nil {
					return fail(fmt.Errorf("criu: pages file %s shorter than its pagemap: %w", pm.PagesFile(), err))
				}
				info.TotalPages++
				flags := e.Flags
				if pp, ok := parent.page(va); ok && bytes.Equal(pp, page) {
					flags = (e.Flags &^ PEPresent) | PEParent
				} else {
					if _, err := wr.Write(page); err != nil {
						return fail(err)
					}
					info.KeptPages++
				}
				if n := len(entries); n > 0 && entries[n-1].Flags == flags && entries[n-1].VAddr+uint64(entries[n-1].NrPages)*PageSize == va {
					entries[n-1].NrPages++
				} else {
					entries = append(entries, PagemapEntry{VAddr: va, NrPages: 1, Flags: flags})
				}
			}
		}
		_ = in.Close()
		if err := wr.Flush(); err != nil {
			return fail(err)
		}
		if err := out.Close(); err != nil {
			return fail(err)
		}
		if err := os.Rename(tmp, pm.PagesFile()); err != nil {
			return fail(err)
		}
		pm.Entries = entries
		if err := writePagemap(pm); err != nil {
			return DeltaInfo{}, err
		}
		info.Files = append(info.Files, filepath.Base(m))
	}
	sort.Strings(info.Files)
	b, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return DeltaInfo{}, err
	}
	return info, os.WriteFile(filepath.Join(dir, deltaFile), b, 0o600)
}

// MergeDelta turns a delta directory back into a full checkpoint using the
// parent, which must hash to the delta's recorded parent. Streams.
func MergeDelta(dir string, parent *Parent) error {
	info, err := ReadDeltaInfo(dir)
	if err != nil {
		return err
	}
	if parent.sha != info.ParentSHA256 {
		return fmt.Errorf("%w: delta parent %s, offered %s", ErrParentMismatch, short(info.ParentSHA256), short(parent.sha))
	}
	for _, name := range info.Files {
		pm, err := ReadPagemap(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		in, err := os.Open(pm.PagesFile())
		if err != nil {
			return err
		}
		rd := bufio.NewReaderSize(in, 1<<20)
		tmp := pm.PagesFile() + ".tmp"
		out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			_ = in.Close()
			return err
		}
		wr := bufio.NewWriterSize(out, 1<<20)
		fail := func(err error) error {
			_ = in.Close()
			_ = out.Close()
			_ = os.Remove(tmp)
			return err
		}
		for i := range pm.Entries {
			e := &pm.Entries[i]
			switch {
			case e.Flags&PEPresent != 0:
				if _, err := io.CopyN(wr, rd, int64(uint64(e.NrPages)*PageSize)); err != nil {
					return fail(fmt.Errorf("criu: delta pages file %s shorter than its pagemap: %w", pm.PagesFile(), err))
				}
			case e.Flags&PEParent != 0:
				for j := uint64(0); j < uint64(e.NrPages); j++ {
					pp, ok := parent.page(e.VAddr + j*PageSize)
					if !ok {
						return fail(fmt.Errorf("criu: parent lacks page %#x needed by the delta", e.VAddr+j*PageSize))
					}
					if _, err := wr.Write(pp); err != nil {
						return fail(err)
					}
				}
				e.Flags = (e.Flags &^ PEParent) | PEPresent
			}
		}
		_ = in.Close()
		if err := wr.Flush(); err != nil {
			return fail(err)
		}
		if err := out.Close(); err != nil {
			return fail(err)
		}
		if err := os.Rename(tmp, pm.PagesFile()); err != nil {
			return fail(err)
		}
		if err := writePagemap(pm); err != nil {
			return err
		}
	}
	return os.Remove(filepath.Join(dir, deltaFile))
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// CopyDir copies a flat image directory (used to keep a parent pristine).
func CopyDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		in, err := os.Open(filepath.Join(src, e.Name()))
		if err != nil {
			return err
		}
		out, err := os.OpenFile(filepath.Join(dst, e.Name()), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			_ = in.Close()
			return err
		}
		_, err = io.Copy(out, in)
		_ = in.Close()
		_ = out.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
