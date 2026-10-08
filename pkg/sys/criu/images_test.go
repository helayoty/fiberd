package criu_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/helayoty/fiberd/pkg/sys/criu"
)

// header is the 8 magic bytes a pagemap image starts with.
var header = []byte{0x19, 0x43, 0x56, 0x54, 0x01, 0x00, 0x00, 0x00}

// sized prefixes one raw protobuf message with its 4-byte size, as the
// image stores it.
func sized(m []byte) []byte {
	return append(binary.LittleEndian.AppendUint32(nil, uint32(len(m))), m...)
}

// varints encodes a protobuf message of varint fields given as (field,
// value) pairs, size-prefixed.
func varints(fields ...[2]uint64) []byte {
	var m []byte
	for _, f := range fields {
		m = binary.AppendUvarint(m, f[0]<<3)
		m = binary.AppendUvarint(m, f[1])
	}
	return sized(m)
}

// entryMsg is the pagemap entry message for e.
func entryMsg(e criu.PagemapEntry) []byte {
	return varints([2]uint64{1, e.VAddr}, [2]uint64{2, uint64(e.NrPages)}, [2]uint64{4, uint64(e.Flags)})
}

// pagemapImage encodes a whole pagemap image, header, head and entries.
func pagemapImage(pagesID uint32, entries []criu.PagemapEntry) []byte {
	out := append([]byte{}, header...)
	out = append(out, varints([2]uint64{1, uint64(pagesID)})...)
	for _, e := range entries {
		out = append(out, entryMsg(e)...)
	}
	return out
}

// page is one page filled with b.
func page(b byte) []byte { return bytes.Repeat([]byte{b}, int(criu.PageSize)) }

// checkpoint is one task's images: its entries and, for the present
// ones, their pages in order. The pages file id is the pid.
type checkpoint struct {
	pid     int
	entries []criu.PagemapEntry
	pages   [][]byte
}

func (c checkpoint) pagemap(dir string) string {
	return filepath.Join(dir, fmt.Sprintf("pagemap-%d.img", c.pid))
}

func (c checkpoint) pagesFile(dir string) string {
	return filepath.Join(dir, fmt.Sprintf("pages-%d.img", c.pid))
}

func (c checkpoint) write(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(c.pagemap(dir), pagemapImage(uint32(c.pid), c.entries), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.pagesFile(dir), bytes.Join(c.pages, nil), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

// present and lazy are the entry shapes the tests use.
func present(addr uint64, n uint32) criu.PagemapEntry {
	return criu.PagemapEntry{VAddr: addr, NrPages: n, Flags: criu.PEPresent}
}

func lazy(addr uint64, n uint32) criu.PagemapEntry {
	return criu.PagemapEntry{VAddr: addr, NrPages: n, Flags: criu.PELazy}
}

func inParent(addr uint64, n uint32) criu.PagemapEntry {
	return criu.PagemapEntry{VAddr: addr, NrPages: n, Flags: criu.PEParent}
}

// va is the address of page n. The delta code walks the images at the
// host's page size, which differs between machines.
func va(n uint64) uint64 { return n * criu.PageSize }

// zygote is the parent checkpoint every delta test builds on: pages a,
// b and c at pages 1, 2 and 3, and a lazy run at page 9.
var zygote = checkpoint{pid: 1,
	entries: []criu.PagemapEntry{present(va(1), 3), lazy(va(9), 1)},
	pages:   [][]byte{page('a'), page('b'), page('c')}}

// bufferPages is how many pages fill the 1 MiB the delta code buffers
// before it writes anything.
var bufferPages = int(1 << 20 / criu.PageSize)

// bulk is a checkpoint of n present pages from addr on, all filled with b.
func bulk(pid int, addr uint64, n int, b byte) checkpoint {
	c := checkpoint{pid: pid, entries: []criu.PagemapEntry{present(addr, uint32(n))}}
	for range n {
		c.pages = append(c.pages, page(b))
	}
	return c
}

// linkFull puts /dev/full, which refuses every write with ENOSPC, where
// the delta code will create its temporary pages file.
func linkFull(t *testing.T, path string) {
	t.Helper()
	if err := os.Symlink("/dev/full", path); err != nil {
		t.Fatal(err)
	}
}

// loadZygote writes and loads the parent.
func loadZygote(t *testing.T) *criu.Parent {
	t.Helper()
	dir := t.TempDir()
	zygote.write(t, dir)
	p, err := criu.LoadParent(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

// TestReadPagemap: the head's pages id and every entry come out of a
// well-formed image, unknown fields are skipped, and each way an image
// can be cut short or malformed is named.
func TestReadPagemap(t *testing.T) {
	entries := []criu.PagemapEntry{present(0x1000, 2), inParent(0x5000, 1), {VAddr: 0x7000, NrPages: 4, Flags: criu.PELazy | criu.PEPresent}}
	cases := []struct {
		name    string
		image   []byte // nil for a missing file
		pagesID uint32
		entries []criu.PagemapEntry
		wantErr string
		wantIs  error
	}{
		{name: "head and entries", image: pagemapImage(3, entries), pagesID: 3, entries: entries},
		{name: "head only", image: pagemapImage(9, nil), pagesID: 9},
		{name: "unknown fields of every wire type are skipped",
			image: slices.Concat(header, varints([2]uint64{1, 3}),
				sized(slices.Concat(
					[]byte{0x3a, 0x02, 0xaa, 0xbb},       // field 7, length-delimited
					[]byte{0x41, 1, 2, 3, 4, 5, 6, 7, 8}, // field 8, fixed64
					[]byte{0x4d, 1, 2, 3, 4},             // field 9, fixed32
					varints([2]uint64{1, 0x1000}, [2]uint64{2, 1}, [2]uint64{4, criu.PEPresent})[4:]))),
			pagesID: 3, entries: []criu.PagemapEntry{present(0x1000, 1)}},
		{name: "an empty head reads as pages id 0", image: slices.Concat(header, sized(nil))},
		{name: "missing file", wantIs: fs.ErrNotExist},
		{name: "short header", image: header[:5], wantErr: "short header"},
		{name: "truncated entry size", image: slices.Concat(header, []byte{1, 0}), wantErr: "truncated entry size"},
		{name: "truncated entry", image: slices.Concat(header, []byte{10, 0, 0, 0, 1, 2, 3}), wantErr: "truncated entry"},
		{name: "bad protobuf key", image: slices.Concat(header, sized([]byte{0x80})), wantErr: "bad protobuf key"},
		{name: "bad varint", image: slices.Concat(header, sized([]byte{0x08, 0x80})), wantErr: "bad varint"},
		{name: "bad length-delimited field", image: slices.Concat(header, sized([]byte{0x0a, 0x05, 0x01})), wantErr: "bad length-delimited field"},
		{name: "bad fixed64", image: slices.Concat(header, sized([]byte{0x09, 0x01})), wantErr: "bad fixed64"},
		{name: "bad fixed32", image: slices.Concat(header, sized([]byte{0x0d, 0x01})), wantErr: "bad fixed32"},
		{name: "unsupported wire type", image: slices.Concat(header, sized([]byte{0x0b})), wantErr: "unsupported wire type 3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "pagemap-42.img")
			if tc.image != nil {
				mustWrite(t, path, tc.image)
			}
			pm, err := criu.ReadPagemap(path)
			switch {
			case tc.wantIs != nil:
				if !errors.Is(err, tc.wantIs) {
					t.Fatalf("ReadPagemap = %v, want %v", err, tc.wantIs)
				}
				return
			case tc.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !strings.Contains(err.Error(), path) {
					t.Fatalf("ReadPagemap = %v, want an error naming %s and %q", err, path, tc.wantErr)
				}
				return
			case err != nil:
				t.Fatal(err)
			}
			if pm.Path != path || !bytes.Equal(pm.Header, header) || pm.PagesID != tc.pagesID {
				t.Fatalf("ReadPagemap = path %s header %x id %d, want %s %x %d", pm.Path, pm.Header, pm.PagesID, path, header, tc.pagesID)
			}
			if !slices.Equal(pm.Entries, tc.entries) {
				t.Fatalf("entries = %+v, want %+v", pm.Entries, tc.entries)
			}
			if want := filepath.Join(dir, fmt.Sprintf("pages-%d.img", tc.pagesID)); pm.PagesFile() != want {
				t.Fatalf("PagesFile = %s, want %s", pm.PagesFile(), want)
			}
		})
	}
}

// TestFindPagemaps: the pagemap images of a directory, sorted, and the
// one way the lookup itself can fail.
func TestFindPagemaps(t *testing.T) {
	cases := []struct {
		name   string
		files  []string
		subdir string // the dump directory's name under the temp dir
		want   []string
		wantIs error
	}{
		{name: "pagemaps only, sorted", files: []string{"pagemap-20.img", "pages-20.img", "pagemap-100.img", "mm-20.img", "pagemap.img"},
			want: []string{"pagemap-100.img", "pagemap-20.img"}},
		{name: "none"},
		{name: "a directory name that is a bad pattern", subdir: "a[", wantIs: filepath.ErrBadPattern},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), tc.subdir)
			mustMkdir(t, dir)
			for _, f := range tc.files {
				mustWrite(t, filepath.Join(dir, f), nil)
			}
			got, err := criu.FindPagemaps(dir)
			if tc.wantIs != nil {
				if !errors.Is(err, tc.wantIs) {
					t.Fatalf("FindPagemaps = %v, want %v", err, tc.wantIs)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var want []string
			for _, f := range tc.want {
				want = append(want, filepath.Join(dir, f))
			}
			if !slices.Equal(got, want) {
				t.Fatalf("FindPagemaps = %q, want %q", got, want)
			}
		})
	}
}

// TestLoadParent: a parent is identified by the hash of its pages files
// in name order, an empty one maps nothing, and every way its images
// can be missing, cut short or unmappable is an error.
func TestLoadParent(t *testing.T) {
	two := []checkpoint{
		{pid: 100, entries: []criu.PagemapEntry{present(va(1), 1)}, pages: [][]byte{page('x')}},
		{pid: 20, entries: []criu.PagemapEntry{present(va(2), 2)}, pages: [][]byte{page('y'), page('z')}},
	}
	cases := []struct {
		name    string
		subdir  string // the parent directory's name under the temp dir
		setup   func(t *testing.T, dir string)
		wantSHA string // hex; "" when the setup fails
		wantErr string
		wantIs  error
	}{
		{name: "one task", setup: func(t *testing.T, dir string) { zygote.write(t, dir) },
			wantSHA: hexSHA(bytes.Join(zygote.pages, nil))},
		{name: "two tasks hashed in file name order", setup: func(t *testing.T, dir string) {
			for _, c := range two {
				c.write(t, dir)
			}
		}, wantSHA: hexSHA(slices.Concat(page('x'), page('y'), page('z')))},
		{name: "no present pages", setup: func(t *testing.T, dir string) {
			checkpoint{pid: 1, entries: []criu.PagemapEntry{lazy(va(1), 4)}}.write(t, dir)
		}, wantSHA: hexSHA(nil)},
		{name: "no pagemap", setup: func(*testing.T, string) {}, wantErr: "no pagemap in parent"},
		{name: "pagemap lookup fails", subdir: "a[", setup: func(*testing.T, string) {}, wantErr: "no pagemap in parent"},
		{name: "corrupt pagemap", setup: func(t *testing.T, dir string) {
			mustWrite(t, filepath.Join(dir, "pagemap-1.img"), header[:3])
		}, wantErr: "short header"},
		{name: "missing pages file", setup: func(t *testing.T, dir string) {
			mustWrite(t, zygote.pagemap(dir), pagemapImage(1, zygote.entries))
		}, wantIs: fs.ErrNotExist},
		{name: "pages file is not mappable", setup: func(t *testing.T, dir string) {
			mustWrite(t, zygote.pagemap(dir), pagemapImage(1, zygote.entries))
			mustMkdir(t, zygote.pagesFile(dir))
			mustWrite(t, filepath.Join(zygote.pagesFile(dir), "gives-the-directory-a-size"), nil)
		}, wantErr: "mmap"},
		{name: "pages file shorter than its pagemap", setup: func(t *testing.T, dir string) {
			c := zygote
			c.pages = c.pages[:2]
			c.write(t, dir)
		}, wantErr: "shorter than its pagemap"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), tc.subdir)
			mustMkdir(t, dir)
			tc.setup(t, dir)
			p, err := criu.LoadParent(dir)
			switch {
			case tc.wantIs != nil:
				if !errors.Is(err, tc.wantIs) {
					t.Fatalf("LoadParent = %v, want %v", err, tc.wantIs)
				}
				return
			case tc.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("LoadParent = %v, want an error containing %q", err, tc.wantErr)
				}
				return
			case err != nil:
				t.Fatal(err)
			}
			defer p.Close()
			if p.Dir != dir || p.SHA256() != tc.wantSHA {
				t.Fatalf("LoadParent = dir %s sha %s, want %s %s", p.Dir, p.SHA256(), dir, tc.wantSHA)
			}
			p.Close() // a second Close is harmless
		})
	}
}

func hexSHA(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestDeltaInfo: delta.json is what tells a delta from a checkpoint,
// and it reads back or fails by name.
func TestDeltaInfo(t *testing.T) {
	info := criu.DeltaInfo{PageSize: 4096, ParentSHA256: "ab", TotalPages: 10, KeptPages: 3, Files: []string{"pagemap-1.img"}}
	cases := []struct {
		name     string
		contents string // of delta.json; "" for none
		asDir    bool   // delta.json is a directory
		want     criu.DeltaInfo
		hasDelta bool
		wantIs   error
		wantErr  bool
	}{
		{name: "a delta", contents: mustJSON(t, info), want: info, hasDelta: true},
		{name: "a full checkpoint", wantIs: fs.ErrNotExist},
		{name: "corrupt", contents: "{", hasDelta: true, wantErr: true},
		{name: "unreadable", asDir: true, hasDelta: true, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.contents != "" {
				mustWrite(t, filepath.Join(dir, "delta.json"), []byte(tc.contents))
			}
			if tc.asDir {
				mustMkdir(t, filepath.Join(dir, "delta.json"))
			}
			if got := criu.HasDelta(dir); got != tc.hasDelta {
				t.Fatalf("HasDelta = %v, want %v", got, tc.hasDelta)
			}
			got, err := criu.ReadDeltaInfo(dir)
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("ReadDeltaInfo = %v, want %v", err, tc.wantIs)
			}
			if tc.wantErr && err == nil {
				t.Fatal("ReadDeltaInfo = nil, want an error")
			}
			if err != nil {
				return
			}
			if !slices.Equal(got.Files, tc.want.Files) || got.PageSize != tc.want.PageSize || got.ParentSHA256 != tc.want.ParentSHA256 ||
				got.TotalPages != tc.want.TotalPages || got.KeptPages != tc.want.KeptPages {
				t.Fatalf("ReadDeltaInfo = %+v, want %+v", got, tc.want)
			}
			if got.DeltaBytes() != tc.want.KeptPages*tc.want.PageSize {
				t.Fatalf("DeltaBytes = %d, want %d", got.DeltaBytes(), tc.want.KeptPages*tc.want.PageSize)
			}
		})
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestComputeDelta: pages equal to the parent's at the same address are
// dropped and marked, the rest are kept in order, runs are split and
// re-merged, and the delta records what it covers. Each way the images
// can be unusable is an error that leaves no temporary file behind.
func TestComputeDelta(t *testing.T) {
	cases := []struct {
		name        string
		children    []checkpoint
		setup       func(t *testing.T, dir string) // instead of, or after, writing the children
		total, kept uint64
		wantEntries []criu.PagemapEntry // of the first child
		wantPages   []byte              // its pages file afterwards
		linux       bool                // needs /dev/full or a sealed memfd
		wantErr     string
		wantIs      error
		orIs        error // another errno the same failure has elsewhere
	}{
		{name: "identical to the parent", children: []checkpoint{{pid: 5, entries: zygote.entries, pages: zygote.pages}},
			total: 3, kept: 0, wantEntries: []criu.PagemapEntry{inParent(va(1), 3), lazy(va(9), 1)}},
		{name: "nothing shared", children: []checkpoint{{pid: 5, entries: []criu.PagemapEntry{present(va(1), 2)}, pages: [][]byte{page('p'), page('q')}}},
			total: 2, kept: 2, wantEntries: []criu.PagemapEntry{present(va(1), 2)}, wantPages: slices.Concat(page('p'), page('q'))},
		{name: "runs split where pages differ", children: []checkpoint{{pid: 5,
			entries: []criu.PagemapEntry{present(va(1), 4), lazy(va(9), 1)},
			pages:   [][]byte{page('a'), page('x'), page('c'), page('d')}}},
			total: 4, kept: 2,
			wantEntries: []criu.PagemapEntry{inParent(va(1), 1), present(va(2), 1), inParent(va(3), 1), present(va(4), 1), lazy(va(9), 1)},
			wantPages:   slices.Concat(page('x'), page('d'))},
		{name: "runs merged across the original entries", children: []checkpoint{{pid: 5,
			entries: []criu.PagemapEntry{present(va(1), 3), present(va(4), 1)},
			pages:   [][]byte{page('a'), page('b'), page('x'), page('y')}}},
			total: 4, kept: 2,
			wantEntries: []criu.PagemapEntry{inParent(va(1), 2), present(va(3), 2)},
			wantPages:   slices.Concat(page('x'), page('y'))},
		{name: "other flags survive the drop", children: []checkpoint{{pid: 5,
			entries: []criu.PagemapEntry{{VAddr: va(1), NrPages: 1, Flags: criu.PEPresent | criu.PELazy}},
			pages:   [][]byte{page('a')}}},
			total: 1, kept: 0, wantEntries: []criu.PagemapEntry{{VAddr: va(1), NrPages: 1, Flags: criu.PEParent | criu.PELazy}}},
		{name: "two tasks", children: []checkpoint{
			{pid: 5, entries: []criu.PagemapEntry{present(va(1), 1)}, pages: [][]byte{page('a')}},
			{pid: 6, entries: []criu.PagemapEntry{present(va(2), 1)}, pages: [][]byte{page('z')}}},
			total: 2, kept: 1, wantEntries: []criu.PagemapEntry{inParent(va(1), 1)}},
		{name: "no pagemap", setup: func(*testing.T, string) {}, wantErr: "no pagemap in"},
		{name: "corrupt pagemap", setup: func(t *testing.T, dir string) {
			mustWrite(t, filepath.Join(dir, "pagemap-5.img"), header[:2])
		}, wantErr: "short header"},
		{name: "missing pages file", setup: func(t *testing.T, dir string) {
			mustWrite(t, filepath.Join(dir, "pagemap-5.img"), pagemapImage(5, []criu.PagemapEntry{present(va(1), 1)}))
		}, wantIs: fs.ErrNotExist},
		{name: "temporary pages file blocked", children: []checkpoint{{pid: 5, entries: []criu.PagemapEntry{present(va(1), 1)}, pages: [][]byte{page('a')}}},
			setup:  func(t *testing.T, dir string) { mustMkdir(t, filepath.Join(dir, "pages-5.img.tmp")) },
			wantIs: syscall.EISDIR},
		{name: "pages file shorter than its pagemap", children: []checkpoint{{pid: 5, entries: []criu.PagemapEntry{present(va(1), 2)}, pages: [][]byte{page('a')}}},
			wantErr: "shorter than its pagemap"},
		{name: "delta.json cannot be written", children: []checkpoint{{pid: 5, entries: []criu.PagemapEntry{present(va(1), 1)}, pages: [][]byte{page('a')}}},
			setup:  func(t *testing.T, dir string) { mustMkdir(t, filepath.Join(dir, "delta.json")) },
			wantIs: syscall.EISDIR},
		{name: "disk full when the kept pages are flushed", linux: true,
			children: []checkpoint{{pid: 5, entries: []criu.PagemapEntry{present(va(1), 1)}, pages: [][]byte{page('q')}}},
			setup:    func(t *testing.T, dir string) { linkFull(t, filepath.Join(dir, "pages-5.img.tmp")) },
			wantIs:   syscall.ENOSPC},
		{name: "disk full while the kept pages are written", linux: true,
			children: []checkpoint{bulk(5, va(0x100), bufferPages+2, 'q')},
			setup:    func(t *testing.T, dir string) { linkFull(t, filepath.Join(dir, "pages-5.img.tmp")) },
			wantIs:   syscall.ENOSPC},
		{name: "pages file replaced by a directory", setup: func(t *testing.T, dir string) {
			mustWrite(t, filepath.Join(dir, "pagemap-5.img"), pagemapImage(5, []criu.PagemapEntry{lazy(va(1), 1)}))
			mustMkdir(t, filepath.Join(dir, "pages-5.img"))
		}, wantIs: syscall.EISDIR, orIs: syscall.EEXIST},
		{name: "pagemap that cannot be rewritten", linux: true, setup: func(t *testing.T, dir string) {
			sealedFile(t, filepath.Join(dir, "pagemap-5.img"), pagemapImage(5, []criu.PagemapEntry{present(va(1), 1)}))
			mustWrite(t, filepath.Join(dir, "pages-5.img"), page('a'))
		}, wantIs: syscall.EPERM},
	}
	parent := loadZygote(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.linux && runtime.GOOS != "linux" {
				t.Skip("needs Linux")
			}
			dir := t.TempDir()
			for _, c := range tc.children {
				c.write(t, dir)
			}
			if tc.setup != nil {
				tc.setup(t, dir)
			}
			info, err := criu.ComputeDelta(dir, parent)
			switch {
			case tc.wantIs != nil:
				if !errors.Is(err, tc.wantIs) && (tc.orIs == nil || !errors.Is(err, tc.orIs)) {
					t.Fatalf("ComputeDelta = %v, want %v", err, tc.wantIs)
				}
			case tc.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("ComputeDelta = %v, want an error containing %q", err, tc.wantErr)
				}
			case err != nil:
				t.Fatal(err)
			}
			if err != nil {
				if left, _ := filepath.Glob(filepath.Join(dir, "pages-*.img.tmp")); len(left) > 0 && !strings.Contains(tc.name, "blocked") {
					t.Fatalf("temporary files left behind: %q", left)
				}
				return
			}
			var files []string
			for _, c := range tc.children {
				files = append(files, filepath.Base(c.pagemap(dir)))
			}
			slices.Sort(files)
			if info.PageSize != criu.PageSize || info.ParentSHA256 != parent.SHA256() || info.TotalPages != tc.total ||
				info.KeptPages != tc.kept || !slices.Equal(info.Files, files) {
				t.Fatalf("ComputeDelta = %+v, want page size %d parent %s total %d kept %d files %q",
					info, criu.PageSize, parent.SHA256(), tc.total, tc.kept, files)
			}
			if stored, err := criu.ReadDeltaInfo(dir); err != nil || !slices.Equal(stored.Files, info.Files) || stored.KeptPages != info.KeptPages {
				t.Fatalf("delta.json = %+v, %v, want %+v", stored, err, info)
			}
			c := tc.children[0]
			pm, err := criu.ReadPagemap(c.pagemap(dir))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(pm.Header, header) || pm.PagesID != uint32(c.pid) || !slices.Equal(pm.Entries, tc.wantEntries) {
				t.Fatalf("pagemap after = header %x id %d entries %+v, want %x %d %+v", pm.Header, pm.PagesID, pm.Entries, header, c.pid, tc.wantEntries)
			}
			if got, err := os.ReadFile(c.pagesFile(dir)); err != nil || !bytes.Equal(got, tc.wantPages) {
				t.Fatalf("pages file after = %d bytes, %v, want %d bytes of the kept pages", len(got), err, len(tc.wantPages))
			}
		})
	}
}

// TestMergeDelta: a delta merged with its parent is the checkpoint it
// was computed from, byte for byte, and a delta is refused with a
// parent that is not the one it names.
func TestMergeDelta(t *testing.T) {
	child := checkpoint{pid: 5,
		entries: []criu.PagemapEntry{present(va(1), 4), lazy(va(9), 1)},
		pages:   [][]byte{page('a'), page('x'), page('c'), page('d')}}
	// delta writes a hand-made delta over the parent: the sidecar names
	// files, and the pagemap and pages given stand for pid 5.
	delta := func(t *testing.T, dir, sha string, files []string, entries []criu.PagemapEntry, pages []byte) {
		t.Helper()
		mustWrite(t, filepath.Join(dir, "delta.json"), []byte(mustJSON(t, criu.DeltaInfo{PageSize: criu.PageSize, ParentSHA256: sha, Files: files})))
		if entries != nil {
			mustWrite(t, filepath.Join(dir, "pagemap-5.img"), pagemapImage(5, entries))
		}
		if pages != nil {
			mustWrite(t, filepath.Join(dir, "pages-5.img"), pages)
		}
	}
	cases := []struct {
		name        string
		setup       func(t *testing.T, dir string, parent *criu.Parent)
		wantEntries []criu.PagemapEntry
		wantPages   []byte
		linux       bool // needs /dev/full or a sealed memfd
		wantErr     string
		wantNot     string // what the error must not say
		wantIs      error
		orIs        error // another errno the same failure has elsewhere
	}{
		{name: "round trip", setup: func(t *testing.T, dir string, parent *criu.Parent) {
			child.write(t, dir)
			if _, err := criu.ComputeDelta(dir, parent); err != nil {
				t.Fatal(err)
			}
		}, wantEntries: []criu.PagemapEntry{present(va(1), 1), present(va(2), 1), present(va(3), 1), present(va(4), 1), lazy(va(9), 1)},
			wantPages: bytes.Join(child.pages, nil)},
		{name: "not a delta", setup: func(t *testing.T, dir string, _ *criu.Parent) { child.write(t, dir) }, wantIs: fs.ErrNotExist},
		{name: "corrupt delta.json", setup: func(t *testing.T, dir string, _ *criu.Parent) {
			mustWrite(t, filepath.Join(dir, "delta.json"), []byte("{"))
		}, wantErr: "unexpected end of JSON"},
		{name: "another parent", setup: func(t *testing.T, dir string, _ *criu.Parent) {
			delta(t, dir, "abc", nil, nil, nil)
		}, wantIs: criu.ErrParentMismatch, wantErr: "delta parent abc, offered " + hexSHA(bytes.Join(zygote.pages, nil))[:12]},
		{name: "a pagemap the delta names is missing", setup: func(t *testing.T, dir string, p *criu.Parent) {
			delta(t, dir, p.SHA256(), []string{"pagemap-5.img"}, nil, nil)
		}, wantIs: fs.ErrNotExist},
		{name: "missing pages file", setup: func(t *testing.T, dir string, p *criu.Parent) {
			delta(t, dir, p.SHA256(), []string{"pagemap-5.img"}, []criu.PagemapEntry{inParent(va(1), 1)}, nil)
		}, wantIs: fs.ErrNotExist},
		{name: "temporary pages file blocked", setup: func(t *testing.T, dir string, p *criu.Parent) {
			delta(t, dir, p.SHA256(), []string{"pagemap-5.img"}, []criu.PagemapEntry{inParent(va(1), 1)}, []byte{})
			mustMkdir(t, filepath.Join(dir, "pages-5.img.tmp"))
		}, wantIs: syscall.EISDIR},
		{name: "delta pages file shorter than its pagemap", setup: func(t *testing.T, dir string, p *criu.Parent) {
			delta(t, dir, p.SHA256(), []string{"pagemap-5.img"}, []criu.PagemapEntry{present(va(1), 2)}, page('q'))
		}, wantErr: "delta pages file", wantIs: nil},
		{name: "parent lacks a page the delta needs", setup: func(t *testing.T, dir string, p *criu.Parent) {
			delta(t, dir, p.SHA256(), []string{"pagemap-5.img"}, []criu.PagemapEntry{inParent(va(1), 1), inParent(va(7), 1)}, []byte{})
		}, wantErr: fmt.Sprintf("parent lacks page %#x", va(7))},
		{name: "disk full while a kept page is copied", linux: true, setup: func(t *testing.T, dir string, p *criu.Parent) {
			// The pages file is whole. Only the write fails, and the
			// error must not blame the delta for being short.
			delta(t, dir, p.SHA256(), []string{"pagemap-5.img"}, []criu.PagemapEntry{present(va(1), uint32(bufferPages+1))}, bytes.Repeat(page('q'), bufferPages+1))
			linkFull(t, filepath.Join(dir, "pages-5.img.tmp"))
		}, wantIs: syscall.ENOSPC, wantNot: "shorter"},
		{name: "disk full when a parent page is flushed", linux: true, setup: func(t *testing.T, dir string, p *criu.Parent) {
			delta(t, dir, p.SHA256(), []string{"pagemap-5.img"}, []criu.PagemapEntry{inParent(va(1), 1)}, []byte{})
			linkFull(t, filepath.Join(dir, "pages-5.img.tmp"))
		}, wantIs: syscall.ENOSPC},
		{name: "disk full while the parent's pages are written", linux: true, setup: func(t *testing.T, dir string, p *criu.Parent) {
			entries := slices.Repeat([]criu.PagemapEntry{inParent(va(1), 3)}, bufferPages/3+1)
			delta(t, dir, p.SHA256(), []string{"pagemap-5.img"}, entries, []byte{})
			linkFull(t, filepath.Join(dir, "pages-5.img.tmp"))
		}, wantIs: syscall.ENOSPC},
		{name: "pages file replaced by a directory", setup: func(t *testing.T, dir string, p *criu.Parent) {
			delta(t, dir, p.SHA256(), []string{"pagemap-5.img"}, []criu.PagemapEntry{lazy(va(1), 1)}, nil)
			mustMkdir(t, filepath.Join(dir, "pages-5.img"))
		}, wantIs: syscall.EISDIR, orIs: syscall.EEXIST},
		{name: "pagemap that cannot be rewritten", linux: true, setup: func(t *testing.T, dir string, p *criu.Parent) {
			delta(t, dir, p.SHA256(), []string{"pagemap-5.img"}, nil, []byte{})
			sealedFile(t, filepath.Join(dir, "pagemap-5.img"), pagemapImage(5, []criu.PagemapEntry{lazy(va(1), 1)}))
		}, wantIs: syscall.EPERM},
	}
	parent := loadZygote(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.linux && runtime.GOOS != "linux" {
				t.Skip("needs Linux")
			}
			dir := t.TempDir()
			tc.setup(t, dir, parent)
			err := criu.MergeDelta(dir, parent)
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) && (tc.orIs == nil || !errors.Is(err, tc.orIs)) {
				t.Fatalf("MergeDelta = %v, want %v", err, tc.wantIs)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("MergeDelta = %v, want an error containing %q", err, tc.wantErr)
			}
			if tc.wantNot != "" && err != nil && strings.Contains(err.Error(), tc.wantNot) {
				t.Fatalf("MergeDelta = %v, must not say %q", err, tc.wantNot)
			}
			if tc.wantIs != nil || tc.wantErr != "" {
				if left, _ := filepath.Glob(filepath.Join(dir, "pages-*.img.tmp")); len(left) > 0 && !strings.Contains(tc.name, "blocked") {
					t.Fatalf("temporary files left behind: %q", left)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if criu.HasDelta(dir) {
				t.Fatal("delta.json still there after the merge")
			}
			pm, err := criu.ReadPagemap(child.pagemap(dir))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(pm.Entries, tc.wantEntries) {
				t.Fatalf("entries = %+v, want %+v", pm.Entries, tc.wantEntries)
			}
			if got, err := os.ReadFile(child.pagesFile(dir)); err != nil || !bytes.Equal(got, tc.wantPages) {
				t.Fatalf("pages after the merge differ from the original (%d bytes, %v)", len(got), err)
			}
		})
	}
}
