package wsfs

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"testing"
)

// tarEntry is one entry a test puts in an archive.
type tarEntry struct {
	name string
	typ  byte
	body string
	link string
	mode int64
}

// makeTar writes entries as a tar stream. A regular entry's size is its
// body's length unless size is set.
func makeTar(t testing.TB, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}
		hdr := &tar.Header{Name: e.name, Typeflag: typ, Mode: mode, Linkname: e.link}
		if typ == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := io.WriteString(tw, e.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// hugeTar is a one byte file followed by a file whose header declares
// math.MaxInt64 bytes with a 4 MiB body behind it. A reader that adds
// sizes wraps the sum and admits it.
func hugeTar(t testing.TB) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "a", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "big", Typeflag: tar.TypeReg, Mode: 0o644, Size: math.MaxInt64, Format: tar.FormatPAX}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(make([]byte, 4<<20)); err != nil {
		t.Fatal(err)
	}
	// No Close, which would refuse the short body.
	return buf.Bytes()
}

// manyEntries streams n empty directory headers without holding them
// all in memory.
func manyEntries(n int) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		tw := tar.NewWriter(pw)
		for i := range n {
			if err := tw.WriteHeader(&tar.Header{Name: "d" + strconv.Itoa(i) + "/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
				break
			}
		}
		_ = tw.Close()
		_ = pw.Close()
	}()
	return pr
}

func TestReadArchive(t *testing.T) {
	cases := []struct {
		name    string
		entries []tarEntry
		stream  io.Reader
		limits  Limits
		// zeroBytes keeps Limits.Bytes at zero instead of the test's
		// default.
		zeroBytes bool
		want      []string
		wantErr   error
	}{
		{
			name:    "files and dirs",
			entries: []tarEntry{{name: "d/", typ: tar.TypeDir}, {name: "d/f", body: "hello"}, {name: "g", body: ""}},
			want:    []string{"d", "d/f", "g"},
		},
		{
			name:    "symlink carried as a string",
			entries: []tarEntry{{name: "s", typ: tar.TypeSymlink, link: "/etc/passwd"}},
			want:    []string{"s"},
		},
		{
			name:    "hard link to an earlier file",
			entries: []tarEntry{{name: "a", body: "x"}, {name: "b", typ: tar.TypeLink, link: "a"}},
			want:    []string{"a", "b"},
		},
		{name: "dot dot", entries: []tarEntry{{name: "../x", body: "x"}}, wantErr: ErrArchive},
		{name: "dot dot inside", entries: []tarEntry{{name: "a/../x", body: "x"}}, wantErr: ErrArchive},
		{name: "absolute", entries: []tarEntry{{name: "/etc/x", body: "x"}}, wantErr: ErrArchive},
		{name: "too long", entries: []tarEntry{{name: strings.Repeat("a", MaxPathBytes+1), body: "x"}}, wantErr: ErrArchive},
		{name: "too deep", entries: []tarEntry{{name: strings.Repeat("a/", MaxDepth) + "a", body: "x"}}, wantErr: ErrArchive},
		{name: "dot", entries: []tarEntry{{name: ".", typ: tar.TypeDir}}, wantErr: ErrArchive},
		{name: "hard link out", entries: []tarEntry{{name: "a", body: "x"}, {name: "b", typ: tar.TypeLink, link: "../a"}}, wantErr: ErrArchive},
		{name: "hard link absolute", entries: []tarEntry{{name: "b", typ: tar.TypeLink, link: "/etc/passwd"}}, wantErr: ErrArchive},
		{name: "hard link to a later file", entries: []tarEntry{{name: "b", typ: tar.TypeLink, link: "a"}, {name: "a", body: "x"}}, wantErr: ErrArchive},
		{name: "hard link to a symlink", entries: []tarEntry{{name: "s", typ: tar.TypeSymlink, link: "/etc"}, {name: "b", typ: tar.TypeLink, link: "s"}}, wantErr: ErrArchive},
		{name: "hard link to a dir", entries: []tarEntry{{name: "d/", typ: tar.TypeDir}, {name: "b", typ: tar.TypeLink, link: "d"}}, wantErr: ErrArchive},
		{name: "symlink empty target", entries: []tarEntry{{name: "s", typ: tar.TypeSymlink, link: ""}}, wantErr: ErrArchive},
		{name: "fifo", entries: []tarEntry{{name: "p", typ: tar.TypeFifo}}, wantErr: ErrArchive},
		{name: "char device", entries: []tarEntry{{name: "c", typ: tar.TypeChar}}, wantErr: ErrArchive},
		{name: "block device", entries: []tarEntry{{name: "b", typ: tar.TypeBlock}}, wantErr: ErrArchive},
		{name: "too many entries", entries: []tarEntry{{name: "a", body: ""}, {name: "b", body: ""}, {name: "c", body: ""}}, limits: Limits{Entries: 2}, wantErr: ErrEntries},
		{name: "huge entry count", stream: manyEntries(DefaultEntries + 1), wantErr: ErrEntries},
		{name: "too many bytes", entries: []tarEntry{{name: "a", body: "12345"}, {name: "b", body: "678"}}, limits: Limits{Bytes: 7}, wantErr: ErrTooLarge},
		{name: "bytes at the limit", entries: []tarEntry{{name: "a", body: "12345"}, {name: "b", body: "678"}}, limits: Limits{Bytes: 8}, want: []string{"a", "b"}},
		{name: "zero bytes refuses any file byte", entries: []tarEntry{{name: "a", body: "x"}}, zeroBytes: true, wantErr: ErrTooLarge},
		{name: "zero bytes passes empty files", entries: []tarEntry{{name: "d/", typ: tar.TypeDir}, {name: "a", body: ""}}, zeroBytes: true, want: []string{"d", "a"}},
		{name: "declared size near the maximum", stream: bytes.NewReader(hugeTar(t)), limits: Limits{Bytes: 1 << 20}, wantErr: ErrTooLarge},
		{name: "garbage", stream: strings.NewReader(strings.Repeat("not a tar", 100)), wantErr: ErrArchive},
		{name: "truncated body", stream: bytes.NewReader(makeTar(t, tarEntry{name: "a", body: strings.Repeat("x", 2000)})[:700]), wantErr: ErrArchive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.stream
			if in == nil {
				in = bytes.NewReader(makeTar(t, tc.entries...))
			}
			limits := tc.limits
			if limits.Bytes == 0 && !tc.zeroBytes {
				limits.Bytes = 1 << 20
			}
			var got []string
			err := readArchive(in, limits, func(e entry) error {
				got = append(got, e.Path)
				if e.Body != nil {
					// A read error is left for the reader to report, as
					// the unpacker leaves it.
					b, err := io.ReadAll(e.Body)
					if err == nil && int64(len(b)) != e.Size {
						t.Errorf("%s: body of %d bytes, size %d", e.Path, len(b), e.Size)
					}
				}
				return nil
			})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("readArchive = %v, want %v (entries %v)", err, tc.wantErr, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("readArchive: %v", err)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("entries %v, want %v", got, tc.want)
			}
		})
	}
}

// TestReadArchiveSinkError checks that the sink's error comes back as
// it is, and that a sink which does not read the body leaves the
// stream positioned at the next header.
func TestReadArchiveSinkError(t *testing.T) {
	stop := errors.New("stop")
	in := makeTar(t, tarEntry{name: "a", body: "12345"}, tarEntry{name: "b", body: "678"})
	var seen []string
	err := readArchive(bytes.NewReader(in), Limits{Bytes: 1 << 20}, func(e entry) error {
		seen = append(seen, e.Path)
		if e.Path == "b" {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) || len(seen) != 2 {
		t.Fatalf("err %v, seen %v", err, seen)
	}
}

// FuzzArchive runs the archive reader over arbitrary bytes. It must
// never panic, and every entry it hands out must pass the path rules
// and read no more than its size.
func FuzzArchive(f *testing.F) {
	f.Add(makeTar(f, tarEntry{name: "d/", typ: tar.TypeDir}, tarEntry{name: "d/f", body: "hello"}, tarEntry{name: "l", typ: tar.TypeLink, link: "d/f"}, tarEntry{name: "s", typ: tar.TypeSymlink, link: "d/f"}))
	f.Add(makeTar(f, tarEntry{name: "../x", body: "x"}))
	f.Add(makeTar(f, tarEntry{name: "a", body: strings.Repeat("x", 600)})[:800])
	f.Add([]byte("not a tar at all"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		limits := Limits{Bytes: 1 << 16, Entries: 64}
		var entries, total int64
		err := readArchive(bytes.NewReader(b), limits, func(e entry) error {
			entries++
			if _, err := Clean(e.Path, false); err != nil {
				t.Fatalf("entry %q passed: %v", e.Path, err)
			}
			switch e.Type {
			case tar.TypeDir, tar.TypeReg, tar.TypeSymlink, tar.TypeLink:
			default:
				t.Fatalf("entry %q of type %q passed", e.Path, e.Type)
			}
			if e.Type == tar.TypeLink {
				if _, err := Clean(e.Linkname, false); err != nil {
					t.Fatalf("link %q to %q passed: %v", e.Path, e.Linkname, err)
				}
			}
			if e.Type == tar.TypeSymlink && e.Linkname == "" {
				t.Fatalf("symlink %q with no target passed", e.Path)
			}
			if e.Body != nil {
				n, _ := io.Copy(io.Discard, e.Body)
				if n > e.Size {
					t.Fatalf("entry %q read %d bytes, size %d", e.Path, n, e.Size)
				}
				total += e.Size
			}
			return nil
		})
		if entries > limits.Entries || total > limits.Bytes {
			t.Fatalf("%d entries and %d bytes passed, err %v", entries, total, err)
		}
	})
}

func TestCounter(t *testing.T) {
	cases := []struct {
		name   string
		limits Limits
		steps  []struct {
			bytes, entries int64
			release        bool
			wantErr        bool
		}
		wantBytes, wantEntries int64
	}{
		{
			name:   "fills to the byte limit",
			limits: Limits{Bytes: 10, Entries: 10},
			steps: []struct {
				bytes, entries int64
				release        bool
				wantErr        bool
			}{{bytes: 6, entries: 1}, {bytes: 4, entries: 1}, {bytes: 1, entries: 1, wantErr: true}},
			wantBytes: 10, wantEntries: 2,
		},
		{
			name:   "fills to the entry limit",
			limits: Limits{Bytes: 100, Entries: 2},
			steps: []struct {
				bytes, entries int64
				release        bool
				wantErr        bool
			}{{bytes: 1, entries: 1}, {bytes: 1, entries: 1}, {bytes: 0, entries: 1, wantErr: true}},
			wantBytes: 2, wantEntries: 2,
		},
		{
			name:   "release gives room back",
			limits: Limits{Bytes: 10, Entries: 10},
			steps: []struct {
				bytes, entries int64
				release        bool
				wantErr        bool
			}{{bytes: 10, entries: 1}, {bytes: 10, entries: 1, release: true}, {bytes: 10, entries: 1}},
			wantBytes: 10, wantEntries: 1,
		},
		{
			name:   "release past zero stays visible",
			limits: Limits{Bytes: 10, Entries: 10},
			steps: []struct {
				bytes, entries int64
				release        bool
				wantErr        bool
			}{{bytes: 50, entries: 5, release: true}},
			wantBytes: -50, wantEntries: -5,
		},
		{
			name:   "a request near the maximum after one byte",
			limits: Limits{Bytes: 1000, Entries: 10},
			steps: []struct {
				bytes, entries int64
				release        bool
				wantErr        bool
			}{{bytes: 1, entries: 1}, {bytes: math.MaxInt64, entries: 0, wantErr: true}, {bytes: 0, entries: math.MaxInt64, wantErr: true}},
			wantBytes: 1, wantEntries: 1,
		},
		{
			name:   "zero bytes refuses any byte",
			limits: Limits{Entries: 10},
			steps: []struct {
				bytes, entries int64
				release        bool
				wantErr        bool
			}{{bytes: 1, entries: 1, wantErr: true}, {bytes: 0, entries: 1}},
			wantEntries: 1,
		},
		{
			name:   "negative refused",
			limits: Limits{Bytes: 10, Entries: 10},
			steps: []struct {
				bytes, entries int64
				release        bool
				wantErr        bool
			}{{bytes: -1, entries: 1, wantErr: true}},
		},
		{
			name:   "default entries",
			limits: Limits{Bytes: 10},
			steps: []struct {
				bytes, entries int64
				release        bool
				wantErr        bool
			}{{bytes: 0, entries: DefaultEntries}, {bytes: 0, entries: 1, wantErr: true}},
			wantEntries: DefaultEntries,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCounter(tc.limits)
			for i, s := range tc.steps {
				if s.release {
					c.Release(s.bytes, s.entries)
					continue
				}
				err := c.Reserve(s.bytes, s.entries)
				if (err != nil) != s.wantErr || (err != nil && !errors.Is(err, ErrBudget)) {
					t.Fatalf("step %d: Reserve(%d, %d) = %v, wantErr %v", i, s.bytes, s.entries, err, s.wantErr)
				}
			}
			b, e := c.Held()
			if b != tc.wantBytes || e != tc.wantEntries {
				t.Fatalf("held %d bytes, %d entries, want %d, %d", b, e, tc.wantBytes, tc.wantEntries)
			}
		})
	}
}
