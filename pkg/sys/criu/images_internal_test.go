package criu

import (
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// TestWritePagemapNrPagesFields pins that a written entry carries its
// page count in both field 2 (what a criu before 4.2 reads) and field 5
// (what 4.2 and later read), field 2 clamped to its uint32.
func TestWritePagemapNrPagesFields(t *testing.T) {
	cases := []struct {
		name   string
		n      uint64
		field2 uint64
	}{
		{name: "small run", n: 3, field2: 3},
		{name: "run beyond uint32 clamps field 2", n: 1 << 33, field2: math.MaxUint32},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pagemap-1.img")
			pm := &Pagemap{Path: path, Header: make([]byte, 8), PagesID: 1,
				Entries: []PagemapEntry{{VAddr: 0x1000, NrPages: tc.n, Flags: PEPresent}}}
			if err := writePagemap(pm); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			rest := b[8:]
			var msgs [][]byte
			for len(rest) > 0 {
				n := binary.LittleEndian.Uint32(rest[:4])
				msgs = append(msgs, rest[4:4+n])
				rest = rest[4+n:]
			}
			if len(msgs) != 2 {
				t.Fatalf("wrote %d messages, want a head and one entry", len(msgs))
			}
			fields, err := parseVarintFields(msgs[1])
			if err != nil {
				t.Fatal(err)
			}
			if fields[2] != tc.field2 || fields[5] != tc.n {
				t.Fatalf("entry fields 2 and 5 = %d and %d, want %d and %d", fields[2], fields[5], tc.field2, tc.n)
			}
			got, err := ReadPagemap(path)
			if err != nil {
				t.Fatal(err)
			}
			if got.Entries[0].NrPages != tc.n {
				t.Fatalf("read back %d pages, want %d", got.Entries[0].NrPages, tc.n)
			}
		})
	}
}
