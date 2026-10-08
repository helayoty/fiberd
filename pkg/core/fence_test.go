package core_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// TestParseFence checks that ParseFence inverts Fence.String, including a
// grant UID that holds slashes, and refuses anything that is not
// grant/epoch/seq.
func TestParseFence(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    core.Fence
		wantErr bool
	}{
		{name: "a fence", in: "g1/2/3", want: core.Fence{GrantUID: "g1", Epoch: 2, Seq: 3}},
		{name: "a grant UID with slashes", in: "ns/g1/2/3", want: core.Fence{GrantUID: "ns/g1", Epoch: 2, Seq: 3}},
		{name: "no slash", in: "g1", wantErr: true},
		{name: "one slash", in: "g1/2", wantErr: true},
		{name: "an epoch that is not a number", in: "g1/x/3", wantErr: true},
		{name: "a seq that is not a number", in: "g1/2/x", wantErr: true},
		{name: "a negative epoch", in: "g1/-1/3", wantErr: true},
		{name: "an empty grant", in: "/2/3", wantErr: true},
		{name: "empty", in: "", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := core.ParseFence(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseFence(%q) = %+v %v, want error %v", tc.in, got, err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if got != tc.want || got.String() != tc.in {
				t.Fatalf("ParseFence(%q) = %+v (%s), want %+v", tc.in, got, got, tc.want)
			}
		})
	}
}

// TestFenceNewer checks that a fence supersedes another of the same grant
// by epoch first and seq second, and never one of another grant.
func TestFenceNewer(t *testing.T) {
	f := func(uid string, epoch, seq uint64) core.Fence {
		return core.Fence{GrantUID: uid, Epoch: epoch, Seq: seq}
	}
	cases := []struct {
		name string
		a, b core.Fence
		want bool
	}{
		{name: "a later epoch with a lower seq", a: f("g", 2, 1), b: f("g", 1, 9), want: true},
		{name: "an earlier epoch with a higher seq", a: f("g", 1, 9), b: f("g", 2, 1)},
		{name: "the same epoch with a higher seq", a: f("g", 1, 2), b: f("g", 1, 1), want: true},
		{name: "the same epoch with a lower seq", a: f("g", 1, 1), b: f("g", 1, 2)},
		{name: "the same fence", a: f("g", 1, 1), b: f("g", 1, 1)},
		{name: "another grant", a: f("g", 9, 9), b: f("h", 1, 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.a.Newer(tc.b); got != tc.want {
				t.Fatalf("%s.Newer(%s) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// TestOpenEpochStore checks that each open moves the epoch past the one on
// disk and persists it. A file that does not parse jumps to the clock
// rather than guess. A store that cannot persist does not open.
func TestOpenEpochStore(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, dir string) string // returns the directory to open
		want    uint64                                // 0 means at least the clock's seconds
		wantErr bool
	}{
		{name: "a fresh directory starts at 1", want: 1, prepare: func(_ *testing.T, dir string) string { return dir }},
		{name: "the next open moves past the stored epoch", want: 42, prepare: func(t *testing.T, dir string) string {
			writeEpoch(t, dir, "41")
			return dir
		}},
		{name: "whitespace around the stored epoch is ignored", want: 42, prepare: func(t *testing.T, dir string) string {
			writeEpoch(t, dir, " 41\n")
			return dir
		}},
		{name: "a corrupt epoch jumps to the clock", prepare: func(t *testing.T, dir string) string {
			writeEpoch(t, dir, "forty-one")
			return dir
		}},
		{name: "a directory that is not there does not open", wantErr: true,
			prepare: func(_ *testing.T, dir string) string { return filepath.Join(dir, "missing") }},
		// The read fails, and so does the rename over the directory.
		{name: "an epoch path that is a directory does not open", wantErr: true, prepare: func(t *testing.T, dir string) string {
			if err := os.Mkdir(filepath.Join(dir, "epoch"), 0o700); err != nil {
				t.Fatal(err)
			}
			return dir
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := uint64(time.Now().Unix())
			dir := tc.prepare(t, t.TempDir())
			s, err := core.OpenEpochStore(dir)
			if (err != nil) != tc.wantErr {
				t.Fatalf("OpenEpochStore = %v, want error %v", err, tc.wantErr)
			}
			if err != nil {
				return
			}
			got := s.Current()
			if (tc.want != 0 && got != tc.want) || (tc.want == 0 && got < before) {
				t.Fatalf("epoch = %d, want %d (0 means at least %d)", got, tc.want, before)
			}
			if stored := readEpoch(t, dir); stored != got {
				t.Fatalf("stored epoch = %d, want %d", stored, got)
			}
		})
	}
}

// TestEpochStoreBump checks that a bump moves the epoch by one and
// persists it, and that a bump that cannot persist moves nothing.
func TestEpochStoreBump(t *testing.T) {
	cases := []struct {
		name    string
		gone    bool // the store's directory is gone before the bump
		wantErr bool
	}{
		{name: "a bump moves and persists the epoch"},
		{name: "a bump that cannot persist moves nothing", gone: true, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			s, err := core.OpenEpochStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			before := s.Current()
			if tc.gone {
				if err := os.RemoveAll(dir); err != nil {
					t.Fatal(err)
				}
			}
			next, err := s.Bump()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Bump = %d %v, want error %v", next, err, tc.wantErr)
			}
			if err != nil {
				if s.Current() != before {
					t.Fatalf("epoch after a failed bump = %d, want %d", s.Current(), before)
				}
				return
			}
			if next != before+1 || s.Current() != next || readEpoch(t, dir) != next {
				t.Fatalf("bump = %d, current %d, stored %d; want %d", next, s.Current(), readEpoch(t, dir), before+1)
			}
		})
	}
}

func writeEpoch(t *testing.T, dir, s string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "epoch"), []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readEpoch(t *testing.T, dir string) uint64 {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "epoch"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
