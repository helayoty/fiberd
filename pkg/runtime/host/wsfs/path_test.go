package wsfs

import (
	"errors"
	"strings"
	"testing"
)

func TestClean(t *testing.T) {
	deep := strings.Repeat("a/", MaxDepth-1) + "a"
	cases := []struct {
		name      string
		in        string
		allowRoot bool
		want      string
		wantErr   bool
	}{
		{name: "plain", in: "data.csv", want: "data.csv"},
		{name: "nested", in: "in/data.csv", want: "in/data.csv"},
		{name: "trailing slash", in: "in/", want: "in"},
		{name: "dot file", in: ".hidden", want: ".hidden"},
		{name: "three dots", in: "...", want: "..."},
		{name: "dot dot in a name", in: "a..b", want: "a..b"},
		{name: "deepest allowed", in: deep, want: deep},
		{name: "longest allowed", in: strings.Repeat("a", MaxPathBytes), want: strings.Repeat("a", MaxPathBytes)},
		{name: "root allowed", in: "", allowRoot: true, want: ""},
		{name: "root refused", in: "", wantErr: true},
		{name: "absolute", in: "/etc/passwd", wantErr: true},
		{name: "absolute root", in: "/", wantErr: true},
		{name: "dot dot", in: "..", wantErr: true},
		{name: "dot dot leading", in: "../x", wantErr: true},
		{name: "dot dot inside", in: "a/../x", wantErr: true},
		{name: "dot dot trailing", in: "a/..", wantErr: true},
		{name: "dot", in: ".", wantErr: true},
		{name: "dot inside", in: "a/./b", wantErr: true},
		{name: "empty component", in: "a//b", wantErr: true},
		{name: "NUL", in: "a\x00b", wantErr: true},
		{name: "NUL at end", in: "a\x00", wantErr: true},
		{name: "too long", in: strings.Repeat("a", MaxPathBytes+1), wantErr: true},
		{name: "too deep", in: deep + "/a", wantErr: true},
		{name: "only slashes", in: "//", wantErr: true},
		{name: "backslash is a name", in: `..\x`, want: `..\x`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Clean(tc.in, tc.allowRoot)
			if tc.wantErr {
				if !errors.Is(err, ErrPath) {
					t.Fatalf("Clean(%q) = %q, %v, want ErrPath", tc.in, got, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("Clean(%q) = %q, %v, want %q", tc.in, got, err, tc.want)
			}
		})
	}
}

func TestSplit(t *testing.T) {
	cases := []struct {
		in, dir, base string
	}{
		{"a", "", "a"},
		{"a/b", "a", "b"},
		{"a/b/c", "a/b", "c"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			dir, base := split(tc.in)
			if dir != tc.dir || base != tc.base {
				t.Fatalf("split(%q) = %q, %q, want %q, %q", tc.in, dir, base, tc.dir, tc.base)
			}
		})
	}
}

// FuzzClean checks that an accepted path can only name something
// beneath the root and that a refused one is refused with ErrPath.
func FuzzClean(f *testing.F) {
	for _, s := range []string{"", "a", "a/b", "../a", "/a", "a/../b", "a\x00", "a//b", ".", "..", "a/", strings.Repeat("a/", 70)} {
		f.Add(s, false)
		f.Add(s, true)
	}
	f.Fuzz(func(t *testing.T, p string, allowRoot bool) {
		got, err := Clean(p, allowRoot)
		if err != nil {
			if !errors.Is(err, ErrPath) {
				t.Fatalf("Clean(%q) = %v, not ErrPath", p, err)
			}
			if got != "" {
				t.Fatalf("Clean(%q) returned %q with an error", p, got)
			}
			return
		}
		if got == "" && !allowRoot {
			t.Fatalf("Clean(%q) accepted the root", p)
		}
		if len(got) > len(p) || len(got) > MaxPathBytes {
			t.Fatalf("Clean(%q) = %q, longer than allowed", p, got)
		}
		if got != "" && (got[0] == '/' || got[len(got)-1] == '/') {
			t.Fatalf("Clean(%q) = %q, absolute or with a trailing slash", p, got)
		}
		if strings.IndexByte(got, 0) >= 0 {
			t.Fatalf("Clean(%q) = %q with a NUL", p, got)
		}
		if got != "" {
			comps := strings.Split(got, "/")
			if len(comps) > MaxDepth {
				t.Fatalf("Clean(%q) = %q, %d components", p, got, len(comps))
			}
			for _, c := range comps {
				if c == "" || c == "." || c == ".." {
					t.Fatalf("Clean(%q) = %q with component %q", p, got, c)
				}
			}
		}
	})
}
