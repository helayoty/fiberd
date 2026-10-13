package artifact

import (
	"errors"
	"io/fs"
	"testing"
)

// TestParseLdd checks what HostInfo records as the libc from ldd's
// first line, and that any ldd that cannot answer leaves it unknown.
func TestParseLdd(t *testing.T) {
	cases := []struct {
		name string
		out  string
		err  error
		want string
	}{
		{name: "glibc names itself", out: "ldd (GNU libc) 2.36\nCopyright (C) 2022\n", want: "(gnu libc) 2.36"},
		{name: "a distribution's glibc keeps its own words", out: "ldd (Debian GLIBC 2.36-9+deb12u7) 2.36\n", want: "(debian glibc 2.36-9+deb12u7) 2.36"},
		{name: "a first line of one word names no libc", out: "ldd\n", want: ""},
		{name: "an ldd that prints nothing", out: "", want: "unknown"},
		{name: "an ldd that prints only blank lines", out: "\n\n", want: "unknown"},
		{name: "an ldd that fails, as musl's does", out: "musl libc\n", err: errors.New("exit status 1"), want: "unknown"},
		{name: "no ldd at all", err: fs.ErrNotExist, want: "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseLdd([]byte(tc.out), tc.err); got != tc.want {
				t.Fatalf("parseLdd(%q, %v) = %q, want %q", tc.out, tc.err, got, tc.want)
			}
		})
	}
}
