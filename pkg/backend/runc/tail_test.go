//go:build unix

package runc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTailFile checks what an error about a container that never came
// up quotes of runc's log and the zygote's.
func TestTailFile(t *testing.T) {
	long := strings.Repeat("a line of the log that is long enough to matter\n", 100) // 4800 bytes
	cases := []struct {
		name  string
		write func(t *testing.T, path string) // leaves the file to read at path
		limit int64
		want  string
	}{
		{name: "a missing file is empty", limit: 64, write: func(*testing.T, string) {}},
		{name: "an empty file is empty", limit: 64, write: func(t *testing.T, path string) {
			if err := os.WriteFile(path, nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a short file comes whole", limit: 64, want: "runc said\nso\n", write: func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("runc said\nso\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a file at the limit comes whole", limit: 13, want: "runc said\nso\n", write: func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("runc said\nso\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a long file is cut to whole lines within the limit", limit: 100,
			want: strings.Repeat("a line of the log that is long enough to matter\n", 2), // 96 bytes, not a partial line
			write: func(t *testing.T, path string) {
				if err := os.WriteFile(path, []byte(long), 0o644); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "a long line without a newline is cut mid-line", limit: 8, want: "yyyyyyyy", write: func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte(strings.Repeat("x", 50)+strings.Repeat("y", 8)), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a link is not followed", limit: 64, write: func(t *testing.T, path string) {
			target := filepath.Join(filepath.Dir(path), "secret")
			if err := os.WriteFile(target, []byte("not for the log\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a directory is empty", limit: 64, write: func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "runc.log")
			tc.write(t, path)
			got := tailFile(path, tc.limit)
			if got != tc.want {
				t.Fatalf("tailFile = %q, want %q", got, tc.want)
			}
			if int64(len(got)) > tc.limit {
				t.Fatalf("tailFile returned %d bytes over the limit %d", len(got), tc.limit)
			}
		})
	}
}
