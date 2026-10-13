package fiberd

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestEnsurePrivate checks that <state>/private exists afterwards, is a real
// directory of mode 0700, and nothing a fiber may have left at that name
// is written through. Files under -state are never moved. The mode is
// tightened through a chmod the test watches, and a file system that
// refuses it (tests/sys TestFiberdEnsurePrivateReadOnly mounts one) is
// a chmod that answers EROFS.
func TestEnsurePrivate(t *testing.T) {
	cases := []struct {
		name      string
		under     map[string]string // files under -state before the call
		privateAs string            // "", "dir0755", "symlink", "file" or "toolong"
		stateAs   string            // "" or "under-file": -state cannot be made
		chmodErr  error             // what chmod answers
		runs      int
		wantErr   string
	}{
		{name: "an empty state dir gets a private dir", runs: 1},
		{name: "a second run changes nothing", runs: 2},
		{name: "an existing private dir is made 0700", privateAs: "dir0755", runs: 1},
		{name: "files under state stay where they are", under: map[string]string{"ledger.json": "{}", "epoch": "3", "templates/x": "t"}, runs: 1},
		{name: "a symlink at the private dir's name is refused", privateAs: "symlink", runs: 1, wantErr: "is a symlink"},
		{name: "a file at the private dir's name is refused", privateAs: "file", runs: 1, wantErr: "is not a directory"},
		{name: "a state dir that cannot be made", stateAs: "under-file", runs: 1, wantErr: "state dir: "},
		{name: "a private dir the kernel cannot make", privateAs: "toolong", runs: 1, wantErr: "private state dir: "},
		{name: "a private dir whose mode cannot be tightened", privateAs: "dir0755", chmodErr: syscall.EROFS, runs: 1,
			wantErr: "private state dir: read-only file system"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := filepath.Join(t.TempDir(), "state")
			private := filepath.Join(state, "private")
			if err := os.MkdirAll(state, 0o700); err != nil {
				t.Fatal(err)
			}
			switch {
			case tc.stateAs == "under-file":
				state = filepath.Join(state, "file", "state")
				private = filepath.Join(state, "private")
				if err := os.WriteFile(filepath.Dir(state), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			case tc.privateAs == "toolong":
				// One name past every file system's limit.
				private = filepath.Join(state, strings.Repeat("p", 300))
			}
			for name, body := range tc.under {
				p := filepath.Join(state, name)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			elsewhere := filepath.Join(t.TempDir(), "elsewhere")
			switch tc.privateAs {
			case "dir0755":
				if err := os.Mkdir(private, 0o755); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Mkdir(elsewhere, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(elsewhere, private); err != nil {
					t.Fatal(err)
				}
			case "file":
				if err := os.WriteFile(private, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			chmods := 0
			chmod := func(path string, mode os.FileMode) error {
				chmods++
				if path != private || mode != 0o700 {
					t.Fatalf("chmod(%s, %v), want the private dir and 0700", path, mode)
				}
				if tc.chmodErr != nil {
					return tc.chmodErr
				}
				return os.Chmod(path, mode)
			}
			for i := 0; i < tc.runs; i++ {
				err := ensurePrivate(state, private, chmod)
				if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
					t.Fatalf("run %d: %v, want %q", i+1, err, tc.wantErr)
				}
				if tc.wantErr == "" && err != nil {
					t.Fatalf("run %d: %v", i+1, err)
				}
			}
			if tc.wantErr != "" {
				if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
					t.Fatalf("the symlink's target was written to: %v", entries)
				}
				return
			}
			st, err := os.Lstat(private)
			if err != nil {
				t.Fatal(err)
			}
			if !st.IsDir() || st.Mode().Perm() != 0o700 {
				t.Fatalf("private dir mode = %v, want a 0700 directory", st.Mode())
			}
			if entries, _ := os.ReadDir(private); len(entries) != 0 {
				t.Fatalf("private dir holds %v, want nothing moved in", entries)
			}
			if chmods != tc.runs {
				t.Fatalf("chmod ran %d times, want once per run (%d)", chmods, tc.runs)
			}
			for name := range tc.under {
				if _, err := os.Lstat(filepath.Join(state, name)); err != nil {
					t.Fatalf("%s should have stayed under state: %v", name, err)
				}
			}
		})
	}
}
