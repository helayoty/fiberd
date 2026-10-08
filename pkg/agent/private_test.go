package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEnsurePrivate checks that <state>/private exists afterwards, is a real
// directory of mode 0700, and nothing a fiber may have left at that name
// is written through. Files under -state are never moved.
func TestEnsurePrivate(t *testing.T) {
	cases := []struct {
		name      string
		under     map[string]string // files under -state before the call
		privateAs string            // "", "dir0755", "symlink", "file", "toolong" or "readonly"
		stateAs   string            // "" or "under-file": -state cannot be made
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
		{name: "a private dir whose mode cannot be tightened", privateAs: "readonly", runs: 1, wantErr: "read-only file system"},
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
			case "readonly":
				readOnlyDir(t, private)
			}
			for i := 0; i < tc.runs; i++ {
				err := ensurePrivate(state, private)
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
			for name := range tc.under {
				if _, err := os.Lstat(filepath.Join(state, name)); err != nil {
					t.Fatalf("%s should have stayed under state: %v", name, err)
				}
			}
		})
	}
}
