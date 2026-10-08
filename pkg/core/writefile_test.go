package core

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomic(t *testing.T) {
	cases := []struct {
		name     string
		old      string // content already at the path, "" means none
		dirAtDst bool   // the path is a directory, so the rename fails
		noDir    bool   // the path's directory does not exist
		perm     os.FileMode
		wantErr  bool
	}{
		{name: "creates a new file", perm: 0o600},
		{name: "replaces the content", old: "old", perm: 0o600},
		{name: "keeps the requested perm", old: "old", perm: 0o640},
		{name: "a failed rename leaves no temp file", dirAtDst: true, perm: 0o600, wantErr: true},
		{name: "a missing directory fails before writing", noDir: true, perm: 0o600, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.noDir {
				missing := filepath.Join(dir, "missing", "state")
				if err := writeFileAtomic(missing, []byte("new"), tc.perm); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("writeFileAtomic = %v, want ErrNotExist", err)
				}
				return
			}
			path := filepath.Join(dir, "state")
			switch {
			case tc.dirAtDst:
				if err := os.MkdirAll(filepath.Join(path, "keep"), 0o700); err != nil {
					t.Fatal(err)
				}
			case tc.old != "":
				if err := os.WriteFile(path, []byte(tc.old), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			err := writeFileAtomic(path, []byte("new"), tc.perm)
			if (err != nil) != tc.wantErr {
				t.Fatalf("writeFileAtomic = %v, wantErr %v", err, tc.wantErr)
			}

			ents, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(ents) != 1 || ents[0].Name() != "state" {
				var names []string
				for _, e := range ents {
					names = append(names, e.Name())
				}
				t.Fatalf("dir holds %v, want only state", names)
			}
			if tc.dirAtDst {
				if _, err := os.Stat(filepath.Join(path, "keep")); err != nil {
					t.Fatalf("the old directory was disturbed: %v", err)
				}
				return
			}
			b, err := os.ReadFile(path)
			if err != nil || string(b) != "new" {
				t.Fatalf("content = %q, %v; want new", b, err)
			}
			fi, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := fi.Mode().Perm(); got != tc.perm {
				t.Fatalf("perm = %o, want %o", got, tc.perm)
			}
		})
	}
}

// TestSyncDir checks that a directory syncs and a missing one is an error.
func TestSyncDir(t *testing.T) {
	cases := []struct {
		name    string
		missing bool
		wantErr error
	}{
		{name: "a directory syncs"},
		{name: "a missing directory is an error", missing: true, wantErr: os.ErrNotExist},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.missing {
				dir = filepath.Join(dir, "missing")
			}
			if err := syncDir(dir); !errors.Is(err, tc.wantErr) {
				t.Fatalf("syncDir = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
