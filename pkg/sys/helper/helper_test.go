package helper

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// decoyPath points PATH at a directory holding an executable for every
// given name, so a test sees any lookup that reads it.
func decoyPath(t *testing.T, names ...string) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
}

// TestResolve checks where a name resolves, whatever PATH holds.
func TestResolve(t *testing.T) {
	cases := []struct {
		name    string
		helper  string
		files   map[string]os.FileMode // under the search directories
		want    string                 // under the search directories, or absolute
		wantIs  error
		wantErr string
	}{
		{name: "the first directory wins", helper: "tool", files: map[string]os.FileMode{"first/tool": 0o755, "second/tool": 0o755}, want: "first/tool"},
		{name: "a later directory", helper: "tool", files: map[string]os.FileMode{"second/tool": 0o755}, want: "second/tool"},
		{name: "a file that is not executable is passed over", helper: "tool", files: map[string]os.FileMode{"first/tool": 0o644, "second/tool": 0o755}, want: "second/tool"},
		{name: "a directory is passed over", helper: "tool", files: map[string]os.FileMode{"first/tool/inner": 0o755}, wantIs: fs.ErrNotExist},
		{name: "a name only on PATH is not found", helper: "tool", wantIs: fs.ErrNotExist},
		{name: "an empty name is not found", wantIs: fs.ErrNotExist},
		{name: "an absolute name passes through", helper: "/no/such/tool", want: "/no/such/tool"},
		{name: "a path from the working directory is refused", helper: "./tool", wantErr: "neither absolute nor a bare name"},
		{name: "a relative path is refused", helper: "bin/tool", wantErr: "neither absolute nor a bare name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decoyPath(t, "tool")
			root := t.TempDir()
			dirs := []string{filepath.Join(root, "first"), filepath.Join(root, "second")}
			for _, dir := range dirs {
				if err := os.Mkdir(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			for file, mode := range tc.files {
				path := filepath.Join(root, file)
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, nil, mode); err != nil {
					t.Fatal(err)
				}
			}
			got, err := resolve(tc.helper, dirs)
			if tc.wantIs != nil || tc.wantErr != "" {
				if err == nil || !errors.Is(err, tc.wantIs) && tc.wantIs != nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("resolve = %q, %v, want %v %q", got, err, tc.wantIs, tc.wantErr)
				}
				return
			}
			want := tc.want
			if !filepath.IsAbs(want) {
				want = filepath.Join(root, want)
			}
			if err != nil || got != want {
				t.Fatalf("resolve = %q, %v, want %q", got, err, want)
			}
		})
	}
}

// TestCommand checks the command a helper gets, without starting it. Its
// environment is PathEnv alone, and its path never comes from PATH.
func TestCommand(t *testing.T) {
	cases := []struct {
		name    string
		helper  string
		args    []string
		inDirs  bool // the path is in one of the fixed directories
		want    string
		wantIs  error
		wantErr string
	}{
		{name: "an absolute name", helper: "/opt/tool", args: []string{"--version"}, want: "/opt/tool"},
		{name: "a bare name is found in the fixed directories", helper: "sh", args: []string{"-c", "true"}, inDirs: true},
		{name: "a bare name nowhere fails at the start", helper: "fiberd-test-no-such-helper", wantIs: fs.ErrNotExist},
		{name: "a relative path fails at the start", helper: "./tool", wantErr: "neither absolute nor a bare name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decoyPath(t, "sh", "fiberd-test-no-such-helper")
			cmd := Command(context.Background(), tc.helper, tc.args...)
			if !slices.Equal(cmd.Env, []string{PathEnv}) {
				t.Fatalf("Env = %q, want only %q", cmd.Env, PathEnv)
			}
			if !strings.Contains(cmd.Path, "/") {
				t.Fatalf("Path = %q, which os/exec would search for", cmd.Path)
			}
			if tc.wantIs != nil || tc.wantErr != "" {
				if cmd.Err == nil || !errors.Is(cmd.Err, tc.wantIs) && tc.wantIs != nil || !strings.Contains(cmd.Err.Error(), tc.wantErr) {
					t.Fatalf("Err = %v, want %v %q", cmd.Err, tc.wantIs, tc.wantErr)
				}
				return
			}
			if cmd.Err != nil {
				t.Fatalf("Err = %v, want nil", cmd.Err)
			}
			if tc.want != "" && cmd.Path != tc.want {
				t.Fatalf("Path = %q, want %q", cmd.Path, tc.want)
			}
			if tc.inDirs && !slices.Contains(dirs, filepath.Dir(cmd.Path)) {
				t.Fatalf("Path = %q, want it in %q", cmd.Path, dirs)
			}
			if !slices.Equal(cmd.Args[1:], tc.args) {
				t.Fatalf("Args = %q, want %q after the path", cmd.Args, tc.args)
			}
		})
	}
}

// TestDirs checks the places the images and Debian put the helpers.
func TestDirs(t *testing.T) {
	cases := []struct{ name, dir string }{
		{name: "criu in the images", dir: "/usr/local/sbin"},
		{name: "runsc in the images", dir: "/usr/local/bin"},
		{name: "Debian's runc", dir: "/usr/sbin"},
		{name: "Debian's runc, ldd and unshare", dir: "/usr/bin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !slices.Contains(dirs, tc.dir) {
				t.Fatalf("dirs = %q, want %s in it", dirs, tc.dir)
			}
		})
	}
}

// directStarts are the files that may call os/exec's Command functions,
// with how many calls each holds. Everything else starts a helper through
// Command here.
var directStarts = map[string]int{
	"pkg/sys/helper/helper.go":                   1,
	"pkg/backend/proc/proc_linux.go":             1, // a zygote, which sets its own fixed environment
	"pkg/artifact/checkpoint_linux.go":           1, // a zygote, which sets its own fixed environment
	"pkg/backend/cloudhv/jail_linux.go":          1, // fiberd's own stage, with an empty environment
	"pkg/backend/hyperlight/hyperlight_linux.go": 1, // the Hyperlight helper
	"cmd/zygotectl/main.go":                      1, // the Hyperlight helper's --version, as a home runs it
}

// TestHelpersStartThroughCommand reads the source for direct starts.
func TestHelpersStartThroughCommand(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	cases := []struct{ name, dir string }{
		{name: "packages", dir: "pkg"},
		{name: "binaries", dir: "cmd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			found := map[string]int{}
			err := filepath.WalkDir(filepath.Join(root, tc.dir), func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() && d.Name() == "testdata" {
					return filepath.SkipDir
				}
				if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
					return nil
				}
				n, err := countDirectStarts(path)
				if err != nil || n == 0 {
					return err
				}
				rel, err := filepath.Rel(root, path)
				if err != nil {
					return err
				}
				found[filepath.ToSlash(rel)] = n
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			for file, n := range found {
				if n != directStarts[file] {
					t.Errorf("%s calls exec.Command %d times, want %d: start a helper through helper.Command", file, n, directStarts[file])
				}
			}
		})
	}
}

// countDirectStarts counts the calls of exec.Command and
// exec.CommandContext in the Go file at path.
func countDirectStarts(path string) (int, error) {
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		return 0, err
	}
	n := 0
	ast.Inspect(f, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				pkg, ok := sel.X.(*ast.Ident)
				if ok && pkg.Name == "exec" && (sel.Sel.Name == "Command" || sel.Sel.Name == "CommandContext") {
					n++
				}
			}
		}
		return true
	})
	return n, nil
}
