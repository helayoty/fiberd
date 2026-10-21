//go:build linux

package wsfs

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fixture is one workspace under a temp directory, with an "outside"
// directory beside it standing in for the rest of the host. Everything
// is on one file system, so links between them are possible.
type fixture struct {
	ws      *Workspace
	budget  *Counter
	root    string
	stage   string
	outside string
	victim  string
}

const victimBody = "host bytes"

func newFixture(t *testing.T, limits Limits) *fixture {
	t.Helper()
	// A short base, since a unix socket path is limited to about 100
	// bytes and t.TempDir carries the test name.
	base, err := os.MkdirTemp("", "wsfs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	fx := &fixture{
		budget:  NewCounter(limits),
		root:    filepath.Join(base, "ws", rootName),
		stage:   filepath.Join(base, "ws", stageName),
		outside: filepath.Join(base, "outside"),
	}
	fx.victim = filepath.Join(fx.outside, "victim")
	if err := os.Mkdir(fx.outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fx.victim, []byte(victimBody), 0o644); err != nil {
		t.Fatal(err)
	}
	ws, err := Open(filepath.Join(base, "ws"), Options{Budget: fx.budget, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ws.Close)
	fx.ws = ws
	return fx
}

// check fails the test when the host side changed or staging holds
// leftovers.
func (fx *fixture) check(t *testing.T) {
	t.Helper()
	b, err := os.ReadFile(fx.victim)
	if err != nil || string(b) != victimBody {
		t.Fatalf("victim changed: %q, %v", b, err)
	}
	names, err := os.ReadDir(fx.outside)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if n.Name() != "victim" {
			t.Fatalf("outside gained %q", n.Name())
		}
	}
	names, err = os.ReadDir(fx.stage)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 0 {
		t.Fatalf("staging holds %d names", len(names))
	}
}

func (fx *fixture) in(rel string) string { return filepath.Join(fx.root, filepath.FromSlash(rel)) }

func (fx *fixture) write(t *testing.T, rel, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(fx.in(rel)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fx.in(rel), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (fx *fixture) symlink(t *testing.T, rel, target string) {
	t.Helper()
	if err := os.Symlink(target, fx.in(rel)); err != nil {
		t.Fatal(err)
	}
}

func (fx *fixture) fifo(t *testing.T, rel string) {
	t.Helper()
	if err := unix.Mkfifo(fx.in(rel), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (fx *fixture) socket(t *testing.T, rel string) {
	t.Helper()
	ln, err := net.Listen("unix", fx.in(rel))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
}

func (fx *fixture) upload(t *testing.T, rel, body string) Info {
	t.Helper()
	info, err := fx.ws.Upload(rel, int64(len(body)), 0, nil, strings.NewReader(body))
	if err != nil {
		t.Fatalf("Upload(%q): %v", rel, err)
	}
	return info
}

func sum(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// withTimeout fails the test when fn takes longer than d, so an open
// that blocks on a FIFO fails instead of hanging the package.
func withTimeout(t *testing.T, d time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("blocked for more than %v", d)
	}
}

func TestOpen(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T, dir string)
		opts    Options
		wantErr bool
		check   func(t *testing.T, dir string)
	}{
		{
			name: "fresh dir makes root and a private stage",
			opts: Options{Budget: NewCounter(Limits{Bytes: 1})},
			check: func(t *testing.T, dir string) {
				st, err := os.Stat(filepath.Join(dir, stageName))
				if err != nil || st.Mode().Perm() != 0o700 {
					t.Fatalf("stage: %v, %v", st, err)
				}
				if st, err := os.Stat(filepath.Join(dir, rootName)); err != nil || !st.IsDir() {
					t.Fatalf("root: %v, %v", st, err)
				}
			},
		},
		{
			name: "reopen sweeps the stage",
			setup: func(t *testing.T, dir string) {
				if err := os.MkdirAll(filepath.Join(dir, stageName), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, stageName, "1.1"), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			opts: Options{Budget: NewCounter(Limits{Bytes: 1})},
			check: func(t *testing.T, dir string) {
				names, _ := os.ReadDir(filepath.Join(dir, stageName))
				if len(names) != 0 {
					t.Fatalf("stage holds %d names", len(names))
				}
			},
		},
		{
			name:    "no budget",
			opts:    Options{},
			wantErr: true,
		},
		{
			name: "root is a link",
			setup: func(t *testing.T, dir string) {
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/", filepath.Join(dir, rootName)); err != nil {
					t.Fatal(err)
				}
			},
			opts:    Options{Budget: NewCounter(Limits{Bytes: 1})},
			wantErr: true,
		},
		{
			name: "dir is a file",
			setup: func(t *testing.T, dir string) {
				if err := os.WriteFile(dir, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			opts:    Options{Budget: NewCounter(Limits{Bytes: 1})},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "ws")
			if tc.setup != nil {
				tc.setup(t, dir)
			}
			ws, err := Open(dir, tc.opts)
			if tc.wantErr {
				if err == nil {
					ws.Close()
					t.Fatal("Open passed")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer ws.Close()
			if tc.check != nil {
				tc.check(t, dir)
			}
		})
	}
}

func TestUpload(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		body    string
		size    int64
		mode    fs.FileMode
		sum     []byte
		limits  Limits
		setup   func(t *testing.T, fx *fixture)
		wantErr error
		// wantHeld is the budget after, when the upload passed.
		wantHeld int64
		check    func(t *testing.T, fx *fixture)
	}{
		{name: "plain", path: "data.csv", body: "a,b\n", wantHeld: 4, check: func(t *testing.T, fx *fixture) {
			b, err := os.ReadFile(fx.in("data.csv"))
			if err != nil || string(b) != "a,b\n" {
				t.Fatalf("%q, %v", b, err)
			}
			st, _ := os.Stat(fx.in("data.csv"))
			if st.Mode().Perm() != 0o644 {
				t.Fatalf("mode %v", st.Mode())
			}
		}},
		{name: "nested makes the directories", path: "in/raw/data.csv", body: "x", wantHeld: 1, check: func(t *testing.T, fx *fixture) {
			if _, err := os.Stat(fx.in("in/raw/data.csv")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "mode is exact", path: "secret", body: "x", mode: 0o600, wantHeld: 1, check: func(t *testing.T, fx *fixture) {
			st, _ := os.Stat(fx.in("secret"))
			if st.Mode().Perm() != 0o600 {
				t.Fatalf("mode %v", st.Mode())
			}
		}},
		{name: "setuid bits dropped", path: "s", body: "x", mode: 0o4755 | fs.ModeSetuid, wantHeld: 1, check: func(t *testing.T, fx *fixture) {
			st, _ := os.Stat(fx.in("s"))
			if st.Mode()&fs.ModeSetuid != 0 || st.Mode().Perm() != 0o755 {
				t.Fatalf("mode %v", st.Mode())
			}
		}},
		{name: "replaces a file and releases its bytes", path: "f", body: "new", setup: func(t *testing.T, fx *fixture) {
			fx.upload(t, "f", "old bytes")
		}, wantHeld: 3},
		{name: "replaces a planted link, never follows it", path: "f", body: "new", setup: func(t *testing.T, fx *fixture) {
			fx.symlink(t, "f", fx.victim)
		}, wantHeld: 3, check: func(t *testing.T, fx *fixture) {
			st, err := os.Lstat(fx.in("f"))
			if err != nil || !st.Mode().IsRegular() {
				t.Fatalf("f: %v, %v", st, err)
			}
		}},
		{name: "replaces a FIFO", path: "f", body: "new", setup: func(t *testing.T, fx *fixture) {
			fx.fifo(t, "f")
		}, wantHeld: 3},
		{name: "replaces a socket", path: "f", body: "new", setup: func(t *testing.T, fx *fixture) {
			fx.socket(t, "f")
		}, wantHeld: 3},
		{name: "replaces one name of a hard link, not the inode", path: "b", body: "new", setup: func(t *testing.T, fx *fixture) {
			fx.write(t, "a", "shared")
			if err := os.Link(fx.in("a"), fx.in("b")); err != nil {
				t.Fatal(err)
			}
		}, wantHeld: 3, check: func(t *testing.T, fx *fixture) {
			a, _ := os.ReadFile(fx.in("a"))
			b, _ := os.ReadFile(fx.in("b"))
			if string(a) != "shared" || string(b) != "new" {
				t.Fatalf("a %q, b %q", a, b)
			}
		}},
		{name: "target is a directory", path: "d", body: "x", setup: func(t *testing.T, fx *fixture) {
			fx.write(t, "d/inner", "x")
		}, wantErr: ErrNotRegular},
		{name: "target is an empty directory", path: "d", body: "x", setup: func(t *testing.T, fx *fixture) {
			if err := os.Mkdir(fx.in("d"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, wantErr: ErrNotRegular},
		{name: "parent is a link to the host", path: "d/f", body: "x", setup: func(t *testing.T, fx *fixture) {
			fx.symlink(t, "d", fx.outside)
		}, wantErr: ErrPath},
		{name: "parent is a link inside", path: "d/f", body: "x", setup: func(t *testing.T, fx *fixture) {
			if err := os.Mkdir(fx.in("real"), 0o755); err != nil {
				t.Fatal(err)
			}
			fx.symlink(t, "d", "real")
		}, wantErr: ErrPath},
		{name: "parent is a magic link", path: "d/f", body: "x", setup: func(t *testing.T, fx *fixture) {
			fx.symlink(t, "d", "/proc/self/cwd")
		}, wantErr: ErrPath},
		{name: "parent is a file", path: "d/f", body: "x", setup: func(t *testing.T, fx *fixture) {
			fx.write(t, "d", "x")
		}, wantErr: ErrPath},
		{name: "parent is a FIFO", path: "d/f", body: "x", setup: func(t *testing.T, fx *fixture) {
			fx.fifo(t, "d")
		}, wantErr: ErrPath},
		{name: "dot dot", path: "../x", body: "x", wantErr: ErrPath},
		{name: "dot dot inside", path: "a/../x", body: "x", wantErr: ErrPath},
		{name: "absolute", path: fixtureVictimPath, body: "x", wantErr: ErrPath},
		{name: "NUL", path: "a\x00b", body: "x", wantErr: ErrPath},
		{name: "too long", path: strings.Repeat("a", MaxPathBytes+1), body: "x", wantErr: ErrPath},
		{name: "too deep", path: strings.Repeat("a/", MaxDepth) + "a", body: "x", wantErr: ErrPath},
		{name: "empty", path: "", body: "x", wantErr: ErrPath},
		{name: "sha256 matches", path: "f", body: "hello", sum: sum("hello"), wantHeld: 5},
		{name: "sha256 mismatch", path: "f", body: "hello", sum: sum("hellp"), wantErr: ErrChecksum},
		{name: "sha256 wrong length", path: "f", body: "hello", sum: []byte{1, 2, 3}, wantErr: ErrChecksum},
		{name: "body shorter than declared", path: "f", body: "hel", size: 5, wantErr: ErrSize},
		{name: "body longer than declared", path: "f", body: "hello!", size: 5, wantErr: ErrSize},
		{name: "negative size", path: "f", body: "", size: -1, wantErr: ErrSize},
		{name: "over budget", path: "f", body: strings.Repeat("x", 100), limits: Limits{Bytes: 99}, wantErr: ErrBudget},
		{name: "at budget", path: "f", body: strings.Repeat("x", 100), limits: Limits{Bytes: 100}, wantHeld: 100},
		{name: "entries over budget", path: "e", body: "x", limits: Limits{Bytes: 100, Entries: 1}, setup: func(t *testing.T, fx *fixture) {
			fx.upload(t, "first", "x")
		}, wantErr: ErrBudget},
		{name: "replacing does not need a new entry", path: "first", body: "y", limits: Limits{Bytes: 100, Entries: 1}, setup: func(t *testing.T, fx *fixture) {
			fx.upload(t, "first", "x")
		}, wantHeld: 1},
		{name: "declared size near the maximum", path: "big", body: strings.Repeat("x", 64<<10), size: math.MaxInt64, limits: Limits{Bytes: 1 << 20}, setup: func(t *testing.T, fx *fixture) {
			fx.upload(t, "one", "x")
		}, wantErr: ErrBudget},
		{name: "replacing a file the fiber made frees nothing", path: "b", body: "x", limits: Limits{Bytes: 1000}, setup: func(t *testing.T, fx *fixture) {
			fx.upload(t, "a", strings.Repeat("x", 900))
			fx.write(t, "b", "")
			if err := os.Truncate(fx.in("b"), 1<<40); err != nil {
				t.Fatal(err)
			}
		}, wantHeld: 901, check: func(t *testing.T, fx *fixture) {
			if _, err := fx.ws.Upload("c", 900, 0, nil, strings.NewReader(strings.Repeat("x", 900))); !errors.Is(err, ErrBudget) {
				t.Fatalf("a third 900 bytes under a 1000 byte budget: %v", err)
			}
		}},
		{name: "replacing a file fiberd wrote frees what it reserved", path: "a", body: "xyz", limits: Limits{Bytes: 1000}, setup: func(t *testing.T, fx *fixture) {
			fx.upload(t, "a", strings.Repeat("x", 900))
			// The fiber grows it. Only the 900 reserved come back.
			f, err := os.OpenFile(fx.in("a"), os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = f.WriteString(strings.Repeat("y", 50))
			_ = f.Close()
		}, wantHeld: 3},
		{name: "replacing one name of a file fiberd wrote frees nothing while another name holds it", path: "a", body: "xyz", limits: Limits{Bytes: 1000}, setup: func(t *testing.T, fx *fixture) {
			fx.upload(t, "a", "shared")
			if err := os.Link(fx.in("a"), fx.in("b")); err != nil {
				t.Fatal(err)
			}
		}, wantHeld: 9, check: func(t *testing.T, fx *fixture) {
			// The last name goes and the 6 come back.
			if _, err := fx.ws.Upload("b", 1, 0, nil, strings.NewReader("z")); err != nil {
				t.Fatal(err)
			}
			if b, _ := fx.budget.Held(); b != 4 {
				t.Fatalf("held %d, want 4", b)
			}
		}},
		{name: "empty body", path: "f", body: "", wantHeld: 0, check: func(t *testing.T, fx *fixture) {
			st, err := os.Stat(fx.in("f"))
			if err != nil || st.Size() != 0 {
				t.Fatalf("%v, %v", st, err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			limits := tc.limits
			if limits.Bytes == 0 {
				limits.Bytes = 1 << 20
			}
			fx := newFixture(t, limits)
			if tc.setup != nil {
				tc.setup(t, fx)
			}
			size := tc.size
			if size == 0 {
				size = int64(len(tc.body))
			}
			p := tc.path
			if p == fixtureVictimPath {
				p = fx.victim
			}
			info, err := fx.ws.Upload(p, size, tc.mode, tc.sum, strings.NewReader(tc.body))
			fx.check(t)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Upload = %+v, %v, want %v", info, err, tc.wantErr)
				}
				// A failed upload holds nothing of its own. What the setup
				// uploaded stays.
				if tc.setup == nil {
					if b, e := fx.budget.Held(); b != 0 || e != 0 {
						t.Fatalf("budget holds %d bytes, %d entries after a failure", b, e)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("Upload: %v", err)
			}
			if info.Path != p || info.Size != size || !bytes.Equal(info.SHA256, sum(tc.body)) {
				t.Fatalf("info %+v", info)
			}
			if b, _ := fx.budget.Held(); b != tc.wantHeld {
				t.Fatalf("budget holds %d bytes, want %d", b, tc.wantHeld)
			}
			if tc.check != nil {
				tc.check(t, fx)
			}
		})
	}
}

// fixtureVictimPath marks a case whose path is the fixture's absolute
// victim path.
const fixtureVictimPath = "<victim>"

// TestUploadRace uploads while another goroutine keeps swapping a name
// on the path for a link to the host. The upload either lands as a
// regular file under the root or is refused, and the host file and
// directory never change. Run with -race and -count.
func TestUploadRace(t *testing.T) {
	cases := []struct {
		name string
		path string
		// swap flips the planted name between a link to the host and
		// its honest form once.
		swap func(fx *fixture)
	}{
		{
			name: "the file's own name",
			path: "t",
			swap: func(fx *fixture) {
				_ = os.Remove(fx.in("t"))
				_ = os.Symlink(fx.victim, fx.in("t"))
				_ = os.Remove(fx.in("t"))
				_ = os.WriteFile(fx.in("t"), []byte("fiber"), 0o644)
			},
		},
		{
			name: "a parent directory",
			path: "d/t",
			swap: func(fx *fixture) {
				_ = os.RemoveAll(fx.in("d"))
				_ = os.Symlink(fx.outside, fx.in("d"))
				_ = os.Remove(fx.in("d"))
				_ = os.Mkdir(fx.in("d"), 0o755)
			},
		},
		{
			name: "a parent swapped for a link to a sibling",
			path: "d/t",
			swap: func(fx *fixture) {
				_ = os.RemoveAll(fx.in("d"))
				_ = os.Symlink("e", fx.in("d"))
				_ = os.Remove(fx.in("d"))
				_ = os.Mkdir(fx.in("d"), 0o755)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t, Limits{Bytes: 1 << 20})
			if err := os.Mkdir(fx.in("e"), 0o755); err != nil {
				t.Fatal(err)
			}
			stop := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
						tc.swap(fx)
					}
				}
			}()
			var passed, refused int
			for range 300 {
				_, err := fx.ws.Upload(tc.path, 3, 0, nil, strings.NewReader("new"))
				switch {
				case err == nil:
					passed++
					fx.budget.Release(3, 1)
				case errors.Is(err, ErrPath), errors.Is(err, fs.ErrNotExist):
					refused++
				default:
					t.Fatalf("Upload: %v", err)
				}
			}
			close(stop)
			wg.Wait()
			fx.check(t)
			if entries, _ := os.ReadDir(fx.in("e")); len(entries) != 0 {
				t.Fatalf("sibling gained %d names", len(entries))
			}
			t.Logf("%d passed, %d refused", passed, refused)
		})
	}
}

func TestDownload(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		offset int64
		setup  func(t *testing.T, fx *fixture)
		want   string
		// wantSize is the size Info reports, the whole file whatever
		// the offset.
		wantSize int64
		wantErr  error
	}{
		{name: "plain", path: "f", setup: func(t *testing.T, fx *fixture) { fx.write(t, "f", "hello") }, want: "hello", wantSize: 5},
		{name: "nested", path: "d/f", setup: func(t *testing.T, fx *fixture) { fx.write(t, "d/f", "hello") }, want: "hello", wantSize: 5},
		{name: "offset", path: "f", offset: 2, setup: func(t *testing.T, fx *fixture) { fx.write(t, "f", "hello") }, want: "llo", wantSize: 5},
		{name: "offset at the end", path: "f", offset: 5, setup: func(t *testing.T, fx *fixture) { fx.write(t, "f", "hello") }, want: "", wantSize: 5},
		{name: "offset past the end", path: "f", offset: 50, setup: func(t *testing.T, fx *fixture) { fx.write(t, "f", "hello") }, want: "", wantSize: 5},
		{name: "negative offset", path: "f", offset: -1, setup: func(t *testing.T, fx *fixture) { fx.write(t, "f", "hello") }, wantErr: ErrSize},
		{name: "hard link inside", path: "b", setup: func(t *testing.T, fx *fixture) {
			fx.write(t, "a", "shared")
			if err := os.Link(fx.in("a"), fx.in("b")); err != nil {
				t.Fatal(err)
			}
		}, want: "shared", wantSize: 6},
		{name: "FIFO", path: "p", setup: func(t *testing.T, fx *fixture) { fx.fifo(t, "p") }, wantErr: ErrNotRegular},
		{name: "socket", path: "s", setup: func(t *testing.T, fx *fixture) { fx.socket(t, "s") }, wantErr: ErrNotRegular},
		{name: "directory", path: "d", setup: func(t *testing.T, fx *fixture) { fx.write(t, "d/f", "x") }, wantErr: ErrNotRegular},
		{name: "link to the host", path: "l", setup: func(t *testing.T, fx *fixture) { fx.symlink(t, "l", fx.victim) }, wantErr: ErrPath},
		{name: "link inside", path: "l", setup: func(t *testing.T, fx *fixture) {
			fx.write(t, "f", "x")
			fx.symlink(t, "l", "f")
		}, wantErr: ErrPath},
		{name: "magic link", path: "m", setup: func(t *testing.T, fx *fixture) { fx.symlink(t, "m", "/proc/self/fd/0") }, wantErr: ErrPath},
		{name: "link in the parent", path: "d/f", setup: func(t *testing.T, fx *fixture) { fx.symlink(t, "d", fx.outside) }, wantErr: ErrPath},
		{name: "missing", path: "nope", wantErr: fs.ErrNotExist},
		{name: "dot dot", path: "../outside/victim", wantErr: ErrPath},
		{name: "absolute", path: "/etc/passwd", wantErr: ErrPath},
		{name: "root", path: "", wantErr: ErrPath},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t, Limits{Bytes: 1 << 20})
			if tc.setup != nil {
				tc.setup(t, fx)
			}
			var f *File
			var err error
			withTimeout(t, 5*time.Second, func() { f, err = fx.ws.Download(tc.path, tc.offset) })
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Download = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			b, err := io.ReadAll(f)
			if err != nil || string(b) != tc.want {
				t.Fatalf("read %q, %v, want %q", b, err, tc.want)
			}
			if f.Info().Path != tc.path || f.Info().Size != tc.wantSize {
				t.Fatalf("info %+v", f.Info())
			}
		})
	}
}

// TestDownloadBound checks the reader against a file the fiber changes
// after the open.
func TestDownloadBound(t *testing.T) {
	cases := []struct {
		name    string
		change  func(t *testing.T, fx *fixture)
		want    string
		wantErr error
	}{
		{name: "grows", change: func(t *testing.T, fx *fixture) {
			f, err := os.OpenFile(fx.in("f"), os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = f.WriteString(" and more")
			_ = f.Close()
		}, want: "hello"},
		{name: "shrinks", change: func(t *testing.T, fx *fixture) {
			if err := os.Truncate(fx.in("f"), 2); err != nil {
				t.Fatal(err)
			}
		}, want: "he", wantErr: io.ErrUnexpectedEOF},
		{name: "replaced by a link", change: func(t *testing.T, fx *fixture) {
			_ = os.Remove(fx.in("f"))
			fx.symlink(t, "f", fx.victim)
		}, want: "hello"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t, Limits{Bytes: 1 << 20})
			fx.write(t, "f", "hello")
			f, err := fx.ws.Download("f", 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			tc.change(t, fx)
			b, err := io.ReadAll(f)
			if string(b) != tc.want || !errors.Is(err, tc.wantErr) {
				t.Fatalf("read %q, %v, want %q, %v", b, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestList(t *testing.T) {
	mixed := func(t *testing.T, fx *fixture) {
		fx.write(t, "b.txt", "12345")
		fx.write(t, "a/inner", "x")
		fx.symlink(t, "l", fx.victim)
		fx.fifo(t, "p")
		fx.socket(t, "s")
	}
	cases := []struct {
		name    string
		path    string
		limits  Limits
		setup   func(t *testing.T, fx *fixture)
		want    []Info
		wantErr error
	}{
		{name: "root keeps files and directories only", path: "", setup: mixed, want: []Info{
			{Path: "a", Mode: fs.ModeDir | 0o755},
			{Path: "b.txt", Size: 5, Mode: 0o644},
		}},
		{name: "subdirectory", path: "a", setup: mixed, want: []Info{{Path: "a/inner", Size: 1, Mode: 0o644}}},
		{name: "trailing slash", path: "a/", setup: mixed, want: []Info{{Path: "a/inner", Size: 1, Mode: 0o644}}},
		{name: "empty root", path: "", want: []Info{}},
		{name: "link to the host", path: "l", setup: func(t *testing.T, fx *fixture) { fx.symlink(t, "l", fx.outside) }, wantErr: ErrPath},
		{name: "a file", path: "b.txt", setup: mixed, wantErr: ErrPath},
		{name: "missing", path: "nope", wantErr: fs.ErrNotExist},
		{name: "dot dot", path: "..", wantErr: ErrPath},
		{name: "too many entries", path: "", limits: Limits{Bytes: 1 << 20, Entries: 2}, setup: func(t *testing.T, fx *fixture) {
			fx.write(t, "a", "x")
			fx.write(t, "b", "x")
			fx.write(t, "c", "x")
		}, wantErr: ErrEntries},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			limits := tc.limits
			if limits.Bytes == 0 {
				limits.Bytes = 1 << 20
			}
			fx := newFixture(t, limits)
			if tc.setup != nil {
				tc.setup(t, fx)
			}
			got, err := fx.ws.List(tc.path)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("List = %v, %v, want %v", got, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
			for i := range got {
				if got[i].Path != tc.want[i].Path || got[i].Size != tc.want[i].Size || got[i].Mode != tc.want[i].Mode || got[i].ModTime.IsZero() {
					t.Fatalf("entry %d: got %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// tarEntries reads an archive into a map of path to entry, with bodies.
func tarEntries(t *testing.T, b []byte) map[string]tarEntry {
	t.Helper()
	out := map[string]tarEntry{}
	tr := tar.NewReader(bytes.NewReader(b))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out[strings.TrimSuffix(hdr.Name, "/")] = tarEntry{name: hdr.Name, typ: hdr.Typeflag, body: string(body), link: hdr.Linkname, mode: hdr.Mode}
	}
}

func TestCapture(t *testing.T) {
	cases := []struct {
		name   string
		limits Limits
		// zeroBytes keeps Limits.Bytes at zero instead of the test's
		// default.
		zeroBytes bool
		setup     func(t *testing.T, fx *fixture)
		want      map[string]tarEntry
		wantErr   error
	}{
		{
			name: "tree",
			setup: func(t *testing.T, fx *fixture) {
				fx.write(t, "d/f", "hello")
				fx.write(t, "g", "")
				fx.symlink(t, "s", "/etc/passwd")
				fx.symlink(t, "d/r", "../g")
				if err := os.Chmod(fx.in("g"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: map[string]tarEntry{
				"d":   {typ: tar.TypeDir, mode: 0o755},
				"d/f": {typ: tar.TypeReg, body: "hello", mode: 0o644},
				"d/r": {typ: tar.TypeSymlink, link: "../g", mode: 0o777},
				"g":   {typ: tar.TypeReg, mode: 0o600},
				"s":   {typ: tar.TypeSymlink, link: "/etc/passwd", mode: 0o777},
			},
		},
		{
			name: "hard link inside carried once",
			setup: func(t *testing.T, fx *fixture) {
				fx.write(t, "a", "shared")
				if err := os.Link(fx.in("a"), fx.in("b")); err != nil {
					t.Fatal(err)
				}
			},
			want: map[string]tarEntry{
				"a": {typ: tar.TypeReg, body: "shared", mode: 0o644},
				"b": {typ: tar.TypeLink, link: "a", mode: 0o644},
			},
		},
		{
			name: "hard link to the host refused",
			setup: func(t *testing.T, fx *fixture) {
				if err := os.Link(fx.victim, fx.in("x")); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: ErrForeignLink,
		},
		{
			name: "FIFO, socket and the link to them skipped",
			setup: func(t *testing.T, fx *fixture) {
				fx.fifo(t, "p")
				fx.socket(t, "s")
				fx.write(t, "f", "x")
			},
			want: map[string]tarEntry{"f": {typ: tar.TypeReg, body: "x", mode: 0o644}},
		},
		{
			name:   "sparse file counts by apparent size",
			limits: Limits{Bytes: 1 << 20},
			setup: func(t *testing.T, fx *fixture) {
				fx.write(t, "hole", "")
				if err := os.Truncate(fx.in("hole"), 8<<20); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: ErrTooLarge,
		},
		{
			name:   "sparse file under the limit is carried whole",
			limits: Limits{Bytes: 1 << 20},
			setup: func(t *testing.T, fx *fixture) {
				fx.write(t, "hole", "")
				if err := os.Truncate(fx.in("hole"), 4096); err != nil {
					t.Fatal(err)
				}
			},
			want: map[string]tarEntry{"hole": {typ: tar.TypeReg, body: strings.Repeat("\x00", 4096), mode: 0o644}},
		},
		{
			name:   "too many entries",
			limits: Limits{Bytes: 1 << 20, Entries: 3},
			setup: func(t *testing.T, fx *fixture) {
				fx.write(t, "a", "x")
				fx.write(t, "b", "x")
				fx.write(t, "c", "x")
				fx.write(t, "d", "x")
			},
			wantErr: ErrEntries,
		},
		{
			name:   "links count as entries",
			limits: Limits{Bytes: 1 << 20, Entries: 2},
			setup: func(t *testing.T, fx *fixture) {
				fx.write(t, "a", "x")
				fx.symlink(t, "b", "a")
				fx.symlink(t, "c", "a")
			},
			wantErr: ErrEntries,
		},
		{
			name: "directory swapped for a link to the host",
			setup: func(t *testing.T, fx *fixture) {
				fx.symlink(t, "d", fx.outside)
			},
			want: map[string]tarEntry{"d": {typ: tar.TypeSymlink, link: fixtureVictimPath, mode: 0o777}},
		},
		{
			name: "empty",
			want: map[string]tarEntry{},
		},
		{
			name:   "an apparent size near the maximum after a small file",
			limits: Limits{Bytes: 1 << 20},
			setup: func(t *testing.T, fx *fixture) {
				fx.write(t, "a", "x")
				fx.write(t, "b", "")
				if err := os.Truncate(fx.in("b"), math.MaxInt64); err != nil {
					t.Skipf("the file system refuses the apparent size: %v", err)
				}
			},
			wantErr: ErrTooLarge,
		},
		{
			name:      "zero byte limit refuses a file with bytes",
			zeroBytes: true,
			setup: func(t *testing.T, fx *fixture) {
				fx.write(t, "hole", "")
				if err := os.Truncate(fx.in("hole"), 8<<20); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: ErrTooLarge,
		},
		{
			name:      "zero byte limit passes directories and empty files",
			zeroBytes: true,
			setup: func(t *testing.T, fx *fixture) {
				fx.write(t, "d/e", "")
			},
			want: map[string]tarEntry{
				"d":   {typ: tar.TypeDir, mode: 0o755},
				"d/e": {typ: tar.TypeReg, mode: 0o644},
			},
		},
		{
			name: "deeper than Unpack allows",
			setup: func(t *testing.T, fx *fixture) {
				fx.write(t, strings.Repeat("d/", MaxDepth)+"f", "x")
			},
			wantErr: ErrPath,
		},
		{
			name: "longer than Unpack allows",
			setup: func(t *testing.T, fx *fixture) {
				// 17 names of 255 bytes pass PATH_MAX, so the tree is
				// made one descriptor at a time, as a fiber would.
				long := strings.Repeat("n", 255)
				cur := fx.ws.root
				for range 17 {
					if err := unix.Mkdirat(cur, long, 0o755); err != nil {
						t.Fatal(err)
					}
					next, err := unix.Openat(cur, long, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
					if err != nil {
						t.Fatal(err)
					}
					if cur != fx.ws.root {
						_ = unix.Close(cur)
					}
					cur = next
				}
				fd, err := unix.Openat(cur, "f", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0o644)
				if err != nil {
					t.Fatal(err)
				}
				_ = unix.Close(fd)
				_ = unix.Close(cur)
			},
			wantErr: ErrPath,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			limits := tc.limits
			if limits.Bytes == 0 && !tc.zeroBytes {
				limits.Bytes = 1 << 20
			}
			fx := newFixture(t, limits)
			if tc.setup != nil {
				tc.setup(t, fx)
			}
			var buf bytes.Buffer
			var err error
			withTimeout(t, 10*time.Second, func() { err = fx.ws.Capture(&buf) })
			fx.check(t)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Capture = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := tarEntries(t, buf.Bytes())
			if len(got) != len(tc.want) {
				t.Fatalf("got %d entries %v, want %d", len(got), got, len(tc.want))
			}
			for p, want := range tc.want {
				g, ok := got[p]
				if !ok {
					t.Fatalf("missing %q in %v", p, got)
				}
				link := want.link
				if link == fixtureVictimPath {
					link = fx.outside
				}
				if g.typ != want.typ || g.body != want.body || g.link != link || g.mode != want.mode {
					t.Fatalf("%q: got %+v, want %+v", p, g, want)
				}
			}
		})
	}
}

func TestUnpack(t *testing.T) {
	cases := []struct {
		name    string
		limits  Limits
		entries []tarEntry
		stream  io.Reader
		setup   func(t *testing.T, fx *fixture)
		wantErr error
		// wantHeld is the budget after a pass.
		wantBytes, wantEntries int64
		check                  func(t *testing.T, fx *fixture)
	}{
		{
			name: "tree",
			entries: []tarEntry{
				{name: "d/", typ: tar.TypeDir, mode: 0o700},
				{name: "d/f", body: "hello", mode: 0o600},
				{name: "g", body: "", mode: 0o644},
				{name: "s", typ: tar.TypeSymlink, link: "/etc/passwd"},
				{name: "l", typ: tar.TypeLink, link: "d/f"},
			},
			wantBytes: 5, wantEntries: 5,
			check: func(t *testing.T, fx *fixture) {
				if b, err := os.ReadFile(fx.in("d/f")); err != nil || string(b) != "hello" {
					t.Fatalf("d/f: %q, %v", b, err)
				}
				if st, _ := os.Stat(fx.in("d/f")); st.Mode().Perm() != 0o600 {
					t.Fatalf("d/f mode %v", st.Mode())
				}
				if st, _ := os.Stat(fx.in("d")); st.Mode().Perm() != 0o700 {
					t.Fatalf("d mode %v", st.Mode())
				}
				if target, err := os.Readlink(fx.in("s")); err != nil || target != "/etc/passwd" {
					t.Fatalf("s: %q, %v", target, err)
				}
				a, _ := os.Stat(fx.in("d/f"))
				b, _ := os.Stat(fx.in("l"))
				if !os.SameFile(a, b) {
					t.Fatal("l is not a hard link to d/f")
				}
			},
		},
		{
			name:      "missing parents are made",
			entries:   []tarEntry{{name: "a/b/c", body: "x"}},
			wantBytes: 1, wantEntries: 1,
			check: func(t *testing.T, fx *fixture) {
				if _, err := os.Stat(fx.in("a/b/c")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:      "read-only directory still gets its files",
			entries:   []tarEntry{{name: "d/", typ: tar.TypeDir, mode: 0o555}, {name: "d/f", body: "x"}},
			wantBytes: 1, wantEntries: 2,
		},
		{name: "dot dot", entries: []tarEntry{{name: "../escape", body: "x"}}, wantErr: ErrArchive},
		{name: "absolute", entries: []tarEntry{{name: "/etc/escape", body: "x"}}, wantErr: ErrArchive},
		{name: "dot dot in a directory", entries: []tarEntry{{name: "d/../../escape/", typ: tar.TypeDir}}, wantErr: ErrArchive},
		{
			name:    "symlink then write through it",
			entries: []tarEntry{{name: "d", typ: tar.TypeSymlink, link: fixtureVictimPath}, {name: "d/escape", body: "x"}},
			wantErr: ErrPath,
		},
		{
			name:      "symlink then a file at its name replaces it",
			entries:   []tarEntry{{name: "x", typ: tar.TypeSymlink, link: "<victim-file>"}, {name: "x", body: "new"}},
			wantBytes: 3, wantEntries: 1,
			check: func(t *testing.T, fx *fixture) {
				st, err := os.Lstat(fx.in("x"))
				if err != nil || !st.Mode().IsRegular() {
					t.Fatalf("x: %v, %v", st, err)
				}
			},
		},
		{
			name:    "symlink then a directory at its name",
			entries: []tarEntry{{name: "d", typ: tar.TypeSymlink, link: fixtureVictimPath}, {name: "d/", typ: tar.TypeDir}},
			wantErr: ErrArchive,
		},
		{
			name:    "symlink to a sibling then write through it",
			entries: []tarEntry{{name: "e/", typ: tar.TypeDir}, {name: "d", typ: tar.TypeSymlink, link: "e"}, {name: "d/f", body: "x"}},
			wantErr: ErrPath,
		},
		{name: "hard link out", entries: []tarEntry{{name: "a", body: "x"}, {name: "b", typ: tar.TypeLink, link: "../outside/victim"}}, wantErr: ErrArchive},
		{name: "hard link to a symlink", entries: []tarEntry{{name: "s", typ: tar.TypeSymlink, link: "<victim-file>"}, {name: "b", typ: tar.TypeLink, link: "s"}}, wantErr: ErrArchive},
		{name: "directory then a file at its name", entries: []tarEntry{{name: "d/", typ: tar.TypeDir}, {name: "d", body: "x"}}, wantErr: ErrNotRegular},
		{name: "directory twice", entries: []tarEntry{{name: "d/", typ: tar.TypeDir}, {name: "d/", typ: tar.TypeDir}}, wantErr: ErrArchive},
		{name: "FIFO", entries: []tarEntry{{name: "p", typ: tar.TypeFifo}}, wantErr: ErrArchive},
		{name: "device", entries: []tarEntry{{name: "c", typ: tar.TypeChar}}, wantErr: ErrArchive},
		{name: "huge entry count", stream: manyEntries(DefaultEntries + 1), wantErr: ErrEntries},
		{name: "too many entries", limits: Limits{Bytes: 1 << 20, Entries: 2}, entries: []tarEntry{{name: "a", body: "x"}, {name: "b", body: "x"}, {name: "c", body: "x"}}, wantErr: ErrEntries},
		{name: "too many bytes", limits: Limits{Bytes: 4}, entries: []tarEntry{{name: "a", body: "123"}, {name: "b", body: "45"}}, wantErr: ErrTooLarge},
		{name: "over budget", limits: Limits{Bytes: 1 << 20}, setup: func(t *testing.T, fx *fixture) {
			// The budget is smaller than the limits allow.
			fx.budget.limit.Bytes = 4
		}, entries: []tarEntry{{name: "a", body: "123"}, {name: "b", body: "45"}}, wantErr: ErrBudget},
		{name: "truncated", stream: bytes.NewReader(makeTar(t, tarEntry{name: "a", body: strings.Repeat("x", 2000)})[:700]), wantErr: ErrArchive},
		{name: "garbage", stream: strings.NewReader(strings.Repeat("junk", 300)), wantErr: ErrArchive},
		{name: "root not empty", setup: func(t *testing.T, fx *fixture) { fx.write(t, "old", "x") }, entries: []tarEntry{{name: "a", body: "x"}}, wantErr: ErrNotEmpty},
		{name: "empty archive", entries: nil, wantBytes: 0, wantEntries: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			limits := tc.limits
			if limits.Bytes == 0 {
				limits.Bytes = 1 << 20
			}
			fx := newFixture(t, limits)
			if tc.setup != nil {
				tc.setup(t, fx)
			}
			in := tc.stream
			if in == nil {
				entries := make([]tarEntry, len(tc.entries))
				for i, e := range tc.entries {
					switch e.link {
					case fixtureVictimPath:
						e.link = fx.outside
					case "<victim-file>":
						e.link = fx.victim
					}
					entries[i] = e
				}
				in = bytes.NewReader(makeTar(t, entries...))
			}
			err := fx.ws.Unpack(in)
			fx.check(t)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Unpack = %v, want %v", err, tc.wantErr)
				}
				if b, e := fx.budget.Held(); b != 0 || e != 0 {
					t.Fatalf("budget holds %d bytes, %d entries after a failure", b, e)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if b, e := fx.budget.Held(); b != tc.wantBytes || e != tc.wantEntries {
				t.Fatalf("budget holds %d bytes, %d entries, want %d, %d", b, e, tc.wantBytes, tc.wantEntries)
			}
			if tc.check != nil {
				tc.check(t, fx)
			}
		})
	}
}

// TestRoundTrip captures a tree and unpacks it into a fresh workspace,
// then captures that and compares the archives.
func TestRoundTrip(t *testing.T) {
	src := newFixture(t, Limits{Bytes: 1 << 20})
	src.write(t, "d/f", "hello")
	src.write(t, "d/e/g", strings.Repeat("x", 70000))
	src.write(t, "top", "")
	src.symlink(t, "s", "d/f")
	src.symlink(t, "abs", "/etc/passwd")
	if err := os.Link(src.in("d/f"), src.in("d/e/link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(src.in("top"), 0o640); err != nil {
		t.Fatal(err)
	}
	src.fifo(t, "p")
	var a bytes.Buffer
	if err := src.ws.Capture(&a); err != nil {
		t.Fatal(err)
	}
	dst := newFixture(t, Limits{Bytes: 1 << 20})
	if err := dst.ws.Unpack(bytes.NewReader(a.Bytes())); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := dst.ws.Capture(&b); err != nil {
		t.Fatal(err)
	}
	ga, gb := tarEntries(t, a.Bytes()), tarEntries(t, b.Bytes())
	if len(ga) != 8 || len(gb) != len(ga) {
		t.Fatalf("%d and %d entries", len(ga), len(gb))
	}
	for p, ea := range ga {
		eb := gb[p]
		if ea.typ != eb.typ || ea.body != eb.body || ea.link != eb.link || ea.mode != eb.mode {
			t.Fatalf("%q: %+v then %+v", p, ea, eb)
		}
	}
	x, _ := os.Stat(dst.in("d/f"))
	y, _ := os.Stat(dst.in("d/e/link"))
	if !os.SameFile(x, y) {
		t.Fatal("hard link not restored")
	}
	if bytes, entries := dst.budget.Held(); bytes != 70005 || entries != 8 {
		t.Fatalf("budget holds %d bytes, %d entries", bytes, entries)
	}
}

// TestOwner checks that what fiberd writes takes the owner it is given.
// Only root can give files away, so the test runs with its own ids
// unless it is root.
func TestOwner(t *testing.T) {
	owner := &Owner{UID: os.Getuid(), GID: os.Getgid()}
	if os.Geteuid() == 0 {
		owner = &Owner{UID: 65534, GID: 65534}
	}
	base := t.TempDir()
	ws, err := Open(filepath.Join(base, "ws"), Options{Budget: NewCounter(Limits{Bytes: 1 << 20}), Limits: Limits{Bytes: 1 << 20}, Owner: owner})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	if _, err := ws.Upload("d/f", 1, 0, nil, strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}
	if err := ws.Unpack(bytes.NewReader(makeTar(t, tarEntry{name: "u/", typ: tar.TypeDir}, tarEntry{name: "u/g", body: "y"}, tarEntry{name: "u/s", typ: tar.TypeSymlink, link: "g"}))); !errors.Is(err, ErrNotEmpty) {
		t.Fatalf("Unpack into a used root: %v", err)
	}
	ws2, err := Open(filepath.Join(base, "ws2"), Options{Budget: NewCounter(Limits{Bytes: 1 << 20}), Limits: Limits{Bytes: 1 << 20}, Owner: owner})
	if err != nil {
		t.Fatal(err)
	}
	defer ws2.Close()
	if err := ws2.Unpack(bytes.NewReader(makeTar(t, tarEntry{name: "u/", typ: tar.TypeDir}, tarEntry{name: "u/g", body: "y"}, tarEntry{name: "u/s", typ: tar.TypeSymlink, link: "g"}))); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		filepath.Join(base, "ws", rootName),
		filepath.Join(base, "ws", rootName, "d"),
		filepath.Join(base, "ws", rootName, "d", "f"),
		filepath.Join(base, "ws2", rootName, "u"),
		filepath.Join(base, "ws2", rootName, "u", "g"),
		filepath.Join(base, "ws2", rootName, "u", "s"),
	} {
		var st unix.Stat_t
		if err := unix.Lstat(p, &st); err != nil {
			t.Fatal(err)
		}
		if int(st.Uid) != owner.UID || int(st.Gid) != owner.GID {
			t.Fatalf("%s owned by %d:%d, want %d:%d", p, st.Uid, st.Gid, owner.UID, owner.GID)
		}
	}
}

// TestCaptureConcurrent runs several captures of one workspace at once.
// Each must carry every name exactly once. A listing that shared one
// directory offset between them would split the names.
func TestCaptureConcurrent(t *testing.T) {
	cases := []struct {
		name   string
		files  int
		at     int
		rounds int
	}{
		{name: "two at once", files: 3000, at: 2, rounds: 5},
		{name: "four at once", files: 3000, at: 4, rounds: 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t, Limits{Bytes: 1 << 20})
			for i := range tc.files {
				fx.write(t, fmt.Sprintf("f%05d", i), "")
			}
			for range tc.rounds {
				var wg sync.WaitGroup
				results := make([]map[string]tarEntry, tc.at)
				errs := make([]error, tc.at)
				for i := range tc.at {
					wg.Add(1)
					go func() {
						defer wg.Done()
						var buf bytes.Buffer
						if errs[i] = fx.ws.Capture(&buf); errs[i] == nil {
							results[i] = tarEntries(t, buf.Bytes())
						}
					}()
				}
				wg.Wait()
				for i := range tc.at {
					if errs[i] != nil {
						t.Fatalf("capture %d: %v", i, errs[i])
					}
					if len(results[i]) != tc.files {
						t.Fatalf("capture %d carried %d names, want %d", i, len(results[i]), tc.files)
					}
				}
			}
		})
	}
}

// netBudget is a Budget that keeps the net reservation and never
// clamps, so a release of what was never reserved shows as negative.
type netBudget struct {
	mu      sync.Mutex
	bytes   int64
	entries int64
}

func (n *netBudget) Reserve(b, e int64) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.bytes += b
	n.entries += e
	return nil
}

func (n *netBudget) Release(b, e int64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.bytes -= b
	n.entries -= e
}

// TestUnpackNet checks what Unpack leaves reserved on a budget that
// does not clamp, after a pass and after a failure.
func TestUnpackNet(t *testing.T) {
	cases := []struct {
		name                   string
		entries                []tarEntry
		wantErr                error
		wantBytes, wantEntries int64
	}{
		{name: "duplicate name then a refused entry", entries: []tarEntry{{name: "a", body: strings.Repeat("x", 100)}, {name: "a", body: strings.Repeat("y", 100)}, {name: "p", typ: tar.TypeFifo}}, wantErr: ErrArchive},
		{name: "duplicate name passes", entries: []tarEntry{{name: "a", body: strings.Repeat("x", 100)}, {name: "a", body: strings.Repeat("y", 100)}}, wantBytes: 100, wantEntries: 1},
		{name: "refused entry after two files", entries: []tarEntry{{name: "a", body: "x"}, {name: "b", body: "yz"}, {name: "../c", body: "w"}}, wantErr: ErrArchive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nb := &netBudget{}
			ws, err := Open(filepath.Join(t.TempDir(), "ws"), Options{Budget: nb, Limits: Limits{Bytes: 1 << 20}})
			if err != nil {
				t.Fatal(err)
			}
			defer ws.Close()
			err = ws.Unpack(bytes.NewReader(makeTar(t, tc.entries...)))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Unpack = %v, want %v", err, tc.wantErr)
			}
			if nb.bytes != tc.wantBytes || nb.entries != tc.wantEntries {
				t.Fatalf("net %d bytes, %d entries, want %d, %d", nb.bytes, nb.entries, tc.wantBytes, tc.wantEntries)
			}
		})
	}
}

// TestCaptureMemory checks that the hard link map holds only files
// with more than one name, so a large tree without links costs nothing
// there.
func TestCaptureMemory(t *testing.T) {
	cases := []struct {
		name  string
		files int
		links int
		want  int
	}{
		{name: "no links", files: 2000, want: 0},
		{name: "two linked pairs", files: 2000, links: 2, want: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t, Limits{Bytes: 1 << 20})
			for i := range tc.files {
				fx.write(t, fmt.Sprintf("f%05d", i), "")
			}
			for i := range tc.links {
				if err := os.Link(fx.in(fmt.Sprintf("f%05d", i)), fx.in(fmt.Sprintf("l%d", i))); err != nil {
					t.Fatal(err)
				}
			}
			c := &capture{w: fx.ws, tw: tar.NewWriter(io.Discard), first: map[inode]string{}, names: map[inode]int64{}, nlink: map[inode]int64{}}
			if err := c.dir(fx.ws.root, ""); err != nil {
				t.Fatal(err)
			}
			if len(c.first) != tc.want || len(c.names) != tc.want || len(c.nlink) != tc.want {
				t.Fatalf("maps hold %d, %d, %d, want %d", len(c.first), len(c.names), len(c.nlink), tc.want)
			}
		})
	}
}

// TestSize checks that Size counts the tree as Capture would, without
// reading a file: apparent bytes of regular files, a file with several
// names once, every name as an entry, and nothing of what is not a
// regular file. A tree past the entry ceiling is refused.
func TestSize(t *testing.T) {
	cases := []struct {
		name        string
		limits      Limits
		build       func(t *testing.T, fx *fixture)
		wantBytes   int64
		wantEntries int64
		wantErr     error
	}{
		{name: "empty", limits: Limits{Bytes: 1 << 20}},
		{name: "files and directories", limits: Limits{Bytes: 1 << 20}, build: func(t *testing.T, fx *fixture) {
			fx.write(t, "a", "12345")
			fx.write(t, "d/b", "123")
			fx.write(t, "d/e/c", "")
		}, wantBytes: 8, wantEntries: 5},
		{name: "a hard link counts its bytes once and its names twice", limits: Limits{Bytes: 1 << 20}, build: func(t *testing.T, fx *fixture) {
			fx.write(t, "a", "1234")
			if err := os.Link(fx.in("a"), fx.in("b")); err != nil {
				t.Fatal(err)
			}
		}, wantBytes: 4, wantEntries: 2},
		{name: "a symlink, a FIFO and a socket are entries without bytes", limits: Limits{Bytes: 1 << 20}, build: func(t *testing.T, fx *fixture) {
			fx.write(t, "a", "12")
			fx.symlink(t, "l", "a")
			fx.fifo(t, "f")
			fx.socket(t, "s")
		}, wantBytes: 2, wantEntries: 4},
		{name: "a symlink to a directory is never followed", limits: Limits{Bytes: 1 << 20}, build: func(t *testing.T, fx *fixture) {
			fx.symlink(t, "out", fx.outside)
		}, wantBytes: 0, wantEntries: 1},
		{name: "a sparse file counts by apparent size", limits: Limits{Bytes: 1 << 20}, build: func(t *testing.T, fx *fixture) {
			if err := os.Truncate(fx.in("hole"), 1<<30); err != nil {
				fx.write(t, "hole", "")
				if err := os.Truncate(fx.in("hole"), 1<<30); err != nil {
					t.Fatal(err)
				}
			}
		}, wantBytes: 1 << 30, wantEntries: 1},
		{name: "too many entries", limits: Limits{Bytes: 1 << 20, Entries: 3}, build: func(t *testing.T, fx *fixture) {
			for i := range 4 {
				fx.write(t, fmt.Sprintf("f%d", i), "")
			}
		}, wantErr: ErrEntries},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t, tc.limits)
			if tc.build != nil {
				tc.build(t, fx)
			}
			bytes, entries, err := fx.ws.Size()
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Size = %v, want %v", err, tc.wantErr)
			}
			if err == nil && (bytes != tc.wantBytes || entries != tc.wantEntries) {
				t.Fatalf("Size = %d bytes, %d entries, want %d, %d", bytes, entries, tc.wantBytes, tc.wantEntries)
			}
		})
	}
}
