//go:build linux

package gvisor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
)

// fakeTmpfs stands in for the kernel's tmpfs calls, which need
// CAP_SYS_ADMIN. A directory counts as a tmpfs once it is in mounts.
type fakeTmpfs struct {
	mu       sync.Mutex
	mounts   map[string]bool
	statErr  error
	mountErr error
	calls    []string
	mounted  int // mounts that succeeded
}

func newFakeTmpfs() *fakeTmpfs { return &fakeTmpfs{mounts: map[string]bool{}} }

func (f *fakeTmpfs) ops() *tmpfsOps {
	return &tmpfsOps{
		isTmpfs: func(dir string) (bool, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.calls = append(f.calls, "statfs "+dir)
			return f.mounts[dir], f.statErr
		},
		mount: func(dir string) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.calls = append(f.calls, "mount "+dir)
			if f.mountErr != nil {
				return f.mountErr
			}
			f.mounts[dir] = true
			f.mounted++
			return nil
		},
		unmount: func(dir string) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.calls = append(f.calls, "unmount "+dir)
			delete(f.mounts, dir)
			return nil
		},
	}
}

func (f *fakeTmpfs) mountedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mounted
}

func (f *fakeTmpfs) log() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, "; ")
}

// shortState is a state directory short enough for the pool socket under
// it, which a unix socket path bounds at 108 bytes.
func shortState(t *testing.T) string {
	t.Helper()
	state, err := os.MkdirTemp("", "gv")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(state) })
	return filepath.Join(state, "state")
}

// mode is the permission bits of path, 0 when it cannot be read.
func mode(path string) os.FileMode {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Mode().Perm()
}

// TestOptionsDefaults checks what New fills in for unset options.
func TestOptionsDefaults(t *testing.T) {
	cases := []struct {
		name string
		in   Options
		want Options
	}{
		{name: "nothing set", in: Options{Rootfs: "/r"},
			want: Options{Runsc: "runsc", Rootfs: "/r", StateDir: "/var/lib/fiberd/gvisor", MaxRestores: max(1, runtime.GOMAXPROCS(0))}},
		{name: "everything set", in: Options{Runsc: "/opt/runsc", Rootfs: "/r", StateDir: "/s", MaxRestores: 3, TemplatesOnDisk: true},
			want: Options{Runsc: "/opt/runsc", Rootfs: "/r", StateDir: "/s", MaxRestores: 3, TemplatesOnDisk: true}},
		{name: "a negative restore bound", in: Options{Rootfs: "/r", StateDir: "/s", MaxRestores: -2},
			want: Options{Runsc: "runsc", Rootfs: "/r", StateDir: "/s", MaxRestores: max(1, runtime.GOMAXPROCS(0))}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.withDefaults(); got != tc.want {
				t.Fatalf("withDefaults = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestTemplatesTmpfs checks who mounts the templates tmpfs and when. New
// mounts it after the sweep, keeps one a previous life left, mounts
// nothing when told to keep templates on disk, and offers no tier when
// it cannot have the directory it was asked for. Close unmounts only what
// New mounted. The directory is 0700 either way, also when an earlier
// fiberd left it 0755 (regression: it was 0755). A tmpfs a previous life
// left is one also when templates are kept on disk (regression: the
// flag skipped the check, so every image there got O_DIRECT).
func TestTemplatesTmpfs(t *testing.T) {
	cases := []struct {
		name string
		// before prepares the state directory and the fake kernel.
		before      func(t *testing.T, state string, fs *fakeTmpfs)
		onDisk      bool
		wantTier    core.Tier
		wantWhy     string // in ProbeErr
		wantMount   bool   // New mounted a tmpfs
		wantOnTmpfs bool
		wantUnmount bool // Close unmounted it
	}{
		{name: "a fresh home mounts a tmpfs", wantTier: core.TierSnapshot, wantMount: true, wantOnTmpfs: true, wantUnmount: true},
		{name: "a tmpfs a previous life left is kept and emptied", before: func(t *testing.T, state string, fs *fakeTmpfs) {
			stale := filepath.Join(state, "templates", "w-old-1", "images")
			if err := os.MkdirAll(stale, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(stale, imageFile), []byte("old"), 0o644); err != nil {
				t.Fatal(err)
			}
			fs.mounts[filepath.Join(state, "templates")] = true
		}, wantTier: core.TierSnapshot, wantOnTmpfs: true},
		{name: "an on-disk directory left 0755 is emptied, covered and made 0700", before: func(t *testing.T, state string, _ *fakeTmpfs) {
			stale := filepath.Join(state, "templates", "w-old-1", "images")
			if err := os.MkdirAll(stale, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(state, "templates"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, wantTier: core.TierSnapshot, wantMount: true, wantOnTmpfs: true, wantUnmount: true},
		{name: "templates on disk, left 0755, made 0700", onDisk: true, before: func(t *testing.T, state string, _ *fakeTmpfs) {
			if err := os.MkdirAll(filepath.Join(state, "templates"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(state, "templates"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, wantTier: core.TierSnapshot},
		{name: "templates on disk, on a tmpfs a previous life left, is on a tmpfs", onDisk: true, before: func(_ *testing.T, state string, fs *fakeTmpfs) {
			fs.mounts[filepath.Join(state, "templates")] = true
		}, wantTier: core.TierSnapshot, wantOnTmpfs: true},
		{name: "the mount is refused", before: func(_ *testing.T, _ string, fs *fakeTmpfs) { fs.mountErr = syscall.EPERM },
			wantWhy: "mount a tmpfs on"},
		{name: "the file system cannot be told", before: func(_ *testing.T, _ string, fs *fakeTmpfs) { fs.statErr = syscall.EIO },
			wantWhy: "templates directory: input/output error"},
		{name: "the directory is a file", before: func(t *testing.T, state string, _ *fakeTmpfs) {
			if err := os.MkdirAll(state, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(state, "templates"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, wantWhy: "not a directory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := shortState(t)
			fs := newFakeTmpfs()
			if tc.before != nil {
				tc.before(t, state, fs)
			}
			f := newFakeRunsc(knobs{})
			t.Cleanup(f.endAll)
			b := newBackend(Options{Runsc: "runsc", Rootfs: t.TempDir(), StateDir: state, TemplatesOnDisk: tc.onDisk}, f.run, fs.ops())
			dir := filepath.Join(state, "templates")
			if b.Tier() != tc.wantTier {
				t.Fatalf("Tier = %s (%v), want %s", b.Tier(), b.ProbeErr(), tc.wantTier)
			}
			if tc.wantWhy != "" && (b.ProbeErr() == nil || !strings.Contains(b.ProbeErr().Error(), tc.wantWhy)) {
				t.Fatalf("ProbeErr = %v, want one mentioning %q", b.ProbeErr(), tc.wantWhy)
			}
			if tc.wantWhy == "mount a tmpfs on" && !strings.Contains(b.ProbeErr().Error(), "-gvisor-templates-on-disk") {
				t.Fatalf("ProbeErr = %v, want it to name the way out", b.ProbeErr())
			}
			if got := fs.mountedCount() == 1; got != tc.wantMount || b.mounted != tc.wantMount || b.onTmpfs != tc.wantOnTmpfs {
				t.Fatalf("mounted %v (backend says %v, on tmpfs %v), want %v and on tmpfs %v; calls %s", got, b.mounted, b.onTmpfs, tc.wantMount, tc.wantOnTmpfs, fs.log())
			}
			if tc.onDisk && strings.Contains(fs.log(), "mount ") {
				t.Fatalf("templates on disk mounted: %s", fs.log())
			}
			if tc.wantTier == core.TierSnapshot {
				if m := mode(dir); m != 0o700 {
					t.Fatalf("templates directory mode %v, want 0700", m)
				}
				if ents, err := os.ReadDir(dir); err != nil || len(ents) != 0 {
					t.Fatalf("templates directory holds %v (%v) after the sweep", ents, err)
				}
			}
			b.Close()
			b.Close()
			if got := strings.Count(fs.log(), "unmount "+dir); (got == 1) != tc.wantUnmount || got > 1 {
				t.Fatalf("Close unmounted %d times, want %v; calls %s", got, tc.wantUnmount, fs.log())
			}
		})
	}
}

// TestTemplateImageModes checks that a warm instance's directory, its
// image and its bundle are fiberd's alone (regression: the directory was
// 0755 and runsc's image files 0644), and that a template image on the
// tmpfs is checkpointed and restored without O_DIRECT, while one on disk
// and a park image keep it. A tmpfs a previous life left counts as one
// under -gvisor-templates-on-disk too (regression: O_DIRECT on it).
func TestTemplateImageModes(t *testing.T) {
	cases := []struct {
		name       string
		onDisk     bool
		leftTmpfs  bool // a previous life left a tmpfs on the directory
		wantDirect bool // the template checkpoint and its restores use O_DIRECT
	}{
		{name: "templates on the tmpfs"},
		{name: "templates on disk", onDisk: true, wantDirect: true},
		{name: "templates on disk, on a tmpfs a previous life left", onDisk: true, leftTmpfs: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRunsc(knobs{})
			rootfs := t.TempDir()
			state := shortState(t)
			fs := newFakeTmpfs()
			if tc.leftTmpfs {
				fs.mounts[filepath.Join(state, "templates")] = true
			}
			b := newBackend(Options{Runsc: "runsc", Rootfs: rootfs, StateDir: state, TemplatesOnDisk: tc.onDisk}, f.run, fs.ops())
			b.await = f.awaitExit
			if b.Tier() != core.TierSnapshot {
				t.Fatalf("Tier = %s (%v)", b.Tier(), b.ProbeErr())
			}
			t.Cleanup(func() { endFake(t, b, f) })
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			workDir := filepath.Join(t.TempDir(), "g")
			if _, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "g", Template: backend.Template{Argv: []string{"/bin/refzygote", "--gvisor"}}, CgroupFD: -1, ProbeCgroupFD: -1, WorkDir: workDir}); err != nil {
				t.Fatalf("Warm: %v", err)
			}
			wc := warmCID(t, b, "g")
			tdir := filepath.Join(b.templatesDir(), wc)
			for path, want := range map[string]os.FileMode{
				b.templatesDir():                             0o700,
				tdir:                                         0o700,
				filepath.Join(tdir, "images"):                0o700,
				filepath.Join(tdir, "images", imageFile):     0o600,
				filepath.Join(tdir, "bundle"):                0o700,
				filepath.Join(tdir, "bundle", "config.json"): 0o600,
			} {
				if got := mode(path); got != want {
					t.Errorf("%s mode %v, want %v", path, got, want)
				}
			}
			fc := "g/1-1"
			if _, err := b.Clone(ctx, "g", backend.FiberSpec{Fence: fc, Endpoint: filepath.Join(workDir, "ep.sock"), CgroupFD: -1, Deadline: 2 * time.Second, Generation: 1}); err != nil {
				t.Fatalf("Clone: %v", err)
			}
			fcid := boxCID(t, b, fc)
			if got := mode(filepath.Join(b.bundleDir(fcid), "config.json")); got != 0o600 {
				t.Errorf("fiber bundle mode %v, want 0600", got)
			}
			park := filepath.Join(t.TempDir(), "park")
			if err := b.Park(ctx, fc, backend.ParkSpec{Dir: park, Deadline: 2 * time.Second}); err != nil {
				t.Fatalf("Park: %v", err)
			}
			if got := mode(filepath.Join(park, "config.json")); got != 0o600 {
				t.Errorf("park bundle mode %v, want 0600", got)
			}
			calls := f.calls()
			ckpt := findCall(calls, "checkpoint --leave-running --image-path "+filepath.Join(tdir, "images"))
			restore := findCall(calls, "restore", "--image-path "+filepath.Join(tdir, "images"), fcid)
			parked := findCall(calls, "checkpoint --image-path "+park)
			if ckpt == "" || restore == "" || parked == "" {
				t.Fatalf("checkpoint %q, restore %q, park %q among\n%s", ckpt, restore, parked, strings.Join(calls, "\n"))
			}
			if strings.Contains(ckpt, directIO) != tc.wantDirect || strings.Contains(restore, directIO) != tc.wantDirect {
				t.Fatalf("checkpoint %q and restore %q, want O_DIRECT %v", ckpt, restore, tc.wantDirect)
			}
			if !strings.Contains(parked, directIO) {
				t.Fatalf("park %q without O_DIRECT", parked)
			}
		})
	}
}

// TestOwnerOnly checks the walk that tightens an image runsc wrote.
func TestOwnerOnly(t *testing.T) {
	cases := []struct {
		name    string
		make    func(t *testing.T, dir string)
		wantErr error
		want    map[string]os.FileMode // relative path -> mode
	}{
		{name: "nested files and directories", make: func(t *testing.T, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "a", "b"), 0o755); err != nil {
				t.Fatal(err)
			}
			for _, p := range []string{"top.img", "a/mid.img", "a/b/deep.img"} {
				if err := os.WriteFile(filepath.Join(dir, p), []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
		}, want: map[string]os.FileMode{".": 0o700, "a": 0o700, "a/b": 0o700, "top.img": 0o600, "a/mid.img": 0o600, "a/b/deep.img": 0o600}},
		{name: "a link is left alone, and so is what it names", make: func(t *testing.T, dir string) {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(filepath.Dir(dir), "outside"), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("../outside", filepath.Join(dir, "link")); err != nil {
				t.Fatal(err)
			}
		}, want: map[string]os.FileMode{".": 0o700, "../outside": 0o644}},
		{name: "a missing directory", make: func(*testing.T, string) {}, wantErr: os.ErrNotExist},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "images")
			tc.make(t, dir)
			err := ownerOnly(dir)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ownerOnly = %v, want %v", err, tc.wantErr)
			}
			for rel, want := range tc.want {
				if got := mode(filepath.Join(dir, rel)); got != want {
					t.Errorf("%s mode %v, want %v", rel, got, want)
				}
			}
		})
	}
}

// TestCloseEndsWarms checks that Close ends a Warm in flight and waits
// for it before it detaches the tmpfs, so no template image is written
// to the disk under the mount point, and that a Warm after Close is
// refused. Regression: Close knew only registered warms, so one waiting
// for its template outlived the detach and checkpointed onto the disk.
func TestCloseEndsWarms(t *testing.T) {
	cases := []struct {
		name string
		// closeFirst closes the backend before the warm starts.
		closeFirst bool
		wantErr    error
	}{
		{name: "a warm waiting for its template is ended, and Close waits for it", wantErr: context.Canceled},
		{name: "a warm after Close is refused", closeFirst: true, wantErr: errClosed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRunsc(knobs{NoMarker: true})
			t.Cleanup(f.endAll)
			fs := newFakeTmpfs()
			b := newBackend(Options{Runsc: "runsc", Rootfs: t.TempDir(), StateDir: shortState(t)}, f.run, fs.ops())
			b.await = f.awaitExit
			if b.Tier() != core.TierSnapshot {
				t.Fatalf("Tier = %s (%v)", b.Tier(), b.ProbeErr())
			}
			// Longer than closeWait, so a Close that does not end the warm
			// is seen to leave it running.
			ctx, cancel := context.WithTimeout(context.Background(), 2*closeWait)
			defer cancel()
			if tc.closeFirst {
				b.Close()
			}
			warmErr := make(chan error, 1)
			go func() {
				_, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "g", Template: backend.Template{Argv: []string{"/bin/refzygote", "--gvisor"}}, CgroupFD: -1, ProbeCgroupFD: -1, WorkDir: filepath.Join(t.TempDir(), "g")})
				warmErr <- err
			}()
			if !tc.closeFirst {
				waitFor(t, "the template sandbox to run", func() bool { return findCall(f.calls(), "run --detach") != "" })
				closed := make(chan struct{})
				go func() {
					b.Close()
					close(closed)
				}()
				select {
				case <-closed:
				case <-time.After(closeWait / 2):
					t.Fatal("Close did not return once the warm in flight was ended")
				}
			}
			var err error
			select {
			case err = <-warmErr:
			case <-time.After(time.Second):
				t.Fatal("the warm is still in flight after Close")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Warm = %v, want %v", err, tc.wantErr)
			}
			calls := f.calls()
			if findCall(calls, "checkpoint") != "" {
				t.Fatalf("a template image was written after Close:\n%s", strings.Join(calls, "\n"))
			}
			if cid := lastField(findCall(calls, "run --detach")); cid != "" {
				if f.alive(cid) {
					t.Fatalf("the template sandbox %s outlived Close", cid)
				}
				if _, err := os.Lstat(filepath.Join(b.templatesDir(), cid)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("the warm's directory stayed under the detached mount point: %v", err)
				}
			}
			if ents, _ := os.ReadDir(b.templatesDir()); len(ents) != 0 {
				t.Fatalf("templates directory holds %v after Close", ents)
			}
			if !strings.Contains(fs.log(), "unmount ") {
				t.Fatalf("Close did not unmount: %s", fs.log())
			}
			if !reapersDone(b, time.Second) {
				t.Fatal("a reaper is still running after Close")
			}
		})
	}
}

// TestTemplatesSourceNamesFiberd pins the templates tmpfs's mount source
// to the prefix a proc zygote drops (backend.MountSourcePrefix), so a
// proc home in the same mount namespace never carries this backend's
// template images into a fiber (regression: the source was a literal,
// and fibers parked on a mixed host could not be resumed once the tmpfs
// was gone).
func TestTemplatesSourceNamesFiberd(t *testing.T) {
	cases := []struct {
		name   string
		source string
		want   bool
	}{
		{name: "the templates tmpfs", source: templatesSource, want: true},
		{name: "a plain tmpfs", source: "tmpfs", want: false},
		{name: "the prefix inside a name", source: "my-fiberd-templates", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := strings.HasPrefix(tc.source, backend.MountSourcePrefix); got != tc.want {
				t.Fatalf("HasPrefix(%q, %q) = %v, want %v", tc.source, backend.MountSourcePrefix, got, tc.want)
			}
		})
	}
}
