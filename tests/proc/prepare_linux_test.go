//go:build linux

package proctest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

var (
	earlyThreadOnce sync.Once
	earlyThreadBin  string
	earlyThreadErr  error
)

// earlyThread builds the template in testdata/earlythread.c once per test
// binary, beside refzygote, with the library it misuses, and returns its
// path.
func earlyThread(t *testing.T) string {
	t.Helper()
	earlyThreadOnce.Do(func() {
		earlyThreadBin = filepath.Join(filepath.Dir(zygoteBin), "earlythread")
		build := exec.Command("gcc", "-O2", "-pthread", "-o", earlyThreadBin, "testdata/earlythread.c", "../../zygote/libfiberzygote.c")
		if out, err := build.CombinedOutput(); err != nil {
			earlyThreadErr = fmt.Errorf("%w: %s", err, out)
		}
	})
	if earlyThreadErr != nil {
		t.Skipf("cannot build earlythread: %v", earlyThreadErr)
	}
	return earlyThreadBin
}

// TestPrepareFailureFailsTheWarm pins that a zygote which could not
// prepare the mount namespace its fibers copy is no warm template. It
// answers PREPARE with ERROR ? naming the reason instead of READY and
// ends, Warm fails with that reason, the zygote's log names it, and no
// fiber is born. Every fiber of a plain proc grant asks for a mount
// namespace, so a zygote that would refuse them all must not let the home
// report the grant ready. The old zygote said READY first and the reason
// after it, so the warm went through, the home reported the template
// ready, and every clone was then refused. That is what the compare-proc
// grant Pod did in kind, sitting ready behind a cover its zygote could
// not build. A HIDE path that is a file is one such failure, and a
// template that starts a thread before fz_init is another, since the
// library cannot then take a namespace for the whole process.
func TestPrepareFailureFailsTheWarm(t *testing.T) {
	cases := []struct {
		name string
		// argv is the template, and hide the HIDE paths, set up under
		// dir. wantErr is what Warm's error must mention, and wantLog
		// what the zygote's log must.
		argv    func(t *testing.T, dir string) (argv, hide []string)
		wantErr func(dir string) []string
		wantLog string
	}{
		{
			name: "a HIDE path that is a file cannot be covered",
			argv: func(t *testing.T, dir string) ([]string, []string) {
				file := filepath.Join(dir, "a-file")
				if err := os.WriteFile(file, []byte("visible\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				return []string{zygoteBin, "--heap-mb", "16"}, []string{file}
			},
			wantErr: func(dir string) []string {
				return []string{"could not prepare the mount namespace", "the zygote could not cover a HIDE path (" + filepath.Join(dir, "a-file") + ": Not a directory)"}
			},
			wantLog: "PREPARE refused: the zygote could not cover a HIDE path",
		},
		{
			name: "a thread before fz_init leaves the zygote without a namespace of its own",
			argv: func(t *testing.T, dir string) ([]string, []string) {
				return []string{earlyThread(t)}, []string{hiddenDir}
			},
			wantErr: func(string) []string {
				return []string{"could not prepare the mount namespace", "a thread existed before fz_init, so the zygote took no mount namespace of its own"}
			},
			wantLog: "PREPARE refused: a thread existed before fz_init",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			argv, hide := tc.argv(t, dir)
			_, _, err := tryWarmArgv(t, dir, "gp", argv, hide)
			for _, want := range tc.wantErr(dir) {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("warm = %v, want it to fail with an error mentioning %q", err, want)
				}
			}
			ents, _ := os.ReadDir(dir)
			for _, e := range ents {
				if strings.HasSuffix(e.Name(), ".sock") {
					t.Fatalf("a fiber serves at %s although the warm failed", e.Name())
				}
			}
			b, err := os.ReadFile(filepath.Join(dir, "zygote.log"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(b), tc.wantLog) {
				t.Fatalf("zygote log:\n%s\nwant it to say %q", b, tc.wantLog)
			}
		})
	}
}

// TestZygoteCannotSeeHiddenPaths pins that the zygote itself, not only
// its fibers, lives behind the covers once it has said READY. Its root,
// read through /proc/<pid>/root, shows the hidden directory empty and the
// other grant's run directory gone, while this test, in the host's
// namespace, sees both. The old zygote shared the host's namespace and
// saw everything, since each child covered the paths for itself.
func TestZygoteCannotSeeHiddenPaths(t *testing.T) {
	cases := []struct {
		name string
		// path is relative to the run directory's parent, or absolute.
		// hostSees and zygoteSees are what stat finds from each side.
		path                 func(parent, own, other, secret string) string
		hostSees, zygoteSees string
	}{
		{name: "the hidden secret", path: func(_, _, _, secret string) string { return secret }, hostSees: "file", zygoteSees: "ENOENT"},
		{name: "the other grant's run directory", path: func(_, _, other, _ string) string { return other }, hostSees: "dir", zygoteSees: "ENOENT"},
		{name: "the other grant's socket", path: func(_, _, other, _ string) string { return filepath.Join(other, "x.sock") }, hostSees: "file", zygoteSees: "ENOENT"},
		{name: "its own run directory", path: func(_, own, _, _ string) string { return own }, hostSees: "dir", zygoteSees: "dir"},
		{name: "the run directory's parent", path: func(parent, _, _, _ string) string { return parent }, hostSees: "dir", zygoteSees: "dir"},
	}
	parent := t.TempDir()
	own := filepath.Join(parent, "gz")
	other := filepath.Join(parent, "other")
	for _, d := range []string{own, other} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(other, "x.sock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// The secret sits outside the run directory, so it is the HIDE cover
	// that hides it and not the run directory's.
	secretDir, secret := secretUnder(t, t.TempDir())
	be, w := warmDirect(t, own, []string{secretDir})
	// A fiber is born too, so the zygote is known to serve with the view
	// under test, and the fiber sees what the zygote sees.
	if _, err := cloneDirect(t, be, w, own, "gz/1-1", ""); err != nil {
		t.Fatalf("clone: %v", err)
	}
	ep := filepath.Join(own, "gz-1-1.sock")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.path(parent, own, other, secret)
			if got := statKind(path); got != tc.hostSees {
				t.Fatalf("the host sees %s as %q, want %q", path, got, tc.hostSees)
			}
			if got := statKind(filepath.Join(fmt.Sprintf("/proc/%d/root", w.PID), path)); got != tc.zygoteSees {
				t.Errorf("the zygote sees %s as %q, want %q", path, got, tc.zygoteSees)
			}
			if got := talk(t, ep, "stat "+path); got != tc.zygoteSees {
				t.Errorf("the fiber sees %s as %q, want %q", path, got, tc.zygoteSees)
			}
		})
	}
}

// statKind is what stat finds at path, as refzygote's stat probe says it.
func statKind(path string) string {
	st, err := os.Stat(path)
	switch {
	case err == nil && st.IsDir():
		return "dir"
	case err == nil && st.Mode().IsRegular():
		return "file"
	case err == nil:
		return "other"
	case os.IsNotExist(err):
		return "ENOENT"
	default:
		return err.Error()
	}
}

// TestLateSysMountIsNotWritable pins that a mount the host adds under
// /sys after READY gives a later fiber nothing to write. The zygote's
// namespace is private, so the mount never reaches it or any fiber's
// copy, and the fiber finds the mount point empty. A fiber born before
// the mount is unaffected too, and /sys itself stays read-only as before.
// The old code copied the host's namespace at each birth, so the new
// mount reached the fiber and was made read-only there (EROFS). Either
// answer keeps the host's knobs closed, and this test takes any but ok.
func TestLateSysMountIsNotWritable(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to mount under /sys")
	}
	// A mount point under /sys that is an empty directory here. The
	// kernels and containers the tests run on differ in what sits
	// under /sys, so the first that fits is taken.
	point := ""
	for _, p := range []string{"/sys/fs/bpf", "/sys/kernel/debug", "/sys/kernel/tracing", "/sys/fs/fuse/connections", "/sys/kernel/config"} {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			point = p
			break
		}
	}
	if point == "" {
		t.Skip("no mount point under /sys to use")
	}
	dir := t.TempDir()
	be, w := warmDirect(t, dir, nil)
	if _, err := cloneDirect(t, be, w, dir, "gs/1-1", ""); err != nil {
		t.Fatalf("clone before the mount: %v", err)
	}
	if err := syscall.Mount("tmpfs", point, "tmpfs", 0, "size=64k,mode=0755"); err != nil {
		t.Skipf("cannot mount a tmpfs at %s: %v", point, err)
	}
	t.Cleanup(func() { _ = syscall.Unmount(point, syscall.MNT_DETACH) })
	knob := filepath.Join(point, "late-knob")
	if err := os.WriteFile(knob, []byte("host writes this\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := cloneDirect(t, be, w, dir, "gs/1-2", ""); err != nil {
		t.Fatalf("clone after the mount: %v", err)
	}
	cases := []struct {
		name, endpoint string
	}{
		{name: "fiber born before the mount", endpoint: filepath.Join(dir, "gs-1-1.sock")},
		{name: "fiber born after the mount", endpoint: filepath.Join(dir, "gs-1-2.sock")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := talk(t, tc.endpoint, "wopen "+knob); got == "ok" {
				t.Fatalf("open %s for writing = ok, want it refused or absent", knob)
			} else {
				t.Logf("open %s for writing = %s", knob, got)
			}
			if got := talk(t, tc.endpoint, "wopen /sys/kernel/mm/transparent_hugepage/enabled"); got != "EROFS" && got != "ENOENT" {
				t.Fatalf("open a sysfs knob for writing = %q, want EROFS", got)
			}
		})
	}
}
