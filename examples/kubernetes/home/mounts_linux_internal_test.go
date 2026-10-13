//go:build linux

package home

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/helayoty/fiberd/examples/kubernetes/kube"
	"github.com/helayoty/fiberd/examples/kubernetes/kube/kubetest"
)

// fakeMounter is a mount table in memory. Paths in ro answer EROFS until
// a remount of them succeeds. Every mount is recorded as "bind <path>" or
// "remount <path>", and fail names the ones that are refused.
type fakeMounter struct {
	ro    map[string]bool
	fail  map[string]error
	calls []string
}

func (m *fakeMounter) Access(path string, _ uint32) error {
	if m.ro[path] {
		return syscall.EROFS
	}
	return nil
}

func (m *fakeMounter) Mount(_, target, _ string, flags uintptr, _ string) error {
	key := "bind " + target
	if flags&syscall.MS_REMOUNT != 0 {
		key = "remount " + target
	}
	m.calls = append(m.calls, key)
	if err := m.fail[key]; err != nil {
		return err
	}
	if flags&syscall.MS_REMOUNT != 0 {
		m.ro[target] = false
	}
	return nil
}

// useMounter puts m behind the package for the test's duration.
func useMounter(t *testing.T, m *fakeMounter) {
	t.Helper()
	old := mounts
	mounts = m
	t.Cleanup(func() { mounts = old })
}

// TestWritableMounts checks that fiberd makes its read-only cgroupfs
// and criu's sysctls writable, and what it does when it cannot. The
// cgroupfs is /cg and the sysctls are /a and /b.
func TestWritableMounts(t *testing.T) {
	cases := []struct {
		name     string
		ro       []string
		fail     map[string]error
		calls    []string
		wantErr  string
		writable []string // paths that must be writable afterwards
		readOnly []string // paths that must still be read-only
	}{
		{name: "everything writable is left as it is",
			writable: []string{"/cg", "/a", "/b"}},
		{name: "a read-only cgroupfs is remounted read-write",
			ro: []string{"/cg"}, calls: []string{"remount /cg"}, writable: []string{"/cg"}},
		{name: "a cgroupfs that cannot be remounted is an error",
			ro: []string{"/cg"}, fail: map[string]error{"remount /cg": syscall.EPERM}, calls: []string{"remount /cg"},
			wantErr: "remount /cg read-write", readOnly: []string{"/cg"}},
		{name: "a read-only sysctl is bound over itself read-write; a writable one is left",
			ro: []string{"/a"}, calls: []string{"bind /a", "remount /a"}, writable: []string{"/a", "/b"}},
		{name: "a sysctl that cannot be bound is a warning, and the next one is still made writable",
			ro: []string{"/a", "/b"}, fail: map[string]error{"bind /a": syscall.EPERM},
			calls: []string{"bind /a", "bind /b", "remount /b"}, readOnly: []string{"/a"}, writable: []string{"/b"}},
		{name: "a sysctl that cannot be remounted is a warning",
			ro: []string{"/a"}, fail: map[string]error{"remount /a": syscall.EPERM},
			calls: []string{"bind /a", "remount /a"}, readOnly: []string{"/a"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &fakeMounter{ro: map[string]bool{}, fail: tc.fail}
			for _, p := range tc.ro {
				m.ro[p] = true
			}
			useMounter(t, m)
			old := criuSysctls
			criuSysctls = []string{"/a", "/b"}
			t.Cleanup(func() { criuSysctls = old })
			err := writableMounts("/cg")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !errors.Is(err, syscall.EPERM) {
					t.Fatalf("writableMounts = %v, want %q wrapping EPERM", err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(m.calls, tc.calls) {
				t.Fatalf("mounts = %q, want %q", m.calls, tc.calls)
			}
			for _, p := range tc.writable {
				if readOnly(p) {
					t.Fatalf("%s is still read-only", p)
				}
			}
			for _, p := range tc.readOnly {
				if !readOnly(p) {
					t.Fatalf("%s became writable although its mount failed", p)
				}
			}
		})
	}
}

// TestNewFailsOnAReadOnlyCgroup checks that New makes a read-only
// cgroupfs writable before it delegates under it, and refuses to start
// when it cannot, since nothing could be bounded there.
func TestNewFailsOnAReadOnlyCgroup(t *testing.T) {
	cases := []struct {
		name    string
		fail    map[string]error
		wantErr string
	}{
		{name: "a read-only cgroupfs is made writable first"},
		{name: "a cgroupfs that cannot be made writable", fail: map[string]error{"remount": syscall.EPERM}, wantErr: "k8s: remount "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cg := filepath.Join(dir, "cgroup")
			if err := os.Mkdir(cg, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(cg, "cgroup.subtree_control"), []byte("memory pids\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			m := &fakeMounter{ro: map[string]bool{cg: true}, fail: map[string]error{}}
			for k, err := range tc.fail {
				m.fail[k+" "+cg] = err
			}
			useMounter(t, m)
			old := criuSysctls
			criuSysctls = nil
			t.Cleanup(func() { criuSysctls = old })
			srv := kubetest.New()
			t.Cleanup(srv.Close)
			srv.Put("/api/v1/namespaces/ns/pods/p", map[string]any{})
			h, err := New(Config{Client: &kube.Client{Base: srv.URL()}, Namespace: "ns", PodName: "p",
				CgroupRoot: cg, TokenFile: filepath.Join(dir, "no-token")})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("New = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := h.CgroupRoot(); got != filepath.Join(cg, "grants") || !slices.Equal(m.calls, []string{"remount " + cg}) {
				t.Fatalf("cgroup root = %q after mounts %q, want the grants subtree after one remount", got, m.calls)
			}
		})
	}
}
