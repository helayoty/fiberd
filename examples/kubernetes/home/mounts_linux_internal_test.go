//go:build linux

package home

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/helayoty/fiberd/examples/kubernetes/kube"
	"github.com/helayoty/fiberd/examples/kubernetes/kube/kubetest"
)

// mountTmpfs mounts a fresh tmpfs at dir until the test ends.
func mountTmpfs(t *testing.T, dir string) {
	t.Helper()
	if err := syscall.Mount("tmpfs", dir, "tmpfs", 0, ""); err != nil {
		t.Skipf("cannot mount here (needs root and CAP_SYS_ADMIN): %v", err)
	}
	t.Cleanup(func() { _ = syscall.Unmount(dir, syscall.MNT_DETACH) })
}

// readOnlyMount makes the mount at dir read-only for this mount only, the
// way a runtime mounts /proc/sys and the cgroupfs into a Pod.
func readOnlyMount(t *testing.T, dir string) {
	t.Helper()
	if err := syscall.Mount("", dir, "", syscall.MS_REMOUNT|syscall.MS_BIND|syscall.MS_RDONLY, ""); err != nil {
		t.Fatal(err)
	}
}

// TestWritableMounts checks that the agent makes its read-only cgroupfs
// and criu's sysctls writable, and what it does when it cannot.
func TestWritableMounts(t *testing.T) {
	cases := []struct {
		name string
		// prep returns the cgroupfs to pass and the sysctl files to use.
		prep     func(t *testing.T, dir string) (cgroupfs string, sysctls []string)
		wantErr  string
		writable []string // paths that must be writable afterwards
	}{
		{name: "a writable cgroupfs is left as it is",
			prep:     func(_ *testing.T, dir string) (string, []string) { return dir, nil },
			writable: []string{""}},
		{name: "a read-only cgroupfs is remounted read-write",
			prep: func(t *testing.T, dir string) (string, []string) {
				mountTmpfs(t, dir)
				readOnlyMount(t, dir)
				return dir, nil
			},
			writable: []string{""}},
		{name: "a read-only cgroupfs that is not a mount point cannot be remounted, which is an error",
			prep: func(t *testing.T, dir string) (string, []string) {
				mountTmpfs(t, dir)
				if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
					t.Fatal(err)
				}
				readOnlyMount(t, dir)
				return filepath.Join(dir, "sub"), nil
			},
			wantErr: "remount " + "%s/sub read-write"},
		{name: "a read-only sysctl is bound over itself read-write; a writable one is left",
			prep: func(t *testing.T, dir string) (string, []string) {
				mountTmpfs(t, dir)
				for _, f := range []string{"ns_last_pid", "other"} {
					if err := os.WriteFile(filepath.Join(dir, f), []byte("1"), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				ro := filepath.Join(dir, "ro")
				if err := os.Mkdir(ro, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := syscall.Mount(dir, ro, "", syscall.MS_BIND, ""); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = syscall.Unmount(ro, syscall.MNT_DETACH) })
				readOnlyMount(t, ro)
				t.Cleanup(func() { _ = syscall.Unmount(filepath.Join(ro, "ns_last_pid"), syscall.MNT_DETACH) })
				return t.TempDir(), []string{filepath.Join(ro, "ns_last_pid"), filepath.Join(dir, "other")}
			},
			writable: []string{"ro/ns_last_pid", "other"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cgroupfs, sysctls := tc.prep(t, dir)
			old := criuSysctls
			criuSysctls = sysctls
			t.Cleanup(func() { criuSysctls = old })
			err := writableMounts(cgroupfs)
			if tc.wantErr != "" {
				want := strings.ReplaceAll(tc.wantErr, "%s", dir)
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("writableMounts = %v, want %q", err, want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range tc.writable {
				path := cgroupfs
				if p != "" {
					path = filepath.Join(dir, p)
				}
				if readOnly(path) {
					t.Fatalf("%s is still read-only", path)
				}
			}
		})
	}
}

// TestNewFailsOnAReadOnlyCgroup checks that New refuses to start when the
// cgroupfs stays read-only, since nothing could be bounded under it.
func TestNewFailsOnAReadOnlyCgroup(t *testing.T) {
	cases := []struct {
		name    string
		wantErr string
	}{
		{name: "a cgroupfs that cannot be made writable", wantErr: "k8s: remount "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			mountTmpfs(t, dir)
			sub := filepath.Join(dir, "cgroup")
			if err := os.Mkdir(sub, 0o755); err != nil {
				t.Fatal(err)
			}
			readOnlyMount(t, dir)
			srv := kubetest.New()
			t.Cleanup(srv.Close)
			srv.Put("/api/v1/namespaces/ns/pods/p", map[string]any{})
			_, err := New(Config{Client: &kube.Client{Base: srv.URL()}, Namespace: "ns", PodName: "p",
				CgroupRoot: sub, TokenFile: filepath.Join(dir, "no-token")})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("New = %v, want %q", err, tc.wantErr)
			}
		})
	}
}
