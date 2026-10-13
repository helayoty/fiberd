//go:build linux && integration

package kubernetestest

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/helayoty/fiberd/examples/kubernetes/home"
	"github.com/helayoty/fiberd/examples/kubernetes/kube"
	"github.com/helayoty/fiberd/examples/kubernetes/kube/kubetest"
)

// mountTmpfs mounts a fresh tmpfs at dir until the test ends.
func mountTmpfs(t *testing.T, dir string) {
	t.Helper()
	if err := syscall.Mount("tmpfs", dir, "tmpfs", 0, ""); err != nil {
		t.Fatalf("cannot mount here (needs root and CAP_SYS_ADMIN): %v", err)
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

// fakeCgroupFiles makes dir look like a delegated cgroup v2 root, so the
// home carves its subtree there once the mount is writable.
func fakeCgroupFiles(t *testing.T, dir string) {
	t.Helper()
	for name, body := range map[string]string{"cgroup.subtree_control": "memory pids\n", "cgroup.procs": ""} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// newHome is home.New against an API server holding the Pod, on cgroupRoot.
func newHome(t *testing.T, cgroupRoot string) (*home.Home, error) {
	t.Helper()
	srv := kubetest.New()
	t.Cleanup(srv.Close)
	srv.Put("/api/v1/namespaces/ns/pods/p", map[string]any{})
	return home.New(home.Config{Client: &kube.Client{Base: srv.URL()}, Namespace: "ns", PodName: "p",
		CgroupRoot: cgroupRoot, TokenFile: filepath.Join(t.TempDir(), "no-token")})
}

// TestWritableMountsRemounts checks that a Pod's read-only cgroupfs is
// remounted read-write by New, so the home can delegate under it, and
// that a writable one is left as it is.
func TestWritableMountsRemounts(t *testing.T) {
	cases := []struct {
		name     string
		readOnly bool
	}{
		{name: "a read-only cgroupfs is remounted read-write", readOnly: true},
		{name: "a writable cgroupfs is left as it is"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			mountTmpfs(t, dir)
			fakeCgroupFiles(t, dir)
			if tc.readOnly {
				readOnlyMount(t, dir)
			}
			h, err := newHome(t, dir)
			if err != nil {
				t.Fatalf("New = %v", err)
			}
			if got := h.CgroupRoot(); got != filepath.Join(dir, "grants") {
				t.Fatalf("cgroup root = %q, want the grants subtree under %s", got, dir)
			}
			if err := os.WriteFile(filepath.Join(dir, "probe"), nil, 0o644); err != nil {
				t.Fatalf("%s is still read-only: %v", dir, err)
			}
		})
	}
}

// TestNewFailsOnAReadOnlyCgroup checks that New refuses to start when the
// cgroupfs stays read-only, since nothing could be bounded under it. A
// read-only directory that is not itself a mount point cannot be
// remounted.
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
			fakeCgroupFiles(t, sub)
			readOnlyMount(t, dir)
			_, err := newHome(t, sub)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("New = %v, want %q", err, tc.wantErr)
			}
		})
	}
}
