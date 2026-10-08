//go:build linux

package proctest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	procbackend "github.com/helayoty/fiberd/pkg/backend/proc"
	"github.com/helayoty/fiberd/pkg/core"
)

// mountAt returns the optional fields (shared:N, master:N, ...) of the
// mount at path in this namespace, and whether there is one.
func mountAt(t *testing.T, path string) ([]string, bool) {
	t.Helper()
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	var opts []string
	found := false
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 7 || f[4] != path {
			continue
		}
		found, opts = true, nil
		for _, o := range f[6:] {
			if o == "-" {
				break
			}
			opts = append(opts, o)
		}
	}
	return opts, found
}

// TestRootBindIsPrivateAndCleaned: the restore root is a bind of / the
// fork backend mounts for CRIU's --root. It must not follow a symlink
// planted at its path, must be a private mount, and must be gone, mount
// and directory, when the backend closes. One a previous run left behind
// (a crash) is unmounted when a backend opens at the same path, since a
// fiber only drops the current root from its namespace and a stale one
// would show it the host's / without the hidden paths covered.
func TestRootBindIsPrivateAndCleaned(t *testing.T) {
	base := filepath.Join("/tmp", fmt.Sprintf("fz-root-%d", os.Getpid()))
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, p := range []string{"symlink", "fresh", "stale"} {
			_ = syscall.Unmount(filepath.Join(base, p), syscall.MNT_DETACH)
		}
		_ = os.RemoveAll(base)
	})
	cases := []struct {
		name string
		path string
		// prepare sets the scene at path before the backend opens.
		prepare       func(t *testing.T, path string)
		wantResumeErr bool
	}{
		{
			name: "symlink at the path is refused",
			path: filepath.Join(base, "symlink"),
			prepare: func(t *testing.T, path string) {
				if err := os.Symlink(t.TempDir(), path); err != nil {
					t.Fatal(err)
				}
			},
			wantResumeErr: true,
		},
		{name: "fresh path", path: filepath.Join(base, "fresh")},
		{
			name: "stale bind from a previous run",
			path: filepath.Join(base, "stale"),
			prepare: func(t *testing.T, path string) {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := syscall.Mount("/", path, "", syscall.MS_BIND, ""); err != nil {
					t.Fatal(err)
				}
			},
		},
		{name: "path reused after a clean close", path: filepath.Join(base, "fresh")},
	}
	ctx := context.Background()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.prepare != nil {
				tc.prepare(t, tc.path)
			}
			be := procbackend.New(procbackend.Options{RootBind: tc.path})
			if _, mounted := mountAt(t, tc.path); mounted {
				t.Fatalf("%s is still a mount point after the backend opened", tc.path)
			}
			rt := newRuntimeWith(t, be)
			if rt.Tier() < core.TierCheckpoint {
				t.Skip("criu not usable here; runtime offers", rt.Tier())
			}
			g := core.Grant{UID: "grb", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			h1, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "grb", Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			talk(t, h1.Endpoint, "incr")
			ref, err := rt.Park(ctx, h1.ID, true)
			if err != nil {
				t.Fatalf("park: %v", err)
			}
			h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: "grb", Epoch: 1, Seq: 2}, Deadline: 5 * time.Second})
			if tc.wantResumeErr {
				if err == nil {
					_ = rt.Release(ctx, h2.ID, true)
					t.Fatal("resume over a symlink succeeded")
				}
				if _, mounted := mountAt(t, tc.path); mounted {
					t.Fatalf("%s was mounted over: %v", tc.path, err)
				}
				if fi, lerr := os.Lstat(tc.path); lerr != nil || fi.Mode()&os.ModeSymlink == 0 {
					t.Fatalf("the symlink at %s was replaced (%v, %v)", tc.path, fi, lerr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resume: %v", err)
			}
			if got := talk(t, h2.Endpoint, "get"); got != "1" {
				t.Fatalf("resumed fiber get = %q, want 1", got)
			}
			opts, mounted := mountAt(t, tc.path)
			if !mounted {
				t.Fatalf("%s is not a mount point while a fiber is resumed on it", tc.path)
			}
			for _, o := range opts {
				if strings.HasPrefix(o, "shared:") || strings.HasPrefix(o, "master:") {
					t.Fatalf("restore root propagates: %v", opts)
				}
			}
			if err := rt.Release(ctx, h2.ID, true); err != nil {
				t.Fatal(err)
			}
			rt.(interface{ Close() }).Close()
			if _, mounted := mountAt(t, tc.path); mounted {
				t.Fatalf("%s is still mounted after Close", tc.path)
			}
			if _, err := os.Lstat(tc.path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("Lstat %s after Close = %v, want not exist", tc.path, err)
			}
		})
	}
}
