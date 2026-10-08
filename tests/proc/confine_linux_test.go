//go:build linux

package proctest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
	procbackend "github.com/helayoty/fiberd/pkg/backend/proc"
)

// warmDirect opens the fork backend on its own, without the host
// runtime, and warms one zygote for a grant whose run directory is dir
// and that hides the given paths. Fibers are forked into the test's own
// cgroup with no leaf, because these tests are about the zygote's answers,
// not accounting. Their endpoints go under dir, the only part of dir's
// parent a fiber sees.
func warmDirect(t *testing.T, dir string, hide []string) (*procbackend.Backend, backend.Warm) {
	t.Helper()
	be := procbackend.NewBackend(procbackend.Options{})
	t.Cleanup(be.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	w, err := be.Warm(ctx, backend.WarmSpec{
		GrantUID:      "gd",
		Template:      backend.Template{Argv: []string{zygoteBin, "--heap-mb", "16"}},
		CgroupFD:      -1,
		ProbeCgroupFD: -1,
		WorkDir:       dir,
		Hide:          hide,
	})
	if err != nil {
		t.Fatalf("warm: %v", err)
	}
	return be, w
}

// cloneDirect forks one fiber of w serving a unix socket under dir, the
// run directory w was warmed with.
func cloneDirect(t *testing.T, be *procbackend.Backend, w backend.Warm, dir, fence, payload string) (backend.Fiber, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return be.Clone(ctx, w.ID, backend.FiberSpec{
		Fence:    fence,
		Endpoint: filepath.Join(dir, strings.ReplaceAll(fence, "/", "-")+".sock"),
		CgroupFD: -1,
		Deadline: 2 * time.Second,
		OwnPIDNS: true,
		Payload:  []byte(payload),
	})
}

// TestHideFailureRefusesClone pins that a fiber runs only when every HIDE
// path is covered, so a hidden secret is never left visible. The zygote
// covers the paths once, in its own mount namespace before READY, so a
// path that cannot be covered fails the warm, as more paths than the
// zygote holds do, and no clone is ever asked of such a zygote. The
// property is the old one, that no fiber runs with a HIDE path
// uncovered. The oldest code found out in each child, which ended with
// exit 113. The code after it had the zygote say READY and refuse every
// clone, which let a home report ready on a grant that served nothing.
func TestHideFailureRefusesClone(t *testing.T) {
	cases := []struct {
		name string
		// hide makes the grant's HIDE paths under dir. secret is a file
		// the fiber must not read when it runs.
		hide func(t *testing.T, dir string) (hide []string, secret string)
		// wantErr names what the warm's error must say, or nil for
		// success, when a fiber runs.
		wantErr []string
	}{
		{
			name: "an uncoverable path fails the warm",
			hide: func(t *testing.T, dir string) ([]string, string) {
				file := filepath.Join(dir, "a-file")
				if err := os.WriteFile(file, []byte("visible\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				secretDir, secret := secretUnder(t, dir)
				return []string{file, secretDir}, secret
			},
			wantErr: []string{"could not prepare the mount namespace", "the zygote could not cover a HIDE path"},
		},
		{
			name: "a refused HIDE line fails the warm",
			hide: func(t *testing.T, dir string) ([]string, string) {
				// The zygote holds 16 paths. The secret is the 17th, whose
				// HIDE line it refuses.
				var hide []string
				for i := 0; i < 16; i++ {
					d := filepath.Join(dir, fmt.Sprintf("extra-%d", i))
					if err := os.Mkdir(d, 0o700); err != nil {
						t.Fatal(err)
					}
					hide = append(hide, d)
				}
				secretDir, secret := secretUnder(t, dir)
				return append(hide, secretDir), secret
			},
			wantErr: []string{"could not prepare the mount namespace", "HIDE: too many paths"},
		},
		{
			name: "a long uncoverable path is still named in the reason",
			hide: func(t *testing.T, dir string) ([]string, string) {
				// Five directories of 200 characters, then a file, so the
				// ERROR naming the path passes the 1024 bytes the old
				// zygote's send buffer held. It dropped the line, and the
				// agent saw a bare EOF instead of the reason.
				long := dir
				for i := 0; i < 5; i++ {
					long = filepath.Join(long, strings.Repeat("d", 200))
				}
				if err := os.MkdirAll(long, 0o700); err != nil {
					t.Fatal(err)
				}
				file := filepath.Join(long, "a-file")
				if err := os.WriteFile(file, []byte("visible\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				secretDir, secret := secretUnder(t, dir)
				return []string{file, secretDir}, secret
			},
			wantErr: []string{"the zygote could not cover a HIDE path", strings.Repeat("d", 200) + "/a-file: Not a directory"},
		},
		{
			name: "every path covered, the fiber runs",
			hide: func(t *testing.T, dir string) ([]string, string) {
				secretDir, secret := secretUnder(t, dir)
				return []string{secretDir}, secret
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			hide, secret := tc.hide(t, dir)
			if tc.wantErr != nil {
				_, _, err := tryWarmArgv(t, dir, "gd", []string{zygoteBin, "--heap-mb", "16"}, hide)
				for _, want := range tc.wantErr {
					if err == nil || !strings.Contains(err.Error(), want) {
						t.Fatalf("warm = %v, want it to fail with an error mentioning %q", err, want)
					}
				}
				return
			}
			be, w := warmDirect(t, dir, hide)
			if _, err := cloneDirect(t, be, w, dir, "gd/1-1", ""); err != nil {
				t.Fatalf("clone: %v", err)
			}
			ep := filepath.Join(dir, "gd-1-1.sock")
			if got := talk(t, ep, "read "+secret); got != "-" {
				t.Fatalf("read of the secret = %q, want - (covered)", got)
			}
			if got := talk(t, ep, "status CapEff"); got != "0000000000000000" {
				t.Fatalf("CapEff = %q, want none", got)
			}
		})
	}
}

// secretUnder makes dir/secrets/key, a secret no fiber may read.
func secretUnder(t *testing.T, dir string) (secretDir, secret string) {
	t.Helper()
	secretDir = filepath.Join(dir, "secrets")
	if err := os.Mkdir(secretDir, 0o700); err != nil {
		t.Fatal(err)
	}
	secret = filepath.Join(secretDir, "key")
	if err := os.WriteFile(secret, []byte("agent only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return secretDir, secret
}
