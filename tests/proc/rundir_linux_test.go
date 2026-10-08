//go:build linux

package proctest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	fiberendpoint "github.com/helayoty/fiberd/pkg/endpoint"
)

// TestFiberSeesOnlyItsRunDir: every grant's run directory sits under the
// agent's one run directory, and a proc fiber is euid 0, so until the
// zygote narrowed the view a fiber of one grant could stat, unlink and
// rebind another grant's endpoint sockets and fence files. Now the
// fiber's mount namespace covers the run directory with an empty
// read-only tmpfs and binds its own grant's directory back, so another
// grant's directory does not exist for it while its own endpoint still
// serves and the fence file the host writes beside it is readable. A
// park and resume keep the view: CRIU restores the cover and binds the
// resuming grant's directory.
func TestFiberSeesOnlyItsRunDir(t *testing.T) {
	cases := []struct {
		name     string
		template string
	}{
		{name: "current library", template: zygoteBin + " --heap-mb 32"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRuntimeFrom(t, nil, tc.template)
			ctx := context.Background()
			runDir := filepath.Join("/tmp", "fz-"+fmt.Sprint(os.Getpid()))
			ga := core.Grant{UID: "gra", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20}
			gb := core.Grant{UID: "grb", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20}
			for _, g := range []core.Grant{ga, gb} {
				if err := rt.PrepareTemplate(ctx, g); err != nil {
					t.Fatal(err)
				}
			}
			ha, err := rt.Clone(ctx, core.CloneSpec{Grant: ga, Fence: core.Fence{GrantUID: "gra", Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
			if err != nil {
				t.Fatalf("clone A: %v", err)
			}
			hb, err := rt.Clone(ctx, core.CloneSpec{Grant: gb, Fence: core.Fence{GrantUID: "grb", Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
			if err != nil {
				t.Fatalf("clone B: %v", err)
			}
			// A fence file of B's, as the host writes one beside a
			// resumed fiber's endpoint.
			bFence := fiberendpoint.UnixPath(hb.Endpoint) + ".fence"
			if err := os.WriteFile(bFence, []byte("grb/1/1\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			// probe runs the read-only stat probe in the fiber at ep
			// against every path and compares with what it should see.
			probe := func(when, ep string, want map[string]string) {
				t.Helper()
				for path, kind := range want {
					if got := talk(t, ep, "stat "+path); got != kind {
						t.Errorf("%s: fiber at %s sees %s as %q, want %q", when, ep, path, got, kind)
					}
				}
			}
			fromA := map[string]string{
				runDir:                                     "dir",
				filepath.Join(runDir, "gra"):               "dir",
				fiberendpoint.UnixPath(ha.Endpoint):        "sock",
				filepath.Join(runDir, "grb"):               "ENOENT",
				fiberendpoint.UnixPath(hb.Endpoint):        "ENOENT",
				bFence:                                     "ENOENT",
				filepath.Join(runDir, "grb", "zygote.log"): "ENOENT",
			}
			probe("born A", ha.Endpoint, fromA)
			probe("born B", hb.Endpoint, map[string]string{
				fiberendpoint.UnixPath(hb.Endpoint): "sock",
				fiberendpoint.UnixPath(ha.Endpoint): "ENOENT",
				filepath.Join(runDir, "gra"):        "ENOENT",
			})
			if got := talk(t, ha.Endpoint, "fence"); got != "gra/1/1" {
				t.Fatalf("A fence = %q", got)
			}
			if got := talk(t, hb.Endpoint, "ping"); got != "pong" {
				t.Fatalf("B ping = %q", got)
			}

			// Across a park and resume of A, with B still running.
			if rt.Tier() < core.TierCheckpoint {
				t.Skipf("criu not usable here; runtime offers %v, park and resume not checked", rt.Tier())
			}
			ref, err := rt.Park(ctx, ha.ID, true)
			if err != nil {
				t.Fatalf("park A: %v", err)
			}
			ha2, err := rt.Clone(ctx, core.CloneSpec{Grant: ga, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: "gra", Epoch: 1, Seq: 2}, Deadline: 5 * time.Second})
			if err != nil {
				t.Fatalf("resume A: %v", err)
			}
			if got := talk(t, ha2.Endpoint, "ping"); got != "pong" {
				t.Fatalf("resumed A ping = %q", got)
			}
			fromA[fiberendpoint.UnixPath(ha2.Endpoint)] = "sock"
			probe("resumed A", ha2.Endpoint, fromA)
			// The fence file the host wrote for the new incarnation is
			// in A's directory, which the fiber sees through its bind.
			if got := talk(t, ha2.Endpoint, "read "+fiberendpoint.UnixPath(ha2.Endpoint)+".fence"); got != "gra/1/2" {
				t.Fatalf("resumed A reads its fence file as %q, want gra/1/2", got)
			}
			probe("B after A resumed", hb.Endpoint, map[string]string{
				fiberendpoint.UnixPath(ha2.Endpoint):            "ENOENT",
				fiberendpoint.UnixPath(ha2.Endpoint) + ".fence": "ENOENT",
			})
			for _, h := range []core.FiberHandle{ha2, hb} {
				if err := rt.Release(ctx, h.ID, true); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
