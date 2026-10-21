//go:build linux && integration

package runctest

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/tests/internal/testenv"
)

// TestFiberFilter pins the fiber filter on a runc fiber, born and after a
// park and resume. The restore puts the fiber in a fresh user namespace,
// so the filter it carries is what still refuses it a nested one there.
// A runc fiber keeps CAP_SYS_ADMIN alone, which CRIU's parasite needs,
// and its program refuses the mount family that capability would allow.
func TestFiberFilter(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	hm := newHome(t, nil)
	ctx := context.Background()
	g := core.Grant{UID: "sc", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20}
	if err := hm.rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	fence := core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}
	h, err := hm.rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: fence, Deadline: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	const sysAdmin = "0000000000200000"
	status := []struct{ cmd, want string }{
		{cmd: "status Seccomp", want: "2"},
		{cmd: "status NoNewPrivs", want: "1"},
		{cmd: "status CapEff", want: sysAdmin},
		{cmd: "status CapPrm", want: sysAdmin},
		{cmd: "status CapBnd", want: sysAdmin},
		{cmd: "status CapInh", want: "0000000000000000"},
		{cmd: "status CapAmb", want: "0000000000000000"},
		{cmd: "probe mount", want: "EPERM"},
		{cmd: "probe pivot-root", want: "EPERM"},
		{cmd: "probe chroot", want: "EPERM"},
	}
	check := func(when string, h core.FiberHandle, fence core.Fence) {
		for _, s := range status {
			t.Run(when+"/"+s.cmd, func(t *testing.T) {
				if got := talk(t, h.Endpoint, s.cmd); got != s.want {
					t.Errorf("%s = %q, want %q", s.cmd, got, s.want)
				}
			})
		}
		testenv.CheckFilter(t, when, func(t *testing.T, line string) string { return talk(t, h.Endpoint, line) })
		// fiberPID finds the fiber in its own leaf, where the birth's
		// clone3 put it.
		t.Run(when+"/in its leaf", func(t *testing.T) { hm.fiberPID(t, fence) })
	}
	check("born", h, fence)
	if got := statusField(t, hm.zygotePID(t, g.UID), "Seccomp"); got != "2" {
		t.Errorf("zygote Seccomp = %q, want 2: the filter is the zygote's, installed before READY", got)
	}
	talk(t, h.Endpoint, "incr")
	h2 := parkResume(t, hm.rt, g, h, 2)
	defer func() { _ = hm.rt.Release(ctx, h2.ID, true) }()
	if got := talk(t, h2.Endpoint, "get"); got != "1" {
		t.Fatalf("counter after resume = %q, want 1", got)
	}
	check("resumed", h2, core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 2})
}
