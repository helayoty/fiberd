//go:build linux && integration

package proctest

import (
	"context"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// TestWorkspaceQuotaEscapeRefused pins the file-transfer disk budget.
// The workspace budget is a project quota on the home. A proc fiber owns
// its workspace files in the initial user namespace, where the kernel
// lets an owner change a file's project id, so without the filter it
// could retag the files and leave the quota. The fiber filter refuses
// the two ioctl commands and the file_setattr syscall that do it, each
// with EPERM, so the escape is closed before a byte moves.
//
// This is a regression test for helayoty/fiberd#33. On the old filter,
// which did not look at ioctl and did not list file_setattr, the three
// probes answer something other than EPERM.
func TestWorkspaceQuotaEscapeRefused(t *testing.T) {
	needRoot(t)
	rt := newRuntime(t)
	ctx := context.Background()
	g := core.Grant{UID: "gquota", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	t.Cleanup(func() { _ = rt.Release(ctx, h.ID, true) })

	cases := []struct {
		name, probe, want string
	}{
		{name: "FS_IOC_FSSETXATTR sets the project id", probe: "fssetxattr", want: "EPERM"},
		{name: "FS_IOC_SETFLAGS clears PROJINHERIT", probe: "setflags", want: "EPERM"},
		{name: "file_setattr is the syscall twin", probe: "file-setattr", want: "EPERM"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := talk(t, h.Endpoint, "probe "+tc.probe); got != tc.want {
				t.Errorf("probe %s = %q, want %q", tc.probe, got, tc.want)
			}
		})
	}
}
