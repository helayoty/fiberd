//go:build linux && integration

package proctest

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/helayoty/fiberd/pkg/core"
)

// TestChannelBorrowedByFiberdAlone pins what keeps a resume's record
// private. fiberd takes the peer end of a restored fiber's channel pair
// with pidfd_open and pidfd_getfd, which needs ptrace rights over the
// fiber: this process has them, as root with CAP_SYS_PTRACE in the
// initial user namespace. A fiber of another grant has neither. It is
// the init of a pid namespace of its own, where the other fiber's pid
// names nothing, so pidfd_open answers ESRCH before any ptrace check,
// and it holds no capability. The rows ask fiber B to borrow fiber A's
// channel ends, as fiberd would, by A's host pid. The fiber filter
// refuses pidfd_getfd to every fiber besides.
func TestChannelBorrowedByFiberdAlone(t *testing.T) {
	ctx := context.Background()
	rt := newRuntime(t)
	ga := core.Grant{UID: "gba", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20}
	gb := core.Grant{UID: "gbb", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20}
	for _, g := range []core.Grant{ga, gb} {
		if err := rt.PrepareTemplate(ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	ha, err := rt.Clone(ctx, core.CloneSpec{Grant: ga, Fence: core.Fence{GrantUID: ga.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatalf("clone A: %v", err)
	}
	hb, err := rt.Clone(ctx, core.CloneSpec{Grant: gb, Fence: core.Fence{GrantUID: gb.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatalf("clone B: %v", err)
	}
	t.Cleanup(func() {
		_ = rt.Release(ctx, ha.ID, true)
		_ = rt.Release(ctx, hb.ID, true)
	})
	// A's host pid, from its leaf.
	procs := filepath.Join(cgRoot, filepath.Base(rt.(interface{ CgroupRoot() string }).CgroupRoot()), ga.UID, "fibers", "f-1-1", "cgroup.procs")
	pids := readPIDs(t, procs)
	if len(pids) != 1 {
		t.Fatalf("A's leaf holds %v, want one task", pids)
	}
	pidA := pids[0]
	cases := []struct {
		name string
		fd   int
	}{
		{name: "the end the fiber reads", fd: 4},
		{name: "the peer end fiberd borrows", fd: 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// This process can, which is what a resume relies on.
			pidfd, err := unix.PidfdOpen(pidA, 0)
			if err != nil {
				t.Fatalf("pidfd_open of A from fiberd: %v", err)
			}
			defer func() { _ = unix.Close(pidfd) }()
			got, err := unix.PidfdGetfd(pidfd, tc.fd, 0)
			if err != nil {
				t.Fatalf("pidfd_getfd %d of A from fiberd: %v", tc.fd, err)
			}
			_ = unix.Close(got)
			// B cannot, by A's host pid or by any pid B can name.
			if got := talk(t, hb.Endpoint, fmt.Sprintf("borrow %d %d", pidA, tc.fd)); got != "ESRCH" {
				t.Fatalf("B borrowing fd %d of A's host pid %d = %q, want ESRCH (A does not exist in B's pid namespace)", tc.fd, pidA, got)
			}
			// Nor from itself, since the fiber filter refuses
			// pidfd_getfd to every fiber. fiberd's own call, from
			// outside the filter, is the one that works.
			if got := talk(t, hb.Endpoint, "borrow 1 "+strconv.Itoa(tc.fd)); got != "EPERM" {
				t.Fatalf("B borrowing fd %d of its own pid 1 = %q, want EPERM (the fiber filter refuses pidfd_getfd)", tc.fd, got)
			}
		})
	}
}
