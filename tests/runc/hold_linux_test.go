//go:build linux

package runctest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	runcbackend "github.com/helayoty/fiberd/pkg/backend/runc"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/runtime/host"
)

// oneSlot is a pool in which every grant collides with every other.
const oneSlot = "1073741824:1"

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: still not so after 5s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// gone reports whether path no longer exists.
func gone(path string) bool {
	_, err := os.Stat(path)
	return errors.Is(err, os.ErrNotExist)
}

// killZygote ends the grant's zygote through its cgroup, as the
// conformance suite's engine-loss hook does, and waits until the home
// has noticed (the container and its bundle are gone).
func (h *home) killZygote(t *testing.T, grant string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(h.cgRoot, grant, "zygote", "cgroup.kill"), []byte("1"), 0); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "zygote bundle released", func() bool { return gone(filepath.Join(h.stateDir, "bundles", "w-"+grant)) })
}

// TestResumedFiberHoldsRange pins that a fiber restored on this home holds
// its grant's id range slot for as long as it runs, zygote or no zygote.
// Another grant hashing to the slot is refused meanwhile, so the two never
// share a host uid.
func TestResumedFiberHoldsRange(t *testing.T) {
	cases := []struct {
		name          string
		killWarm      bool
		freeAfterExit bool // the other grant is admitted once the fiber is released
	}{
		{name: "zygote killed, the resumed fiber alone holds the slot", killWarm: true, freeAfterExit: true},
		{name: "zygote up, it keeps the slot after the fiber", killWarm: false, freeAfterExit: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool, err := runcbackend.ParsePool(oneSlot)
			if err != nil {
				t.Fatal(err)
			}
			hm := newHome(t, func(ro *runcbackend.Options, _ *host.Config) { ro.Pool = pool })
			ctx := context.Background()
			g1 := core.Grant{UID: "hold1", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20}
			g2 := core.Grant{UID: "hold2", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20}
			if err := hm.rt.PrepareTemplate(ctx, g1); err != nil {
				t.Fatal(err)
			}
			h, err := hm.rt.Clone(ctx, core.CloneSpec{Grant: g1, Fence: core.Fence{GrantUID: g1.UID, Epoch: 1, Seq: 1}, Deadline: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			talk(t, h.Endpoint, "incr")
			ref, err := hm.rt.Park(ctx, h.ID, true)
			if err != nil {
				t.Fatalf("park: %v", err)
			}
			copyDir := filepath.Join(hm.stateDir, "rootfs", "w-"+g1.UID)
			if tc.killWarm {
				hm.killZygote(t, g1.UID)
				waitFor(t, "dead zygote's rootfs copy removed", func() bool { return gone(copyDir) })
			}
			h2, err := hm.rt.Clone(ctx, core.CloneSpec{Grant: g1, Source: core.SourceDelta, Ref: ref,
				Fence: core.Fence{GrantUID: g1.UID, Epoch: 1, Seq: 2}, Deadline: 5 * time.Second})
			if err != nil {
				t.Fatalf("resume: %v", err)
			}
			if got := talk(t, h2.Endpoint, "get"); got != "1" {
				t.Fatalf("counter after resume = %q, want 1", got)
			}
			start := hm.mappedRoot(t, g1.UID)
			if uid := statusField(t, hm.fiberPID(t, core.Fence{GrantUID: g1.UID, Epoch: 1, Seq: 2}), "Uid"); fields(uid) != fmt.Sprintf("%d %d %d %d", start, start, start, start) {
				t.Fatalf("resumed fiber runs as %q, want host uid %d", uid, start)
			}
			if err := hm.rt.PrepareTemplate(ctx, g2); !errors.Is(err, runcbackend.ErrRangeCollision) {
				t.Fatalf("PrepareTemplate(%s) with a fiber of %s live in the slot = %v, want ErrRangeCollision", g2.UID, g1.UID, err)
			}
			if _, err := os.Stat(filepath.Join(hm.cgRoot, g2.UID)); err == nil {
				t.Fatalf("a cgroup was made for the refused grant %s", g2.UID)
			}
			if err := hm.rt.Release(ctx, h2.ID, true); err != nil {
				t.Fatalf("release: %v", err)
			}
			if tc.freeAfterExit {
				waitFor(t, "slot freed by the last fiber", func() bool { return hm.rt.PrepareTemplate(ctx, g2) == nil })
				if gone(filepath.Join(hm.stateDir, "rootfs", "w-"+g2.UID)) {
					t.Fatalf("%s was admitted but has no rootfs copy", g2.UID)
				}
				if !gone(copyDir) {
					t.Fatalf("%s left its rootfs copy %s behind with nothing of it running", g1.UID, copyDir)
				}
				return
			}
			time.Sleep(200 * time.Millisecond) // long enough for a wrong release to land
			if err := hm.rt.PrepareTemplate(ctx, g2); !errors.Is(err, runcbackend.ErrRangeCollision) {
				t.Fatalf("PrepareTemplate(%s) with the zygote of %s up = %v, want ErrRangeCollision", g2.UID, g1.UID, err)
			}
			if gone(copyDir) {
				t.Fatalf("the fiber's exit removed the rootfs copy %s from under the zygote", copyDir)
			}
		})
	}
}

// TestResumeOnlyCopyReleased pins that the root filesystem copy a resume
// makes on a home that never warmed the grant goes when the resumed fiber
// does. A home whose zygote is up keeps the copy, because the zygote uses it.
func TestResumeOnlyCopyReleased(t *testing.T) {
	cases := []struct {
		name       string
		warmSecond bool
		wantGone   bool
	}{
		{name: "second home never warmed the grant", warmSecond: false, wantGone: true},
		{name: "second home has the zygote up", warmSecond: true, wantGone: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := newHome(t, nil), newHome(t, nil)
			ctx := context.Background()
			g := core.Grant{UID: "only", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20}
			if err := a.rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			if tc.warmSecond {
				if err := b.rt.PrepareTemplate(ctx, g); err != nil {
					t.Fatal(err)
				}
			}
			h, err := a.rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			talk(t, h.Endpoint, "incr")
			ref, err := a.rt.Park(ctx, h.ID, true)
			if err != nil {
				t.Fatalf("park: %v", err)
			}
			copyDir := filepath.Join(b.stateDir, "rootfs", "w-"+g.UID)
			if !tc.warmSecond && !gone(copyDir) {
				t.Fatalf("%s has a rootfs copy before anything of the grant ran there", b.stateDir)
			}
			h2, err := b.rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref,
				Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 2}, Deadline: 5 * time.Second})
			if err != nil {
				t.Fatalf("resume on the second home: %v", err)
			}
			if got := talk(t, h2.Endpoint, "get"); got != "1" {
				t.Fatalf("counter on the second home = %q, want 1", got)
			}
			if gone(copyDir) {
				t.Fatalf("the resumed fiber runs without a rootfs copy at %s", copyDir)
			}
			if err := b.rt.Release(ctx, h2.ID, true); err != nil {
				t.Fatalf("release: %v", err)
			}
			if tc.wantGone {
				waitFor(t, "resume-only rootfs copy removed", func() bool { return gone(copyDir) })
				return
			}
			time.Sleep(200 * time.Millisecond)
			if gone(copyDir) {
				t.Fatalf("the fiber's exit removed the rootfs copy %s from under the zygote", copyDir)
			}
		})
	}
}

// TestSweepAtOpen pins that root filesystem copies and bundles a previous
// life left under the state directory are removed when the backend opens.
// Nothing of a prior epoch may still use them.
func TestSweepAtOpen(t *testing.T) {
	cases := []struct {
		name  string
		top   string // under the state directory
		inner string // under the leftover
	}{
		{name: "rootfs copy", top: "rootfs", inner: "bin"},
		{name: "bundle", top: "bundles", inner: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stateDir := filepath.Join(work, fmt.Sprintf("sweep%d", time.Now().UnixNano()%1_000_000))
			leftover := filepath.Join(stateDir, tc.top, "w-stale")
			if err := os.MkdirAll(filepath.Join(leftover, tc.inner), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(leftover, tc.inner, "file"), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			be, err := runcbackend.New(runcbackend.Options{Rootfs: rootfs, StateDir: stateDir})
			if err != nil {
				t.Fatal(err)
			}
			defer be.Close()
			if !gone(leftover) {
				t.Fatalf("%s still there after the backend opened", leftover)
			}
		})
	}
}

// TestSubIDOverlapRefusedAtOpen pins that a pool overlapping a subordinate
// id range the host handed out is refused at open, naming the entry. A
// pool clear of every entry opens.
func TestSubIDOverlapRefusedAtOpen(t *testing.T) {
	pool, err := runcbackend.ParsePool("200000:4")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		subuid  string
		wantErr string
	}{
		{name: "clear", subuid: "alice:100000:65536\n"},
		{name: "overlap", subuid: "alice:100000:65536\nbob:300000:65536\n", wantErr: `entry "bob:300000:65536"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			subuid := filepath.Join(dir, "subuid")
			if err := os.WriteFile(subuid, []byte(tc.subuid), 0o644); err != nil {
				t.Fatal(err)
			}
			be, err := runcbackend.New(runcbackend.Options{Rootfs: rootfs, StateDir: filepath.Join(dir, "state"), Pool: pool,
				SubIDFiles: []string{subuid, filepath.Join(dir, "no-subgid")}})
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("New = %v, want nil", err)
				}
				be.Close()
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("New = %v, want an error mentioning %q", err, tc.wantErr)
			}
		})
	}
}
