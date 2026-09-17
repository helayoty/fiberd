package core_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// auditLog keeps audit records in memory.
type auditLog struct{ recs []core.AuditRecord }

func (r *auditLog) Append(_ context.Context, _ core.Durability, rec core.AuditRecord) error {
	r.recs = append(r.recs, rec)
	return nil
}

// TestBumpEpochRevokesEveryFence: scope loss while the agent lives is an
// epoch bump in place: running fibers are released with a scope-revoked
// record, their fences answer NotFound, new fences carry the new epoch,
// parked sessions resume under it, and grants stay admitted.
func TestBumpEpochRevokesEveryFence(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:t", FiberMax: 4, LeaseExpiry: time.Now().Add(time.Hour)}
	a := newAgent(t, "up", core.TierCheckpoint, g)
	a.NodeID = ""
	store, err := core.OpenEpochStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a.Epoch = store
	rec := &auditLog{}
	a.Audit = rec
	a.Scope = func() []core.ScopeClaim { return []core.ScopeClaim{{Name: "namespace", Value: "tenant-a"}} }
	ctx := context.Background()
	req := core.CloneRequest{GrantJWT: []byte("g1"), Deadline: time.Second}
	run, code, err := a.Clone(ctx, req)
	if err != nil || code != core.OK {
		t.Fatalf("clone: %v %d", err, code)
	}
	p, _, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Session: "P", Deadline: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, code, err := a.Park(ctx, p.FiberID, true); err != nil || code != core.OK {
		t.Fatalf("park: %v %d", err, code)
	}
	before := a.Ledger.Epoch()

	next, err := a.BumpEpoch(ctx, "namespace deleted")
	if err != nil {
		t.Fatal(err)
	}
	if next <= before || a.Ledger.Epoch() != next || store.Current() != next {
		t.Fatalf("epoch after bump = ledger %d store %d, before %d", a.Ledger.Epoch(), store.Current(), before)
	}
	if _, code, err := a.Park(ctx, run.FiberID, false); code != core.NotFound || !errors.Is(err, core.ErrFiberUnknown) {
		t.Fatalf("park of a revoked fence = %d %v, want NotFound", code, err)
	}
	if _, ok := a.Ledger.Grant(g.UID); !ok {
		t.Fatal("grant revoked by an epoch bump; only fences must be")
	}
	fresh, _, err := a.Clone(ctx, req)
	if err != nil || fresh.Fence.Epoch != next {
		t.Fatalf("fresh fence after bump = %+v (%v), want epoch %d", fresh.Fence, err, next)
	}
	r, _, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Session: "P", Deadline: time.Second})
	if err != nil || r.Kind != core.ActResume || r.Fence.Epoch != next {
		t.Fatalf("parked session after bump = %v %+v (%v), want RESUME in epoch %d", r.Kind, r.Fence, err, next)
	}
	// The audit trail names the reason and carries the home's scope.
	var revoked int
	for _, rc := range rec.recs {
		if rc.Event == "scope-revoked" {
			revoked++
			if rc.Detail != "namespace deleted" || rc.Scope["namespace"] != "tenant-a" {
				t.Fatalf("scope-revoked record = %+v", rc)
			}
		}
	}
	if revoked != 1 {
		t.Fatalf("scope-revoked records = %d, want 1 (the running fiber; the parked one was not running)", revoked)
	}
}

// TestFabricProvisionedWithGrantAndReleasedWithIt: the home's fabric hook
// runs before the template is warmed and its release with Revoke.
func TestFabricProvisionedWithGrantAndReleasedWithIt(t *testing.T) {
	g := core.Grant{UID: "g2", TemplateDigest: "sha256:t", FiberMax: 1}
	a := newAgent(t, "up", core.TierWarm, g)
	a.NodeID = ""
	var provisioned, released int
	a.Fabric = func(_ context.Context, got core.Grant) (core.FabricChannel, func(), error) {
		if got.UID != g.UID {
			t.Fatalf("fabric for %s, want %s", got.UID, g.UID)
		}
		provisioned++
		return core.FabricChannel{Kind: "static", Devices: []string{"/dev/sim0"}}, func() { released++ }, nil
	}
	ctx := context.Background()
	if code, err := a.Admit(ctx, g); err != nil || code != core.OK {
		t.Fatalf("admit: %v %d", err, code)
	}
	if provisioned != 1 || released != 0 {
		t.Fatalf("after admit: provisioned=%d released=%d", provisioned, released)
	}
	a.Revoke(g.UID)
	if released != 1 {
		t.Fatalf("after revoke: released=%d, want 1", released)
	}
	if _, ok := a.Ledger.Grant(g.UID); ok {
		t.Fatal("grant still admitted after Revoke")
	}
}
