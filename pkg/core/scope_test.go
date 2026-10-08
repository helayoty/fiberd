package core_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// auditLog keeps audit records in memory. It is safe for concurrent use.
type auditLog struct {
	mu   sync.Mutex
	recs []core.AuditRecord
}

func (r *auditLog) Append(_ context.Context, _ core.Durability, rec core.AuditRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recs = append(r.recs, rec)
	return nil
}

// events returns the records with this event, in order.
func (r *auditLog) events(event string) []core.AuditRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []core.AuditRecord
	for _, rec := range r.recs {
		if rec.Event == event {
			out = append(out, rec)
		}
	}
	return out
}

// TestBumpEpochRevokesEveryFence: scope loss while the agent lives is an
// epoch bump in place: running fibers are released with a scope-revoked
// record, their fences answer NotFound, new fences carry the new epoch,
// parked sessions resume under it, and grants stay admitted. The setup
// runs one fiber and parks one session. The steps bump and then probe.
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
	parkedReq := core.CloneRequest{GrantJWT: []byte("g1"), Session: "P", Deadline: time.Second}
	run, code, err := a.Clone(ctx, req)
	if err != nil || code != core.OK {
		t.Fatalf("clone: %v %d", err, code)
	}
	p, _, err := a.Clone(ctx, parkedReq)
	if err != nil {
		t.Fatal(err)
	}
	if _, code, err := a.Park(ctx, p.FiberID, true); err != nil || code != core.OK {
		t.Fatalf("park: %v %d", err, code)
	}
	before := a.Ledger.Epoch()
	var next uint64

	steps := []struct {
		name string
		step func(t *testing.T)
	}{
		{name: "the bump advances the ledger and stored epoch", step: func(t *testing.T) {
			if next, err = a.BumpEpoch(ctx, "namespace deleted"); err != nil {
				t.Fatal(err)
			}
			if next <= before || a.Ledger.Epoch() != next || store.Current() != next {
				t.Fatalf("epoch after bump = ledger %d store %d, before %d", a.Ledger.Epoch(), store.Current(), before)
			}
		}},
		{name: "park of a revoked fence is not found", step: func(t *testing.T) {
			if _, code, err := a.Park(ctx, run.FiberID, false); code != core.NotFound || !errors.Is(err, core.ErrFiberUnknown) {
				t.Fatalf("park of a revoked fence = %d %v, want NotFound", code, err)
			}
		}},
		{name: "the grant stays admitted; only fences are revoked", step: func(t *testing.T) {
			if _, ok := a.Ledger.Grant(g.UID); !ok {
				t.Fatal("grant revoked by an epoch bump; only fences must be")
			}
		}},
		{name: "a fresh fence carries the new epoch", step: func(t *testing.T) {
			fresh, _, err := a.Clone(ctx, req)
			if err != nil || fresh.Fence.Epoch != next {
				t.Fatalf("fresh fence after bump = %+v (%v), want epoch %d", fresh.Fence, err, next)
			}
		}},
		{name: "the parked session resumes in the new epoch", step: func(t *testing.T) {
			r, _, err := a.Clone(ctx, parkedReq)
			if err != nil || r.Kind != core.ActResume || r.Fence.Epoch != next {
				t.Fatalf("parked session after bump = %v %+v (%v), want RESUME in epoch %d", r.Kind, r.Fence, err, next)
			}
		}},
		// One record, for the running fiber. The parked one was not running.
		{name: "the audit trail names the reason and carries the home's scope", step: func(t *testing.T) {
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
		}},
	}
	for _, tc := range steps {
		if !t.Run(tc.name, tc.step) {
			return // later steps build on this one
		}
	}
}

// TestFabricProvisionedWithGrantAndReleasedWithIt: the home's fabric hook
// runs before the template is warmed and its release with Revoke. The
// steps run in order against one agent.
func TestFabricProvisionedWithGrantAndReleasedWithIt(t *testing.T) {
	g := core.Grant{UID: "g2", TemplateDigest: "sha256:t", FiberMax: 1}
	a := newAgent(t, "up", core.TierWarm, g)
	a.NodeID = ""
	var provisioned, released int
	a.Fabric = func(_ context.Context, got core.Grant) (core.FabricChannel, func(), error) {
		if got.UID != g.UID {
			t.Errorf("fabric for %s, want %s", got.UID, g.UID)
		}
		provisioned++
		return core.FabricChannel{Kind: "static", Devices: []string{"/dev/sim0"}}, func() { released++ }, nil
	}
	ctx := context.Background()
	steps := []struct {
		name            string
		act             func(t *testing.T)
		wantProvisioned int
		wantReleased    int
		wantAdmitted    bool
	}{
		{name: "admit provisions the fabric", act: func(t *testing.T) {
			if code, err := a.Admit(ctx, g); err != nil || code != core.OK {
				t.Fatalf("admit: %v %d", err, code)
			}
		}, wantProvisioned: 1, wantAdmitted: true},
		{name: "revoke releases the fabric with the grant", act: func(*testing.T) { a.Revoke(g.UID) },
			wantProvisioned: 1, wantReleased: 1},
	}
	for _, tc := range steps {
		if !t.Run(tc.name, func(t *testing.T) {
			tc.act(t)
			if provisioned != tc.wantProvisioned || released != tc.wantReleased {
				t.Fatalf("provisioned=%d released=%d, want %d %d", provisioned, released, tc.wantProvisioned, tc.wantReleased)
			}
			if _, ok := a.Ledger.Grant(g.UID); ok != tc.wantAdmitted {
				t.Fatalf("grant admitted = %v, want %v", ok, tc.wantAdmitted)
			}
		}) {
			return // later steps build on this one
		}
	}
}

// TestBumpEpochOutcomes checks BumpEpoch's failures and its sweep. Without
// an epoch store, or with one that cannot persist the new epoch, nothing
// moves and nothing is released. A fiber the runtime cannot release, or
// whose sync record fails, still leaves the ledger, and the sweep goes on
// to the next. A fiber already under the new epoch is kept.
func TestBumpEpochOutcomes(t *testing.T) {
	cases := []struct {
		name        string
		noStore     bool
		storeGone   bool   // the epoch store's directory is gone
		ledgerAhead uint64 // the ledger's epoch is this far ahead of the store's
		releaseErr  error
		syncAudit   bool // the grant's records are sync and fail
		fibers      int
		wantErr     bool
		wantMoved   bool // the ledger's epoch moved
		wantRunning int
		wantRecords int // scope-revoked records
	}{
		{name: "without an epoch store nothing moves", noStore: true, fibers: 1, wantErr: true, wantRunning: 1},
		{name: "an epoch that cannot be persisted moves nothing", storeGone: true, fibers: 1, wantErr: true, wantRunning: 1},
		{name: "every running fiber is released and recorded", fibers: 2, wantMoved: true, wantRecords: 2},
		{name: "a release the runtime refuses still drops the fiber", releaseErr: errors.New("kill: EPERM"), fibers: 2,
			wantMoved: true, wantRecords: 2},
		{name: "a sync record that fails does not stop the sweep", syncAudit: true, fibers: 2, wantMoved: true},
		// The store's next epoch is the ledger's own, as when a clone was
		// minted under the new epoch before the sweep ran.
		{name: "a fiber already under the new epoch is kept", ledgerAhead: 1, fibers: 1, wantRunning: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := core.Grant{UID: "g1", FiberMax: 4}
			if tc.syncAudit {
				g.Policy.Durability = core.Sync
			}
			a := newAgent(t, "up", core.TierCheckpoint, g)
			a.NodeID = ""
			dir := filepath.Join(t.TempDir(), "state")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			store, err := core.OpenEpochStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			if !tc.noStore {
				a.Epoch = store
			}
			a.Ledger = core.NewLedger(store.Current() + tc.ledgerAhead)
			rt := &listingRuntime{fakeRuntime: fakeRuntime{tier: core.TierCheckpoint}, releaseErr: tc.releaseErr}
			a.Runtime = rt
			rec := &auditLog{}
			a.Audit = rec
			ctx := context.Background()
			for range tc.fibers {
				if _, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Deadline: time.Second}); err != nil || code != core.OK {
					t.Fatalf("clone = %d %v", code, err)
				}
			}
			if tc.syncAudit {
				a.Audit = failingAuditor{}
			}
			if tc.storeGone {
				if err := os.RemoveAll(dir); err != nil {
					t.Fatal(err)
				}
			}
			before := a.Ledger.Epoch()
			next, err := a.BumpEpoch(ctx, "namespace deleted")
			if (err != nil) != tc.wantErr {
				t.Fatalf("BumpEpoch = %d %v, want error %v", next, err, tc.wantErr)
			}
			if moved := a.Ledger.Epoch() != before; moved != tc.wantMoved {
				t.Fatalf("ledger epoch %d -> %d, want moved %v", before, a.Ledger.Epoch(), tc.wantMoved)
			}
			if err == nil && next != store.Current() {
				t.Fatalf("BumpEpoch = %d, store holds %d", next, store.Current())
			}
			if n := len(a.Ledger.RunningFibers()); n != tc.wantRunning {
				t.Fatalf("running fibers = %d, want %d", n, tc.wantRunning)
			}
			if released := len(rt.released); released != tc.fibers-tc.wantRunning {
				t.Fatalf("released %v, want %d fibers", rt.released, tc.fibers-tc.wantRunning)
			}
			if n := len(rec.events("scope-revoked")); n != tc.wantRecords {
				t.Fatalf("scope-revoked records = %d, want %d", n, tc.wantRecords)
			}
		})
	}
}
