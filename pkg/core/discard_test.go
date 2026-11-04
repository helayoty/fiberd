package core_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/Azure/fiberd/pkg/core"
)

// discardRuntime is mobileRuntime that can also delete a session's
// published copy without claiming it, as a home's DeleteDelta does.
type discardRuntime struct {
	*mobileRuntime
	deleted   []string // handles deleted from the store
	deleteErr error    // the registry refuses the delete
}

func (d *discardRuntime) DeleteDelta(_ context.Context, g core.Grant, session, handle string) (string, bool, error) {
	if d.deleteErr != nil {
		return "", false, d.deleteErr
	}
	d.st.mu.Lock()
	defer d.st.mu.Unlock()
	key := d.key(g, session)
	if p, ok := d.st.deltas[key]; !ok || p.ref != handle {
		return "", false, nil
	}
	delete(d.st.deltas, key)
	d.deleted = append(d.deleted, handle)
	return "registry/" + handle, true, nil
}

// newDiscardHome is a home with a discardRuntime over the shared store,
// an audit log, and a verifier that knows every grant given.
func newDiscardHome(t *testing.T, home string, st *store, grants ...core.Grant) (*core.Core, *discardRuntime, *auditLog) {
	t.Helper()
	a := newCore(t, "up", core.TierCheckpoint, grants...)
	a.NodeID = home
	rt := &discardRuntime{mobileRuntime: &mobileRuntime{
		fakeRuntime: fakeRuntime{tier: core.TierCheckpoint, exits: make(chan core.FiberExit, 8)}, home: home, st: st}}
	a.Runtime = rt
	rec := &auditLog{}
	a.Audit = rec
	return a, rt, rec
}

// TestDiscard checks what Discard does with a session by where the
// session is. Parked here, its published copy is withdrawn, its delta
// dropped and the session forgotten. In the store only, the store's copy
// is deleted. Running, unnamed, nowhere, or filed under another tenant,
// nothing changes.
func TestDiscard(t *testing.T) {
	ga := core.Grant{UID: "ga", Tenant: "acme", Audience: "A", TemplateDigest: "sha256:t", FiberMax: 4, WBudgetBytes: 10 << 20}
	gb := core.Grant{UID: "gb", Tenant: "acme", Audience: "B", TemplateDigest: "sha256:t", FiberMax: 4, WBudgetBytes: 10 << 20}
	globex := core.Grant{UID: "gx", Tenant: "globex", Audience: "A", TemplateDigest: "sha256:t", FiberMax: 4}
	untenanted := core.Grant{UID: "gn", Audience: "A", TemplateDigest: "sha256:t", FiberMax: 4}
	bound := core.Grant{UID: "gc", Tenant: "acme", Audience: "A", TemplateDigest: "sha256:t", FiberMax: 4, CallerThumbprint: "x5t-owner"}
	expired := core.Grant{UID: "ge", Tenant: "acme", Audience: "A", TemplateDigest: "sha256:t", FiberMax: 4, LeaseExpiry: time.Now().Add(-time.Minute)}
	const key = "acme/sha256:t/S" // acme's S in the store
	ctx := context.Background()

	type homes struct {
		a, b   *core.Core
		ra, rb *discardRuntime
		st     *store
	}
	clone := func(t *testing.T, a *core.Core, token string) core.CloneResponse {
		t.Helper()
		r, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte(token), Session: "S", Deadline: time.Second})
		if err != nil || code != core.OK {
			t.Fatalf("clone S on %s: %d %v", a.NodeID, code, err)
		}
		return r
	}
	// park clones S on a home and parks it, and returns the delta ref.
	park := func(t *testing.T, a *core.Core, token string) string {
		t.Helper()
		r := clone(t, a, token)
		if _, code, err := a.Park(ctx, r.FiberID, true); err != nil || code != core.OK {
			t.Fatalf("park S on %s: %d %v", a.NodeID, code, err)
		}
		return "delta-" + a.NodeID + "-" + r.FiberID
	}

	cases := []struct {
		name string
		// setup leaves the homes as the case needs them and returns the
		// detail the discard record must carry, "" for none.
		setup      func(t *testing.T, h *homes) string
		token      string // "" is ga
		session    string // "" is S
		empty      bool   // the request names no session
		thumbprint string
		wantCode   core.StatusCode
		wantErr    error
		wantState  string // S under ga on A afterwards
		wantStored bool   // acme's S is still in the store
		// wantDropped: A's runtime was told to drop a local delta.
		wantDropped bool
		wantRetired bool // A withdrew the copy it published
		wantDeleted int  // store copies deleted without a claim
	}{
		{name: "a session parked here is discarded, here and in the store",
			setup:    func(t *testing.T, h *homes) string { return park(t, h.a, "ga") },
			wantCode: core.OK, wantState: "gone", wantDropped: true, wantRetired: true},
		{name: "a session parked elsewhere is deleted from the store",
			setup: func(t *testing.T, h *homes) string {
				return "registry/" + park(t, h.b, "gb")
			},
			wantCode: core.OK, wantState: "gone", wantDeleted: 1},
		{name: "a copy here claimed elsewhere since is dropped, and the store's is deleted",
			setup: func(t *testing.T, h *homes) string {
				ref := park(t, h.a, "ga")
				resumed := clone(t, h.b, "gb")
				h.st.mu.Lock()
				h.st.claimedRefs = append(h.st.claimedRefs, ref)
				h.st.mu.Unlock()
				if _, code, err := h.b.Park(ctx, resumed.FiberID, true); err != nil || code != core.OK {
					t.Fatalf("park S on B: %d %v", code, err)
				}
				return "registry/delta-B-" + resumed.FiberID
			},
			wantCode: core.OK, wantState: "gone", wantDropped: true, wantDeleted: 1},
		{name: "a running session is refused",
			setup:    func(t *testing.T, h *homes) string { clone(t, h.a, "ga"); return "" },
			wantCode: core.Invalid, wantErr: core.ErrSessionRunning, wantState: "running"},
		{name: "a request without a session is invalid", empty: true,
			wantCode: core.Invalid, wantState: "gone"},
		{name: "a grant without a tenant is refused", token: "gn",
			wantCode: core.NeedsTier, wantErr: core.ErrNoTenant, wantState: "gone"},
		{name: "a session nowhere is not found",
			wantCode: core.NotFound, wantErr: core.ErrSessionUnknown, wantState: "gone"},
		{name: "another tenant's session is not found, and stays", token: "gx",
			setup:    func(t *testing.T, h *homes) string { park(t, h.a, "ga"); return "" },
			wantCode: core.NotFound, wantErr: core.ErrSessionUnknown, wantState: "parked", wantStored: true},
		{name: "an expired grant is refused before anything is touched", token: "ge",
			setup: func(t *testing.T, h *homes) string {
				park(t, h.b, "gb")
				h.ra.findErr = errors.New("the store must not be asked")
				return ""
			},
			wantCode: core.DeferredFallback, wantErr: core.ErrGrantExpired, wantState: "gone", wantStored: true},
		{name: "a token for another caller is refused", token: "gc", thumbprint: "x5t-other",
			wantCode: core.Unauthenticated, wantErr: core.ErrCallerMismatch, wantState: "gone"},
		{name: "a store that cannot withdraw the published copy refuses and keeps the session",
			setup: func(t *testing.T, h *homes) string {
				park(t, h.a, "ga")
				h.ra.retireFails = 1
				return ""
			},
			wantCode: core.Internal, wantState: "parked", wantStored: true},
		{name: "a registry that refuses the delete is internal",
			setup: func(t *testing.T, h *homes) string {
				park(t, h.b, "gb")
				h.ra.deleteErr = errors.New("registry: 405 method not allowed")
				return ""
			},
			wantCode: core.Internal, wantState: "gone", wantStored: true},
		{name: "a home without a store finds nothing to delete",
			setup: func(t *testing.T, h *homes) string {
				park(t, h.b, "gb")
				h.a.Runtime = h.ra.fakeRuntime
				return ""
			},
			wantCode: core.NotFound, wantErr: core.ErrSessionUnknown, wantState: "gone", wantStored: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := &store{deltas: map[string]published{}}
			a, ra, rec := newDiscardHome(t, "A", st, ga, globex, untenanted, bound, expired)
			b, rb, _ := newDiscardHome(t, "B", st, gb)
			h := &homes{a: a, b: b, ra: ra, rb: rb, st: st}
			detail := ""
			if tc.setup != nil {
				detail = tc.setup(t, h)
			}
			token, session := tc.token, tc.session
			if token == "" {
				token = "ga"
			}
			if session == "" && !tc.empty {
				session = "S"
			}
			code, err := a.Discard(ctx, core.DiscardRequest{GrantJWT: []byte(token), Session: session, CallerThumbprint: tc.thumbprint})
			if code != tc.wantCode {
				t.Fatalf("Discard = %d %v, want %d", code, err, tc.wantCode)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("Discard err = %v, want %v", err, tc.wantErr)
			}
			if got := ledgerState(a.Ledger, "ga", "S"); got != tc.wantState {
				t.Fatalf("S on A = %s, want %s", got, tc.wantState)
			}
			if got := st.stored(key); got != tc.wantStored {
				t.Fatalf("acme's S in the store = %v, want %v", got, tc.wantStored)
			}
			if got := len(ra.discarded) > 0; got != tc.wantDropped {
				t.Fatalf("A dropped %v, want a local delta dropped %v", ra.discarded, tc.wantDropped)
			}
			if got := len(ra.retired) > 0; got != tc.wantRetired {
				t.Fatalf("A retired %v, want its published copy withdrawn %v", ra.retired, tc.wantRetired)
			}
			if len(ra.deleted) != tc.wantDeleted {
				t.Fatalf("A deleted %v from the store, want %d", ra.deleted, tc.wantDeleted)
			}
			details := []string{}
			for _, r := range rec.events("discard") {
				details = append(details, r.Detail)
			}
			if detail == "" && tc.wantCode != core.OK {
				if len(details) != 0 {
					t.Fatalf("discard records %v, want none", details)
				}
				return
			}
			if !slices.Contains(details, detail) {
				t.Fatalf("discard records %v, want one for %s", details, detail)
			}
			// Nothing of S is left to resume, so the next Clone creates.
			if r := clone(t, a, "ga"); r.Kind != core.ActCreate {
				t.Fatalf("clone S after the discard = %v, want CREATE", r.Kind)
			}
		})
	}
}
