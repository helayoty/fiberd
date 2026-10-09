package core_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/core/coretest"
)

// mobileRuntime is fakeRuntime plus a shared "registry": a map from
// grant/session to a published delta, shared between two runtimes so two
// agents can hand a session to each other.
type store struct {
	mu          sync.Mutex // guards the store and every runtime's records of it
	deltas      map[string]published
	claimedRefs []string // local refs whose published copy was claimed away
}

type published struct {
	ref    string
	wBytes uint64
	home   string
	owner  *mobileRuntime
}

type mobileRuntime struct {
	fakeRuntime
	home      string
	st        *store
	claims    []string
	discarded []string // claimed refs the agent told it to drop
	retired   []string // local refs whose published copy the agent withdrew
	deltaW    uint64   // W the next park will report
	// retireFails is how many RetireDelta calls fail before one works,
	// like a registry that is down for a while.
	retireFails int
	pubErr      error
	// refuse, when set, is what FindDelta answers for a session it finds:
	// the runtime's parity gate saying "not here".
	refuse error
	// claimEnter and claimWait, when set, make every claim announce itself
	// and then wait for the test before it takes the delta, like a pull
	// that takes time.
	claimEnter chan struct{}
	claimWait  chan struct{}
	findErr    error // the store cannot be reached
	claimErr   error // the pull fails, leaving the store as it was
	discardErr error // dropping a claimed copy fails
}

func (m *mobileRuntime) key(g core.Grant, session string) string {
	domain, err := g.SessionDomain()
	if err != nil {
		panic(err) // the agent never asks the store for a grant without a domain
	}
	return domain + "/" + session
}

func (m *mobileRuntime) PublishDelta(_ context.Context, ref string, g core.Grant, session string) (string, error) {
	if m.pubErr != nil {
		return "", m.pubErr
	}
	m.st.mu.Lock()
	defer m.st.mu.Unlock()
	m.st.deltas[m.key(g, session)] = published{ref: ref, wBytes: m.deltaW, home: m.home, owner: m}
	return "registry/" + ref, nil
}

func (m *mobileRuntime) FindDelta(_ context.Context, g core.Grant, session string) (core.RemoteDelta, bool, error) {
	if m.findErr != nil {
		return core.RemoteDelta{}, false, m.findErr
	}
	m.st.mu.Lock()
	p, ok := m.st.deltas[m.key(g, session)]
	m.st.mu.Unlock()
	if !ok {
		return core.RemoteDelta{}, false, nil
	}
	rd := core.RemoteDelta{WBytes: p.wBytes, Home: p.home, Handle: p.ref}
	if m.refuse != nil {
		return rd, true, &core.RemoteMiss{Err: m.refuse, PreferredHome: p.home}
	}
	return rd, true, nil
}

func (m *mobileRuntime) ClaimDelta(_ context.Context, g core.Grant, session string, rd core.RemoteDelta) (string, error) {
	if m.claimEnter != nil {
		m.claimEnter <- struct{}{}
		<-m.claimWait
	}
	if m.claimErr != nil {
		return "", m.claimErr
	}
	m.st.mu.Lock()
	defer m.st.mu.Unlock()
	delete(m.st.deltas, m.key(g, session))
	m.claims = append(m.claims, rd.Handle)
	return fmt.Sprintf("claimed:%s#%d", rd.Handle, len(m.claims)), nil
}

func (m *mobileRuntime) DiscardDelta(_ context.Context, ref string) error {
	m.st.mu.Lock()
	defer m.st.mu.Unlock()
	m.discarded = append(m.discarded, ref)
	return m.discardErr
}

// RetireDelta withdraws the store's copy while it is this runtime's
// publish of ref, as a home deletes a tag that still holds its digest.
func (m *mobileRuntime) RetireDelta(_ context.Context, ref string) error {
	m.st.mu.Lock()
	defer m.st.mu.Unlock()
	if m.retireFails > 0 {
		m.retireFails--
		return errors.New("registry: 503")
	}
	for k, p := range m.st.deltas {
		if p.ref == ref && p.owner == m {
			delete(m.st.deltas, k)
			m.retired = append(m.retired, ref)
		}
	}
	return nil
}

func (m *mobileRuntime) Owned(_ context.Context, ref string) bool {
	m.st.mu.Lock()
	defer m.st.mu.Unlock()
	for _, p := range m.st.deltas {
		if p.ref == ref && p.owner == m {
			return true
		}
	}
	// Published and gone from the store: someone claimed it. Never
	// published (no entry ever): ours.
	for _, c := range m.st.claimedRefs {
		if c == ref {
			return false
		}
	}
	return true
}

// nClaims is how many claims the runtime has made.
func (m *mobileRuntime) nClaims() int {
	m.st.mu.Lock()
	defer m.st.mu.Unlock()
	return len(m.claims)
}

// stored reports whether a session is published in the store.
func (st *store) stored(key string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	_, ok := st.deltas[key]
	return ok
}

func (m *mobileRuntime) Park(_ context.Context, id string, _ bool) (string, error) {
	return "delta-" + m.home + "-" + id, nil
}

func (m *mobileRuntime) Clone(_ context.Context, spec core.CloneSpec) (core.FiberHandle, error) {
	return core.FiberHandle{ID: spec.Fence.String(), Endpoint: m.home + ":" + spec.Fence.String()}, nil
}

func newMobileAgent(t *testing.T, home string, st *store, g core.Grant) (*core.Agent, *mobileRuntime) {
	t.Helper()
	rt := &mobileRuntime{fakeRuntime: fakeRuntime{tier: core.TierCheckpoint, exits: make(chan core.FiberExit, 8)}, home: home, st: st}
	a := newAgent(t, "up", core.TierCheckpoint, g)
	a.NodeID = home
	a.Runtime = rt
	return a, rt
}

// TestSessionMovesBetweenHomes runs two homes with one grant each and one
// shared template. The session domain is the template digest, so both see
// the same parked state. A session parked on A is claimed and resumed by B,
// after which A's stale copy must not resume. The steps run in order.
func TestSessionMovesBetweenHomes(t *testing.T) {
	ga := core.Grant{UID: "ga", Tenant: "acme", Audience: "A", TemplateDigest: "sha256:t", FiberMax: 4, WBudgetBytes: 10 << 20}
	gb := core.Grant{UID: "gb", Tenant: "acme", Audience: "B", TemplateDigest: "sha256:t", FiberMax: 4, WBudgetBytes: 10 << 20}
	st := &store{deltas: map[string]published{}}
	a, ra := newMobileAgent(t, "A", st, ga)
	b, rb := newMobileAgent(t, "B", st, gb)
	ctx := context.Background()
	reqA := core.CloneRequest{GrantJWT: []byte("ga"), Session: "S", Deadline: time.Second}
	reqB := core.CloneRequest{GrantJWT: []byte("gb"), Session: "S", Deadline: time.Second}
	var r1 core.CloneResponse
	steps := []struct {
		name string
		step func(t *testing.T)
	}{
		{name: "A creates the session", step: func(t *testing.T) {
			var code core.StatusCode
			var err error
			if r1, code, err = a.Clone(ctx, reqA); err != nil || code != core.OK || r1.Kind != core.ActCreate {
				t.Fatalf("A clone: %v %d %v", err, code, r1.Kind)
			}
		}},
		{name: "A parks it and the park publishes under the tenant and template domain", step: func(t *testing.T) {
			ra.deltaW = 4 << 20
			if _, code, err := a.Park(ctx, r1.FiberID, true); err != nil || code != core.OK {
				t.Fatalf("A park: %v %d", err, code)
			}
			if !st.stored("acme/sha256:t/S") {
				t.Fatal("park did not publish the delta under the tenant and template domain")
			}
		}},
		{name: "B, which never saw it, finds, claims and resumes it with its own grant", step: func(t *testing.T) {
			r2, code, err := b.Clone(ctx, reqB)
			if err != nil || code != core.OK {
				t.Fatalf("B clone: %v %d", err, code)
			}
			if r2.Kind != core.ActResume || len(rb.claims) != 1 {
				t.Fatalf("B clone kind = %v claims = %v, want RESUME after one claim", r2.Kind, rb.claims)
			}
			if st.stored("acme/sha256:t/S") {
				t.Fatal("claim left the delta in the store")
			}
		}},
		// The store no longer has S (B holds it live), so A creates fresh.
		{name: "A does not resume its stale parked copy", step: func(t *testing.T) {
			st.claimedRefs = append(st.claimedRefs, "delta-A-"+r1.FiberID)
			r3, code, err := a.Clone(ctx, reqA)
			if err != nil || code != core.OK {
				t.Fatalf("A clone after claim: %v %d", err, code)
			}
			if r3.Kind != core.ActCreate {
				t.Fatalf("A resumed a session B had claimed: kind %v", r3.Kind)
			}
		}},
	}
	for _, tc := range steps {
		if !t.Run(tc.name, tc.step) {
			return // later steps build on this one
		}
	}
}

// TestSessionDomain checks that parked state is shared within a session
// domain: the tenant, then the template digest, unless the policy names
// a session class. A grant without a tenant has no domain.
func TestSessionDomain(t *testing.T) {
	cases := []struct {
		name  string
		grant core.Grant
		want  string
		err   error
	}{
		{name: "without a session class it is the tenant and the template digest",
			grant: core.Grant{UID: "ga", Audience: "A", Tenant: "acme", TemplateDigest: "sha256:t"}, want: "acme/sha256:t"},
		{name: "another audience of the tenant on the same template shares it",
			grant: core.Grant{UID: "gb", Audience: "B", Tenant: "acme", TemplateDigest: "sha256:t"}, want: "acme/sha256:t"},
		{name: "a session class defines its own domain within the tenant",
			grant: core.Grant{UID: "gc", Audience: "B", Tenant: "acme", TemplateDigest: "sha256:t", Policy: core.Policy{SessionClass: "models"}}, want: "acme/models"},
		{name: "another tenant on the same template and class is another domain",
			grant: core.Grant{UID: "gd", Audience: "B", Tenant: "globex", TemplateDigest: "sha256:t", Policy: core.Policy{SessionClass: "models"}}, want: "globex/models"},
		{name: "without a tenant there is no domain",
			grant: core.Grant{UID: "ge", Audience: "A", TemplateDigest: "sha256:t", Policy: core.Policy{SessionClass: "models"}}, err: core.ErrNoTenant},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.grant.SessionDomain()
			if !errors.Is(err, tc.err) || got != tc.want {
				t.Fatalf("SessionDomain = %q, %v, want %q, %v", got, err, tc.want, tc.err)
			}
		})
	}
}

// TestParkedSessionPickup has home A park session S, which succeeds even
// when publishing fails, and then clones S again from a home. A delta over
// the mobility budget, or one parity refuses, is deferred to its preferred
// home and stays in the store. Otherwise it is claimed and resumed. An
// unpublished session resumes locally.
//
// When the ledger refuses a claimed copy, a session that arrived meanwhile
// makes the copy a duplicate, which is dropped. A grant that went away
// makes it the only copy, which is kept.
func TestParkedSessionPickup(t *testing.T) {
	ctx := context.Background()
	yield := func(_ *testing.T, b *core.Agent) { b.Yield(ctx, "g1", "ladder") }
	remove := func(t *testing.T, b *core.Agent) {
		r, err := core.OpenRevoked(filepath.Join(t.TempDir(), "revoked.json"), time.Hour, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		b.Revoked = r
		b.Remove(ctx, "g1")
	}
	arrive := func(t *testing.T, b *core.Agent) {
		if !b.Ledger.RestoreParked(core.SessionSnapshot{Name: "S", GrantUID: "g1", State: core.StateParked, DeltaRef: "delta-local"}) {
			t.Fatal("could not register S on B mid-claim")
		}
	}
	cases := []struct {
		name          string
		budget        uint64 // the grant's W budget
		deltaW        uint64 // W the park reports
		pubErr        error  // publishing the delta fails
		refuse        error  // the picker's parity gate refuses S
		from          string // the home that clones S again: "A" or "B"
		laneDown      bool
		homeCap       uint64                            // the picker's MobilityBudget, 0 means unset
		failAudit     string                            // a sync grant whose picker fails this audit event
		midClaim      func(t *testing.T, a *core.Agent) // runs on the picker while its claim is in flight
		findErr       error                             // the picker cannot reach the store
		claimErr      error                             // the picker's pull fails
		discardErr    error                             // the picker cannot drop a claimed copy
		wantCode      core.StatusCode
		wantErr       error
		wantPreferred string
		wantKind      core.Action // when OK
		wantStored    bool        // S still published in the store
		wantClaims    int         // claims made by the picker
		wantDiscarded int         // claimed copies the picker dropped
	}{
		{name: "a grant yielded mid-claim keeps the claimed copy and answers the miss", budget: 8 << 20, from: "B", midClaim: yield,
			wantCode: core.DeferredFallback, wantErr: core.ErrGrantUnknown, wantClaims: 1},
		{name: "a grant removed mid-claim keeps the claimed copy and answers revoked", budget: 8 << 20, from: "B", midClaim: remove,
			wantCode: core.DeferredFallback, wantErr: core.ErrGrantRevoked, wantClaims: 1},
		{name: "a session that arrived here mid-claim resumes and the claimed copy is dropped", budget: 8 << 20, from: "B", midClaim: arrive,
			wantCode: core.OK, wantKind: core.ActResume, wantClaims: 1, wantDiscarded: 1},
		{name: "too large to move is deferred with the preferred home", budget: 1 << 20, deltaW: 3 << 20, from: "B",
			wantCode: core.DeferredFallback, wantErr: core.ErrDeltaTooLarge, wantPreferred: "A", wantStored: true},
		{name: "too large with the lane down is shed", budget: 1 << 20, deltaW: 3 << 20, from: "B", laneDown: true,
			wantCode: core.Shed, wantErr: core.ErrDeltaTooLarge, wantStored: true},
		{name: "a home-level cap wins over the grant's budget", budget: 1 << 20, deltaW: 3 << 20, from: "B", homeCap: 8 << 20,
			wantCode: core.OK, wantKind: core.ActResume, wantClaims: 1},
		{name: "incompatible parked state is deferred with the preferred home and stays stored", budget: 8 << 20, from: "B",
			refuse:   fmt.Errorf("%w: kernel 9.9.9", core.ErrIncompatible),
			wantCode: core.DeferredFallback, wantErr: core.ErrIncompatible, wantPreferred: "A", wantStored: true},
		{name: "with the parity gate open it is claimed and resumed", budget: 8 << 20, from: "B",
			wantCode: core.OK, wantKind: core.ActResume, wantClaims: 1},
		{name: "a publish failure keeps the session local", pubErr: errors.New("registry down"), from: "A",
			wantCode: core.OK, wantKind: core.ActResume},
		{name: "a failed sync audit of the move refuses the clone", budget: 8 << 20, from: "B", failAudit: "migrate-in",
			wantCode: core.Internal, wantErr: core.ErrAudit, wantClaims: 1},
		// Like a home without a store, it creates a fresh session.
		{name: "an unreachable store creates the session fresh", budget: 8 << 20, from: "B", findErr: errors.New("registry: connection refused"),
			wantCode: core.OK, wantKind: core.ActCreate, wantStored: true},
		{name: "a pull that fails is deferred with the preferred home and stays stored", budget: 8 << 20, from: "B", claimErr: errors.New("registry: 503"),
			wantCode: core.DeferredFallback, wantErr: core.ErrNotReady, wantPreferred: "A", wantStored: true},
		{name: "a claimed copy that cannot be dropped does not stop the resume", budget: 8 << 20, from: "B", midClaim: arrive,
			discardErr: errors.New("rm: EBUSY"), wantCode: core.OK, wantKind: core.ActResume, wantClaims: 1, wantDiscarded: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := core.Grant{UID: "g1", Tenant: "acme", TemplateDigest: "sha256:t", FiberMax: 4, WBudgetBytes: tc.budget}
			if tc.failAudit != "" {
				g.Policy.Durability = core.Sync
			}
			st := &store{deltas: map[string]published{}}
			a, ra := newMobileAgent(t, "A", st, g)
			b, rb := newMobileAgent(t, "B", st, g)
			a.NodeID, b.NodeID = "", ""
			ra.deltaW, ra.pubErr = tc.deltaW, tc.pubErr
			req := core.CloneRequest{GrantJWT: []byte("g1"), Session: "S", Deadline: time.Second}
			r1, _, _ := a.Clone(ctx, req)
			if _, code, err := a.Park(ctx, r1.FiberID, true); err != nil || code != core.OK {
				t.Fatalf("park must succeed even when publishing fails: %v %d", err, code)
			}
			picker, prt := b, rb
			if tc.from == "A" {
				picker, prt = a, ra
			}
			prt.refuse = tc.refuse
			prt.findErr, prt.claimErr, prt.discardErr = tc.findErr, tc.claimErr, tc.discardErr
			if tc.failAudit != "" {
				picker.Audit = eventAuditor{tc.failAudit}
			}
			if tc.laneDown {
				picker.Health.MarkSync(time.Now().Add(-time.Minute))
			}
			if tc.homeCap != 0 {
				picker.MobilityBudget = func(core.Grant) uint64 { return tc.homeCap }
			}

			var (
				r    core.CloneResponse
				code core.StatusCode
				err  error
			)
			if tc.midClaim == nil {
				r, code, err = picker.Clone(ctx, req)
			} else {
				// The claim announces itself and waits, so the test acts on
				// the picker between the claim and the ledger's restore.
				prt.claimEnter, prt.claimWait = make(chan struct{}, 1), make(chan struct{})
				type result struct {
					resp core.CloneResponse
					code core.StatusCode
					err  error
				}
				done := make(chan result, 1)
				go func() {
					r, code, err := picker.Clone(ctx, req)
					done <- result{r, code, err}
				}()
				select {
				case <-prt.claimEnter:
				case <-time.After(5 * time.Second):
					t.Fatal("the clone never reached a claim")
				}
				tc.midClaim(t, picker)
				close(prt.claimWait)
				res := <-done
				r, code, err = res.resp, res.code, res.err
			}
			if code != tc.wantCode || !errors.Is(err, tc.wantErr) {
				t.Fatalf("%s clone = %d %v, want %d %v", tc.from, code, err, tc.wantCode, tc.wantErr)
			}
			if len(prt.discarded) != tc.wantDiscarded {
				t.Fatalf("claimed copies dropped = %v, want %d", prt.discarded, tc.wantDiscarded)
			}
			if tc.wantPreferred != "" {
				var rm *core.RemoteMiss
				if !errors.As(err, &rm) || rm.PreferredHome != tc.wantPreferred {
					t.Fatalf("preferred home = %+v, want %s", rm, tc.wantPreferred)
				}
			}
			if code == core.OK && r.Kind != tc.wantKind {
				t.Fatalf("%s clone kind = %v, want %v", tc.from, r.Kind, tc.wantKind)
			}
			if ok := st.stored("acme/sha256:t/S"); ok != tc.wantStored {
				t.Fatalf("S in the store = %v, want %v", ok, tc.wantStored)
			}
			if len(prt.claims) != tc.wantClaims {
				t.Fatalf("claims = %v, want %d", prt.claims, tc.wantClaims)
			}
		})
	}
}

// eventAuditor fails the sync records of one event and accepts the rest.
type eventAuditor struct{ fail string }

func (e eventAuditor) Append(_ context.Context, d core.Durability, r core.AuditRecord) error {
	if d == core.Sync && r.Event == e.fail {
		return core.ErrAudit
	}
	return nil
}

// TestConcurrentClaims clones a session parked on A from several callers
// on B at once. They serialize on the session. The first claims and
// resumes it, and the rest attach to that fiber. Otherwise each caller
// would pull the state and resume the session again.
func TestConcurrentClaims(t *testing.T) {
	cases := []struct {
		name   string
		clones int
	}{
		{name: "two concurrent first sights claim once and resume once", clones: 2},
		{name: "four concurrent first sights claim once and resume once", clones: 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := core.Grant{UID: "g1", Tenant: "acme", TemplateDigest: "sha256:t", FiberMax: 4, WBudgetBytes: 8 << 20}
			st := &store{deltas: map[string]published{}}
			a, _ := newMobileAgent(t, "A", st, g)
			b, rb := newMobileAgent(t, "B", st, g)
			a.NodeID, b.NodeID = "", ""
			ctx := context.Background()
			req := core.CloneRequest{GrantJWT: []byte("g1"), Session: "S", Deadline: time.Second}
			r1, code, err := a.Clone(ctx, req)
			if err != nil || code != core.OK {
				t.Fatalf("A clone: %v %d", err, code)
			}
			if _, code, err := a.Park(ctx, r1.FiberID, true); err != nil || code != core.OK {
				t.Fatalf("A park: %v %d", err, code)
			}
			// Every claim announces itself and waits for the test, so a
			// second claim in flight shows up as a second announcement.
			rb.claimEnter, rb.claimWait = make(chan struct{}, tc.clones), make(chan struct{})
			var once sync.Once
			let := func() { once.Do(func() { close(rb.claimWait) }) }
			defer let()
			type result struct {
				resp core.CloneResponse
				code core.StatusCode
				err  error
			}
			results := make(chan result, tc.clones)
			for i := 0; i < tc.clones; i++ {
				go func() {
					r, code, err := b.Clone(ctx, req)
					results <- result{r, code, err}
				}()
			}
			select {
			case <-rb.claimEnter:
			case <-time.After(5 * time.Second):
				t.Fatal("no clone reached a claim")
			}
			select {
			case <-rb.claimEnter:
				t.Fatal("a second claim of S was in flight alongside the first")
			case <-time.After(200 * time.Millisecond):
			}
			let()
			kinds := map[core.Action]int{}
			var fiber string
			for i := 0; i < tc.clones; i++ {
				r := <-results
				if r.err != nil || r.code != core.OK {
					t.Fatalf("B clone: %v %d", r.err, r.code)
				}
				kinds[r.resp.Kind]++
				if fiber == "" {
					fiber = r.resp.FiberID
				} else if r.resp.FiberID != fiber {
					t.Fatalf("clones answered fibers %s and %s, want one", fiber, r.resp.FiberID)
				}
			}
			if kinds[core.ActResume] != 1 || kinds[core.ActAttach] != tc.clones-1 {
				t.Fatalf("kinds = %v, want 1 resume and %d attaches", kinds, tc.clones-1)
			}
			if n := rb.nClaims(); n != 1 {
				t.Fatalf("claims = %d, want 1", n)
			}
			if st.stored("acme/sha256:t/S") {
				t.Fatal("claim left the delta in the store")
			}
			if s, _ := coretest.GrantStatus(b.Ledger, "g1"); s.Running != 1 || s.Parked != 0 {
				t.Fatalf("B status = %+v, want 1 running and nothing parked", s)
			}
		})
	}
}

// TestResumedDeltaLifecycle follows the delta a session was resumed from.
// The ledger keeps its ref with the running incarnation, since the park
// stored it under the parked fence and the running fiber has another. A
// Release with discard drops it, the next park drops it as superseded,
// and a Release without discard leaves it on disk. The resume itself
// withdraws the copy published at the park, so a Clone after the Release
// creates fresh instead of claiming that older state.
func TestResumedDeltaLifecycle(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name        string
		noPark      bool // release the created fiber: nothing was resumed
		repark      bool // park the resumed fiber instead of releasing it
		discard     bool // Release(discard)
		retireFails int  // registry calls that fail before one works
		// wantStoredAfterResume: the published copy survived the resume.
		wantStoredAfterResume bool
		wantRetired           int
		wantDiscarded         int
		wantStored            bool        // the store holds S at the end
		wantNext              core.Action // what the next Clone of S does
	}{
		{name: "a created fiber has no delta to discard", noPark: true, discard: true, wantNext: core.ActCreate},
		{name: "release with discard drops the delta the fiber was resumed from", discard: true,
			wantRetired: 1, wantDiscarded: 1, wantNext: core.ActCreate},
		{name: "release without discard keeps it on disk, and the published copy is gone since the resume",
			wantRetired: 1, wantNext: core.ActCreate},
		{name: "the next park drops the delta it supersedes", repark: true,
			wantRetired: 1, wantDiscarded: 1, wantStored: true, wantNext: core.ActResume},
		{name: "a withdrawal the registry refused is retried by the discarding release", discard: true, retireFails: 1,
			wantStoredAfterResume: true, wantRetired: 1, wantDiscarded: 1, wantNext: core.ActCreate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := core.Grant{UID: "g1", Tenant: "acme", Audience: "A", TemplateDigest: "sha256:t", FiberMax: 4, WBudgetBytes: 8 << 20}
			st := &store{deltas: map[string]published{}}
			a, ra := newMobileAgent(t, "A", st, g)
			ra.retireFails = tc.retireFails
			req := core.CloneRequest{GrantJWT: []byte("g1"), Session: "S", Deadline: time.Second}
			r1, code, err := a.Clone(ctx, req)
			if err != nil || code != core.OK || r1.Kind != core.ActCreate {
				t.Fatalf("create: %v %d %v", err, code, r1.Kind)
			}
			id, ref1 := r1.FiberID, "delta-A-"+r1.FiberID
			if !tc.noPark {
				if _, code, err := a.Park(ctx, id, false); err != nil || code != core.OK {
					t.Fatalf("park: %v %d", err, code)
				}
				if !st.stored("acme/sha256:t/S") {
					t.Fatal("park did not publish the delta")
				}
				r2, code, err := a.Clone(ctx, req)
				if err != nil || code != core.OK || r2.Kind != core.ActResume {
					t.Fatalf("resume: %v %d %v", err, code, r2.Kind)
				}
				id = r2.FiberID
				if got := st.stored("acme/sha256:t/S"); got != tc.wantStoredAfterResume {
					t.Errorf("published copy after the local resume = %v, want %v", got, tc.wantStoredAfterResume)
				}
			}
			if tc.repark {
				if _, code, err := a.Park(ctx, id, false); err != nil || code != core.OK {
					t.Fatalf("second park: %v %d", err, code)
				}
				if state, ref, ok := a.Ledger.SessionState("g1", "S"); !ok || state != core.StateParked || ref != "delta-A-"+id {
					t.Fatalf("after the second park S = %v %q %v, want parked at the new delta", state, ref, ok)
				}
			} else if code, err := a.Release(ctx, id, tc.discard); err != nil || code != core.OK {
				t.Fatalf("release: %v %d", err, code)
			}
			if len(ra.retired) != tc.wantRetired || (tc.wantRetired == 1 && ra.retired[0] != ref1) {
				t.Errorf("retired = %v, want %d of %s", ra.retired, tc.wantRetired, ref1)
			}
			if len(ra.discarded) != tc.wantDiscarded || (tc.wantDiscarded == 1 && ra.discarded[0] != ref1) {
				t.Errorf("discarded = %v, want %d of %s", ra.discarded, tc.wantDiscarded, ref1)
			}
			if got := st.stored("acme/sha256:t/S"); got != tc.wantStored {
				t.Errorf("published copy at the end = %v, want %v", got, tc.wantStored)
			}
			r3, code, err := a.Clone(ctx, req)
			if err != nil || code != core.OK || r3.Kind != tc.wantNext {
				t.Fatalf("next clone: %v %d %v, want %v", err, code, r3.Kind, tc.wantNext)
			}
		})
	}
}

// TestLostFiberDiscardsResumedDelta checks the rule that a resumed delta
// is consumed by its resume. However the running fiber is lost, the delta
// it came from goes, since nothing can resume it and it holds delta
// quota. A parked session's delta stays through the same events.
func TestLostFiberDiscardsResumedDelta(t *testing.T) {
	ctx := context.Background()
	// lose ends the running fiber (or the whole agent) one way.
	type loser func(t *testing.T, a *core.Agent, ra *mobileRuntime, fiber string)
	exit := func(_ *testing.T, a *core.Agent, _ *mobileRuntime, fiber string) {
		a.OnExit(ctx, core.FiberExit{FiberID: fiber, Reason: "oom", Detail: "dirtied past w_budget"})
	}
	yield := func(_ *testing.T, a *core.Agent, _ *mobileRuntime, _ string) { a.Yield(ctx, "g1", "ladder") }
	remove := func(t *testing.T, a *core.Agent, _ *mobileRuntime, _ string) {
		r, err := core.OpenRevoked(filepath.Join(t.TempDir(), "revoked.json"), time.Hour, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		a.Revoked = r
		a.Remove(ctx, "g1")
	}
	bump := func(t *testing.T, a *core.Agent, _ *mobileRuntime, _ string) {
		store, err := core.OpenEpochStore(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		a.Epoch = store
		if _, err := a.BumpEpoch(ctx, "scope lost"); err != nil {
			t.Fatal(err)
		}
	}
	restart := func(t *testing.T, a *core.Agent, ra *mobileRuntime, _ string) {
		// A new agent over the same runtime boots from the snapshot the
		// old one left, as after a crash.
		snap := a.Ledger.Snapshot()
		b := newAgent(t, "up", core.TierCheckpoint)
		b.NodeID, b.Runtime, b.Ledger = "A", ra, core.NewLedger(snap.Epoch+1)
		if _, err := b.Reconcile(ctx, snap); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name          string
		lose          loser
		parked        bool // the session is parked, not resumed, when the fiber is lost
		wantDiscarded int
	}{
		{name: "an exit of its own drops the delta the fiber came from", lose: exit, wantDiscarded: 1},
		{name: "a yield of the grant drops it", lose: yield, wantDiscarded: 1},
		{name: "a removal of the grant drops it", lose: remove, wantDiscarded: 1},
		{name: "an epoch bump drops it", lose: bump, wantDiscarded: 1},
		{name: "a restart that finds the session running drops it", lose: restart, wantDiscarded: 1},
		{name: "a yield keeps a parked session's delta", lose: yield, parked: true},
		{name: "a restart keeps a parked session's delta", lose: restart, parked: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := core.Grant{UID: "g1", Tenant: "acme", Audience: "A", TemplateDigest: "sha256:t", FiberMax: 4, WBudgetBytes: 8 << 20}
			st := &store{deltas: map[string]published{}}
			a, ra := newMobileAgent(t, "A", st, g)
			req := core.CloneRequest{GrantJWT: []byte("g1"), Session: "S", Deadline: time.Second}
			r1, code, err := a.Clone(ctx, req)
			if err != nil || code != core.OK || r1.Kind != core.ActCreate {
				t.Fatalf("create: %v %d %v", err, code, r1.Kind)
			}
			ref1 := "delta-A-" + r1.FiberID
			if _, code, err := a.Park(ctx, r1.FiberID, false); err != nil || code != core.OK {
				t.Fatalf("park: %v %d", err, code)
			}
			fiber := r1.FiberID
			if !tc.parked {
				r2, code, err := a.Clone(ctx, req)
				if err != nil || code != core.OK || r2.Kind != core.ActResume {
					t.Fatalf("resume: %v %d %v", err, code, r2.Kind)
				}
				fiber = r2.FiberID
			}
			tc.lose(t, a, ra, fiber)
			if len(ra.discarded) != tc.wantDiscarded || (tc.wantDiscarded == 1 && ra.discarded[0] != ref1) {
				t.Errorf("discarded = %v, want %d of %s", ra.discarded, tc.wantDiscarded, ref1)
			}
			if tc.parked && !ra.HasDeltaLike(ref1) {
				t.Errorf("the parked delta %s was dropped", ref1)
			}
		})
	}
}

// HasDeltaLike reports whether the runtime was never told to drop ref.
func (m *mobileRuntime) HasDeltaLike(ref string) bool {
	m.st.mu.Lock()
	defer m.st.mu.Unlock()
	for _, d := range m.discarded {
		if d == ref {
			return false
		}
	}
	return true
}

// TestMigrateOutDiscardsDelta checks what the publishing home does with
// its parked copy once another home has claimed the session: the copy is
// older state no one may resume, so it is dropped with the quota and the
// port it held, and the session is created fresh here. A drop that fails
// is logged and changes nothing else.
func TestMigrateOutDiscardsDelta(t *testing.T) {
	cases := []struct {
		name       string
		discardErr error
	}{
		{name: "the stale copy is dropped"},
		{name: "a drop that fails still forgets the session", discardErr: errors.New("busy")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ga := core.Grant{UID: "ga", Tenant: "acme", Audience: "A", TemplateDigest: "sha256:t", FiberMax: 4, WBudgetBytes: 10 << 20}
			gb := core.Grant{UID: "gb", Tenant: "acme", Audience: "B", TemplateDigest: "sha256:t", FiberMax: 4, WBudgetBytes: 10 << 20}
			st := &store{deltas: map[string]published{}}
			a, ra := newMobileAgent(t, "A", st, ga)
			b, _ := newMobileAgent(t, "B", st, gb)
			ra.discardErr = tc.discardErr
			ctx := context.Background()
			r1, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("ga"), Session: "S", Deadline: time.Second})
			if err != nil || code != core.OK {
				t.Fatalf("A clone: %v %d", err, code)
			}
			if _, code, err := a.Park(ctx, r1.FiberID, true); err != nil || code != core.OK {
				t.Fatalf("A park: %v %d", err, code)
			}
			if r2, code, err := b.Clone(ctx, core.CloneRequest{GrantJWT: []byte("gb"), Session: "S", Deadline: time.Second}); err != nil || code != core.OK || r2.Kind != core.ActResume {
				t.Fatalf("B clone: %v %d %v", err, code, r2.Kind)
			}
			ref := "delta-A-" + r1.FiberID
			st.claimedRefs = append(st.claimedRefs, ref)
			r3, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("ga"), Session: "S", Deadline: time.Second})
			if err != nil || code != core.OK || r3.Kind != core.ActCreate {
				t.Fatalf("A clone after the claim: %v %d %v, want a fresh create", err, code, r3.Kind)
			}
			if len(ra.discarded) != 1 || ra.discarded[0] != ref {
				t.Fatalf("A dropped %v, want its stale copy %s", ra.discarded, ref)
			}
			if _, _, known := a.Ledger.SessionState("ga", "S"); known {
				if st, _, _ := a.Ledger.SessionState("ga", "S"); st != core.StateRunning {
					t.Fatalf("S on A is %v, want the fresh session running", st)
				}
			}
		})
	}
}

// TestTenantKeepsSessionsApart has tenant acme park session S on home A
// and then has another grant clone S on home B. The session domain is the
// tenant and then the template, so a grant of the same tenant resumes it
// whatever its UID and audience, and a grant of another tenant on the
// same template, class and name creates a fresh session and leaves
// acme's in the store. Before the tenant, the domain was the template
// alone, and B resumed A's session for anyone who guessed its name.
func TestTenantKeepsSessionsApart(t *testing.T) {
	cases := []struct {
		name       string
		claimant   core.Grant
		wantKind   core.Action
		wantStored bool // acme's S still in the store afterwards
	}{
		{name: "the same tenant resumes it through another grant on another home",
			claimant:   core.Grant{UID: "gb", Tenant: "acme", Audience: "B", TemplateDigest: "sha256:t", FiberMax: 4, WBudgetBytes: 10 << 20},
			wantKind:   core.ActResume,
			wantStored: false},
		{name: "another tenant on the same template creates fresh and finds nothing",
			claimant:   core.Grant{UID: "gb", Tenant: "globex", Audience: "B", TemplateDigest: "sha256:t", FiberMax: 4, WBudgetBytes: 10 << 20},
			wantKind:   core.ActCreate,
			wantStored: true},
		{name: "another tenant with the same session class creates fresh and finds nothing",
			claimant: core.Grant{UID: "gb", Tenant: "globex", Audience: "B", TemplateDigest: "sha256:t", FiberMax: 4, WBudgetBytes: 10 << 20,
				Policy: core.Policy{SessionClass: "models"}},
			wantKind:   core.ActCreate,
			wantStored: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			owner := core.Grant{UID: "ga", Tenant: "acme", Audience: "A", TemplateDigest: "sha256:t", FiberMax: 4, WBudgetBytes: 10 << 20,
				Policy: tc.claimant.Policy}
			st := &store{deltas: map[string]published{}}
			a, _ := newMobileAgent(t, "A", st, owner)
			b, rb := newMobileAgent(t, "B", st, tc.claimant)
			r, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("ga"), Session: "S", Deadline: time.Second})
			if err != nil || code != core.OK || r.Kind != core.ActCreate {
				t.Fatalf("A clone: %v %d %v", err, code, r.Kind)
			}
			if _, code, err := a.Park(ctx, r.FiberID, true); err != nil || code != core.OK {
				t.Fatalf("A park: %v %d", err, code)
			}
			ownerKey := "acme/sha256:t/S"
			if owner.Policy.SessionClass != "" {
				ownerKey = "acme/" + owner.Policy.SessionClass + "/S"
			}
			if !st.stored(ownerKey) {
				t.Fatalf("A's park did not publish %s", ownerKey)
			}
			r2, code, err := b.Clone(ctx, core.CloneRequest{GrantJWT: []byte("gb"), Session: "S", Deadline: time.Second})
			if err != nil || code != core.OK {
				t.Fatalf("B clone: %v %d", err, code)
			}
			if r2.Kind != tc.wantKind {
				t.Fatalf("B clone kind = %v, want %v", r2.Kind, tc.wantKind)
			}
			if got := st.stored(ownerKey); got != tc.wantStored {
				t.Fatalf("acme's S in the store after B's clone = %v, want %v", got, tc.wantStored)
			}
			if wantClaims := map[bool]int{true: 1, false: 0}[tc.wantKind == core.ActResume]; rb.nClaims() != wantClaims {
				t.Fatalf("B claimed %d sessions, want %d", rb.nClaims(), wantClaims)
			}
		})
	}
}

// TestNamedSessionNeedsTenant checks that a grant without a tenant runs
// anonymous fibers only. A named Clone under it is refused up front as
// FailedPrecondition, and so is a named Park should the grant be
// delivered again without its tenant. Anonymous fibers clone and park.
func TestNamedSessionNeedsTenant(t *testing.T) {
	with := core.Grant{UID: "g1", Tenant: "acme", Audience: "A", TemplateDigest: "sha256:t", FiberMax: 4}
	without := core.Grant{UID: "g1", Audience: "A", TemplateDigest: "sha256:t", FiberMax: 4}
	cases := []struct {
		name      string
		grant     core.Grant
		session   string
		redeliver *core.Grant // admitted again before the park
		wantClone core.StatusCode
		wantPark  core.StatusCode
	}{
		{name: "a named clone without a tenant is refused", grant: without, session: "S", wantClone: core.NeedsTier},
		{name: "an anonymous clone and park without a tenant work", grant: without, wantClone: core.OK, wantPark: core.OK},
		{name: "a named clone and park with a tenant work", grant: with, session: "S", wantClone: core.OK, wantPark: core.OK},
		{name: "a named park is refused once the grant lost its tenant", grant: with, session: "S", redeliver: &without,
			wantClone: core.OK, wantPark: core.NeedsTier},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			a, _ := newMobileAgent(t, "A", &store{deltas: map[string]published{}}, tc.grant)
			r, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Session: tc.session, Deadline: time.Second})
			if code != tc.wantClone {
				t.Fatalf("clone = %d %v, want %d", code, err, tc.wantClone)
			}
			if code != core.OK {
				if !errors.Is(err, core.ErrNoTenant) {
					t.Fatalf("clone err = %v, want ErrNoTenant", err)
				}
				if st, _ := coretest.GrantStatus(a.Ledger, "g1"); st.Running != 0 {
					t.Fatalf("a refused clone left %d fibers running", st.Running)
				}
				return
			}
			if tc.redeliver != nil {
				a.Ledger.AdmitGrant(*tc.redeliver)
			}
			_, code, err = a.Park(ctx, r.FiberID, true)
			if code != tc.wantPark {
				t.Fatalf("park = %d %v, want %d", code, err, tc.wantPark)
			}
			st, _ := coretest.GrantStatus(a.Ledger, "g1")
			if code != core.OK {
				if !errors.Is(err, core.ErrNoTenant) {
					t.Fatalf("park err = %v, want ErrNoTenant", err)
				}
				if st.Running != 1 || st.Parked != 0 {
					t.Fatalf("after a refused park: running %d parked %d, want the fiber still running", st.Running, st.Parked)
				}
				return
			}
			if st.Running != 0 {
				t.Fatalf("after the park: running %d, want 0", st.Running)
			}
		})
	}
}

// slowPublish is a mobileRuntime whose publish announces itself and then
// waits for the test, like a push that takes time.
type slowPublish struct {
	*mobileRuntime
	enter chan struct{}
	wait  chan struct{}
}

func (s slowPublish) PublishDelta(ctx context.Context, ref string, g core.Grant, session string) (string, error) {
	s.enter <- struct{}{}
	<-s.wait
	return s.mobileRuntime.PublishDelta(ctx, ref, g, session)
}

// TestParkRacesClone clones under a grant while a park of its session S
// is between the ledger's park and the publish. A Clone(S) waits for the
// park to finish, so it resumes the delta after it is published and its
// resume withdraws that copy. A clone of another session is not held.
// Before the fix Park took no session gate, so the clone resumed S from
// the ledger's parked state while the publish was still running, the
// publish then put the superseded checkpoint in the store, and another
// home claimed it, so S ran twice.
func TestParkRacesClone(t *testing.T) {
	cases := []struct {
		name       string
		session    string // what the concurrent clone asks for
		wantWait   bool   // it waits for the park
		wantKind   core.Action
		wantStored bool        // S is still published once both are done
		wantOnB    core.Action // what B's Clone(S) then does
	}{
		{name: "a clone of the parking session waits and resumes after the publish", session: "S", wantWait: true, wantKind: core.ActResume, wantOnB: core.ActCreate},
		{name: "a clone of another session is not held", session: "T", wantKind: core.ActCreate, wantStored: true, wantOnB: core.ActResume},
	}
	type result struct {
		r    core.CloneResponse
		code core.StatusCode
		err  error
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ga := core.Grant{UID: "ga", Tenant: "acme", Audience: "A", TemplateDigest: "sha256:t", FiberMax: 4, WBudgetBytes: 10 << 20}
			gb := core.Grant{UID: "gb", Tenant: "acme", Audience: "B", TemplateDigest: "sha256:t", FiberMax: 4, WBudgetBytes: 10 << 20}
			st := &store{deltas: map[string]published{}}
			a, ra := newMobileAgent(t, "A", st, ga)
			b, _ := newMobileAgent(t, "B", st, gb)
			sp := slowPublish{mobileRuntime: ra, enter: make(chan struct{}), wait: make(chan struct{})}
			a.Runtime = sp
			ra.deltaW = 1 << 20
			var once sync.Once
			publish := func() { once.Do(func() { close(sp.wait) }) }
			t.Cleanup(publish)
			ctx := context.Background()
			first, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("ga"), Session: "S", Deadline: time.Second})
			if err != nil || code != core.OK {
				t.Fatalf("clone S = %d %v", code, err)
			}
			parked := make(chan struct{})
			go func() {
				defer close(parked)
				if _, code, err := a.Park(ctx, first.FiberID, true); err != nil || code != core.OK {
					t.Errorf("park = %d %v", code, err)
				}
			}()
			<-sp.enter // the ledger says parked, the publish has not happened
			cloned := make(chan result, 1)
			go func() {
				r, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("ga"), Session: tc.session, Deadline: time.Second})
				cloned <- result{r, code, err}
			}()
			select {
			case r := <-cloned:
				if tc.wantWait {
					t.Fatalf("clone of %s = %v %d %v before the park published", tc.session, r.r.Kind, r.code, r.err)
				}
				cloned <- r
			case <-time.After(100 * time.Millisecond):
				if !tc.wantWait {
					t.Fatalf("clone of %s is held by the park of S", tc.session)
				}
			}
			publish()
			<-parked
			r := <-cloned
			if r.err != nil || r.code != core.OK || r.r.Kind != tc.wantKind {
				t.Fatalf("clone of %s = %v %d %v, want %v", tc.session, r.r.Kind, r.code, r.err, tc.wantKind)
			}
			if st.stored("acme/sha256:t/S") != tc.wantStored {
				t.Fatalf("S published after the park and the clone = %v, want %v", !tc.wantStored, tc.wantStored)
			}
			onB, code, err := b.Clone(ctx, core.CloneRequest{GrantJWT: []byte("gb"), Session: "S", Deadline: time.Second})
			if err != nil || code != core.OK || onB.Kind != tc.wantOnB {
				t.Fatalf("B's clone of S = %v %d %v, want %v", onB.Kind, code, err, tc.wantOnB)
			}
		})
	}
}
