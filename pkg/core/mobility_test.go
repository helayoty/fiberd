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
	deltaW    uint64   // W the next park will report
	pubErr    error
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
	return g.SessionDomain() + "/" + session
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
	ga := core.Grant{UID: "ga", Audience: "A", TemplateDigest: "sha256:t", FiberMax: 4, WBudgetBytes: 10 << 20}
	gb := core.Grant{UID: "gb", Audience: "B", TemplateDigest: "sha256:t", FiberMax: 4, WBudgetBytes: 10 << 20}
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
		{name: "A parks it and the park publishes under the template domain", step: func(t *testing.T) {
			ra.deltaW = 4 << 20
			if _, code, err := a.Park(ctx, r1.FiberID, true); err != nil || code != core.OK {
				t.Fatalf("A park: %v %d", err, code)
			}
			if !st.stored("sha256:t/S") {
				t.Fatal("park did not publish the delta under the template domain")
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
			if st.stored("sha256:t/S") {
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
// domain. That is the template digest, unless the policy names a session
// class.
func TestSessionDomain(t *testing.T) {
	cases := []struct {
		name  string
		grant core.Grant
		want  string
	}{
		{name: "without a session class it is the template digest",
			grant: core.Grant{UID: "ga", Audience: "A", TemplateDigest: "sha256:t"}, want: "sha256:t"},
		{name: "another audience on the same template shares it",
			grant: core.Grant{UID: "gb", Audience: "B", TemplateDigest: "sha256:t"}, want: "sha256:t"},
		{name: "a session class defines its own domain",
			grant: core.Grant{UID: "gc", Audience: "B", TemplateDigest: "sha256:t", Policy: core.Policy{SessionClass: "tenant-2"}}, want: "tenant-2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.grant.SessionDomain(); got != tc.want {
				t.Fatalf("SessionDomain = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestParkedSessionPickup has home A park session S, which succeeds even
// when publishing fails. Then a home clones S again. A delta over the
// mobility budget, or one the parity gate refuses, is deferred to its
// preferred home (shed with the lane down) and stays in the store.
// Otherwise it is claimed and resumed. An unpublished session still
// resumes locally.
//
// A claim takes the store's only tag, so what happens to the claimed copy
// when the ledger refuses it matters. The session arriving here meanwhile
// means the copy is a duplicate and is dropped. The grant going away
// meanwhile means the copy is the only one, so it is kept and the caller
// gets the miss the revocation implies.
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
			g := core.Grant{UID: "g1", TemplateDigest: "sha256:t", FiberMax: 4, WBudgetBytes: tc.budget}
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
			if ok := st.stored("sha256:t/S"); ok != tc.wantStored {
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
			g := core.Grant{UID: "g1", TemplateDigest: "sha256:t", FiberMax: 4, WBudgetBytes: 8 << 20}
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
			if st.stored("sha256:t/S") {
				t.Fatal("claim left the delta in the store")
			}
			if s, _ := coretest.GrantStatus(b.Ledger, "g1"); s.Running != 1 || s.Parked != 0 {
				t.Fatalf("B status = %+v, want 1 running and nothing parked", s)
			}
		})
	}
}
