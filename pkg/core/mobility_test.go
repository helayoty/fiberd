package core_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// mobileRuntime is fakeRuntime plus a shared "registry": a map from
// grant/session to a published delta, shared between two runtimes so two
// agents can hand a session to each other.
type store struct {
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
	home   string
	st     *store
	claims []string
	deltaW uint64 // W the next park will report
	pubErr error
	// refuse, when set, is what FindDelta answers for a session it finds:
	// the runtime's parity gate saying "not here".
	refuse error
}

func (m *mobileRuntime) key(g core.Grant, session string) string {
	return g.SessionDomain() + "/" + session
}

func (m *mobileRuntime) PublishDelta(_ context.Context, ref string, g core.Grant, session string) (string, error) {
	if m.pubErr != nil {
		return "", m.pubErr
	}
	m.st.deltas[m.key(g, session)] = published{ref: ref, wBytes: m.deltaW, home: m.home, owner: m}
	return "registry/" + ref, nil
}

func (m *mobileRuntime) FindDelta(_ context.Context, g core.Grant, session string) (core.RemoteDelta, bool, error) {
	p, ok := m.st.deltas[m.key(g, session)]
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
	delete(m.st.deltas, m.key(g, session))
	m.claims = append(m.claims, rd.Handle)
	return "claimed:" + rd.Handle, nil
}

func (m *mobileRuntime) Owned(_ context.Context, ref string) bool {
	for _, p := range m.st.deltas {
		if p.ref == ref && p.owner == m {
			return true
		}
	}
	// Published and gone from the store: someone claimed it. Never
	// published (no entry ever): ours.
	for _, c := range m.claimedElsewhere() {
		if c == ref {
			return false
		}
	}
	return true
}

func (m *mobileRuntime) claimedElsewhere() []string { return m.st.claimedRefs }

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

func TestSessionMovesBetweenHomes(t *testing.T) {
	// Two homes, two grants (one per audience), one template: the session
	// domain is the template digest, so both see the same parked state.
	ga := core.Grant{UID: "ga", Audience: "A", TemplateDigest: "sha256:t", FiberMax: 4, WBudgetBytes: 10 << 20}
	gb := core.Grant{UID: "gb", Audience: "B", TemplateDigest: "sha256:t", FiberMax: 4, WBudgetBytes: 10 << 20}
	st := &store{deltas: map[string]published{}}
	a, ra := newMobileAgent(t, "A", st, ga)
	b, rb := newMobileAgent(t, "B", st, gb)
	ctx := context.Background()
	reqA := core.CloneRequest{GrantJWT: []byte("ga"), Session: "S", Deadline: time.Second}
	reqB := core.CloneRequest{GrantJWT: []byte("gb"), Session: "S", Deadline: time.Second}

	// A creates and parks S; the park publishes under the template domain.
	r1, code, err := a.Clone(ctx, reqA)
	if err != nil || code != core.OK || r1.Kind != core.ActCreate {
		t.Fatalf("A clone: %v %d %v", err, code, r1.Kind)
	}
	ra.deltaW = 4 << 20
	if _, code, err := a.Park(ctx, r1.FiberID, true); err != nil || code != core.OK {
		t.Fatalf("A park: %v %d", err, code)
	}
	if _, ok := st.deltas["sha256:t/S"]; !ok {
		t.Fatal("park did not publish the delta under the template domain")
	}

	// B has never seen S: it finds, claims and resumes it with its own grant.
	r2, code, err := b.Clone(ctx, reqB)
	if err != nil || code != core.OK {
		t.Fatalf("B clone: %v %d", err, code)
	}
	if r2.Kind != core.ActResume || len(rb.claims) != 1 {
		t.Fatalf("B clone kind = %v claims = %v, want RESUME after one claim", r2.Kind, rb.claims)
	}
	if _, ok := st.deltas["sha256:t/S"]; ok {
		t.Fatal("claim left the delta in the store")
	}

	// A still holds a stale parked copy; it must not resume it. The store
	// no longer has S (B holds it live), so A creates fresh.
	st.claimedRefs = append(st.claimedRefs, "delta-A-"+r1.FiberID)
	r3, code, err := a.Clone(ctx, reqA)
	if err != nil || code != core.OK {
		t.Fatalf("A clone after claim: %v %d", err, code)
	}
	if r3.Kind != core.ActCreate {
		t.Fatalf("A resumed a session B had claimed: kind %v", r3.Kind)
	}

	// A different session class is a different domain: a grant with one
	// does not see the template-domain session.
	gc := core.Grant{UID: "gc", Audience: "B", TemplateDigest: "sha256:t", Policy: core.Policy{SessionClass: "tenant-2"}}
	if gc.SessionDomain() == ga.SessionDomain() {
		t.Fatal("session class must define its own domain")
	}
}

func TestTooLargeToMoveIsDeferredWithPreferredHome(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:t", FiberMax: 4, WBudgetBytes: 1 << 20}
	st := &store{deltas: map[string]published{}}
	a, ra := newMobileAgent(t, "A", st, g)
	b, _ := newMobileAgent(t, "B", st, g)
	a.NodeID, b.NodeID = "", ""
	ctx := context.Background()
	req := core.CloneRequest{GrantJWT: []byte("g1"), Session: "S", Deadline: time.Second}
	r1, _, _ := a.Clone(ctx, req)
	ra.deltaW = 3 << 20 // over the 1 MiB budget
	if _, code, err := a.Park(ctx, r1.FiberID, true); err != nil || code != core.OK {
		t.Fatal(err)
	}
	_, code, err := b.Clone(ctx, req)
	if code != core.DeferredFallback || !errors.Is(err, core.ErrDeltaTooLarge) {
		t.Fatalf("B clone = %d %v, want DeferredFallback ErrDeltaTooLarge", code, err)
	}
	var rm *core.RemoteMiss
	if !errors.As(err, &rm) || rm.PreferredHome != "A" {
		t.Fatalf("preferred home = %+v, want A", rm)
	}
	// With the lane down the same miss is SHED.
	b.Health.MarkSync(time.Now().Add(-time.Minute))
	if _, code, _ := b.Clone(ctx, req); code != core.Shed {
		t.Fatalf("too large with lane down = %d, want Shed", code)
	}
	// A home-level cap wins over the grant's budget.
	b.Health.MarkSync(time.Now())
	b.MobilityBudget = func(core.Grant) uint64 { return 8 << 20 }
	if r, code, err := b.Clone(ctx, req); err != nil || code != core.OK || r.Kind != core.ActResume {
		t.Fatalf("with a larger home cap = %v %d %v, want RESUME", err, code, r.Kind)
	}
}

func TestIncompatibleParkedStateIsDeferredWithPreferredHome(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:t", FiberMax: 4, WBudgetBytes: 8 << 20}
	st := &store{deltas: map[string]published{}}
	a, _ := newMobileAgent(t, "A", st, g)
	b, rb := newMobileAgent(t, "B", st, g)
	a.NodeID, b.NodeID = "", ""
	ctx := context.Background()
	req := core.CloneRequest{GrantJWT: []byte("g1"), Session: "S", Deadline: time.Second}
	r1, _, _ := a.Clone(ctx, req)
	if _, code, err := a.Park(ctx, r1.FiberID, true); err != nil || code != core.OK {
		t.Fatal(err)
	}
	// B's runtime finds S but its parity gate refuses it: the caller is
	// sent to A, and the store still has S for A (or a compatible home).
	rb.refuse = fmt.Errorf("%w: kernel 9.9.9", core.ErrIncompatible)
	_, code, err := b.Clone(ctx, req)
	var rm *core.RemoteMiss
	if code != core.DeferredFallback || !errors.Is(err, core.ErrIncompatible) || !errors.As(err, &rm) || rm.PreferredHome != "A" {
		t.Fatalf("B clone = %d %v, want DeferredFallback ErrIncompatible preferring A", code, err)
	}
	if _, ok := st.deltas["sha256:t/S"]; !ok {
		t.Fatal("a refused session must stay in the store")
	}
	if len(rb.claims) != 0 {
		t.Fatal("B claimed what it refused")
	}
	// A store error that is not a refusal still creates fresh (any home
	// without a store would).
	rb.refuse = nil
	if r, code, err := b.Clone(ctx, req); err != nil || code != core.OK || r.Kind != core.ActResume {
		t.Fatalf("B clone with the gate open = %v %d %v, want RESUME", err, code, r.Kind)
	}
}

func TestPublishFailureKeepsSessionLocal(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:t", FiberMax: 4}
	st := &store{deltas: map[string]published{}}
	a, ra := newMobileAgent(t, "A", st, g)
	a.NodeID = ""
	ra.pubErr = errors.New("registry down")
	ctx := context.Background()
	req := core.CloneRequest{GrantJWT: []byte("g1"), Session: "S", Deadline: time.Second}
	r1, _, _ := a.Clone(ctx, req)
	if _, code, err := a.Park(ctx, r1.FiberID, true); err != nil || code != core.OK {
		t.Fatalf("park must succeed even when publishing fails: %v %d", err, code)
	}
	if r, _, _ := a.Clone(ctx, req); r.Kind != core.ActResume {
		t.Fatalf("local resume after failed publish = %v, want RESUME", r.Kind)
	}
}
