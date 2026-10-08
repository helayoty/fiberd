package home_test

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/home"
	"github.com/helayoty/fiberd/pkg/runtime/stub"
)

type ready struct {
	uid   string
	ready bool
}

// fakeHome hands Drive a lane the test feeds and records readiness.
type fakeHome struct {
	lane    chan home.GrantEvent
	laneErr error

	mu        sync.Mutex
	published []ready
}

func (h *fakeHome) Name() string { return "fake" }
func (h *fakeHome) Grants(context.Context) (<-chan home.GrantEvent, error) {
	if h.laneErr != nil {
		return nil, h.laneErr
	}
	if h.lane == nil {
		return nil, nil // a nil channel, not a nil-valued typed one
	}
	return h.lane, nil
}
func (h *fakeHome) Health() *core.SourceHealth { return nil }
func (h *fakeHome) CgroupRoot() string         { return "" }
func (h *fakeHome) AdvertisedEndpoint() string { return "" }
func (h *fakeHome) PublishReady(_ context.Context, uid string, r bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.published = append(h.published, ready{uid, r})
	return nil
}
func (h *fakeHome) Scope() []core.ScopeClaim { return nil }
func (h *fakeHome) Fabric(context.Context, core.Grant) (core.FabricChannel, func(), error) {
	return core.FabricChannel{}, func() {}, nil
}
func (h *fakeHome) Run(context.Context) {}

func token(t *testing.T, g core.Grant) []byte {
	t.Helper()
	b, err := protojson.Marshal(grant.ToProto(g))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newAgent(t *testing.T) *core.Agent {
	t.Helper()
	revoked, err := core.OpenRevoked(filepath.Join(t.TempDir(), "revoked.json"), time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return &core.Agent{Ledger: core.NewLedger(1), Budget: core.NewBudget(100, 1<<20),
		Runtime: stub.New(), Verify: grant.InsecureJSONVerifier{}, Revoked: revoked}
}

// TestDriveEvents feeds a lane and checks what the agent admitted and
// what the home was told once the lane closes.
func TestDriveEvents(t *testing.T) {
	g1 := token(t, core.Grant{UID: "g1", FiberMax: 1})
	// The stub runtime offers FIBER_CHECKPOINT, so a grant needing more
	// verifies but is refused at admission.
	tooHigh := token(t, core.Grant{UID: "g2", MinTier: core.TierSnapshot})
	added := func(tok []byte) home.GrantEvent { return home.GrantEvent{Kind: home.GrantAdded, Token: tok} }
	removed := func(uid string) home.GrantEvent { return home.GrantEvent{Kind: home.GrantRemoved, UID: uid} }

	cases := []struct {
		name      string
		events    []home.GrantEvent
		admitted  []string
		published []ready
	}{
		{name: "a grant that verifies is admitted and published ready",
			events: []home.GrantEvent{added(g1)}, admitted: []string{"g1"}, published: []ready{{"g1", true}}},
		{name: "a token that does not verify is skipped",
			events: []home.GrantEvent{added([]byte("not a grant")), added(g1)}, admitted: []string{"g1"}, published: []ready{{"g1", true}}},
		{name: "a grant the agent refuses is not published",
			events: []home.GrantEvent{added(tooHigh)}},
		{name: "a removal takes the grant away and publishes not ready",
			events: []home.GrantEvent{added(g1), removed("g1")}, published: []ready{{"g1", true}, {"g1", false}}},
		{name: "the lane delivering a removed grant again lifts its denial",
			events:    []home.GrantEvent{added(g1), removed("g1"), added(g1)},
			admitted:  []string{"g1"},
			published: []ready{{"g1", true}, {"g1", false}, {"g1", true}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := newAgent(t)
			h := &fakeHome{lane: make(chan home.GrantEvent)}
			done := make(chan struct{})
			go func() { defer close(done); home.Drive(context.Background(), h, a) }()
			for _, ev := range c.events {
				h.lane <- ev // unbuffered, so Drive took the previous event
			}
			close(h.lane)
			waitDone(t, done)

			var admitted []string
			for _, st := range a.Ledger.Statuses() {
				admitted = append(admitted, st.GrantUID)
			}
			if !slices.Equal(admitted, c.admitted) {
				t.Fatalf("admitted %v, want %v", admitted, c.admitted)
			}
			for _, uid := range c.admitted {
				if g, _ := a.Ledger.Grant(uid); g.Token != string(g1) {
					t.Fatalf("grant %s keeps token %q, want the lane's", uid, g.Token)
				}
			}
			if !slices.Equal(h.published, c.published) {
				t.Fatalf("published %v, want %v", h.published, c.published)
			}
		})
	}
}

// TestDriveReturns checks every way the lane ends Drive.
func TestDriveReturns(t *testing.T) {
	cases := []struct {
		name   string
		home   *fakeHome
		cancel bool
	}{
		{name: "the lane fails to open", home: &fakeHome{laneErr: errors.New("no lane")}},
		{name: "the home has no lane", home: &fakeHome{}},
		{name: "the context ends while the lane is open", home: &fakeHome{lane: make(chan home.GrantEvent)}, cancel: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if c.cancel {
				cancel()
			}
			a := newAgent(t)
			done := make(chan struct{})
			go func() { defer close(done); home.Drive(ctx, c.home, a) }()
			waitDone(t, done)
			if len(c.home.published) != 0 {
				t.Fatalf("published %v with no events", c.home.published)
			}
		})
	}
}

func waitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Drive did not return")
	}
}
