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

// fakeHome hands Drive a delivery channel the test feeds and records readiness.
type fakeHome struct {
	events    chan home.GrantEvent
	eventsErr error

	mu        sync.Mutex
	published []ready
}

func (h *fakeHome) Name() string { return "fake" }
func (h *fakeHome) Grants(context.Context) (<-chan home.GrantEvent, error) {
	if h.eventsErr != nil {
		return nil, h.eventsErr
	}
	if h.events == nil {
		return nil, nil // a nil channel, not a nil-valued typed one
	}
	return h.events, nil
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
func (h *fakeHome) Devices(context.Context, core.Grant) (core.DeviceChannel, func(), error) {
	return core.DeviceChannel{}, func() {}, nil
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

func newCore(t *testing.T) *core.Core {
	t.Helper()
	revoked, err := core.OpenRevoked(filepath.Join(t.TempDir(), "revoked.json"), time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return &core.Core{Ledger: core.NewLedger(1), RateLimit: core.NewRateLimit(100, 1<<20),
		Runtime: stub.New(), Verify: grant.InsecureJSONVerifier{}, Revoked: revoked}
}

// TestDriveEvents feeds deliveries and checks what fiberd admitted and
// what the home was told once delivery closes.
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
		{name: "a grant fiberd refuses is not published",
			events: []home.GrantEvent{added(tooHigh)}},
		{name: "a removal takes the grant away and publishes not ready",
			events: []home.GrantEvent{added(g1), removed("g1")}, published: []ready{{"g1", true}, {"g1", false}}},
		{name: "delivering a removed grant again lifts its denial",
			events:    []home.GrantEvent{added(g1), removed("g1"), added(g1)},
			admitted:  []string{"g1"},
			published: []ready{{"g1", true}, {"g1", false}, {"g1", true}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := newCore(t)
			h := &fakeHome{events: make(chan home.GrantEvent)}
			done := make(chan struct{})
			go func() { defer close(done); home.Drive(context.Background(), h, a) }()
			for _, ev := range c.events {
				h.events <- ev // unbuffered, so Drive took the previous event
			}
			close(h.events)
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
					t.Fatalf("grant %s keeps token %q, want the delivered one", uid, g.Token)
				}
			}
			if !slices.Equal(h.published, c.published) {
				t.Fatalf("published %v, want %v", h.published, c.published)
			}
		})
	}
}

// TestDriveReturns checks every way delivery ends Drive.
func TestDriveReturns(t *testing.T) {
	cases := []struct {
		name   string
		home   *fakeHome
		cancel bool
	}{
		{name: "delivery fails to open", home: &fakeHome{eventsErr: errors.New("no delivery")}},
		{name: "the home delivers nothing", home: &fakeHome{}},
		{name: "the context ends while delivery is open", home: &fakeHome{events: make(chan home.GrantEvent)}, cancel: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if c.cancel {
				cancel()
			}
			a := newCore(t)
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
