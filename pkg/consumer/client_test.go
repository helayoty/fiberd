package consumer_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/helayoty/fiberd/pkg/consumer"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/rpc"
	"github.com/helayoty/fiberd/pkg/runtime/stub"
)

type home struct {
	agent  *core.Agent
	health *core.SourceHealth
	client *consumer.Client
}

func newHome(t *testing.T, tier core.Tier) *home {
	t.Helper()
	health := core.NewSourceHealth(10*time.Second, time.Now())
	ag := &core.Agent{
		NodeID: "node-a", Ledger: core.NewLedger(1), Budget: core.NewBudget(1000, 256<<20),
		Runtime: stub.NewWithTier(tier), Audit: core.NopAuditor{}, Verify: grant.InsecureJSONVerifier{},
		Health: health, StatusInterval: 20 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go ag.Run(ctx)
	lis := bufconn.Listen(1 << 20)
	gs := rpc.NewGRPCServer(&rpc.Server{Agent: ag, Issuer: "https://issuer.test", RetryAfter: 2 * time.Second})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	c := consumer.New(conn)
	t.Cleanup(func() { _ = c.Close() })
	return &home{agent: ag, health: health, client: c}
}

func jsonGrant(t *testing.T, g core.Grant) string {
	t.Helper()
	b, err := protojson.Marshal(grant.ToProto(g))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCloneAttachParkResume(t *testing.T) {
	h := newHome(t, core.TierCheckpoint)
	ctx := context.Background()
	g := jsonGrant(t, core.Grant{UID: "g1", Audience: "node-a", FiberMax: 2})
	f, err := h.client.Clone(ctx, g, "S", time.Second, nil)
	if err != nil || f.Kind != consumer.Create || f.Endpoint == "" || f.Fence.Seq != 1 {
		t.Fatalf("create = %+v (%v)", f, err)
	}
	again, err := h.client.Clone(ctx, g, "S", time.Second, nil)
	if err != nil || again.Kind != consumer.Attach || again.ID != f.ID {
		t.Fatalf("attach = %+v (%v)", again, err)
	}
	if err := h.client.Park(ctx, f.ID, true); err != nil {
		t.Fatal(err)
	}
	r, err := h.client.Clone(ctx, g, "S", time.Second, nil)
	if err != nil || r.Kind != consumer.Resume || r.Fence.Seq != 2 {
		t.Fatalf("resume = %+v (%v)", r, err)
	}
	if err := h.client.Release(ctx, r.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := h.client.Release(ctx, r.ID, false); !consumer.NotFound(err) {
		t.Fatalf("release twice = %v, want NotFound", err)
	}
}

func TestMissesAreTyped(t *testing.T) {
	h := newHome(t, core.TierCheckpoint)
	ctx := context.Background()
	g := jsonGrant(t, core.Grant{UID: "g2", Audience: "node-a", FiberMax: 1})
	if _, err := h.client.Clone(ctx, g, "", time.Second, nil); err != nil {
		t.Fatal(err)
	}
	// Grant full with the lane healthy: DEFERRED, the ordinary path.
	_, err := h.client.Clone(ctx, g, "", time.Second, nil)
	var def *consumer.Deferred
	if !errors.As(err, &def) || def.Issuer != "https://issuer.test" {
		t.Fatalf("full grant = %v, want *Deferred", err)
	}
	// Lane down: SHED with retry_after; CloneRetry waits it out until ctx
	// ends, then returns the last miss.
	h.health.MarkSync(time.Now().Add(-time.Hour))
	_, err = h.client.Clone(ctx, g, "", time.Second, nil)
	var shed *consumer.Shed
	if !errors.As(err, &shed) || shed.RetryAfter != 2*time.Second {
		t.Fatalf("lane down = %v, want *Shed with retry 2s", err)
	}
	short, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = h.client.CloneRetry(short, g, "", time.Second, nil)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) < 100*time.Millisecond {
		t.Fatalf("CloneRetry under SHED = %v after %s", err, time.Since(start))
	}
	// Tier gap is not a miss.
	warm := newHome(t, core.TierWarm)
	_, err = warm.client.Clone(ctx, jsonGrant(t, core.Grant{UID: "g3", Audience: "node-a", FiberMax: 1, MinTier: core.TierCheckpoint}), "", time.Second, nil)
	var gap *consumer.TierGap
	if !errors.As(err, &gap) {
		t.Fatalf("min_tier above the home = %v, want *TierGap", err)
	}
}

func TestWatchStreamsStatus(t *testing.T) {
	h := newHome(t, core.TierCheckpoint)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g := jsonGrant(t, core.Grant{UID: "g4", Audience: "node-a", FiberMax: 2})
	if _, err := h.client.Clone(ctx, g, "", time.Second, nil); err != nil {
		t.Fatal(err)
	}
	seen := make(chan consumer.Status, 8)
	go func() { _ = h.client.Watch(ctx, func(s consumer.Status) { seen <- s }) }()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case s := <-seen:
			if s.GrantUID == "g4" && s.Running == 1 {
				return
			}
		case <-deadline:
			t.Fatal("no status for g4 with running=1")
		}
	}
}
