package rpc_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/rpc"
	"github.com/helayoty/fiberd/pkg/runtime/stub"
)

type harness struct {
	agent  *core.Agent
	health *core.SourceHealth
	client grantv1.FibersClient
}

func newHarness(t *testing.T, tier core.Tier) *harness {
	t.Helper()
	health := core.NewSourceHealth(10*time.Second, time.Now())
	ag := &core.Agent{
		NodeID:         "node-a",
		Ledger:         core.NewLedger(1),
		Budget:         core.NewBudget(1000, 256<<20),
		Runtime:        stub.NewWithTier(tier),
		Audit:          core.NopAuditor{},
		Verify:         grant.InsecureJSONVerifier{},
		Health:         health,
		StatusInterval: 20 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go ag.Run(ctx)

	lis := bufconn.Listen(1 << 20)
	gs := rpc.NewGRPCServer(&rpc.Server{Agent: ag, Issuer: "https://issuer.test", RetryAfter: 3 * time.Second})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &harness{agent: ag, health: health, client: grantv1.NewFibersClient(conn)}
}

func jsonGrant(t *testing.T, g core.Grant) string {
	t.Helper()
	b, err := protojson.Marshal(grant.ToProto(g))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestMissCarriesDetail(t *testing.T) {
	h := newHarness(t, core.TierCheckpoint)
	ctx := context.Background()
	g := jsonGrant(t, core.Grant{UID: "g1", Audience: "node-a", FiberMax: 1})

	if _, err := h.client.Clone(ctx, &grantv1.CloneRequest{GrantJwt: g}); err != nil {
		t.Fatalf("first clone: %v", err)
	}
	// Healthy lane, grant full -> DEFERRED_FALLBACK with Miss.
	_, err := h.client.Clone(ctx, &grantv1.CloneRequest{GrantJwt: g})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("full/healthy code = %v, want Unavailable (%v)", status.Code(err), err)
	}
	miss, ok := rpc.MissFromError(err)
	if !ok || miss.GetCode() != grantv1.MissCode_DEFERRED_FALLBACK || miss.GetIssuer() != "https://issuer.test" {
		t.Fatalf("miss = %+v ok=%v, want DEFERRED_FALLBACK from issuer", miss, ok)
	}
	// Dead lane, grant full -> SHED with retry_after.
	h.health.MarkSync(time.Now().Add(-time.Minute))
	_, err = h.client.Clone(ctx, &grantv1.CloneRequest{GrantJwt: g})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("full/unhealthy code = %v, want ResourceExhausted (%v)", status.Code(err), err)
	}
	miss, ok = rpc.MissFromError(err)
	if !ok || miss.GetCode() != grantv1.MissCode_SHED || miss.GetRetryAfterS() != 3 {
		t.Fatalf("miss = %+v ok=%v, want SHED retry_after_s=3", miss, ok)
	}
}

func TestEveryOutcomeMaps(t *testing.T) {
	s := &rpc.Server{Issuer: "iss"}
	cases := []struct {
		code     core.StatusCode
		wantCode codes.Code
		wantMiss bool
	}{
		{core.OK, codes.OK, false},
		{core.Shed, codes.ResourceExhausted, true},
		{core.DeferredFallback, codes.Unavailable, true},
		{core.NeedsTier, codes.FailedPrecondition, false},
		{core.Invalid, codes.InvalidArgument, false},
		{core.Unauthenticated, codes.Unauthenticated, false},
		{core.NotFound, codes.NotFound, false},
		{core.Internal, codes.Internal, false},
	}
	for _, tc := range cases {
		err := s.ToError(tc.code, errors.New("x"))
		if status.Code(err) != tc.wantCode {
			t.Errorf("%d -> %v, want %v", tc.code, status.Code(err), tc.wantCode)
		}
		if _, ok := rpc.MissFromError(err); ok != tc.wantMiss {
			t.Errorf("%d miss detail present=%v, want %v", tc.code, ok, tc.wantMiss)
		}
	}
}

func TestDeferredMissCarriesPreferredHome(t *testing.T) {
	s := &rpc.Server{Issuer: "iss"}
	err := s.ToError(core.DeferredFallback, &core.RemoteMiss{Err: core.ErrDeltaTooLarge, PreferredHome: "home-a"})
	miss, ok := rpc.MissFromError(err)
	if !ok || miss.GetCode() != grantv1.MissCode_DEFERRED_FALLBACK || miss.GetPreferredHome() != "home-a" {
		t.Fatalf("miss = %+v ok=%v, want DEFERRED_FALLBACK preferring home-a", miss, ok)
	}
}

func TestAdmissionRejectsUnknownFields(t *testing.T) {
	h := newHarness(t, core.TierCheckpoint)
	ctx := context.Background()
	g := jsonGrant(t, core.Grant{UID: "g1", Audience: "node-a"})

	// Build a wire message that carries field 99 ("image") alongside the
	// legal fields: what a caller trying to shape a workload would send.
	legal, _ := proto.Marshal(&grantv1.CloneRequest{GrantJwt: g})
	extra := append([]byte{}, legal...)
	extra = append(extra, 0x9a, 0x06) // field 99, wire type 2
	extra = append(extra, byte(len("evil")))
	extra = append(extra, "evil"...)
	var smuggled grantv1.CloneRequest
	if err := proto.Unmarshal(extra, &smuggled); err != nil {
		t.Fatal(err)
	}
	if len(smuggled.ProtoReflect().GetUnknown()) == 0 {
		t.Fatal("test setup: unknown field was not preserved")
	}
	_, err := h.client.Clone(ctx, &smuggled)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("clone with unknown field = %v, want InvalidArgument", err)
	}
	// Clean request is fine.
	if _, err := h.client.Clone(ctx, &grantv1.CloneRequest{GrantJwt: g}); err != nil {
		t.Fatalf("clean clone: %v", err)
	}
}

func TestIdempotentAttachAndTierFloor(t *testing.T) {
	h := newHarness(t, core.TierWarm)
	ctx := context.Background()
	g := jsonGrant(t, core.Grant{UID: "g1", Audience: "node-a"})
	r1, err := h.client.Clone(ctx, &grantv1.CloneRequest{GrantJwt: g, Session: "S"})
	if err != nil || r1.GetKind() != grantv1.CloneKind_CREATE {
		t.Fatalf("first: %v %v", err, r1.GetKind())
	}
	r2, err := h.client.Clone(ctx, &grantv1.CloneRequest{GrantJwt: g, Session: "S"})
	if err != nil || r2.GetKind() != grantv1.CloneKind_ATTACH || r2.GetEndpoint() != r1.GetEndpoint() ||
		!proto.Equal(r1.GetFence(), r2.GetFence()) {
		t.Fatalf("second: %v %+v (first %+v)", err, r2, r1)
	}
	if _, err := h.client.Park(ctx, &grantv1.ParkRequest{FiberId: r1.GetFiberId()}); err != nil {
		t.Fatalf("park: %v", err)
	}
	// Parked session on a FIBER_WARM target: FailedPrecondition, never a fork.
	_, err = h.client.Clone(ctx, &grantv1.CloneRequest{GrantJwt: g, Session: "S"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("resume on warm target = %v, want FailedPrecondition", err)
	}
	// min_tier above the target: FailedPrecondition too.
	gc := jsonGrant(t, core.Grant{UID: "g2", Audience: "node-a", MinTier: core.TierCheckpoint})
	_, err = h.client.Clone(ctx, &grantv1.CloneRequest{GrantJwt: gc})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("min_tier checkpoint on warm target = %v, want FailedPrecondition", err)
	}
	// Unknown fiber: NotFound.
	_, err = h.client.Park(ctx, &grantv1.ParkRequest{FiberId: "g1/0/1"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("park unknown = %v, want NotFound", err)
	}
}

func TestWatchReportsOOM(t *testing.T) {
	h := newHarness(t, core.TierCheckpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	g := jsonGrant(t, core.Grant{UID: "g1", Audience: "node-a", FiberMax: 2, WBudgetBytes: 1 << 20})
	if _, err := h.client.Clone(ctx, &grantv1.CloneRequest{GrantJwt: g, Payload: []byte(`{"dirty_bytes": 1024}`)}); err != nil {
		t.Fatalf("small clone: %v", err)
	}
	if _, err := h.client.Clone(ctx, &grantv1.CloneRequest{GrantJwt: g, Payload: []byte(`{"dirty_bytes": 4194304}`)}); err != nil {
		t.Fatalf("over-budget clone should be accepted then killed: %v", err)
	}
	stream, err := h.client.Watch(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	for {
		st, err := stream.Recv()
		if err != nil {
			t.Fatalf("watch ended before running settled to 1: %v", err)
		}
		if st.GetGrantUid() == "g1" && st.GetRunning() == 1 && st.GetWUsedBytes() == 1024 {
			return
		}
	}
}
