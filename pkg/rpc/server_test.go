package rpc_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http/httptest"
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
	"github.com/helayoty/fiberd/pkg/tlsconf"
)

type harness struct {
	agent  *core.Agent
	health *core.SourceHealth
	server *rpc.Server
	client grantv1.FibersClient
}

// boundVerifier is the insecure JSON verifier with every grant bound to
// one caller certificate, as a signed grant with a cnf claim would be.
type boundVerifier struct{ thumbprint string }

func (v boundVerifier) Verify(ctx context.Context, token []byte) (core.Grant, error) {
	g, err := grant.InsecureJSONVerifier{}.Verify(ctx, token)
	g.CallerThumbprint = v.thumbprint
	return g, err
}

func newHarness(t *testing.T, tier core.Tier, opts ...func(*core.Agent)) *harness {
	t.Helper()
	health := core.NewSourceHealth(10*time.Second, time.Now())
	ag := &core.Agent{
		NodeID:         "node-a",
		Ledger:         core.NewLedger(1),
		Budget:         core.NewBudget(1000, 256<<20),
		Runtime:        stub.NewWithTier(tier),
		Verify:         grant.InsecureJSONVerifier{},
		Health:         health,
		StatusInterval: 20 * time.Millisecond,
	}
	for _, o := range opts {
		o(ag)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go ag.Run(ctx)

	lis := bufconn.Listen(1 << 20)
	srv := &rpc.Server{Agent: ag, Issuer: "https://issuer.test", RetryAfter: 3 * time.Second}
	gs := rpc.NewGRPCServer(srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &harness{agent: ag, health: health, server: srv, client: grantv1.NewFibersClient(conn)}
}

func jsonGrant(t *testing.T, g core.Grant) string {
	t.Helper()
	b, err := protojson.Marshal(grant.ToProto(g))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A grant at its fiber limit is a miss whose detail travels in the gRPC
// status. It is DEFERRED_FALLBACK while the lane is healthy and SHED with
// retry_after once it is dead.
func TestMissCarriesDetail(t *testing.T) {
	cases := []struct {
		name      string
		laneDead  bool
		wantCode  codes.Code
		wantMiss  grantv1.MissCode
		wantRetry uint32
	}{
		{name: "full grant with a healthy lane defers", wantCode: codes.Unavailable,
			wantMiss: grantv1.MissCode_DEFERRED_FALLBACK},
		{name: "full grant with a dead lane sheds with retry_after", laneDead: true, wantCode: codes.ResourceExhausted,
			wantMiss: grantv1.MissCode_SHED, wantRetry: 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, core.TierCheckpoint)
			ctx := context.Background()
			g := jsonGrant(t, core.Grant{UID: "g1", Audience: "node-a", Tenant: "acme", FiberMax: 1})
			if _, err := h.client.Clone(ctx, &grantv1.CloneRequest{GrantJwt: g}); err != nil {
				t.Fatalf("first clone: %v", err)
			}
			if tc.laneDead {
				h.health.MarkSync(time.Now().Add(-time.Minute))
			}
			_, err := h.client.Clone(ctx, &grantv1.CloneRequest{GrantJwt: g})
			if status.Code(err) != tc.wantCode {
				t.Fatalf("code = %v, want %v (%v)", status.Code(err), tc.wantCode, err)
			}
			miss, ok := rpc.MissFromError(err)
			if !ok || miss.GetCode() != tc.wantMiss || miss.GetIssuer() != "https://issuer.test" || miss.GetRetryAfterS() != tc.wantRetry {
				t.Fatalf("miss = %+v ok=%v, want %v from issuer with retry_after_s=%d", miss, ok, tc.wantMiss, tc.wantRetry)
			}
		})
	}
}

// Every agent outcome maps to one gRPC code. Only the two capacity misses
// carry a Miss detail, and a deferred remote miss names the home the
// caller should prefer.
func TestEveryOutcomeMaps(t *testing.T) {
	s := &rpc.Server{Issuer: "iss"}
	cases := []struct {
		name         string
		code         core.StatusCode
		err          error
		wantCode     codes.Code
		wantMiss     bool
		wantMissCode grantv1.MissCode
		wantHome     string
		wantRetry    uint32
	}{
		{name: "OK is no error", code: core.OK, wantCode: codes.OK},
		{name: "SHED is ResourceExhausted with a miss and the default retry", code: core.Shed, wantCode: codes.ResourceExhausted,
			wantMiss: true, wantMissCode: grantv1.MissCode_SHED, wantRetry: uint32(rpc.DefaultRetryAfter / time.Second)},
		{name: "DEFERRED_FALLBACK is Unavailable with a miss", code: core.DeferredFallback, wantCode: codes.Unavailable,
			wantMiss: true, wantMissCode: grantv1.MissCode_DEFERRED_FALLBACK},
		{name: "a deferred remote miss carries the preferred home", code: core.DeferredFallback,
			err:      &core.RemoteMiss{Err: core.ErrDeltaTooLarge, PreferredHome: "home-a"},
			wantCode: codes.Unavailable, wantMiss: true, wantMissCode: grantv1.MissCode_DEFERRED_FALLBACK, wantHome: "home-a"},
		{name: "NeedsTier is FailedPrecondition", code: core.NeedsTier, wantCode: codes.FailedPrecondition},
		{name: "Invalid is InvalidArgument", code: core.Invalid, wantCode: codes.InvalidArgument},
		{name: "Unauthenticated is Unauthenticated", code: core.Unauthenticated, wantCode: codes.Unauthenticated},
		{name: "NotFound is NotFound", code: core.NotFound, wantCode: codes.NotFound},
		{name: "Internal is Internal", code: core.Internal, wantCode: codes.Internal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cause := tc.err
			if cause == nil {
				cause = errors.New("x")
			}
			err := s.ToError(tc.code, cause)
			if status.Code(err) != tc.wantCode {
				t.Fatalf("%d -> %v, want %v", tc.code, status.Code(err), tc.wantCode)
			}
			miss, ok := rpc.MissFromError(err)
			if ok != tc.wantMiss {
				t.Fatalf("%d miss detail present=%v, want %v", tc.code, ok, tc.wantMiss)
			}
			if ok && (miss.GetCode() != tc.wantMissCode || miss.GetPreferredHome() != tc.wantHome ||
				miss.GetIssuer() != "iss" || miss.GetRetryAfterS() != tc.wantRetry) {
				t.Fatalf("miss = %+v, want %v from iss preferring %q retrying after %ds", miss, tc.wantMissCode, tc.wantHome, tc.wantRetry)
			}
			if rpc.IsMiss(err) != tc.wantMiss {
				t.Fatalf("IsMiss = %v, want %v", rpc.IsMiss(err), tc.wantMiss)
			}
		})
	}
}

// Admission refuses fields the protocol does not define, which is what a
// caller trying to shape a workload would send.
func TestAdmissionRejectsUnknownFields(t *testing.T) {
	h := newHarness(t, core.TierCheckpoint)
	ctx := context.Background()
	g := jsonGrant(t, core.Grant{UID: "g1", Audience: "node-a", Tenant: "acme"})

	// Build a wire message that carries field 99 ("image") alongside the
	// legal fields.
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

	cases := []struct {
		name string
		req  *grantv1.CloneRequest
		want codes.Code
	}{
		{name: "a clone with an unknown field is InvalidArgument", req: &smuggled, want: codes.InvalidArgument},
		{name: "the same clone without it is admitted", req: &grantv1.CloneRequest{GrantJwt: g}, want: codes.OK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := h.client.Clone(ctx, tc.req); status.Code(err) != tc.want {
				t.Fatalf("clone = %v, want %v", err, tc.want)
			}
		})
	}
}

// One session on a FIBER_WARM target runs in order. A second clone attaches
// to the first fiber. Once parked, the session cannot resume here and is
// never forked. A min_tier above the target and an unknown fiber are
// refused.
func TestIdempotentAttachAndTierFloor(t *testing.T) {
	h := newHarness(t, core.TierWarm)
	ctx := context.Background()
	g := jsonGrant(t, core.Grant{UID: "g1", Audience: "node-a", Tenant: "acme"})
	gc := jsonGrant(t, core.Grant{UID: "g2", Audience: "node-a", Tenant: "acme", MinTier: core.TierCheckpoint})

	var first *grantv1.CloneResponse
	clone := func(grantJWT, session string) func() (*grantv1.CloneResponse, error) {
		return func() (*grantv1.CloneResponse, error) {
			return h.client.Clone(ctx, &grantv1.CloneRequest{GrantJwt: grantJWT, Session: session})
		}
	}
	park := func(id func() string) func() (*grantv1.CloneResponse, error) {
		return func() (*grantv1.CloneResponse, error) {
			_, err := h.client.Park(ctx, &grantv1.ParkRequest{FiberId: id()})
			return nil, err
		}
	}
	steps := []struct {
		name     string
		op       func() (*grantv1.CloneResponse, error) // nil response means not a clone
		want     codes.Code
		wantKind grantv1.CloneKind
		sameAs   bool // endpoint and fence equal the first clone's
	}{
		{name: "the first clone of a session creates", op: clone(g, "S"), wantKind: grantv1.CloneKind_CREATE},
		{name: "a second clone of the session attaches to the same fiber", op: clone(g, "S"),
			wantKind: grantv1.CloneKind_ATTACH, sameAs: true},
		{name: "the session's fiber parks", op: park(func() string { return first.GetFiberId() })},
		{name: "resuming a parked session on a warm target is FailedPrecondition, never a fork",
			op: clone(g, "S"), want: codes.FailedPrecondition},
		{name: "min_tier above the target is FailedPrecondition", op: clone(gc, ""), want: codes.FailedPrecondition},
		{name: "parking an unknown fiber is NotFound", op: park(func() string { return "g1/0/1" }), want: codes.NotFound},
	}
	for _, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			r, err := st.op()
			if status.Code(err) != st.want {
				t.Fatalf("err = %v, want %v", err, st.want)
			}
			if r == nil {
				return
			}
			if r.GetKind() != st.wantKind {
				t.Fatalf("kind = %v, want %v", r.GetKind(), st.wantKind)
			}
			if first == nil {
				first = r
			}
			if st.sameAs && (r.GetEndpoint() != first.GetEndpoint() || !proto.Equal(first.GetFence(), r.GetFence())) {
				t.Fatalf("attach = %+v, want the endpoint and fence of %+v", r, first)
			}
		})
	}
}

func TestCallerOwnsItsGrantsFibers(t *testing.T) {
	owner := tlsconf.Caller{Thumbprint: "owner-x5t"}
	other := tlsconf.Caller{Thumbprint: "other-x5t"}
	h := newHarness(t, core.TierCheckpoint, func(a *core.Agent) { a.Verify = boundVerifier{thumbprint: owner.Thumbprint} })
	gw := (&rpc.Gateway{Server: h.server}).Handler()
	g := jsonGrant(t, core.Grant{UID: "g1", Audience: "node-a", Tenant: "acme"})

	park := func(ctx context.Context, id string) error {
		_, err := h.server.Park(ctx, &grantv1.ParkRequest{FiberId: id})
		return err
	}
	release := func(ctx context.Context, id string) error {
		_, err := h.server.Release(ctx, &grantv1.ReleaseRequest{FiberId: id})
		return err
	}
	cases := []struct {
		name       string
		caller     *tlsconf.Caller // nil is plaintext with no caller identity
		op         func(ctx context.Context, fiberID string) error
		want       codes.Code
		wantListed bool // GET /v1/status shows g1
	}{
		{name: "owner parks", caller: &owner, op: park, want: codes.OK, wantListed: true},
		{name: "owner releases", caller: &owner, op: release, want: codes.OK, wantListed: true},
		{name: "another caller cannot park", caller: &other, op: park, want: codes.NotFound},
		{name: "another caller cannot release", caller: &other, op: release, want: codes.NotFound},
		{name: "plaintext has no caller to check", op: park, want: codes.OK, wantListed: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := h.server.Clone(rpc.WithCaller(context.Background(), owner), &grantv1.CloneRequest{GrantJwt: g})
			if err != nil {
				t.Fatalf("clone by owner: %v", err)
			}
			ctx := context.Background()
			if tc.caller != nil {
				ctx = rpc.WithCaller(ctx, *tc.caller)
			}
			if err := tc.op(ctx, r.GetFiberId()); status.Code(err) != tc.want {
				t.Fatalf("op = %v, want %v", err, tc.want)
			}

			rec := httptest.NewRecorder()
			gw.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/status", nil).WithContext(ctx))
			var sts []map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &sts); err != nil {
				t.Fatalf("status body %q: %v", rec.Body.String(), err)
			}
			listed := false
			for _, st := range sts {
				listed = listed || st["grantUid"] == "g1"
			}
			if listed != tc.wantListed {
				t.Fatalf("status lists g1 = %v, want %v (%s)", listed, tc.wantListed, rec.Body.String())
			}
		})
	}
}

// Watch streams per-grant status until it settles. A fiber over its W
// budget is accepted, then killed, and drops out of the running count.
func TestWatchReportsOOM(t *testing.T) {
	cases := []struct {
		name        string
		dirty       []string // dirty_bytes payload of each clone, in order
		wantRunning uint32
		wantUsed    uint64
	}{
		{name: "a fiber within W is reported running", dirty: []string{"1024"}, wantRunning: 1, wantUsed: 1024},
		{name: "an over-budget fiber is accepted, then killed", dirty: []string{"1024", "4194304"}, wantRunning: 1, wantUsed: 1024},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, core.TierCheckpoint)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			g := jsonGrant(t, core.Grant{UID: "g1", Audience: "node-a", Tenant: "acme", FiberMax: 2, WBudgetBytes: 1 << 20})
			for _, d := range tc.dirty {
				if _, err := h.client.Clone(ctx, &grantv1.CloneRequest{GrantJwt: g, Payload: []byte(`{"dirty_bytes": ` + d + `}`)}); err != nil {
					t.Fatalf("clone dirtying %s bytes: %v", d, err)
				}
			}
			stream, err := h.client.Watch(ctx, &emptypb.Empty{})
			if err != nil {
				t.Fatal(err)
			}
			for {
				st, err := stream.Recv()
				if err != nil {
					t.Fatalf("watch ended before running settled to %d: %v", tc.wantRunning, err)
				}
				if st.GetGrantUid() == "g1" && st.GetRunning() == tc.wantRunning && st.GetWUsedBytes() == tc.wantUsed {
					return
				}
			}
		})
	}
}

// MissFromError finds the Miss among a status's details, and nothing in an
// error that is not a status or carries no Miss.
func TestMissFromError(t *testing.T) {
	withDetail := func(c codes.Code, d *grantv1.Fence) error {
		st, err := status.New(c, "x").WithDetails(d)
		if err != nil {
			t.Fatal(err)
		}
		return st.Err()
	}
	miss := &grantv1.Miss{Code: grantv1.MissCode_DEFERRED_FALLBACK, Issuer: "iss"}
	cases := []struct {
		name string
		err  error
		want *grantv1.Miss
	}{
		{name: "no error", err: nil},
		{name: "a plain error", err: errors.New("boom")},
		{name: "a status without details", err: status.Error(codes.Unavailable, "x")},
		{name: "a status with another detail", err: withDetail(codes.Unavailable, &grantv1.Fence{GrantUid: "g"})},
		{name: "a status with a miss after another detail", err: func() error {
			st, err := status.New(codes.Unavailable, "x").WithDetails(&grantv1.Fence{}, miss)
			if err != nil {
				t.Fatal(err)
			}
			return st.Err()
		}(), want: miss},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := rpc.MissFromError(tc.err)
			if ok != (tc.want != nil) || !proto.Equal(got, tc.want) {
				t.Fatalf("MissFromError = %v, %v, want %v", got, ok, tc.want)
			}
			if rpc.IsMiss(tc.err) != ok {
				t.Fatalf("IsMiss = %v, want %v", rpc.IsMiss(tc.err), ok)
			}
		})
	}
}

// failingWatch is a Watch stream whose Send fails, or that cancels its
// context on the first Send.
type failingWatch struct {
	grpc.ServerStream
	ctx    context.Context
	cancel context.CancelFunc
	err    error
	sent   []*grantv1.Status
}

func (w *failingWatch) Context() context.Context { return w.ctx }

func (w *failingWatch) Send(st *grantv1.Status) error {
	w.sent = append(w.sent, st)
	if w.err == nil {
		w.cancel()
	}
	return w.err
}

// Watch ends with the stream's error when a Send fails, and with the
// context's error when the client goes away.
func TestWatchEnds(t *testing.T) {
	errGone := errors.New("transport is closing")
	cases := []struct {
		name    string
		sendErr error
		want    error
	}{
		{name: "a failed send ends the watch with its error", sendErr: errGone, want: errGone},
		{name: "a client that goes away ends the watch with its context", want: context.Canceled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, core.TierCheckpoint)
			if _, err := h.client.Clone(context.Background(), &grantv1.CloneRequest{GrantJwt: jsonGrant(t, core.Grant{UID: "g1", Audience: "node-a", Tenant: "acme"})}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			w := &failingWatch{ctx: ctx, cancel: cancel, err: tc.sendErr}
			if err := h.server.Watch(&emptypb.Empty{}, w); !errors.Is(err, tc.want) {
				t.Fatalf("Watch = %v, want %v", err, tc.want)
			}
			if len(w.sent) == 0 || w.sent[0].GetGrantUid() != "g1" {
				t.Fatalf("sent = %v, want g1's status first", w.sent)
			}
		})
	}
}

func TestFenceFromProto(t *testing.T) {
	cases := []struct {
		name string
		in   *grantv1.Fence
		want core.Fence
	}{
		{name: "a nil fence is the zero fence", in: nil, want: core.Fence{}},
		{name: "every field carries over", in: &grantv1.Fence{GrantUid: "g1", Epoch: 3, Seq: 9}, want: core.Fence{GrantUID: "g1", Epoch: 3, Seq: 9}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rpc.FenceFromProto(tc.in); got != tc.want {
				t.Fatalf("FenceFromProto = %+v, want %+v", got, tc.want)
			}
		})
	}
}
