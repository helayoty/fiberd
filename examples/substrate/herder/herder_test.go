package herder

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/helayoty/fiberd/pkg/consumer"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/rpc"
	"github.com/helayoty/fiberd/pkg/runtime/stub"
)

// stubHome: fiberd's agent over the in-memory runtime, reached through
// the consumer client, as the kata example tests do.
func stubHome(t *testing.T) (*core.Agent, *consumer.Client) {
	t.Helper()
	ag := &core.Agent{
		NodeID: "worker-1", Ledger: core.NewLedger(1), Budget: core.NewBudget(1000, 256<<20),
		Runtime: stub.NewWithTier(core.TierCheckpoint), Audit: core.NopAuditor{}, Verify: grant.InsecureJSONVerifier{},
		Health: core.NewSourceHealth(10*time.Second, time.Now()), StatusInterval: 20 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go ag.Run(ctx)
	lis := bufconn.Listen(1 << 20)
	gs := rpc.NewGRPCServer(&rpc.Server{Agent: ag, Issuer: "https://issuer.test", RetryAfter: time.Second})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	return ag, consumer.New(conn)
}

// jsonGrants mints development (unsigned) grants, one per template.
type jsonGrants struct {
	t        *testing.T
	fiberMax int
	minted   map[string]core.Grant
}

func (j *jsonGrants) Grant(_ context.Context, tmpl Template, memory uint64) (string, core.Grant, error) {
	g, ok := j.minted[tmpl.Digest()]
	if !ok {
		if memory == 0 {
			memory = 32 << 20
		}
		g = core.Grant{UID: "g-" + tmpl.Name, Audience: "worker-1", TemplateDigest: tmpl.Digest(), FiberMax: j.fiberMax, FiberWarm: 1,
			WBudgetBytes: memory, MinTier: core.TierCheckpoint, LeaseExpiry: time.Now().Add(time.Hour)}
		j.minted[tmpl.Digest()] = g
	}
	b, err := protojson.Marshal(grant.ToProto(g))
	if err != nil {
		j.t.Fatal(err)
	}
	return string(b), g, nil
}

type recordingRouter struct{ active map[string]string }

func (r *recordingRouter) Activate(atespace, name, endpoint string) {
	r.active[atespace+"/"+name] = endpoint
}
func (r *recordingRouter) Deactivate(atespace, name string) { delete(r.active, atespace+"/"+name) }

func newService(t *testing.T, fiberMax int) (*Service, *recordingRouter) {
	t.Helper()
	_, client := stubHome(t)
	router := &recordingRouter{active: map[string]string{}}
	s := New(Config{
		Client: client, Grants: &jsonGrants{t: t, fiberMax: fiberMax, minted: map[string]core.Grant{}},
		Router: router, Paths: Paths{Base: t.TempDir()},
		Probe: func(context.Context, string, string) error { return nil },
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.Run(ctx)
	return s, router
}

func runReq(uid string) *ateompbRun {
	return &ateompbRun{Atespace: "team-a", ActorName: "counter-" + uid, ActorUid: uid, ActorTemplateAtespace: "team-a", ActorTemplateName: "counter",
		MemoryBytes: 16 << 20, Spec: &ateompbSpec{Containers: []*ateompbContainer{{Name: "app", Readyz: &ateompbReadyz{HttpGet: &ateompbHTTPGet{Path: "/readyz", Port: 80}}}}}}
}

func code(err error) codes.Code { return status.Code(err) }

func TestRunTerminateAndStats(t *testing.T) {
	ctx := context.Background()
	s, router := newService(t, 4)

	if _, err := s.RunWorkload(ctx, runReq("a1")); err != nil {
		t.Fatalf("run: %v", err)
	}
	if _, name, uid, ok := s.Active(); !ok || uid != "a1" || name != "counter-a1" {
		t.Fatalf("active = %s %s %v", name, uid, ok)
	}
	if ep := router.active["team-a/counter-a1"]; ep == "" {
		t.Fatal("actor not activated on the router")
	}
	// A second actor while one runs: refused, one per worker.
	if _, err := s.RunWorkload(ctx, runReq("a2")); code(err) != codes.FailedPrecondition {
		t.Fatalf("second run: %v", err)
	}
	// Stats: the wrong uid is NOT_FOUND, the right one answers once the
	// agent's status stream ticked.
	if _, err := s.GetWorkloadStats(ctx, &ateompbStatsReq{ActorUid: "nobody"}); code(err) != codes.NotFound {
		t.Fatalf("stats of a stranger: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, err := s.GetWorkloadStats(ctx, &ateompbStatsReq{ActorUid: "a1"})
		if err == nil {
			if resp.GetSample().GetActorUid() != "a1" || resp.GetSample().GetActorTemplateName() != "counter" {
				t.Fatalf("sample %+v", resp.GetSample())
			}
			break
		}
		if code(err) != codes.FailedPrecondition || time.Now().After(deadline) {
			t.Fatalf("stats: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if resp, err := s.GetActiveWorkloadStats(ctx, &ateompbActiveReq{}); err != nil || resp.GetSample() == nil {
		t.Fatalf("active stats: %+v %v", resp, err)
	}

	// Checkpoint of the wrong actor is NOT_FOUND; a DATA scope is refused.
	if _, err := s.CheckpointWorkload(ctx, &ateompbCkpt{ActorUid: "a2", Scope: scopeFull}); code(err) != codes.NotFound {
		t.Fatalf("checkpoint of a stranger: %v", err)
	}
	if _, err := s.CheckpointWorkload(ctx, &ateompbCkpt{ActorUid: "a1", Scope: scopeData}); code(err) != codes.FailedPrecondition {
		t.Fatalf("DATA checkpoint: %v", err)
	}
	if _, _, _, ok := s.Active(); !ok {
		t.Fatal("a refused checkpoint must leave the actor running")
	}

	// Terminate: the fiber is released, the router forgets, stats say none.
	if _, err := s.TerminateWorkload(ctx, &ateompbTerm{ActorUid: "a1"}); err != nil {
		t.Fatalf("terminate: %v", err)
	}
	if _, _, _, ok := s.Active(); ok {
		t.Fatal("still active after terminate")
	}
	if _, ok := router.active["team-a/counter-a1"]; ok {
		t.Fatal("router still routes a terminated actor")
	}
	if resp, _ := s.GetActiveWorkloadStats(ctx, &ateompbActiveReq{}); resp.GetNoSampleReason() != noWorkload {
		t.Fatalf("active stats after terminate: %+v", resp)
	}
	// Terminating what is not here is fine.
	if _, err := s.TerminateWorkload(ctx, &ateompbTerm{ActorUid: "a1"}); err != nil {
		t.Fatalf("second terminate: %v", err)
	}
	// And the worker takes the next actor.
	if _, err := s.RunWorkload(ctx, runReq("a2")); err != nil {
		t.Fatalf("run after terminate: %v", err)
	}
}

func TestMissesMapToSubstrateCodes(t *testing.T) {
	ctx := context.Background()
	// fibers.max = 1 and the warm instance already counts... the stub
	// runtime charges the grant per clone, so a second session under a
	// one-fiber grant is a capacity miss: DEFERRED -> ResourceExhausted.
	s, _ := newService(t, 1)
	if _, err := s.RunWorkload(ctx, runReq("b1")); err != nil {
		t.Fatalf("run: %v", err)
	}
	if _, err := s.TerminateWorkload(ctx, &ateompbTerm{ActorUid: "b1"}); err != nil {
		t.Fatal(err)
	}
	// Restore without a snapshot on disk: the import fails loudly.
	if _, err := s.RestoreWorkload(ctx, &ateompbRestore{ActorUid: "b2", ActorTemplateAtespace: "team-a", ActorTemplateName: "counter", Scope: scopeFull}); code(err) != codes.FailedPrecondition {
		t.Fatalf("restore without files: %v", err)
	}
	if _, err := s.RestoreWorkload(ctx, &ateompbRestore{ActorUid: "b2", Scope: scopeDataOnGolden}); code(err) != codes.FailedPrecondition {
		t.Fatalf("DATA_ON_GOLDEN restore: %v", err)
	}
	if _, err := s.RunWorkload(ctx, &ateompbRun{ActorTemplateName: "counter"}); code(err) != codes.InvalidArgument {
		t.Fatalf("run without a uid: %v", err)
	}
	s.Drain()
	if _, err := s.RunWorkload(ctx, runReq("b3")); code(err) != codes.Unavailable {
		t.Fatalf("run while draining: %v", err)
	}
}

func TestToStatus(t *testing.T) {
	cases := map[error]codes.Code{
		&consumer.Shed{RetryAfter: time.Second}: codes.Unavailable,
		&consumer.Deferred{Reason: "full"}:      codes.ResourceExhausted,
		&consumer.TierGap{Reason: "warm only"}:  codes.FailedPrecondition,
		status.Error(codes.NotFound, "x"):       codes.NotFound,
		context.DeadlineExceeded:                codes.Internal,
	}
	for err, want := range cases {
		if got := code(toStatus(err)); got != want {
			t.Errorf("%v -> %v, want %v", err, got, want)
		}
	}
}
