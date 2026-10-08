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
// The returned stop takes the agent's server down while the client stays.
func stubHome(t *testing.T) (*core.Agent, *consumer.Client, func()) {
	t.Helper()
	ag := &core.Agent{
		NodeID: "worker-1", Ledger: core.NewLedger(1), Budget: core.NewBudget(1000, 256<<20),
		Runtime: stub.NewWithTier(core.TierCheckpoint), Verify: grant.InsecureJSONVerifier{},
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
	return ag, consumer.New(conn), gs.Stop
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
		g = core.Grant{UID: "g-" + tmpl.Name, Audience: "worker-1", Tenant: "substrate", TemplateDigest: tmpl.Digest(), FiberMax: j.fiberMax, FiberWarm: 1,
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
	w := newWorker(t, fiberMax, nil)
	return w.svc, w.router
}

// worker is a Service with what its tests reach around it for.
type worker struct {
	agent  *core.Agent
	svc    *Service
	router *recordingRouter
	client *consumer.Client
	grants *jsonGrants
	stop   func() // takes the agent's server down
}

// newWorker builds a running Service over the stub agent. mod adjusts the
// config before New.
func newWorker(t *testing.T, fiberMax int, mod func(*Config)) *worker {
	t.Helper()
	ag, client, stop := stubHome(t)
	router := &recordingRouter{active: map[string]string{}}
	grants := &jsonGrants{t: t, fiberMax: fiberMax, minted: map[string]core.Grant{}}
	cfg := Config{
		Client: client, Grants: grants,
		Router: router, Paths: Paths{Base: t.TempDir()},
		Probe: func(context.Context, string, string) error { return nil },
	}
	if mod != nil {
		mod(&cfg)
	}
	s := New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.Run(ctx)
	return &worker{agent: ag, svc: s, router: router, client: client, grants: grants, stop: stop}
}

func runReq(uid string) *ateompbRun {
	return &ateompbRun{Atespace: "team-a", ActorName: "counter-" + uid, ActorUid: uid, ActorTemplateAtespace: "team-a", ActorTemplateName: "counter",
		MemoryBytes: 16 << 20, Spec: &ateompbSpec{Containers: []*ateompbContainer{{Name: "app", Readyz: &ateompbReadyz{HttpGet: &ateompbHTTPGet{Path: "/readyz", Port: 80}}}}}}
}

func code(err error) codes.Code { return status.Code(err) }

// step is one call in a sequence against one Service. do makes the call,
// runs any checks beyond its status, and returns its error. The error's
// code must be want.
type step struct {
	name string
	do   func(t *testing.T) error
	want codes.Code
}

// runSteps runs the steps in order and stops at the first that fails,
// because later steps depend on the state it left.
func runSteps(t *testing.T, steps []step) {
	t.Helper()
	for _, tc := range steps {
		if !t.Run(tc.name, func(t *testing.T) {
			if err := tc.do(t); code(err) != tc.want {
				t.Fatalf("code = %v (%v), want %v", code(err), err, tc.want)
			}
		}) {
			t.FailNow()
		}
	}
}

func TestRunTerminateAndStats(t *testing.T) {
	ctx := context.Background()
	s, router := newService(t, 4)
	cases := []step{
		{name: "run: the actor is active and activated on the router", do: func(t *testing.T) error {
			if _, err := s.RunWorkload(ctx, runReq("a1")); err != nil {
				return err
			}
			if _, name, uid, ok := s.Active(); !ok || uid != "a1" || name != "counter-a1" {
				t.Fatalf("active = %s %s %v", name, uid, ok)
			}
			if ep := router.active["team-a/counter-a1"]; ep == "" {
				t.Fatal("actor not activated on the router")
			}
			return nil
		}},
		{name: "a second actor while one runs is refused: one per worker", want: codes.FailedPrecondition, do: func(*testing.T) error {
			_, err := s.RunWorkload(ctx, runReq("a2"))
			return err
		}},
		{name: "stats of a stranger are NOT_FOUND", want: codes.NotFound, do: func(*testing.T) error {
			_, err := s.GetWorkloadStats(ctx, &ateompbStatsReq{ActorUid: "nobody"})
			return err
		}},
		{name: "stats of the actor answer once the agent's status stream ticked", do: func(t *testing.T) error {
			deadline := time.Now().Add(3 * time.Second)
			for {
				resp, err := s.GetWorkloadStats(ctx, &ateompbStatsReq{ActorUid: "a1"})
				if err == nil {
					if resp.GetSample().GetActorUid() != "a1" || resp.GetSample().GetActorTemplateName() != "counter" {
						t.Fatalf("sample %+v", resp.GetSample())
					}
					return nil
				}
				if code(err) != codes.FailedPrecondition || time.Now().After(deadline) {
					return err
				}
				time.Sleep(20 * time.Millisecond)
			}
		}},
		{name: "active stats carry a sample", do: func(t *testing.T) error {
			resp, err := s.GetActiveWorkloadStats(ctx, &ateompbActiveReq{})
			if err == nil && resp.GetSample() == nil {
				t.Fatalf("active stats: %+v", resp)
			}
			return err
		}},
		{name: "checkpoint of a stranger is NOT_FOUND", want: codes.NotFound, do: func(*testing.T) error {
			_, err := s.CheckpointWorkload(ctx, &ateompbCkpt{ActorUid: "a2", Scope: scopeFull})
			return err
		}},
		{name: "a DATA checkpoint is refused and leaves the actor running", want: codes.FailedPrecondition, do: func(t *testing.T) error {
			_, err := s.CheckpointWorkload(ctx, &ateompbCkpt{ActorUid: "a1", Scope: scopeData})
			if _, _, _, ok := s.Active(); !ok {
				t.Fatal("a refused checkpoint must leave the actor running")
			}
			return err
		}},
		{name: "terminate: the fiber is released, the router forgets, stats say none", do: func(t *testing.T) error {
			if _, err := s.TerminateWorkload(ctx, &ateompbTerm{ActorUid: "a1"}); err != nil {
				return err
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
			return nil
		}},
		{name: "terminating what is not here is fine", do: func(*testing.T) error {
			_, err := s.TerminateWorkload(ctx, &ateompbTerm{ActorUid: "a1"})
			return err
		}},
		{name: "the worker takes the next actor", do: func(*testing.T) error {
			_, err := s.RunWorkload(ctx, runReq("a2"))
			return err
		}},
	}
	runSteps(t, cases)
}

// TestMissesMapToSubstrateCodes checks that every miss maps to its
// Substrate code. The stub runtime charges the grant per clone, and the warm
// instance already counts against fibers.max = 1. So a second session is a
// capacity miss (DEFERRED), which maps to ResourceExhausted.
func TestMissesMapToSubstrateCodes(t *testing.T) {
	ctx := context.Background()
	s, _ := newService(t, 1)
	cases := []step{
		{name: "run an actor", do: func(*testing.T) error {
			_, err := s.RunWorkload(ctx, runReq("b1"))
			return err
		}},
		{name: "terminate it", do: func(*testing.T) error {
			_, err := s.TerminateWorkload(ctx, &ateompbTerm{ActorUid: "b1"})
			return err
		}},
		{name: "restore without a snapshot on disk: the import fails loudly", want: codes.FailedPrecondition, do: func(*testing.T) error {
			_, err := s.RestoreWorkload(ctx, &ateompbRestore{ActorUid: "b2", ActorTemplateAtespace: "team-a", ActorTemplateName: "counter", Scope: scopeFull})
			return err
		}},
		{name: "a DATA_ON_GOLDEN restore is refused", want: codes.FailedPrecondition, do: func(*testing.T) error {
			_, err := s.RestoreWorkload(ctx, &ateompbRestore{ActorUid: "b2", Scope: scopeDataOnGolden})
			return err
		}},
		{name: "run without a uid is an invalid argument", want: codes.InvalidArgument, do: func(*testing.T) error {
			_, err := s.RunWorkload(ctx, &ateompbRun{ActorTemplateName: "counter"})
			return err
		}},
		{name: "restore without a uid is an invalid argument", want: codes.InvalidArgument, do: func(*testing.T) error {
			_, err := s.RestoreWorkload(ctx, &ateompbRestore{ActorTemplateName: "counter", Scope: scopeFull})
			return err
		}},
		{name: "run while draining is unavailable", want: codes.Unavailable, do: func(*testing.T) error {
			s.Drain()
			_, err := s.RunWorkload(ctx, runReq("b3"))
			return err
		}},
		{name: "restore while draining is unavailable", want: codes.Unavailable, do: func(*testing.T) error {
			_, err := s.RestoreWorkload(ctx, &ateompbRestore{ActorUid: "b3", ActorTemplateName: "counter", Scope: scopeFull})
			return err
		}},
	}
	runSteps(t, cases)
}

func TestToStatus(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want codes.Code
	}{
		{name: "shed is unavailable", err: &consumer.Shed{RetryAfter: time.Second}, want: codes.Unavailable},
		{name: "deferred is resource exhausted", err: &consumer.Deferred{Reason: "full"}, want: codes.ResourceExhausted},
		{name: "a tier gap is a failed precondition", err: &consumer.TierGap{Reason: "warm only"}, want: codes.FailedPrecondition},
		{name: "a gRPC status passes through", err: status.Error(codes.NotFound, "x"), want: codes.NotFound},
		{name: "anything else is internal", err: context.DeadlineExceeded, want: codes.Internal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := code(toStatus(tc.err)); got != tc.want {
				t.Fatalf("%v -> %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
