package shim_test

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	eventstypes "github.com/containerd/containerd/api/events"
	taskAPI "github.com/containerd/containerd/api/runtime/task/v3"
	"github.com/containerd/containerd/api/types/task"
	"github.com/containerd/containerd/v2/core/events"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/errdefs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/helayoty/fiberd/pkg/consumer"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/rpc"
	"github.com/helayoty/fiberd/pkg/runtime/stub"

	fshim "github.com/helayoty/fiberd/examples/kata/shim"
)

// publisher records the events the shim emits.
type publisher struct {
	mu     sync.Mutex
	topics []string
}

func (p *publisher) Publish(_ context.Context, topic string, _ events.Event) error {
	p.mu.Lock()
	p.topics = append(p.topics, topic)
	p.mu.Unlock()
	return nil
}
func (p *publisher) Close() error { return nil }

type shutdownStub struct{ done chan struct{} }

func (s *shutdownStub) Shutdown()                                    { close(s.done) }
func (s *shutdownStub) RegisterCallback(func(context.Context) error) {}
func (s *shutdownStub) Done() <-chan struct{}                        { return s.done }
func (s *shutdownStub) Err() error                                   { return nil }

type home struct {
	agent  *core.Agent
	client *consumer.Client
}

func newHome(t *testing.T) *home {
	t.Helper()
	ag := &core.Agent{
		NodeID: "node-a", Ledger: core.NewLedger(1), Budget: core.NewBudget(1000, 256<<20),
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
	return &home{agent: ag, client: consumer.New(conn)}
}

func jsonGrant(t *testing.T, g core.Grant) string {
	t.Helper()
	b, err := protojson.Marshal(grant.ToProto(g))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// bundle writes an OCI bundle with the annotations containerd's CRI
// would put there.
func bundle(t *testing.T, annotations map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	spec := map[string]any{"ociVersion": "1.1.0", "annotations": annotations}
	b, _ := json.Marshal(spec)
	if err := os.WriteFile(filepath.Join(dir, "config.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func newService(t *testing.T, h *home) (*fshim.Service, *publisher, *shutdownStub) {
	pub := &publisher{}
	sd := &shutdownStub{done: make(chan struct{})}
	ctx := namespaces.WithNamespace(context.Background(), "k8s.io")
	s := fshim.NewService(ctx, pub, sd)
	s.DialHome = func(context.Context, string) (*consumer.Client, error) { return h.client, nil }
	return s, pub, sd
}

func TestPodContainersAreFibers(t *testing.T) {
	h := newHome(t)
	s, pub, sd := newService(t, h)
	ctx := context.Background()
	g := jsonGrant(t, core.Grant{UID: "g1", Audience: "node-a", FiberMax: 2})

	// The sandbox (pause) container: a record, no fiber.
	sb := bundle(t, map[string]string{"io.kubernetes.cri.container-type": "sandbox", "io.kubernetes.cri.sandbox-id": "sb1"})
	if _, err := s.Create(ctx, &taskAPI.CreateTaskRequest{ID: "sb1", Bundle: sb}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Start(ctx, &taskAPI.StartRequest{ID: "sb1"}); err != nil {
		t.Fatal(err)
	}
	if st, _ := h.agent.Ledger.Status("g1"); st.Running != 0 {
		t.Fatalf("sandbox container cloned a fiber: %+v", st)
	}

	// An app container: Create clones its session.
	cb := bundle(t, map[string]string{
		"io.kubernetes.cri.container-type": "container", "io.kubernetes.cri.sandbox-id": "sb1",
		"io.kubernetes.cri.sandbox-name": "web-0", "io.kubernetes.cri.container-name": "app",
		fshim.AnnotGrant: g, fshim.AnnotHome: "home-a:8484", fshim.AnnotOnStop: "park",
	})
	resp, err := s.Create(ctx, &taskAPI.CreateTaskRequest{ID: "c1", Bundle: cb})
	if err != nil || resp.Pid == 0 {
		t.Fatalf("create = %+v (%v)", resp, err)
	}
	st, _ := h.agent.Ledger.Status("g1")
	if st.Running != 1 {
		t.Fatalf("after create: %+v, want one running fiber", st)
	}
	raw, err := os.ReadFile(filepath.Join(cb, fshim.StateFile))
	if err != nil {
		t.Fatal(err)
	}
	var rec fshim.State
	_ = json.Unmarshal(raw, &rec)
	if rec.Session != "web-0/app" || rec.Home != "home-a:8484" || rec.OnStop != "park" || rec.FiberID == "" {
		t.Fatalf("bundle state = %+v", rec)
	}
	if _, err := s.Start(ctx, &taskAPI.StartRequest{ID: "c1"}); err != nil {
		t.Fatal(err)
	}
	state, _ := s.State(ctx, &taskAPI.StateRequest{ID: "c1"})
	if state.Status != task.Status_RUNNING || state.Bundle != cb {
		t.Fatalf("state = %+v", state)
	}

	// Kill parks (the Pod asked): the fiber's state is kept, Wait returns.
	waited := make(chan *taskAPI.WaitResponse, 1)
	go func() { w, _ := s.Wait(ctx, &taskAPI.WaitRequest{ID: "c1"}); waited <- w }()
	if _, err := s.Kill(ctx, &taskAPI.KillRequest{ID: "c1", Signal: uint32(syscall.SIGTERM)}); err != nil {
		t.Fatal(err)
	}
	select {
	case w := <-waited:
		if w.ExitStatus != 0 {
			t.Fatalf("exit status = %d", w.ExitStatus)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Wait did not return after Kill")
	}
	st, _ = h.agent.Ledger.Status("g1")
	if st.Running != 0 || st.Parked != 1 {
		t.Fatalf("after kill with on-stop=park: %+v", st)
	}
	if _, err := s.Delete(ctx, &taskAPI.DeleteRequest{ID: "c1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cb, fshim.StateFile)); !os.IsNotExist(err) {
		t.Fatal("bundle state survived Delete")
	}

	// The same session again: a RESUME, the container's state carried.
	cb2 := bundle(t, map[string]string{
		"io.kubernetes.cri.container-type": "container", "io.kubernetes.cri.sandbox-id": "sb1",
		"io.kubernetes.cri.sandbox-name": "web-0", "io.kubernetes.cri.container-name": "app", fshim.AnnotGrant: g,
	})
	if _, err := s.Create(ctx, &taskAPI.CreateTaskRequest{ID: "c2", Bundle: cb2}); err != nil {
		t.Fatal(err)
	}
	st, _ = h.agent.Ledger.Status("g1")
	if st.Running != 1 || st.Parked != 0 || st.Latest.Seq != 2 {
		t.Fatalf("after re-create: %+v, want the parked session resumed (seq 2)", st)
	}
	// Delete releases (the default).
	if _, err := s.Delete(ctx, &taskAPI.DeleteRequest{ID: "c2"}); err != nil {
		t.Fatal(err)
	}
	st, _ = h.agent.Ledger.Status("g1")
	if st.Running != 0 || st.Parked != 0 {
		t.Fatalf("after delete: %+v, want nothing left", st)
	}

	// Shutdown only once the sandbox is gone too.
	if _, err := s.Shutdown(ctx, &taskAPI.ShutdownRequest{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sd.Done():
		t.Fatal("shut down with the sandbox container still present")
	default:
	}
	if _, err := s.Delete(ctx, &taskAPI.DeleteRequest{ID: "sb1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Shutdown(ctx, &taskAPI.ShutdownRequest{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sd.Done():
	case <-time.After(time.Second):
		t.Fatal("no shutdown once empty")
	}
	pub.mu.Lock()
	defer pub.mu.Unlock()
	joined := strings.Join(pub.topics, " ")
	for _, want := range []string{"/tasks/create", "/tasks/start", "/tasks/exit", "/tasks/delete"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("events %v lack %s", pub.topics, want)
		}
	}
	_ = eventstypes.TaskCreate{}
}

func TestMissesAndMissingGrant(t *testing.T) {
	h := newHome(t)
	s, _, _ := newService(t, h)
	ctx := context.Background()
	if _, err := s.Create(ctx, &taskAPI.CreateTaskRequest{ID: "x", Bundle: bundle(t, map[string]string{
		"io.kubernetes.cri.container-type": "container"})}); err == nil || !strings.Contains(err.Error(), fshim.AnnotGrant) {
		t.Fatalf("container without a grant = %v", err)
	}
	g := jsonGrant(t, core.Grant{UID: "g2", Audience: "node-a", FiberMax: 1})
	an := map[string]string{"io.kubernetes.cri.container-type": "container", fshim.AnnotGrant: g}
	if _, err := s.Create(ctx, &taskAPI.CreateTaskRequest{ID: "a", Bundle: bundle(t, an)}); err != nil {
		t.Fatal(err)
	}
	// A second container needs a second fiber; the grant allows one:
	// DEFERRED, surfaced as unavailable.
	_, err := s.Create(ctx, &taskAPI.CreateTaskRequest{ID: "b", Bundle: bundle(t, an)})
	if err == nil || !errdefs.IsUnavailable(errdefs.Resolve(err)) && !strings.Contains(err.Error(), "deferred") {
		t.Fatalf("over capacity = %v, want unavailable/deferred", err)
	}
}
