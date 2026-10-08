package shim_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	taskAPI "github.com/containerd/containerd/api/runtime/task/v3"
	"github.com/containerd/containerd/api/types/task"
	"github.com/containerd/containerd/v2/core/events"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/errdefs"
	"github.com/containerd/errdefs/pkg/errgrpc"
	"github.com/containerd/ttrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/consumer"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/core/coretest"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/rpc"
	"github.com/helayoty/fiberd/pkg/runtime/stub"

	fshim "github.com/helayoty/fiberd/examples/kata/shim"
)

// The CRI annotations containerd puts in a container's spec.
const (
	criType          = "io.kubernetes.cri.container-type"
	criSandboxID     = "io.kubernetes.cri.sandbox-id"
	criSandboxName   = "io.kubernetes.cri.sandbox-name"
	criContainerName = "io.kubernetes.cri.container-name"
)

// published is one event the shim emitted, with the namespace it carried.
type published struct {
	topic, ns string
	event     events.Event
}

// publisher records the events the shim emits.
type publisher struct {
	mu     sync.Mutex
	events []published
	closed bool
}

func (p *publisher) Publish(ctx context.Context, topic string, e events.Event) error {
	ns, _ := namespaces.Namespace(ctx)
	p.mu.Lock()
	p.events = append(p.events, published{topic: topic, ns: ns, event: e})
	p.mu.Unlock()
	return nil
}

func (p *publisher) Close() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	return nil
}

func (p *publisher) topics() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, e := range p.events {
		out = append(out, e.topic)
	}
	return out
}

// shutdownStub records the callbacks the service registers.
type shutdownStub struct {
	done      chan struct{}
	mu        sync.Mutex
	callbacks []func(context.Context) error
}

func newShutdownStub() *shutdownStub { return &shutdownStub{done: make(chan struct{})} }

func (s *shutdownStub) Shutdown() { close(s.done) }
func (s *shutdownStub) RegisterCallback(fn func(context.Context) error) {
	s.mu.Lock()
	s.callbacks = append(s.callbacks, fn)
	s.mu.Unlock()
}
func (s *shutdownStub) Done() <-chan struct{} { return s.done }
func (s *shutdownStub) Err() error            { return nil }

// runCallbacks does what containerd's shutdown service does on exit.
func (s *shutdownStub) runCallbacks(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	cbs := slices.Clone(s.callbacks)
	s.mu.Unlock()
	for _, cb := range cbs {
		if err := cb(context.Background()); err != nil {
			t.Fatalf("shutdown callback: %v", err)
		}
	}
}

type home struct {
	agent  *core.Agent
	client *consumer.Client
}

func newHome(t *testing.T) *home {
	t.Helper()
	ag := &core.Agent{
		NodeID: "node-a", Ledger: core.NewLedger(1), Budget: core.NewBudget(1000, 256<<20),
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
	return &home{agent: ag, client: consumer.New(conn)}
}

func (h *home) dial(context.Context, string) (*consumer.Client, error) { return h.client, nil }

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

// rawBundle writes config.json as given.
func rawBundle(t *testing.T, config string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func newService(t *testing.T, dial func(context.Context, string) (*consumer.Client, error)) (*fshim.Service, *publisher, *shutdownStub) {
	t.Helper()
	pub := &publisher{}
	sd := newShutdownStub()
	ctx := namespaces.WithNamespace(context.Background(), "k8s.io")
	s := fshim.NewService(ctx, pub, sd)
	s.DialHome = dial
	return s, pub, sd
}

// appAnnotations is an app container of Pod web-0 under a grant.
func appAnnotations(extra map[string]string) map[string]string {
	an := map[string]string{
		criType: "container", criSandboxID: "sb1", criSandboxName: "web-0", criContainerName: "app",
		fshim.AnnotGrant: "grant-jwt",
	}
	for k, v := range extra {
		an[k] = v
	}
	return an
}

// readState reads the record Create left in the bundle.
func readState(t *testing.T, dir string) (fshim.State, bool) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, fshim.StateFile))
	if errors.Is(err, os.ErrNotExist) {
		return fshim.State{}, false
	}
	if err != nil {
		t.Fatal(err)
	}
	var st fshim.State
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	return st, true
}

func str(s string) *string { return &s }

// native turns a ttrpc-shaped error back into containerd's error space.
func native(err error) error { return errgrpc.ToNative(err) }

// TestPodContainersAreFibers walks one Pod through the shim. It covers the
// sandbox container, an app container parked and resumed as the same
// session, and the shim's shutdown. The steps share one shim and run in order.
func TestPodContainersAreFibers(t *testing.T) {
	h := newHome(t)
	s, pub, sd := newService(t, h.dial)
	ctx := context.Background()
	g := jsonGrant(t, core.Grant{UID: "g1", Audience: "node-a", FiberMax: 2})
	app := func(extra map[string]string) map[string]string {
		an := map[string]string{
			criType: "container", criSandboxID: "sb1",
			criSandboxName: "web-0", criContainerName: "app", fshim.AnnotGrant: g,
		}
		for k, v := range extra {
			an[k] = v
		}
		return an
	}
	// The bundles live as long as the test, as containerd's would.
	sb := bundle(t, map[string]string{criType: "sandbox", criSandboxID: "sb1"})
	cb := bundle(t, app(map[string]string{fshim.AnnotHome: "home-a:8484", fshim.AnnotOnStop: "park"}))
	cb2 := bundle(t, app(nil))

	steps := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"the sandbox (pause) container is a record, no fiber", func(t *testing.T) {
			if _, err := s.Create(ctx, &taskAPI.CreateTaskRequest{ID: "sb1", Bundle: sb}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Start(ctx, &taskAPI.StartRequest{ID: "sb1"}); err != nil {
				t.Fatal(err)
			}
			if st, _ := coretest.GrantStatus(h.agent.Ledger, "g1"); st.Running != 0 {
				t.Fatalf("sandbox container cloned a fiber: %+v", st)
			}
		}},
		{"an app container's Create clones its session and records it in the bundle", func(t *testing.T) {
			resp, err := s.Create(ctx, &taskAPI.CreateTaskRequest{ID: "c1", Bundle: cb})
			if err != nil || resp.Pid == 0 {
				t.Fatalf("create = %+v (%v)", resp, err)
			}
			if st, _ := coretest.GrantStatus(h.agent.Ledger, "g1"); st.Running != 1 {
				t.Fatalf("after create: %+v, want one running fiber", st)
			}
			rec, ok := readState(t, cb)
			if !ok || rec.Session != "web-0/app" || rec.Home != "home-a:8484" || rec.OnStop != "park" || rec.FiberID == "" {
				t.Fatalf("bundle state = %+v (present %v)", rec, ok)
			}
		}},
		{"Start runs it", func(t *testing.T) {
			if _, err := s.Start(ctx, &taskAPI.StartRequest{ID: "c1"}); err != nil {
				t.Fatal(err)
			}
			state, _ := s.State(ctx, &taskAPI.StateRequest{ID: "c1"})
			if state.Status != task.Status_RUNNING || state.Bundle != cb {
				t.Fatalf("state = %+v", state)
			}
		}},
		{"Kill parks, as the Pod asked: the fiber's state is kept and Wait returns", func(t *testing.T) {
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
			if st, _ := coretest.GrantStatus(h.agent.Ledger, "g1"); st.Running != 0 || st.Parked != 1 {
				t.Fatalf("after kill with on-stop=park: %+v", st)
			}
		}},
		{"Delete removes the bundle state", func(t *testing.T) {
			if _, err := s.Delete(ctx, &taskAPI.DeleteRequest{ID: "c1"}); err != nil {
				t.Fatal(err)
			}
			if _, ok := readState(t, cb); ok {
				t.Fatal("bundle state survived Delete")
			}
		}},
		{"the same session again is a RESUME, the container's state carried", func(t *testing.T) {
			if _, err := s.Create(ctx, &taskAPI.CreateTaskRequest{ID: "c2", Bundle: cb2}); err != nil {
				t.Fatal(err)
			}
			if st, _ := coretest.GrantStatus(h.agent.Ledger, "g1"); st.Running != 1 || st.Parked != 0 || st.Latest.Seq != 2 {
				t.Fatalf("after re-create: %+v, want the parked session resumed (seq 2)", st)
			}
		}},
		{"Delete releases by default", func(t *testing.T) {
			if _, err := s.Delete(ctx, &taskAPI.DeleteRequest{ID: "c2"}); err != nil {
				t.Fatal(err)
			}
			if st, _ := coretest.GrantStatus(h.agent.Ledger, "g1"); st.Running != 0 || st.Parked != 0 {
				t.Fatalf("after delete: %+v, want nothing left", st)
			}
		}},
		{"Shutdown with the sandbox container still present does not shut down", func(t *testing.T) {
			if _, err := s.Shutdown(ctx, &taskAPI.ShutdownRequest{}); err != nil {
				t.Fatal(err)
			}
			select {
			case <-sd.Done():
				t.Fatal("shut down with the sandbox container still present")
			default:
			}
		}},
		{"Shutdown once the sandbox is gone too shuts down", func(t *testing.T) {
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
		}},
		{"the task lifecycle events were published", func(t *testing.T) {
			joined := strings.Join(pub.topics(), " ")
			for _, want := range []string{"/tasks/create", "/tasks/start", "/tasks/exit", "/tasks/delete"} {
				if !strings.Contains(joined, want) {
					t.Fatalf("events %v lack %s", pub.topics(), want)
				}
			}
		}},
	}
	for _, step := range steps {
		if !t.Run(step.name, step.run) {
			return // later steps build on this one
		}
	}
}

// TestCreateMisses checks every way Create refuses a container: a bundle
// it cannot read, a container without a grant, a home it cannot reach, and
// a clone the home answers with a miss. A refused container is not
// recorded, in the shim or in its bundle. The steps share one shim and run
// in order, because the real home's grant is full only after the first
// container. The shim dials the real home at DefaultHome and the scripted
// one at its own address.
func TestCreateMisses(t *testing.T) {
	h := newHome(t)
	fake := newFakeHome(t)
	fakeClient := fake.client(t)
	s, _, _ := newService(t, func(_ context.Context, addr string) (*consumer.Client, error) {
		switch addr {
		case fshim.DefaultHome:
			return h.client, nil
		case fake.addr:
			return fakeClient, nil
		}
		return nil, fmt.Errorf("dial %s: %w", addr, errdefs.ErrUnavailable)
	})
	ctx := context.Background()
	g := jsonGrant(t, core.Grant{UID: "g2", Audience: "node-a", FiberMax: 1})
	withGrant := map[string]string{criType: "container", fshim.AnnotGrant: g}
	onFake := map[string]string{criType: "container", fshim.AnnotGrant: "grant-jwt", fshim.AnnotHome: fake.addr}
	unreachable := map[string]string{criType: "container", fshim.AnnotGrant: g, fshim.AnnotHome: "10.0.0.1:1"}
	steps := []struct {
		name        string
		id          string
		annotations map[string]string
		config      *string // raw config.json instead of the annotations; empty writes none
		cloneErr    error   // the scripted home's answer to Clone
		errHas      string  // the error must name this
		is          func(error) bool
		ok          bool // the container is created
	}{
		{name: "a container without a grant is refused as an invalid argument, naming the annotation", id: "x",
			annotations: map[string]string{criType: "container"}, errHas: fshim.AnnotGrant, is: errdefs.IsInvalidArgument},
		{name: "a bundle without config.json is refused, naming the file", id: "nocfg",
			config: str(""), errHas: "config.json"},
		{name: "a config.json that is not JSON is refused, naming the bundle", id: "badcfg",
			config: str("{not json"), errHas: "bundle "},
		{name: "a home the shim cannot dial is refused, naming the home and keeping the dial's class", id: "down",
			annotations: unreachable, errHas: "home 10.0.0.1:1", is: errdefs.IsUnavailable},
		{name: "the first container on a one-fiber grant is created", id: "a", annotations: withGrant, ok: true},
		{name: "a second container needs a second fiber the grant lacks: deferred, surfaced as unavailable", id: "b",
			annotations: withGrant, errHas: "deferred", is: errdefs.IsUnavailable},
		{name: "a SHED miss is unavailable, not resource-exhausted", id: "shed", annotations: onFake,
			cloneErr: missErr(t, codes.ResourceExhausted, grantv1.MissCode_SHED), errHas: "shed", is: errdefs.IsUnavailable},
		{name: "a tier gap is a failed precondition", id: "tier", annotations: onFake,
			cloneErr: status.Error(codes.FailedPrecondition, "needs tier checkpoint"), errHas: "needs tier checkpoint",
			is: errdefs.IsFailedPrecondition},
		{name: "any other refusal keeps its class", id: "bad", annotations: onFake,
			cloneErr: status.Error(codes.InvalidArgument, "grant expired"), errHas: "grant expired", is: errdefs.IsInvalidArgument},
	}
	for _, step := range steps {
		var b string // outlives the step, as containerd's would
		switch {
		case step.config == nil:
			b = bundle(t, step.annotations)
		case *step.config == "":
			b = t.TempDir()
		default:
			b = rawBundle(t, *step.config)
		}
		fake.script(step.cloneErr, nil)
		ok := t.Run(step.name, func(t *testing.T) {
			_, err := s.Create(ctx, &taskAPI.CreateTaskRequest{ID: step.id, Bundle: b})
			if step.ok {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(step.errHas)) {
				t.Fatalf("create = %v, want an error naming %q", err, step.errHas)
			}
			if step.is != nil && !step.is(native(err)) {
				t.Fatalf("create = %v, the wrong error class", err)
			}
			if _, err := s.State(ctx, &taskAPI.StateRequest{ID: step.id}); !errdefs.IsNotFound(native(err)) {
				t.Fatalf("a refused container is recorded: State = %v", err)
			}
			if _, ok := readState(t, b); ok {
				t.Fatal("a refused container left a fiber record in its bundle")
			}
		})
		if !ok {
			return // later steps build on this one
		}
	}
}

// TestCreateRecordsTheFiber checks what Create reads from the Pod's
// annotations, what it asks the home, and what it records.
func TestCreateRecordsTheFiber(t *testing.T) {
	pid := uint32(os.Getpid())
	noNames := map[string]string{criType: "container", fshim.AnnotGrant: "grant-jwt"}
	noType := map[string]string{fshim.AnnotGrant: "grant-jwt", fshim.AnnotSession: "s"}
	cases := []struct {
		name        string
		annotations map[string]string
		stdout      string
		n           int // containers created with these annotations
		wantDials   []string
		wantPayload string
		want        *fshim.State // the bundle's record; nil means a sandbox: no clone, no record
	}{
		{name: "the Pod's annotations name the home, session, on-stop and payload",
			annotations: appAnnotations(map[string]string{fshim.AnnotHome: "home-a:8484", fshim.AnnotSession: "s1",
				fshim.AnnotOnStop: "park", fshim.AnnotPayload: `{"dirty_bytes":1}`}),
			n: 1, wantDials: []string{"home-a:8484"}, wantPayload: `{"dirty_bytes":1}`,
			want: &fshim.State{Home: "home-a:8484", Session: "s1", OnStop: "park"}},
		{name: "by default the home is the node's agent, the session is pod/container, and stop releases",
			annotations: appAnnotations(nil), n: 1, wantDials: []string{fshim.DefaultHome},
			want: &fshim.State{Home: fshim.DefaultHome, Session: "web-0/app", OnStop: "release"}},
		{name: "without CRI names the session is the container id",
			annotations: noNames, n: 1, wantDials: []string{fshim.DefaultHome},
			want: &fshim.State{Home: fshim.DefaultHome, Session: "c0", OnStop: "release"}},
		{name: "a grant without a container type is an app container",
			annotations: noType, n: 1, wantDials: []string{fshim.DefaultHome},
			want: &fshim.State{Home: fshim.DefaultHome, Session: "s", OnStop: "release"}},
		{name: "two containers on one home dial it once and clone twice",
			annotations: appAnnotations(nil), n: 2, wantDials: []string{fshim.DefaultHome},
			want: &fshim.State{Home: fshim.DefaultHome, Session: "web-0/app", OnStop: "release"}},
		{name: "a stdout the shim cannot open does not fail Create",
			annotations: appAnnotations(nil), stdout: "/nonexistent/fiberd/stdout", n: 1, wantDials: []string{fshim.DefaultHome},
			want: &fshim.State{Home: fshim.DefaultHome, Session: "web-0/app", OnStop: "release"}},
		{name: "the sandbox container is a record even with a grant",
			annotations: map[string]string{criType: "sandbox", fshim.AnnotGrant: "grant-jwt"}, n: 1},
		{name: "a spec without annotations is a sandbox", annotations: nil, n: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeHome(t)
			client := fake.client(t)
			var mu sync.Mutex
			var dials []string
			s, pub, _ := newService(t, func(_ context.Context, addr string) (*consumer.Client, error) {
				mu.Lock()
				dials = append(dials, addr)
				mu.Unlock()
				return client, nil
			})
			ctx := context.Background()
			bundles := make([]string, tc.n)
			for i := range tc.n {
				id := fmt.Sprintf("c%d", i)
				bundles[i] = bundle(t, tc.annotations)
				before := time.Now()
				resp, err := s.Create(ctx, &taskAPI.CreateTaskRequest{ID: id, Bundle: bundles[i], Stdout: tc.stdout})
				if err != nil {
					t.Fatal(err)
				}
				if resp.Pid != pid {
					t.Fatalf("create pid = %d, want the shim's %d", resp.Pid, pid)
				}
				st, err := s.State(ctx, &taskAPI.StateRequest{ID: id})
				if err != nil || st.Status != task.Status_CREATED || st.Bundle != bundles[i] || st.Pid != pid || st.ExitedAt != nil {
					t.Fatalf("state = %+v (%v)", st, err)
				}
				clones, _, _ := fake.seen()
				rec, ok := readState(t, bundles[i])
				if tc.want == nil {
					if len(clones) != 0 || ok {
						t.Fatalf("a sandbox cloned %d fibers, record present %v", len(clones), ok)
					}
					continue
				}
				if len(clones) != i+1 {
					t.Fatalf("%d clones after %d creates", len(clones), i+1)
				}
				c := clones[i]
				if c.GetGrantJwt() != "grant-jwt" || c.GetSession() != tc.want.Session || string(c.GetPayload()) != tc.wantPayload {
					t.Fatalf("clone request = %v", c)
				}
				if d := c.GetDeadline().AsTime().Sub(before); d <= 0 || d > 5*time.Second+time.Second {
					t.Fatalf("clone deadline %v after the call, want about 5s", d)
				}
				want := *tc.want
				want.FiberID = fmt.Sprintf("fiber-%d", i+1)
				if !ok || rec != want {
					t.Fatalf("bundle record = %+v (present %v), want %+v", rec, ok, want)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if !slices.Equal(dials, tc.wantDials) {
				t.Fatalf("dialed %v, want %v", dials, tc.wantDials)
			}
			if got := pub.topics(); len(got) != tc.n || got[0] != "/tasks/create" {
				t.Fatalf("events %v, want %d creates", got, tc.n)
			}
		})
	}
}

// TestStopEndsTheFiber checks Start, Kill, Wait and Delete on one app
// container: what the home is asked, the container's exit, and the
// events.
func TestStopEndsTheFiber(t *testing.T) {
	kill := func(sig syscall.Signal) func(context.Context, *testing.T, *fshim.Service) error {
		return func(ctx context.Context, _ *testing.T, s *fshim.Service) error {
			_, err := s.Kill(ctx, &taskAPI.KillRequest{ID: "c1", Signal: uint32(sig)})
			return err
		}
	}
	start := func(ctx context.Context, t *testing.T, s *fshim.Service) error {
		resp, err := s.Start(ctx, &taskAPI.StartRequest{ID: "c1"})
		if err == nil && resp.Pid != uint32(os.Getpid()) {
			t.Fatalf("start pid = %d", resp.Pid)
		}
		return err
	}
	del := func(wantExit uint32) func(context.Context, *testing.T, *fshim.Service) error {
		return func(ctx context.Context, t *testing.T, s *fshim.Service) error {
			resp, err := s.Delete(ctx, &taskAPI.DeleteRequest{ID: "c1"})
			if err == nil && (resp.ExitStatus != wantExit || resp.ExitedAt == nil || resp.Pid != uint32(os.Getpid())) {
				t.Fatalf("delete = %+v, want exit %d", resp, wantExit)
			}
			return err
		}
	}
	type verb = func(context.Context, *testing.T, *fshim.Service) error
	cases := []struct {
		name         string
		onStop       string
		stopErr      error
		verbs        []verb
		wantErr      func(error) bool // of the last verb
		wantStatus   task.Status
		wantExit     uint32
		wantParks    []string
		wantReleases []string
		wantTopics   []string
		wantGone     bool
	}{
		{name: "Start runs the container", verbs: []verb{start},
			wantStatus: task.Status_RUNNING, wantTopics: []string{"/tasks/create", "/tasks/start"}},
		{name: "SIGKILL releases the fiber and exits 137", verbs: []verb{start, kill(syscall.SIGKILL)},
			wantStatus: task.Status_STOPPED, wantExit: 137, wantReleases: []string{"fiber-1"},
			wantTopics: []string{"/tasks/create", "/tasks/start", "/tasks/exit"}},
		{name: "SIGTERM with on-stop park parks the fiber and exits 0", onStop: "park", verbs: []verb{start, kill(syscall.SIGTERM)},
			wantStatus: task.Status_STOPPED, wantParks: []string{"fiber-1"},
			wantTopics: []string{"/tasks/create", "/tasks/start", "/tasks/exit"}},
		{name: "a second Kill changes nothing", verbs: []verb{kill(syscall.SIGTERM), kill(syscall.SIGKILL)},
			wantStatus: task.Status_STOPPED, wantReleases: []string{"fiber-1"},
			wantTopics: []string{"/tasks/create", "/tasks/exit"}},
		{name: "a home that already forgot the fiber does not keep the container running",
			stopErr: status.Error(codes.NotFound, "no such fiber"), verbs: []verb{kill(syscall.SIGKILL)},
			wantStatus: task.Status_STOPPED, wantExit: 137, wantReleases: []string{"fiber-1"},
			wantTopics: []string{"/tasks/create", "/tasks/exit"}},
		{name: "a home that fails the park does not keep the container running", onStop: "park",
			stopErr: status.Error(codes.Internal, "disk full"), verbs: []verb{kill(syscall.SIGKILL)},
			wantStatus: task.Status_STOPPED, wantExit: 137, wantParks: []string{"fiber-1"},
			wantTopics: []string{"/tasks/create", "/tasks/exit"}},
		{name: "Delete without Kill releases the fiber and forgets the container and its record",
			verbs: []verb{start, del(137)}, wantGone: true, wantReleases: []string{"fiber-1"},
			wantTopics: []string{"/tasks/create", "/tasks/start", "/tasks/exit", "/tasks/delete"}},
		{name: "Delete after Kill keeps the Kill's exit status and stops the fiber once",
			verbs: []verb{kill(syscall.SIGTERM), del(0)}, wantGone: true, wantReleases: []string{"fiber-1"},
			wantTopics: []string{"/tasks/create", "/tasks/exit", "/tasks/delete"}},
		// A regression test: Wait returned the bare context error, unlike
		// the shim's other refusals.
		{name: "Wait gives up when its context ends", verbs: []verb{func(ctx context.Context, _ *testing.T, s *fshim.Service) error {
			cctx, cancel := context.WithCancel(ctx)
			cancel()
			_, err := s.Wait(cctx, &taskAPI.WaitRequest{ID: "c1"})
			return err
		}}, wantErr: func(err error) bool { return status.Code(err) == codes.Canceled && errdefs.IsCanceled(native(err)) },
			wantStatus: task.Status_CREATED, wantTopics: []string{"/tasks/create"}},
		{name: "Wait gives up when its deadline passes", verbs: []verb{func(ctx context.Context, _ *testing.T, s *fshim.Service) error {
			dctx, cancel := context.WithDeadline(ctx, time.Now())
			defer cancel()
			_, err := s.Wait(dctx, &taskAPI.WaitRequest{ID: "c1"})
			return err
		}}, wantErr: func(err error) bool {
			return status.Code(err) == codes.DeadlineExceeded && errdefs.IsDeadlineExceeded(native(err))
		}, wantStatus: task.Status_CREATED, wantTopics: []string{"/tasks/create"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeHome(t)
			fake.script(nil, tc.stopErr)
			client := fake.client(t)
			s, pub, _ := newService(t, func(context.Context, string) (*consumer.Client, error) { return client, nil })
			ctx := context.Background()
			b := bundle(t, appAnnotations(map[string]string{fshim.AnnotOnStop: tc.onStop}))
			if _, err := s.Create(ctx, &taskAPI.CreateTaskRequest{ID: "c1", Bundle: b}); err != nil {
				t.Fatal(err)
			}
			var err error
			for _, v := range tc.verbs {
				if err = v(ctx, t, s); err != nil {
					break
				}
			}
			switch {
			case tc.wantErr != nil && !tc.wantErr(err):
				t.Fatalf("err = %v, want the expected class", err)
			case tc.wantErr == nil && err != nil:
				t.Fatal(err)
			}
			_, parks, releases := fake.seen()
			if !slices.Equal(parks, tc.wantParks) || !slices.Equal(releases, tc.wantReleases) {
				t.Fatalf("home saw parks %v releases %v, want %v %v", parks, releases, tc.wantParks, tc.wantReleases)
			}
			if got := pub.topics(); !slices.Equal(got, tc.wantTopics) {
				t.Fatalf("events %v, want %v", got, tc.wantTopics)
			}
			_, recorded := readState(t, b)
			if tc.wantGone {
				if _, err := s.State(ctx, &taskAPI.StateRequest{ID: "c1"}); !errdefs.IsNotFound(native(err)) {
					t.Fatalf("State after Delete = %v, want not found", err)
				}
				if recorded {
					t.Fatal("the bundle's fiber record survived Delete")
				}
				return
			}
			if !recorded {
				t.Fatal("the bundle's fiber record is gone before Delete")
			}
			st, err := s.State(ctx, &taskAPI.StateRequest{ID: "c1"})
			if err != nil || st.Status != tc.wantStatus || st.ExitStatus != tc.wantExit {
				t.Fatalf("state = %+v (%v), want %v exit %d", st, err, tc.wantStatus, tc.wantExit)
			}
			if tc.wantStatus != task.Status_STOPPED {
				return
			}
			if st.ExitedAt == nil {
				t.Fatal("a stopped container has no exit time")
			}
			wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			w, err := s.Wait(wctx, &taskAPI.WaitRequest{ID: "c1"})
			if err != nil || w.ExitStatus != tc.wantExit || !w.ExitedAt.AsTime().Equal(st.ExitedAt.AsTime()) {
				t.Fatalf("wait = %+v (%v), want exit %d at %v", w, err, tc.wantExit, st.ExitedAt.AsTime())
			}
		})
	}
}

// TestRefusals checks the verbs the shim refuses: anything about a
// container it does not have, any exec, and the home's own verbs. A
// refusal leaves the running container as it was.
func TestRefusals(t *testing.T) {
	notFound, notImpl := errdefs.IsNotFound, errdefs.IsNotImplemented
	cases := []struct {
		name string
		call func(context.Context, *fshim.Service) error
		is   func(error) bool
	}{
		{"Start of an unknown container", func(ctx context.Context, s *fshim.Service) error {
			_, err := s.Start(ctx, &taskAPI.StartRequest{ID: "nope"})
			return err
		}, notFound},
		{"Kill of an unknown container", func(ctx context.Context, s *fshim.Service) error {
			_, err := s.Kill(ctx, &taskAPI.KillRequest{ID: "nope"})
			return err
		}, notFound},
		{"Wait on an unknown container", func(ctx context.Context, s *fshim.Service) error {
			_, err := s.Wait(ctx, &taskAPI.WaitRequest{ID: "nope"})
			return err
		}, notFound},
		{"Delete of an unknown container", func(ctx context.Context, s *fshim.Service) error {
			_, err := s.Delete(ctx, &taskAPI.DeleteRequest{ID: "nope"})
			return err
		}, notFound},
		{"State of an unknown container", func(ctx context.Context, s *fshim.Service) error {
			_, err := s.State(ctx, &taskAPI.StateRequest{ID: "nope"})
			return err
		}, notFound},
		{"Pids of an unknown container", func(ctx context.Context, s *fshim.Service) error {
			_, err := s.Pids(ctx, &taskAPI.PidsRequest{ID: "nope"})
			return err
		}, notFound},
		{"Start of an exec", func(ctx context.Context, s *fshim.Service) error {
			_, err := s.Start(ctx, &taskAPI.StartRequest{ID: "c1", ExecID: "e1"})
			return err
		}, notImpl},
		{"Kill of an exec leaves the container running", func(ctx context.Context, s *fshim.Service) error {
			_, err := s.Kill(ctx, &taskAPI.KillRequest{ID: "c1", ExecID: "e1", Signal: uint32(syscall.SIGKILL)})
			return err
		}, notImpl},
		{"Wait on an exec does not wait for the container", func(ctx context.Context, s *fshim.Service) error {
			_, err := s.Wait(ctx, &taskAPI.WaitRequest{ID: "c1", ExecID: "e1"})
			return err
		}, notImpl},
		{"Delete of an exec leaves the container running", func(ctx context.Context, s *fshim.Service) error {
			_, err := s.Delete(ctx, &taskAPI.DeleteRequest{ID: "c1", ExecID: "e1"})
			return err
		}, notImpl},
		{"State of an exec is not the container's", func(ctx context.Context, s *fshim.Service) error {
			_, err := s.State(ctx, &taskAPI.StateRequest{ID: "c1", ExecID: "e1"})
			return err
		}, notImpl},
		{"Exec", func(ctx context.Context, s *fshim.Service) error {
			_, err := s.Exec(ctx, &taskAPI.ExecProcessRequest{ID: "c1", ExecID: "e1"})
			return err
		}, notImpl},
		{"Stats", func(ctx context.Context, s *fshim.Service) error {
			_, err := s.Stats(ctx, &taskAPI.StatsRequest{ID: "c1"})
			return err
		}, notImpl},
		{"ResizePty", func(ctx context.Context, s *fshim.Service) error {
			_, err := s.ResizePty(ctx, &taskAPI.ResizePtyRequest{ID: "c1"})
			return err
		}, notImpl},
		{"Pause", func(ctx context.Context, s *fshim.Service) error {
			_, err := s.Pause(ctx, &taskAPI.PauseRequest{ID: "c1"})
			return err
		}, notImpl},
		{"Resume", func(ctx context.Context, s *fshim.Service) error {
			_, err := s.Resume(ctx, &taskAPI.ResumeRequest{ID: "c1"})
			return err
		}, notImpl},
		{"Checkpoint", func(ctx context.Context, s *fshim.Service) error {
			_, err := s.Checkpoint(ctx, &taskAPI.CheckpointTaskRequest{ID: "c1"})
			return err
		}, notImpl},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeHome(t)
			client := fake.client(t)
			s, _, _ := newService(t, func(context.Context, string) (*consumer.Client, error) { return client, nil })
			ctx := context.Background()
			if _, err := s.Create(ctx, &taskAPI.CreateTaskRequest{ID: "c1", Bundle: bundle(t, appAnnotations(nil))}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Start(ctx, &taskAPI.StartRequest{ID: "c1"}); err != nil {
				t.Fatal(err)
			}
			// A verb that waits for the container would block: the
			// deadline turns that into a failure.
			cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			if err := tc.call(cctx, s); !tc.is(native(err)) {
				t.Fatalf("err = %v, want the expected refusal", err)
			}
			st, err := s.State(ctx, &taskAPI.StateRequest{ID: "c1"})
			if err != nil || st.Status != task.Status_RUNNING {
				t.Fatalf("after the refusal: state = %+v (%v), want running", st, err)
			}
			if _, parks, releases := fake.seen(); len(parks)+len(releases) != 0 {
				t.Fatalf("a refusal stopped the fiber: parks %v releases %v", parks, releases)
			}
		})
	}
}

// TestAnswers checks the verbs the shim answers without a fiber: the
// shim's own pid stands for the task, and closing IO or updating
// resources is accepted and changes nothing.
func TestAnswers(t *testing.T) {
	s, _, _ := newService(t, nil)
	ctx := context.Background()
	if _, err := s.Create(ctx, &taskAPI.CreateTaskRequest{ID: "sb", Bundle: bundle(t, map[string]string{criType: "sandbox"})}); err != nil {
		t.Fatal(err)
	}
	pid := uint32(os.Getpid())
	cases := []struct {
		name string
		call func() (proto.Message, error)
		want proto.Message
	}{
		{"Connect names the shim as the task", func() (proto.Message, error) {
			return s.Connect(ctx, &taskAPI.ConnectRequest{ID: "sb"})
		}, &taskAPI.ConnectResponse{ShimPid: pid, TaskPid: pid}},
		{"Pids lists the shim alone", func() (proto.Message, error) {
			return s.Pids(ctx, &taskAPI.PidsRequest{ID: "sb"})
		}, &taskAPI.PidsResponse{Processes: []*task.ProcessInfo{{Pid: pid}}}},
		{"CloseIO is accepted", func() (proto.Message, error) {
			return s.CloseIO(ctx, &taskAPI.CloseIORequest{ID: "sb", Stdin: true})
		}, &emptypb.Empty{}},
		{"Update is accepted", func() (proto.Message, error) {
			return s.Update(ctx, &taskAPI.UpdateTaskRequest{ID: "sb"})
		}, &emptypb.Empty{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.call()
			if err != nil || !proto.Equal(got, tc.want) {
				t.Fatalf("got %v (%v), want %v", got, err, tc.want)
			}
			st, err := s.State(ctx, &taskAPI.StateRequest{ID: "sb"})
			if err != nil || st.Status != task.Status_CREATED {
				t.Fatalf("state = %+v (%v), want unchanged", st, err)
			}
		})
	}
}

// TestPublishNamespace checks the namespace events carry: the shim's own
// when containerd gave it one, the request's otherwise. A shim without a
// publisher still serves.
func TestPublishNamespace(t *testing.T) {
	cases := []struct {
		name        string
		shimNS      string
		requestNS   string
		noPublisher bool
		want        string
	}{
		{name: "the shim's namespace, for a request without one", shimNS: "k8s.io", want: "k8s.io"},
		{name: "the shim's namespace wins over the request's", shimNS: "k8s.io", requestNS: "other", want: "k8s.io"},
		{name: "the request's namespace when the shim has none", requestNS: "moby", want: "moby"},
		{name: "no publisher: the verbs still succeed", shimNS: "k8s.io", noPublisher: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sctx := context.Background()
			if tc.shimNS != "" {
				sctx = namespaces.WithNamespace(sctx, tc.shimNS)
			}
			pub := &publisher{}
			var s *fshim.Service
			if tc.noPublisher {
				s = fshim.NewService(sctx, nil, nil)
			} else {
				s = fshim.NewService(sctx, pub, nil)
			}
			ctx := context.Background()
			if tc.requestNS != "" {
				ctx = namespaces.WithNamespace(ctx, tc.requestNS)
			}
			b := bundle(t, map[string]string{criType: "sandbox"})
			if _, err := s.Create(ctx, &taskAPI.CreateTaskRequest{ID: "sb", Bundle: b}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Start(ctx, &taskAPI.StartRequest{ID: "sb"}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Delete(ctx, &taskAPI.DeleteRequest{ID: "sb"}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Shutdown(ctx, &taskAPI.ShutdownRequest{}); err != nil {
				t.Fatal(err)
			}
			pub.mu.Lock()
			defer pub.mu.Unlock()
			if tc.noPublisher {
				if len(pub.events) != 0 {
					t.Fatalf("events %v reached an unset publisher", pub.events)
				}
				return
			}
			if len(pub.events) != 4 {
				t.Fatalf("events %+v, want create, start, exit, delete", pub.events)
			}
			for _, e := range pub.events {
				if e.ns != tc.want {
					t.Fatalf("event %s in namespace %q, want %q", e.topic, e.ns, tc.want)
				}
			}
		})
	}
}

// TestShutdownClosesConnections checks the callback the service leaves
// with containerd's shutdown service: it closes every home connection and
// the publisher.
func TestShutdownClosesConnections(t *testing.T) {
	cases := []struct {
		name        string
		noPublisher bool
	}{
		{name: "the home connection and the publisher are closed"},
		{name: "without a publisher the home connection is still closed", noPublisher: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeHome(t)
			client, err := consumer.Dial(context.Background(), fake.addr)
			if err != nil {
				t.Fatal(err)
			}
			pub := &publisher{}
			sd := newShutdownStub()
			var s *fshim.Service
			if tc.noPublisher {
				s = fshim.NewService(context.Background(), nil, sd)
			} else {
				s = fshim.NewService(context.Background(), pub, sd)
			}
			s.DialHome = func(context.Context, string) (*consumer.Client, error) { return client, nil }
			ctx := context.Background()
			if _, err := s.Create(ctx, &taskAPI.CreateTaskRequest{ID: "c1", Bundle: bundle(t, appAnnotations(nil))}); err != nil {
				t.Fatal(err)
			}
			sd.runCallbacks(t)
			if _, err := client.Clone(ctx, "grant-jwt", "s", time.Second, nil); status.Code(err) != codes.Canceled {
				t.Fatalf("clone on the home connection after shutdown = %v, want it closed", err)
			}
			pub.mu.Lock()
			defer pub.mu.Unlock()
			if pub.closed == tc.noPublisher {
				t.Fatalf("publisher closed = %v", pub.closed)
			}
		})
	}
}

// endContext is the ttrpc metadata key TestRegisterTTRPC's interceptor
// reads: "cancel" or "deadline" ends the handler's context that way.
const endContext = "test-end-context"

// TestRegisterTTRPC serves the task service as containerd reaches it, over
// ttrpc, and checks that answers and error classes survive the wire.
func TestRegisterTTRPC(t *testing.T) {
	s, _, _ := newService(t, nil)
	// A call carrying the endContext metadata has its context ended on the
	// shim's side of the wire. The code the shim answers with then reaches
	// the client while the client's own context is still live.
	server, err := ttrpc.NewServer(ttrpc.WithUnaryServerInterceptor(
		func(ctx context.Context, u ttrpc.Unmarshaler, _ *ttrpc.UnaryServerInfo, m ttrpc.Method) (any, error) {
			end, cancel := context.WithCancel(ctx)
			defer cancel()
			switch v, _ := ttrpc.GetMetadataValue(ctx, endContext); v {
			case "cancel":
				cancel()
				ctx = end
			case "deadline":
				ctx, cancel = context.WithDeadline(ctx, time.Now())
				defer cancel()
			}
			return m(ctx, u)
		}))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterTTRPC(server); err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(context.Background(), lis) }()
	t.Cleanup(func() { _ = server.Close() })
	conn, err := net.Dial("tcp", lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tc := ttrpc.NewClient(conn)
	t.Cleanup(func() { _ = tc.Close() })
	client := taskAPI.NewTTRPCTaskClient(tc)
	pid := uint32(os.Getpid())
	b := bundle(t, map[string]string{criType: "sandbox"})

	// ending asks the interceptor above to end the call's context.
	ending := func(ctx context.Context, how string) context.Context {
		return ttrpc.WithMetadata(ctx, ttrpc.MD{endContext: {how}})
	}
	cases := []struct {
		name string
		call func(context.Context) (proto.Message, error)
		want proto.Message
		is   func(error) bool
		code codes.Code // the code on the wire, checked when not OK
	}{
		{name: "Connect answers with the shim's pid", call: func(ctx context.Context) (proto.Message, error) {
			return client.Connect(ctx, &taskAPI.ConnectRequest{ID: "sb"})
		}, want: &taskAPI.ConnectResponse{ShimPid: pid, TaskPid: pid}},
		{name: "Create records the sandbox", call: func(ctx context.Context) (proto.Message, error) {
			return client.Create(ctx, &taskAPI.CreateTaskRequest{ID: "sb", Bundle: b})
		}, want: &taskAPI.CreateTaskResponse{Pid: pid}},
		{name: "State reports it", call: func(ctx context.Context) (proto.Message, error) {
			return client.State(ctx, &taskAPI.StateRequest{ID: "sb"})
		}, want: &taskAPI.StateResponse{ID: "sb", Bundle: b, Pid: pid, Status: task.Status_CREATED}},
		{name: "an unknown container is not found", call: func(ctx context.Context) (proto.Message, error) {
			return client.State(ctx, &taskAPI.StateRequest{ID: "nope"})
		}, is: errdefs.IsNotFound},
		{name: "Pause is not implemented", call: func(ctx context.Context) (proto.Message, error) {
			return client.Pause(ctx, &taskAPI.PauseRequest{ID: "sb"})
		}, is: errdefs.IsNotImplemented},
		{name: "Wait whose context is canceled answers Canceled", call: func(ctx context.Context) (proto.Message, error) {
			return client.Wait(ending(ctx, "cancel"), &taskAPI.WaitRequest{ID: "sb"})
		}, code: codes.Canceled, is: errdefs.IsCanceled},
		{name: "Wait whose deadline passes answers DeadlineExceeded", call: func(ctx context.Context) (proto.Message, error) {
			return client.Wait(ending(ctx, "deadline"), &taskAPI.WaitRequest{ID: "sb"})
		}, code: codes.DeadlineExceeded, is: errdefs.IsDeadlineExceeded},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			got, err := c.call(ctx)
			if c.code != codes.OK && status.Code(err) != c.code {
				t.Fatalf("err = %v, code %v, want %v", err, status.Code(err), c.code)
			}
			if c.is != nil {
				if !c.is(native(err)) {
					t.Fatalf("err = %v, want the expected class", err)
				}
				return
			}
			if err != nil || !proto.Equal(got, c.want) {
				t.Fatalf("got %v (%v), want %v", got, err, c.want)
			}
		})
	}
}

// fifoLines makes a fifo at path, as containerd does for a container's
// stdout, and returns the lines written to it. The reader also holds the
// fifo open for writing, so each writer's close is not an end of file.
func fifoLines(t *testing.T, path string) <-chan string {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	lines := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	return lines
}

// TestStdoutNamesTheFiber checks the lines the shim writes to the
// container's stdout, which kubectl logs shows: the fiber Create made, and
// a stop the home failed.
func TestStdoutNamesTheFiber(t *testing.T) {
	cases := []struct {
		name    string
		onStop  string
		stopErr error
		kill    bool
		want    []string // each must appear in some line
	}{
		{name: "Create names the fiber, its session, endpoint and fence",
			want: []string{"fiber fiber-1 CREATE session=web-0/app endpoint=tcp://127.0.0.1:7000 fence=g/1/1"}},
		{name: "a park the home failed is logged", onStop: "park", stopErr: status.Error(codes.Internal, "disk full"), kill: true,
			want: []string{"fiber fiber-1 CREATE", "park fiber-1: "}},
		{name: "a release the home failed is logged", stopErr: status.Error(codes.Unavailable, "home gone"), kill: true,
			want: []string{"fiber fiber-1 CREATE", "release fiber-1: "}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeHome(t)
			fake.script(nil, tc.stopErr)
			client := fake.client(t)
			s, _, _ := newService(t, func(context.Context, string) (*consumer.Client, error) { return client, nil })
			stdout := filepath.Join(t.TempDir(), "stdout")
			lines := fifoLines(t, stdout)
			ctx := context.Background()
			b := bundle(t, appAnnotations(map[string]string{fshim.AnnotOnStop: tc.onStop}))
			if _, err := s.Create(ctx, &taskAPI.CreateTaskRequest{ID: "c1", Bundle: b, Stdout: stdout}); err != nil {
				t.Fatal(err)
			}
			if tc.kill {
				if _, err := s.Kill(ctx, &taskAPI.KillRequest{ID: "c1", Signal: uint32(syscall.SIGKILL)}); err != nil {
					t.Fatal(err)
				}
			}
			missing := slices.Clone(tc.want)
			deadline := time.After(10 * time.Second)
			var seen []string
			for len(missing) > 0 {
				select {
				case l, ok := <-lines:
					if !ok {
						t.Fatalf("stdout closed; saw %q, missing %q", seen, missing)
					}
					seen = append(seen, l)
					missing = slices.DeleteFunc(missing, func(w string) bool { return strings.HasPrefix(l, w) })
				case <-deadline:
					t.Fatalf("stdout showed %q, missing %q", seen, missing)
				}
			}
		})
	}
}
