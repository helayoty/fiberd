package herder

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/consumer"
	"github.com/helayoty/fiberd/pkg/core"
)

var errNoGrant = errors.New("no grant for this template")

// failingGrants hands out no grant at all.
type failingGrants struct{}

func (failingGrants) Grant(context.Context, Template, uint64) (string, core.Grant, error) {
	return "", core.Grant{}, errNoGrant
}

// badTokenGrants hands out a token the agent cannot verify.
type badTokenGrants struct{}

func (badTokenGrants) Grant(context.Context, Template, uint64) (string, core.Grant, error) {
	return "not a grant", core.Grant{UID: "g-bad"}, nil
}

var counter = Template{"team-a", "counter"}

// TestStartFailures checks that an actor that cannot start leaves the
// worker free and the router untouched, with the code Substrate acts on.
func TestStartFailures(t *testing.T) {
	ctx := context.Background()
	notReady := func(context.Context, string, string) error { return errors.New("connection refused") }
	cases := []struct {
		name  string
		mod   func(*Config)
		setup func(t *testing.T, w *worker) // before the call
		call  func(s *Service) error
		want  codes.Code
		after func(t *testing.T, w *worker) // what the failure left behind
	}{
		{name: "run without a grant for the template is internal",
			mod:  func(c *Config) { c.Grants = failingGrants{} },
			call: func(s *Service) error { _, err := s.RunWorkload(ctx, runReq("a1")); return err },
			want: codes.Internal},
		{name: "restore without a grant for the template is internal",
			mod: func(c *Config) { c.Grants = failingGrants{} },
			call: func(s *Service) error {
				_, err := s.RestoreWorkload(ctx, &ateompbRestore{ActorUid: "a1", ActorTemplateAtespace: "team-a", ActorTemplateName: "counter", Scope: scopeFull})
				return err
			},
			want: codes.Internal},
		{name: "a grant the agent cannot verify keeps the agent's code",
			mod:  func(c *Config) { c.Grants = badTokenGrants{} },
			call: func(s *Service) error { _, err := s.RunWorkload(ctx, runReq("a1")); return err },
			want: codes.Unauthenticated},
		{name: "a run that resumes a parked session is let go",
			setup: func(t *testing.T, w *worker) {
				jwt, _, _ := w.grants.Grant(ctx, counter, 16<<20)
				f, err := w.client.Clone(ctx, jwt, "a1", time.Second, nil)
				if err != nil {
					t.Fatal(err)
				}
				if err := w.client.Park(ctx, f.ID, true); err != nil {
					t.Fatal(err)
				}
			},
			call: func(s *Service) error { _, err := s.RunWorkload(ctx, runReq("a1")); return err },
			want: codes.Internal,
			after: func(t *testing.T, w *worker) {
				if f := w.agent.Ledger.FibersOf("g-counter"); len(f) != 0 {
					t.Fatalf("fibers still running under the grant: %+v", f)
				}
			}},
		{name: "an actor that never turns ready is let go, and its session discarded",
			mod:  func(c *Config) { c.Probe, c.ReadyTimeout = notReady, time.Millisecond },
			call: func(s *Service) error { _, err := s.RunWorkload(ctx, runReq("a1")); return err },
			want: codes.Unavailable,
			after: func(t *testing.T, w *worker) {
				jwt, _, _ := w.grants.Grant(ctx, counter, 16<<20)
				f, err := w.client.Clone(ctx, jwt, "a1", time.Second, nil)
				if err != nil || f.Kind != consumer.Create {
					t.Fatalf("clone after = %v %v, want a fresh session", f.Kind, err)
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorker(t, 4, tc.mod)
			if tc.setup != nil {
				tc.setup(t, w)
			}
			if err := tc.call(w.svc); status.Code(err) != tc.want {
				t.Fatalf("code = %v (%v), want %v", status.Code(err), err, tc.want)
			}
			if _, _, _, ok := w.svc.Active(); ok {
				t.Fatal("a failed start left an actor active")
			}
			if len(w.router.active) != 0 {
				t.Fatalf("a failed start reached the router: %v", w.router.active)
			}
			if tc.after != nil {
				tc.after(t, w)
			}
		})
	}
}

// TestReady checks that every container with a readyz is probed at its
// path on the fiber's endpoint until it answers or its timeout passes.
func TestReady(t *testing.T) {
	container := func(name, path string, timeoutSeconds int32) *ateompbContainer {
		return &ateompbContainer{Name: name, Readyz: &ateompbReadyz{HttpGet: &ateompbHTTPGet{Path: path}, TimeoutSeconds: timeoutSeconds}}
	}
	errDown := errors.New("down")
	cases := []struct {
		name       string
		containers []*ateompbContainer
		failures   int           // the probe fails this often first, or always for -1
		timeout    time.Duration // Config.ReadyTimeout
		cancelled  bool          // the caller's context is already done
		probed     []string      // the paths probed, in order
		err        string
		is         error
	}{
		{name: "a container without a readyz is not probed", containers: []*ateompbContainer{{Name: "sidecar"}}},
		{name: "every container's path is probed", containers: []*ateompbContainer{container("a", "/a", 0), container("b", "/b", 0)},
			probed: []string{"/a", "/b"}},
		{name: "an empty path is /readyz", containers: []*ateompbContainer{container("a", "", 0)}, probed: []string{"/readyz"}},
		{name: "a probe that fails at first is retried until it answers", containers: []*ateompbContainer{container("a", "/r", 0)},
			failures: 2, probed: []string{"/r", "/r", "/r"}},
		{name: "a probe that never answers fails after the timeout", containers: []*ateompbContainer{container("app", "/r", 0)},
			failures: -1, timeout: time.Millisecond, err: "container app: /r did not answer 200 within 1ms", is: errDown},
		{name: "the container's own timeout replaces the default", containers: []*ateompbContainer{container("a", "/r", 5)},
			failures: 2, timeout: time.Millisecond, probed: []string{"/r", "/r", "/r"}},
		{name: "the caller giving up ends the wait", containers: []*ateompbContainer{container("a", "/r", 0)},
			failures: -1, cancelled: true, err: "context canceled", is: context.Canceled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var probed []string
			n := 0
			s := New(Config{ReadyTimeout: tc.timeout, Probe: func(_ context.Context, endpoint, path string) error {
				if endpoint != "tcp://127.0.0.1:1" {
					t.Errorf("probed endpoint %q", endpoint)
				}
				probed = append(probed, path)
				if n++; tc.failures < 0 || n <= tc.failures {
					return errDown
				}
				return nil
			}})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancelled {
				cancel()
			}
			err := s.ready(ctx, "tcp://127.0.0.1:1", &ateompbSpec{Containers: tc.containers})
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) || !errors.Is(err, tc.is) {
					t.Fatalf("ready = %v, want %q wrapping %v", err, tc.err, tc.is)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(probed, ",") != strings.Join(tc.probed, ",") {
				t.Fatalf("probed %v, want %v", probed, tc.probed)
			}
		})
	}
}

// TestLifecycleFailures checks checkpoint and terminate when the agent
// does not follow. The actor stays where atelet can act on it again.
func TestLifecycleFailures(t *testing.T) {
	ctx := context.Background()
	gone := func(t *testing.T, w *worker) {
		if err := w.client.Release(ctx, w.svc.current().fiber.ID, true); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name   string
		break_ func(t *testing.T, w *worker) // after the run, before the call
		call   func(s *Service) error
		want   codes.Code
		active bool // the actor is still here afterwards
		routed bool // the router still routes it
	}{
		{name: "a checkpoint the agent cannot park keeps the actor routed", break_: gone,
			call: func(s *Service) error {
				_, err := s.CheckpointWorkload(ctx, &ateompbCkpt{ActorUid: "a1", Scope: scopeFull})
				return err
			},
			want: codes.NotFound, active: true, routed: true},
		{name: "a parked session that cannot be exported is internal; the actor stays to be terminated",
			call: func(s *Service) error {
				_, err := s.CheckpointWorkload(ctx, &ateompbCkpt{ActorUid: "a1", Scope: scopeFull})
				return err
			},
			want: codes.Internal, active: true},
		{name: "terminating a fiber already gone is done", break_: gone,
			call: func(s *Service) error { _, err := s.TerminateWorkload(ctx, &ateompbTerm{ActorUid: "a1"}); return err },
			want: codes.OK},
		{name: "a terminate the agent does not answer keeps the actor", break_: func(_ *testing.T, w *worker) { w.stop() },
			call: func(s *Service) error { _, err := s.TerminateWorkload(ctx, &ateompbTerm{ActorUid: "a1"}); return err },
			want: codes.Unavailable, active: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorker(t, 4, nil)
			if _, err := w.svc.RunWorkload(ctx, runReq("a1")); err != nil {
				t.Fatal(err)
			}
			if tc.break_ != nil {
				tc.break_(t, w)
			}
			if err := tc.call(w.svc); status.Code(err) != tc.want {
				t.Fatalf("code = %v (%v), want %v", status.Code(err), err, tc.want)
			}
			if _, _, uid, ok := w.svc.Active(); ok != tc.active || (ok && uid != "a1") {
				t.Fatalf("active = %q %v, want %v", uid, ok, tc.active)
			}
			if _, ok := w.router.active["team-a/counter-a1"]; ok != tc.routed {
				t.Fatalf("routed = %v, want %v", ok, tc.routed)
			}
		})
	}
}

// TestStats checks both stats calls against what executes here and what
// the agent last reported for it.
func TestStats(t *testing.T) {
	ctx := context.Background()
	at := time.Unix(1700000000, 42)
	running := func() *actor {
		return &actor{ref: [2]string{"team-a", "counter-a1"}, uid: "a1", tmpl: counter, grant: core.Grant{UID: "g-counter"}}
	}
	cases := []struct {
		name     string
		active   *actor
		stats    map[string]consumer.Status
		sampleAt time.Time
		code     codes.Code            // GetWorkloadStats for a1
		reason   ateompbNoSampleReason // GetActiveWorkloadStats, when it has no sample
		want     *ateompbStatsSample   // the sample both return
	}{
		{name: "nothing executes", code: codes.NotFound, reason: noWorkload},
		{name: "an actor the agent has not reported on yet", active: running(),
			code: codes.FailedPrecondition, reason: notMeasurableYet},
		{name: "a report for the grant but none since this actor started", active: running(),
			stats: map[string]consumer.Status{"g-counter": {GrantUID: "g-counter", WUsedBytes: 7}},
			code:  codes.FailedPrecondition, reason: notMeasurableYet},
		{name: "a reported actor: its grant's W", active: running(), sampleAt: at,
			stats: map[string]consumer.Status{"g-counter": {GrantUID: "g-counter", WUsedBytes: 7}},
			want: &ateompbStatsSample{Atespace: "team-a", ActorName: "counter-a1", ActorUid: "a1",
				ActorTemplateAtespace: "team-a", ActorTemplateName: "counter", Source: sourceCgroup,
				MemoryCurrentBytes: 7, MemoryWorkingSetBytes: 7, ObservedAtUnixNano: at.UnixNano()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := New(Config{})
			s.active = tc.active
			if s.active != nil {
				s.active.sampleAt = tc.sampleAt
			}
			for k, v := range tc.stats {
				s.stats[k] = v
			}
			one, err := s.GetWorkloadStats(ctx, &ateompbStatsReq{ActorUid: "a1"})
			if status.Code(err) != tc.code {
				t.Fatalf("GetWorkloadStats code = %v (%v), want %v", status.Code(err), err, tc.code)
			}
			all, err := s.GetActiveWorkloadStats(ctx, &ateompbActiveReq{})
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == nil {
				if all.GetNoSampleReason() != tc.reason {
					t.Fatalf("active stats = %v, want no sample because %v", all, tc.reason)
				}
				return
			}
			for _, got := range []*ateompbStatsSample{one.GetSample(), all.GetSample()} {
				if got.String() != tc.want.String() {
					t.Fatalf("sample = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// fakeFibers is an agent whose Watch stream breaks once, then reports
// one status and stays open.
type fakeFibers struct {
	grantv1.UnimplementedFibersServer
	mu      sync.Mutex
	watches int
}

func (f *fakeFibers) Watch(_ *emptypb.Empty, stream grantv1.Fibers_WatchServer) error {
	f.mu.Lock()
	f.watches++
	n := f.watches
	f.mu.Unlock()
	if n == 1 {
		return status.Error(codes.Unavailable, "agent restarting")
	}
	if err := stream.Send(&grantv1.Status{GrantUid: "g-counter", Running: 1, WUsedBytes: 99}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return nil
}

// TestRunReconnects checks that the stats survive a broken Watch stream.
// Run dials again and the next report lands, and Run returns once its
// context ends.
func TestRunReconnects(t *testing.T) {
	cases := []struct {
		name      string
		wantBytes uint64
	}{
		{"the report after a reconnect is kept", 99},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lis := bufconn.Listen(1 << 20)
			gs := grpc.NewServer()
			grantv1.RegisterFibersServer(gs, &fakeFibers{})
			go func() { _ = gs.Serve(lis) }()
			t.Cleanup(gs.Stop)
			conn, err := grpc.NewClient("passthrough:///bufconn",
				grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
				grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatal(err)
			}
			s := New(Config{Client: consumer.New(conn)})
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { s.Run(ctx); close(done) }()
			for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
				s.mu.Lock()
				st, ok := s.stats["g-counter"]
				s.mu.Unlock()
				if ok {
					if st.WUsedBytes != tc.wantBytes {
						t.Fatalf("status = %+v, want %d bytes", st, tc.wantBytes)
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("no report after the stream broke")
				}
			}
			cancel()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("Run kept going after its context ended")
			}
		})
	}
}

// TestHTTPProbe checks the default readiness probe, a GET of the path on
// the fiber's endpoint that must answer 200.
func TestHTTPProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	live := "tcp://" + srv.Listener.Addr().String()
	closed := httptest.NewServer(http.NotFoundHandler())
	dead := "tcp://" + closed.Listener.Addr().String()
	closed.Close()
	cases := []struct {
		name     string
		endpoint string
		path     string
		err      string // empty when ready
	}{
		{name: "200 is ready", endpoint: live, path: "/readyz"},
		{name: "any other status is not", endpoint: live, path: "/other", err: "status 503"},
		{name: "an endpoint nobody listens on is not", endpoint: dead, path: "/readyz", err: "connection refused"},
		{name: "an endpoint that does not parse is not", endpoint: "unix:relative", path: "/readyz", err: "must be absolute"},
		{name: "a path that makes no URL is not", endpoint: live, path: " bad", err: "invalid character"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := httpProbe(context.Background(), tc.endpoint, tc.path)
			if tc.err == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("probe = %v, want an error with %q", err, tc.err)
			}
		})
	}
}

// TestNamesAndPaths checks the names a worker shares with atelet and the
// -template keys.
func TestNamesAndPaths(t *testing.T) {
	custom := Paths{Base: "/srv/ateom"}
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"the default base is the gVisor herder's", Paths{}.AteomDir("pod-1"), "/var/lib/ateom-gvisor/ateoms/pod-1"},
		{"a worker's directory is named by its pod", custom.AteomDir("pod-1"), "/srv/ateom/ateoms/pod-1"},
		{"atelet dials the worker's socket", custom.SocketPath("pod-1"), "/srv/ateom/ateoms/pod-1/ateom.sock"},
		{"atelet's own socket is at the base", custom.SupportSocket(), "/srv/ateom/ateom-support.sock"},
		{"an actor's directory", custom.ActorDir("a1"), "/srv/ateom/actors/a1"},
		{"checkpoint files", custom.CheckpointStateDir("a1"), "/srv/ateom/actors/a1/checkpoint-state"},
		{"restore files", custom.RestoreStateDir("a1"), "/srv/ateom/actors/a1/restore-state"},
		{"a template key is atespace/name", TemplateKey(" team-a ", "counter\n"), "team-a/counter"},
		{"a template's digest", counter.Digest(), "team-a/counter"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("got %q, want %q", tc.got, tc.want)
			}
		})
	}
}
