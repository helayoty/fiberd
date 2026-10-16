package herder

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/runtime/host"
	"github.com/helayoty/fiberd/pkg/runtime/stub"
	"github.com/helayoty/fiberd/sdk/go/client"
)

var errNoGrant = errors.New("no grant for this template")

// failingGrants hands out no grant at all.
type failingGrants struct{}

func (failingGrants) Grant(context.Context, Template, uint64) (string, core.Grant, error) {
	return "", core.Grant{}, errNoGrant
}

// badTokenGrants hands out a token fiberd cannot verify.
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
				_, err := s.RestoreWorkload(ctx, &ateompbRestore{ActorUid: "a1", ActorTemplateAtespace: "team-a", ActorTemplateName: "counter", Fidelity: fidelityMemory})
				return err
			},
			want: codes.Internal},
		{name: "a grant fiberd cannot verify keeps fiberd's code",
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
				if f := w.core.Ledger.FibersOf("g-counter"); len(f) != 0 {
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
				if err != nil || f.Kind != client.Create {
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
		return &ateompbContainer{Name: name, WakeupProbe: &ateompbWakeup{HttpGet: &ateompbHTTPGet{Path: path}, TimeoutSeconds: timeoutSeconds}}
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

// TestLifecycleFailures checks checkpoint and terminate when fiberd
// does not follow. The actor stays where atelet can act on it again.
// A checkpoint whose export fails resumes the parked session, so a later
// terminate discards it. Before, the session stayed parked, the
// terminate's release met no fiber, and the next run of the name resumed
// the old session.
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
		active bool   // the actor is still here afterwards
		routed bool   // the router still routes it
		msg    string // the error says this
		after  func(t *testing.T, w *worker)
	}{
		{name: "a checkpoint fiberd cannot park keeps the actor routed", break_: gone,
			call: func(s *Service) error {
				_, err := s.CheckpointWorkload(ctx, &ateompbCkpt{ActorUid: "a1", Fidelity: fidelityMemory})
				return err
			},
			want: codes.NotFound, active: true, routed: true},
		{name: "a parked session that cannot be exported is resumed, routed, and discarded by a terminate",
			call: func(s *Service) error {
				_, err := s.CheckpointWorkload(ctx, &ateompbCkpt{ActorUid: "a1", Fidelity: fidelityMemory})
				return err
			},
			want: codes.Internal, active: true, routed: true,
			after: func(t *testing.T, w *worker) {
				if f := w.core.Ledger.FibersOf("g-counter"); len(f) != 1 || f[0].ID != w.svc.current().fiber.ID {
					t.Fatalf("fibers under the grant = %+v, want the resumed actor's", f)
				}
				if _, err := w.svc.TerminateWorkload(ctx, &ateompbTerm{ActorUid: "a1"}); err != nil {
					t.Fatal(err)
				}
				jwt, _, _ := w.grants.Grant(ctx, counter, 16<<20)
				f, err := w.client.Clone(ctx, jwt, "a1", time.Second, nil)
				if err != nil || f.Kind != client.Create {
					t.Fatalf("clone after the terminate = %v %v, want a fresh session", f.Kind, err)
				}
			}},
		{name: "resume after a failed export fails its readiness probe",
			break_: func(_ *testing.T, w *worker) {
				w.svc.cfg.Probe = func(context.Context, string, string) error { return errors.New("connection refused") }
				w.svc.cfg.ReadyTimeout = time.Millisecond
			},
			call: func(s *Service) error {
				_, err := s.CheckpointWorkload(ctx, &ateompbCkpt{ActorUid: "a1", Fidelity: fidelityMemory})
				return err
			},
			want: codes.Internal, msg: "export parked session a1", active: true,
			after: func(t *testing.T, w *worker) {
				// The parked state is kept: the session is parked and its
				// delta still there.
				st, ref, ok := w.core.Ledger.SessionState("g-counter", "a1")
				if !ok || st != core.StateParked || !w.core.Runtime.(*stub.Runtime).HasDelta(ref) {
					t.Fatalf("session a1 = %v %q %v, want parked with its delta", st, ref, ok)
				}
				if f := w.core.Ledger.FibersOf("g-counter"); len(f) != 0 {
					t.Fatalf("fibers under the grant = %+v, want none", f)
				}
				// A later terminate discards it.
				if _, err := w.svc.TerminateWorkload(ctx, &ateompbTerm{ActorUid: "a1"}); err != nil {
					t.Fatal(err)
				}
				if _, _, _, ok := w.svc.Active(); ok {
					t.Fatal("still active after the terminate")
				}
				if w.core.Runtime.(*stub.Runtime).HasDelta(ref) {
					t.Fatal("the terminate left the parked delta")
				}
				jwt, _, _ := w.grants.Grant(ctx, counter, 16<<20)
				f, err := w.client.Clone(ctx, jwt, "a1", time.Second, nil)
				if err != nil || f.Kind != client.Create {
					t.Fatalf("clone after the terminate = %v %v, want a fresh session", f.Kind, err)
				}
			}},
		{name: "terminating a fiber already gone is done", break_: gone,
			call: func(s *Service) error { _, err := s.TerminateWorkload(ctx, &ateompbTerm{ActorUid: "a1"}); return err },
			want: codes.OK},
		{name: "a terminate fiberd does not answer keeps the actor", break_: func(_ *testing.T, w *worker) { w.stop() },
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
			if err := tc.call(w.svc); status.Code(err) != tc.want || (tc.msg != "" && !strings.Contains(err.Error(), tc.msg)) {
				t.Fatalf("code = %v (%v), want %v with %q", status.Code(err), err, tc.want, tc.msg)
			}
			if _, _, uid, ok := w.svc.Active(); ok != tc.active || (ok && uid != "a1") {
				t.Fatalf("active = %q %v, want %v", uid, ok, tc.active)
			}
			if _, ok := w.router.active["team-a/counter-a1"]; ok != tc.routed {
				t.Fatalf("routed = %v, want %v", ok, tc.routed)
			}
			if tc.after != nil {
				tc.after(t, w)
			}
		})
	}
}

// TestStats checks both stats calls against what executes here and what
// fiberd last reported for it. GetWorkloadStats answers only with a
// measured sample. GetActiveWorkloadStats lists the actor either way, and
// without a source until it is measured.
func TestStats(t *testing.T) {
	ctx := context.Background()
	at, started := time.Unix(1700000000, 42), time.Unix(1699999990, 7)
	running := func() *actor {
		return &actor{ref: [2]string{"team-a", "counter-a1"}, uid: "a1", tmpl: counter, grant: core.Grant{UID: "g-counter"}, started: started}
	}
	identity := func() *ateompbStatsSample {
		return &ateompbStatsSample{Atespace: "team-a", ActorName: "counter-a1", ActorUid: "a1",
			ActorTemplateAtespace: "team-a", ActorTemplateName: "counter", SandboxClass: "gvisor", EpochUnixNano: started.UnixNano()}
	}
	measured := identity()
	measured.Source, measured.MemoryCurrentBytes, measured.MemoryWorkingSetBytes, measured.ObservedAtUnixNano = sourceCgroup, 7, 7, at.UnixNano()
	cases := []struct {
		name     string
		active   *actor
		stats    map[string]client.Status
		sampleAt time.Time
		code     codes.Code          // GetWorkloadStats for a1
		want     *ateompbStatsSample // what GetActiveWorkloadStats lists, and GetWorkloadStats returns when measured
	}{
		{name: "nothing executes: no samples", code: codes.NotFound},
		{name: "an actor fiberd has not reported on yet is listed unmeasured", active: running(),
			code: codes.FailedPrecondition, want: identity()},
		{name: "a report for the grant but none since this actor started is not its measure", active: running(),
			stats: map[string]client.Status{"g-counter": {GrantUID: "g-counter", WUsedBytes: 7}},
			code:  codes.FailedPrecondition, want: identity()},
		{name: "a reported actor: its grant's W", active: running(), sampleAt: at,
			stats: map[string]client.Status{"g-counter": {GrantUID: "g-counter", WUsedBytes: 7}},
			want:  measured},
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
			if err == nil && !proto.Equal(one.GetSample(), tc.want) {
				t.Fatalf("GetWorkloadStats sample = %v, want %v", one.GetSample(), tc.want)
			}
			all, err := s.GetActiveWorkloadStats(ctx, &ateompbActiveReq{})
			if err != nil {
				t.Fatal(err)
			}
			var want []*ateompbStatsSample
			if tc.want != nil {
				want = []*ateompbStatsSample{tc.want}
			}
			if len(all.GetSamples()) != len(want) || (len(want) == 1 && !proto.Equal(all.GetSamples()[0], want[0])) {
				t.Fatalf("active samples = %v, want %v", all.GetSamples(), want)
			}
		})
	}
}

// fakeFibers is a fiberd whose Watch stream breaks once, then reports
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
		return status.Error(codes.Unavailable, "fiberd restarting")
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
			s := New(Config{Client: client.New(conn)})
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
		{"the default base is Substrate's node path", Paths{}.AteomDir("pod-1"), "/var/lib/ate/ateoms/pod-1"},
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

// exportFixture writes into dir the files ExportDelta would have written
// for a parked session "golden" of g's domain, signed and sealed with
// keys. The export is built by hand because the stub fiberd publishes
// nothing to a registry.
func exportFixture(t *testing.T, keys artifact.Keys, g core.Grant, dir string) {
	t.Helper()
	ctx := context.Background()
	domain, err := g.SessionDomain()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	src, sealed, pulled := filepath.Join(root, "src"), filepath.Join(root, "sealed"), filepath.Join(root, "pulled")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "pages-1.img"), []byte("pages"), 0o644); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	if err := artifact.SealDir(src, sealed, keys.Seal, artifact.SealContext{Domain: domain, Session: "golden", Fence: "g/1/1", Expires: exp}); err != nil {
		t.Fatal(err)
	}
	ref := artifact.FileScheme + filepath.Join(root, "registry", "golden") + ":golden"
	ann := map[string]string{artifact.AnnotationDomain: domain, artifact.AnnotationSession: "golden",
		artifact.AnnotationExpires: exp.Format(time.RFC3339), artifact.AnnotationSealKey: keys.Seal.ID}
	if _, err := artifact.PushDir(ctx, sealed, ref, artifact.ArtifactTypeDelta, ann, keys.Signer); err != nil {
		t.Fatal(err)
	}
	loc, _, err := artifact.Resolve(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := artifact.PullDir(ctx, ref, pulled); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := artifact.TarDir(pulled, filepath.Join(dir, host.ExportDeltaFile)); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(host.ExportInfo{Session: "golden", Domain: domain, Digest: loc.Digest, Annotations: loc.Annotations})
	if err := os.WriteFile(filepath.Join(dir, host.ExportInfoFile), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestRestoreWithdrawsImport checks what a restore leaves in the delta
// registry. A restore whose actor does not start withdraws the session
// it imported. Before, the tag stayed for up to the delta TTL (24h), and
// the next run of the name on this worker resumed it. A tag parked again
// since the import is not the import and stays, and a restore that
// starts leaves its tag to fiberd's claim.
func TestRestoreWithdrawsImport(t *testing.T) {
	ctx := context.Background()
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := artifact.Keys{Signer: &jose.JSONWebKey{Key: signer, KeyID: "worker", Algorithm: string(jose.EdDSA)},
		Seal: &artifact.SealKey{ID: "seal", Key: make([]byte, 32)}}
	notReady := func(context.Context, string, string) error { return errors.New("connection refused") }
	// parked leaves a parked session a1 in the stub fiberd, so the
	// restore's clone resumes.
	parked := func(t *testing.T, w *worker) {
		jwt, _, _ := w.grants.Grant(ctx, counter, 16<<20)
		f, err := w.client.Clone(ctx, jwt, "a1", time.Second, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.client.Park(ctx, f.ID, true); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name   string
		parked bool                                                                    // a1 is parked in fiberd before the restore
		probe  func(w *worker, ref string) func(context.Context, string, string) error // nil answers ready
		want   codes.Code
		kept   bool // the tag still resolves after the restore
		moved  bool // ... to another digest than the import's
	}{
		{name: "a clone that is not a resume withdraws the import", want: codes.Internal},
		{name: "an actor that never turns ready withdraws the import", parked: true,
			probe: func(*worker, string) func(context.Context, string, string) error { return notReady },
			want:  codes.Unavailable},
		{name: "a tag parked again since the import is left alone", parked: true,
			probe: func(w *worker, ref string) func(context.Context, string, string) error {
				return func(context.Context, string, string) error {
					// The session's tag moves on while the actor starts.
					dir := filepath.Join(w.svc.cfg.Paths.Base, "repark")
					if err := os.MkdirAll(dir, 0o755); err != nil {
						return err
					}
					if err := os.WriteFile(filepath.Join(dir, "pages-1.img"), []byte("newer pages"), 0o644); err != nil {
						return err
					}
					if _, err := artifact.PushDir(ctx, dir, ref, artifact.ArtifactTypeDelta, nil, keys.Signer); err != nil {
						return err
					}
					return errors.New("connection refused")
				}
			},
			want: codes.Unavailable, kept: true, moved: true},
		{name: "a restore that starts leaves its tag to fiberd", parked: true, want: codes.OK, kept: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorker(t, 4, func(c *Config) {
				c.Host = host.Config{DeltaRegistry: artifact.FileScheme + filepath.Join(c.Paths.Base, "registry"), DeltaKeys: keys, HomeID: "w1"}
				c.ReadyTimeout = time.Millisecond
			})
			if tc.parked {
				parked(t, w)
			}
			_, g, _ := w.grants.Grant(ctx, counter, 16<<20)
			exportFixture(t, keys, g, w.svc.cfg.Paths.RestoreStateDir("a1"))
			// The tag the restore's import publishes a1 under, learnt from
			// an import of its own, which is then taken away again.
			im, err := host.ImportDelta(ctx, w.svc.cfg.Host, g, "a1", w.svc.cfg.Paths.RestoreStateDir("a1"))
			if err != nil {
				t.Fatal(err)
			}
			ref := im.Ref
			if _, err := artifact.Delete(ctx, ref); err != nil {
				t.Fatal(err)
			}
			if tc.probe != nil {
				w.svc.cfg.Probe = tc.probe(w, ref)
			}
			req := runReq("a1")
			_, err = w.svc.RestoreWorkload(ctx, &ateompbRestore{Atespace: req.Atespace, ActorName: req.ActorName, ActorUid: "a1",
				ActorTemplateAtespace: "team-a", ActorTemplateName: "counter", MemoryBytes: req.MemoryBytes, Spec: req.Spec, Fidelity: fidelityMemory})
			if status.Code(err) != tc.want {
				t.Fatalf("code = %v (%v), want %v", status.Code(err), err, tc.want)
			}
			loc, found, err := artifact.Resolve(ctx, ref)
			if err != nil {
				t.Fatal(err)
			}
			if found != tc.kept {
				t.Fatalf("tag %s found = %v, want %v", ref, found, tc.kept)
			}
			if found && (loc.Annotations[artifact.AnnotationSession] == "a1") == tc.moved {
				t.Fatalf("tag holds %v, want moved = %v", loc.Annotations, tc.moved)
			}
		})
	}
}

// TestActorDir checks which directory a checkpoint or restore uses. A
// directory atelet names must lie under the shared base, since the
// herder writes there.
func TestActorDir(t *testing.T) {
	s := New(Config{Paths: Paths{Base: "/srv/ate"}})
	cases := []struct {
		name, named, want string
		code              codes.Code
	}{
		{name: "none named is the fallback", want: "/fallback"},
		{name: "a directory under the base", named: "/srv/ate/actors/a1/checkpoint-state", want: "/srv/ate/actors/a1/checkpoint-state"},
		{name: "a directory under the base is cleaned", named: "/srv/ate/actors/a1/./restore-state/", want: "/srv/ate/actors/a1/restore-state"},
		{name: "the base itself is refused", named: "/srv/ate", code: codes.InvalidArgument},
		{name: "a directory outside the base is refused", named: "/etc/a1", code: codes.InvalidArgument},
		{name: "a directory that climbs out is refused", named: "/srv/ate/actors/../../etc", code: codes.InvalidArgument},
		{name: "a sibling with the base as prefix is refused", named: "/srv/ateX/a1", code: codes.InvalidArgument},
		{name: "a relative directory is refused", named: "srv/ate/actors/a1", code: codes.InvalidArgument},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.actorDir(tc.named, "/fallback")
			if status.Code(err) != tc.code || got != tc.want {
				t.Fatalf("actorDir(%q) = %q %v, want %q %v", tc.named, got, err, tc.want, tc.code)
			}
		})
	}
}
