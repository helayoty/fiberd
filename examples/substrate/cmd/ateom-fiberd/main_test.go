package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"

	"github.com/helayoty/fiberd/pkg/agent"
	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/grant"

	"github.com/helayoty/fiberd/examples/substrate/capacity"
	"github.com/helayoty/fiberd/examples/substrate/herder"
	"github.com/helayoty/fiberd/examples/substrate/ingress"
	ateletpb "github.com/helayoty/fiberd/examples/substrate/proto/atelet"
	ateompb "github.com/helayoty/fiberd/examples/substrate/proto/ateom"
)

// TestMain keeps a SIGTERM aimed at a stopping agent from ending the test
// binary. While a handler is registered, Go never applies the default action.
func TestMain(m *testing.M) {
	sig := make(chan os.Signal, 16)
	signal.Notify(sig, syscall.SIGTERM)
	go func() {
		for range sig {
			// The agent under test handles its own stop.
		}
	}()
	os.Exit(m.Run())
}

func TestEnv(t *testing.T) {
	cases := []struct {
		name, value, want string
	}{
		{"set wins over the default", "set", "set"},
		{"unset is the default", "", "default"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ATEOM_FIBERD_TEST_ENV", tc.value)
			if got := env("ATEOM_FIBERD_TEST_ENV", "default"); got != tc.want {
				t.Fatalf("env = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRuntimeEnv checks which backend the image's environment selects:
// gVisor with the image's rootfs unless told otherwise, and no gVisor
// worker without its rootfs.
func TestRuntimeEnv(t *testing.T) {
	rootfs := t.TempDir()
	type runtime struct{ name, rootfs, runsc, criu string }
	cases := []struct {
		name string
		env  map[string]string
		want runtime
		err  string
	}{
		{name: "gvisor on a rootfs with runsc from PATH", env: map[string]string{"ATEOM_FIBERD_GVISOR_ROOTFS": rootfs},
			want: runtime{"gvisor", rootfs, "runsc", "criu"}},
		{name: "another runsc", env: map[string]string{"ATEOM_FIBERD_GVISOR_ROOTFS": rootfs, "ATEOM_FIBERD_RUNSC": "/opt/runsc"},
			want: runtime{"gvisor", rootfs, "/opt/runsc", "criu"}},
		{name: "the image's default rootfs path", env: map[string]string{"ATEOM_FIBERD_RUNTIME": "stub"},
			want: runtime{"stub", "/var/lib/fiberd/gvisor-rootfs", "runsc", "criu"}},
		{name: "proc with its own criu, for tests of the mechanism", env: map[string]string{"ATEOM_FIBERD_RUNTIME": "proc", "ATEOM_FIBERD_CRIU": "/opt/criu"},
			want: runtime{"proc", "/var/lib/fiberd/gvisor-rootfs", "runsc", "/opt/criu"}},
		{name: "gvisor without its rootfs refuses", env: map[string]string{"ATEOM_FIBERD_GVISOR_ROOTFS": "/nonexistent/rootfs"},
			err: "ATEOM_FIBERD_GVISOR_ROOTFS: /nonexistent/rootfs is not a directory"},
		{name: "gvisor with a file for a rootfs refuses", env: map[string]string{"ATEOM_FIBERD_GVISOR_ROOTFS": "/dev/null"},
			err: "ATEOM_FIBERD_GVISOR_ROOTFS: /dev/null is not a directory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{"ATEOM_FIBERD_RUNTIME", "ATEOM_FIBERD_GVISOR_ROOTFS", "ATEOM_FIBERD_RUNSC", "ATEOM_FIBERD_CRIU"} {
				t.Setenv(k, tc.env[k])
			}
			var c agent.Config
			c.Bind(flag.NewFlagSet("fiberd", flag.ContinueOnError))
			err := runtimeEnv(&c)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("runtimeEnv = %v, want an error with %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := runtime{c.RuntimeName, c.GvisorRootfs, c.Runsc, c.CRIUBin}
			if got != tc.want {
				t.Fatalf("runtime config = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestParseArgs checks that the exact arguments Substrate gives a worker
// container are accepted, and that the pod uid is required.
func TestParseArgs(t *testing.T) {
	substrate := []string{"-pod-uid", "p-1", "-atunnel-listen-address", ":9443", "-atunnel-connect-listen-address", ":8443",
		"-atunnel-credential-bundle", "/var/run/cred.pem", "-atunnel-trust-bundle", "/var/run/trust.pem",
		"-atunnel-egress-listen-address", ":15001", "-atunnel-egress-trust-bundle", "/var/run/egress.pem",
		"-atunnel-client-identity", "spiffe://c/ns/x/sa/router", "-readiness-listen-address", ":8081",
		"-base-path", "/var/lib/ateom-x", "-otlp-relay-socket", "/run/otlp.sock", "-log-level", "debug", "-version"}
	cases := []struct {
		name   string
		podEnv string
		args   []string
		want   options
		err    string
	}{
		{name: "Substrate's worker arguments", args: substrate, want: options{podUID: "p-1", listen: ":9443",
			credBundle: "/var/run/cred.pem", trustBundle: "/var/run/trust.pem", clientID: "spiffe://c/ns/x/sa/router",
			readyAddr: ":8081", paths: herder.Paths{Base: "/var/lib/ateom-x"}}},
		{name: "the defaults, with the pod uid from POD_UID", podEnv: "p-2", want: options{podUID: "p-2", listen: ":443",
			clientID: ingress.DefaultAllowedClientID, readyAddr: "0.0.0.0:8080", paths: herder.Paths{Base: herder.DefaultBase}}},
		{name: "no pod uid", err: "-pod-uid (or POD_UID) is required"},
		{name: "an unknown flag", args: []string{"-pod-uid", "p", "-no-such-flag"}, err: "no-such-flag"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("POD_UID", tc.podEnv)
			fs := flag.NewFlagSet("ateom-fiberd", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			got, err := parseArgs(fs, tc.args)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("parseArgs = %v, want an error with %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("options = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestReadyz checks the kubelet's readiness answer. A warming template
// and an unhealthy agent are both 503, so a poisoned audit spool keeps
// actors off this worker. Only a warm, healthy worker is 200.
func TestReadyz(t *testing.T) {
	poisoned := errors.New(`healthz: 503 Service Unavailable: {"audit":"poisoned"}`)
	cases := []struct {
		name    string
		ready   bool
		healthz error
		status  int
		body    string
	}{
		{name: "warm and healthy is ok", ready: true, status: http.StatusOK, body: "ok"},
		{name: "a warming template is 503", ready: false, status: http.StatusServiceUnavailable, body: "warming"},
		{name: "a poisoned spool is 503 with the agent's answer", ready: true, healthz: poisoned,
			status: http.StatusServiceUnavailable, body: poisoned.Error()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			readyz(func() bool { return tc.ready }, func(context.Context) error { return tc.healthz })(rec, httptest.NewRequest("GET", "/readyz", nil))
			if body := strings.TrimSpace(rec.Body.String()); rec.Code != tc.status || body != tc.body {
				t.Fatalf("readyz = %d %q, want %d %q", rec.Code, body, tc.status, tc.body)
			}
		})
	}
}

// TestWaitTCP checks that the wait for the agent's port ends when the port
// accepts, when the agent fails or exits, when the caller gives up, or at
// the timeout.
func TestWaitTCP(t *testing.T) {
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = up.Close() })
	down, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	downAddr := down.Addr().String()
	_ = down.Close()
	errBoom := errors.New("agent: boom")
	cases := []struct {
		name      string
		addr      string
		agentErr  error
		agentDone bool // the agent returned (with agentErr)
		cancelled bool
		err       string
		is        error
	}{
		{name: "the port accepts", addr: up.Addr().String()},
		{name: "the agent failed", addr: downAddr, agentDone: true, agentErr: errBoom, err: "boom", is: errBoom},
		{name: "the agent exited without an error", addr: downAddr, agentDone: true, err: "agent exited"},
		{name: "the caller gave up", addr: downAddr, cancelled: true, err: "canceled", is: context.Canceled},
		{name: "nothing listens before the timeout", addr: downAddr, err: "not accepting after 1ms"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agentErr := make(chan error, 1)
			if tc.agentDone {
				agentErr <- tc.agentErr
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancelled {
				cancel()
			}
			err := waitTCP(ctx, tc.addr, time.Millisecond, agentErr)
			if tc.err == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("waitTCP = %v, want an error with %q", err, tc.err)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("waitTCP = %v, want it to wrap %v", err, tc.is)
			}
		})
	}
}

// freePort is a loopback address nothing listens on, for the servers run
// starts on fixed addresses.
func freePort(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().String()
}

// shortDir is a temporary directory with a short path, for unix sockets.
func shortDir(t *testing.T) string {
	d, err := os.MkdirTemp("/tmp", "af")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// sharedKeys writes a delta signing key and a seal key, as the deploy
// mounts them, and returns their paths.
func sharedKeys(t *testing.T) (key, seal string) {
	d := t.TempDir()
	key, seal = filepath.Join(d, "delta-key.json"), filepath.Join(d, "delta-seal-key.json")
	k, err := grant.GenerateKey(jose.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := artifact.GenerateSealKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := grant.SaveKey(key, k); err != nil {
		t.Fatal(err)
	}
	if err := grant.SaveKey(seal, sk); err != nil {
		t.Fatal(err)
	}
	return key, seal
}

// worker is the environment one run gets. That is fiberd on the stub
// runtime, under a temp state dir and a fake cgroup root, with the pool's
// shared delta keys.
type worker struct {
	agent, ready, ingress string
	base                  string
}

func newWorker(t *testing.T) worker {
	w := worker{agent: freePort(t), ready: freePort(t), ingress: freePort(t), base: shortDir(t)}
	t.Setenv("ATEOM_FIBERD_STATE", filepath.Join(shortDir(t), "state"))
	t.Setenv("ATEOM_FIBERD_LISTEN", w.agent)
	t.Setenv("ATEOM_FIBERD_RUNTIME", "stub")
	t.Setenv("ATEOM_FIBERD_ISOLATION", "TRUSTED")
	t.Setenv("ATEOM_FIBERD_CGROUP_ROOT", t.TempDir())
	t.Setenv("ATEOM_FIBERD_TEMPLATE", "default=/bin/zygote --http; ;")
	t.Setenv("ATEOM_FIBERD_RUN_DIR", t.TempDir())
	key, seal := sharedKeys(t)
	t.Setenv("ATEOM_FIBERD_DELTA_KEY", key)
	t.Setenv("ATEOM_FIBERD_DELTA_SEAL_KEY", seal)
	t.Setenv("ATEOM_FIBERD_DELTA_TRUST", "")
	return w
}

// stopAgent stops, with SIGTERM, an agent a failed run left behind, and
// waits until its port closes.
func stopAgent(t *testing.T, addr string) {
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			return
		}
		_ = c.Close()
		if time.Now().After(deadline) {
			t.Fatal("the agent kept running after SIGTERM")
		}
	}
}

// TestRunRefuses checks what stops a worker, before and after its agent
// is up.
func TestRunRefuses(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		podUID  string
		cred    string
		base    func(t *testing.T, w worker) string
		err     string
		agentUp bool // the agent came up before the failure
	}{
		{name: "a template entry that is not digest=command", env: map[string]string{"ATEOM_FIBERD_TEMPLATE": "default=/bin/z;oops"},
			err: "ATEOM_FIBERD_TEMPLATE"},
		{name: "an isolation that does not exist", env: map[string]string{"ATEOM_FIBERD_ISOLATION": "SOMEWHAT"},
			err: "ATEOM_FIBERD_ISOLATION"},
		{name: "no pod uid: the home has no audience", podUID: "-", err: "audience and issuer URL are required"},
		{name: "no delta key: a worker never makes its own", env: map[string]string{"ATEOM_FIBERD_DELTA_KEY": ""},
			err: "ATEOM_FIBERD_DELTA_KEY is required"},
		{name: "no seal key: a worker never makes its own", env: map[string]string{"ATEOM_FIBERD_DELTA_SEAL_KEY": ""},
			err: "ATEOM_FIBERD_DELTA_SEAL_KEY is required"},
		{name: "a delta key that is not mounted", env: map[string]string{"ATEOM_FIBERD_DELTA_KEY": "/nonexistent/key.json"},
			err: "ATEOM_FIBERD_DELTA_KEY: stat /nonexistent/key.json"},
		{name: "a seal key that is not mounted", env: map[string]string{"ATEOM_FIBERD_DELTA_SEAL_KEY": "/nonexistent/seal.json"},
			err: "ATEOM_FIBERD_DELTA_SEAL_KEY: stat /nonexistent/seal.json"},
		{name: "a delta key that is not a key", env: map[string]string{"ATEOM_FIBERD_DELTA_KEY": "/dev/null"},
			err: "-delta-key"},
		{name: "an agent that cannot start", env: map[string]string{"ATEOM_FIBERD_RUNTIME": "warp"},
			err: "agent did not come up"},
		{name: "gvisor without its rootfs", env: map[string]string{"ATEOM_FIBERD_RUNTIME": "gvisor", "ATEOM_FIBERD_GVISOR_ROOTFS": "/nonexistent/rootfs"},
			err: "ATEOM_FIBERD_GVISOR_ROOTFS: /nonexistent/rootfs is not a directory"},
		{name: "an ingress credential bundle that cannot be read", cred: "/nonexistent/cred.pem",
			err: "ingress: credential bundle", agentUp: true},
		{name: "a base path that cannot hold the worker's directory", base: func(t *testing.T, _ worker) string {
			f := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(f, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return f
		}, err: "not a directory", agentUp: true},
		{name: "a socket path that cannot be listened on", base: func(t *testing.T, w worker) string {
			// A non-empty directory where the socket goes cannot be removed.
			sock := herder.Paths{Base: w.base}.SocketPath("p-1")
			if err := os.MkdirAll(filepath.Join(sock, "keep"), 0o700); err != nil {
				t.Fatal(err)
			}
			return w.base
		}, err: "address already in use", agentUp: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorker(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			pod := "p-1"
			if tc.podUID == "-" {
				pod = ""
			}
			base := w.base
			if tc.base != nil {
				base = tc.base(t, w)
			}
			err := run(pod, w.ingress, tc.cred, "", ingress.DefaultAllowedClientID, w.ready, herder.Paths{Base: base})
			if tc.agentUp {
				stopAgent(t, w.agent)
			}
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("run = %v, want an error with %q", err, tc.err)
			}
		})
	}
}

// logTail collects the standard logger's output while a test runs.
type logTail struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logTail) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logTail) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func httpGet(t *testing.T, url, actor string) (int, string) {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if actor != "" {
		req.Header.Set(ingress.TargetActorHeader, actor)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b))
}

// fakeAtelet is atelet's AteomSupport service on the node's socket. It
// records the capacity the worker reports.
type fakeAtelet struct {
	ateletpb.UnimplementedAteomSupportServer
	got chan *ateletpb.WorkerResources
}

func (a *fakeAtelet) SetWorkerCapacity(_ context.Context, req *ateletpb.SetWorkerCapacityRequest) (*ateletpb.SetWorkerCapacityResponse, error) {
	a.got <- req.GetCapacity()
	return &ateletpb.SetWorkerCapacityResponse{}, nil
}

func serveAtelet(t *testing.T, paths herder.Paths) *fakeAtelet {
	l, err := net.Listen("unix", paths.SupportSocket())
	if err != nil {
		t.Fatal(err)
	}
	a := &fakeAtelet{got: make(chan *ateletpb.WorkerResources, 4)}
	gs := grpc.NewServer()
	ateletpb.RegisterAteomSupportServer(gs, a)
	go func() { _ = gs.Serve(l) }()
	t.Cleanup(gs.Stop)
	return a
}

// TestRunServesAWorker runs a whole worker as Substrate starts it and
// drives it as atelet, the kubelet and the router do, then stops it with
// SIGTERM. Steps run in order on the one worker.
func TestRunServesAWorker(t *testing.T) {
	logs := &logTail{}
	log.SetOutput(logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	w := newWorker(t)
	limits := t.TempDir()
	for name, v := range map[string]string{capacity.CPUFile: "1000", capacity.MemoryFile: "1073741824"} {
		if err := os.WriteFile(filepath.Join(limits, name), []byte(v+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("ATEOM_FIBERD_CAPACITY_DIR", limits)
	support := serveAtelet(t, herder.Paths{Base: w.base})
	done := make(chan error, 1)
	go func() {
		done <- run("p-1", w.ingress, "", "", ingress.DefaultAllowedClientID, w.ready, herder.Paths{Base: w.base})
	}()
	sock := herder.Paths{Base: w.base}.SocketPath("p-1")
	for deadline := time.Now().Add(30 * time.Second); !strings.Contains(logs.String(), "serving atelet at "+sock); time.Sleep(20 * time.Millisecond) {
		select {
		case err := <-done:
			t.Fatalf("run returned before serving: %v\n%s", err, logs)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("the worker never served atelet\n%s", logs)
		}
	}
	// Empty template entries are skipped.
	if !strings.Contains(logs.String(), "templates map[default:/bin/zygote --http]") {
		t.Fatalf("templates not as configured\n%s", logs)
	}
	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	atelet := ateompb.NewAteomClient(conn)
	ctx := context.Background()
	readyz := "http://" + w.ready + "/readyz"

	steps := []struct {
		name string
		do   func(t *testing.T)
	}{
		{"the worker reports what it can host to atelet", func(t *testing.T) {
			// Without this report Substrate places no actor here.
			want := &ateletpb.WorkerResources{Actors: 1, Resources: &ateletpb.Resources{Limits: []*ateletpb.Limits{
				{Name: "cpu", Quantity: "1000m"}, {Name: "memory", Quantity: "1073741824"}}}}
			select {
			case got := <-support.got:
				if !proto.Equal(got, want) {
					t.Fatalf("capacity = %v, want %v", got, want)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("the worker never reported its capacity\n%s", logs)
			}
		}},
		{"a fresh worker has no actor", func(t *testing.T) {
			resp, err := atelet.GetActiveWorkloadStats(ctx, &ateompb.GetActiveWorkloadStatsRequest{})
			if err != nil || resp.GetNoSampleReason() != ateompb.NoSampleReason_NO_SAMPLE_REASON_NO_WORKLOAD {
				t.Fatalf("active stats = %v, %v, want no workload", resp, err)
			}
		}},
		{"a fresh worker is ready: nothing to warm", func(t *testing.T) {
			if st, body := httpGet(t, readyz, ""); st != http.StatusOK || body != "ok" {
				t.Fatalf("readyz = %d %q", st, body)
			}
		}},
		{"the router reaches no actor yet", func(t *testing.T) {
			if st, _ := httpGet(t, "http://"+w.ingress+"/", "team-a/counter-a1"); st != http.StatusMisdirectedRequest {
				t.Fatalf("ingress = %d, want 421", st)
			}
		}},
		{"atelet runs an actor", func(t *testing.T) {
			_, err := atelet.RunWorkload(ctx, &ateompb.RunWorkloadRequest{Atespace: "team-a", ActorName: "counter-a1", ActorUid: "a1",
				ActorTemplateAtespace: "team-a", ActorTemplateName: "counter", MemoryBytes: 16 << 20})
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"the router reaches the actor's fiber", func(t *testing.T) {
			// The stub runtime's fibers serve nothing, so a routed request
			// is a bad gateway, not a misdirection.
			if st, _ := httpGet(t, "http://"+w.ingress+"/", "team-a/counter-a1"); st != http.StatusBadGateway {
				t.Fatalf("ingress = %d, want 502 from the routed fiber", st)
			}
		}},
		{"readyz follows the template warming", func(t *testing.T) {
			for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
				st, body := httpGet(t, readyz, "")
				if st == http.StatusOK {
					return
				}
				if st != http.StatusServiceUnavailable || body != "warming" || time.Now().After(deadline) {
					t.Fatalf("readyz = %d %q", st, body)
				}
			}
		}},
		{"SIGTERM drains and stops the worker cleanly", func(t *testing.T) {
			if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("run = %v, want nil on SIGTERM", err)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("the worker kept running after SIGTERM")
			}
			if _, err := os.Stat(sock); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("atelet's socket left behind: %v", err)
			}
		}},
	}
	for _, step := range steps {
		if !t.Run(step.name, step.do) {
			t.FailNow()
		}
	}
}

// TestRunLogsListenFailures checks that an ingress or readiness address
// that cannot be listened on is logged, and the worker serves atelet
// anyway.
func TestRunLogsListenFailures(t *testing.T) {
	cases := []struct {
		name    string
		ingress string // "" is a free address
		taken   bool   // the readiness address is already in use
		logged  string
	}{
		{name: "an ingress address that does not exist", ingress: "256.0.0.1:1", logged: "ingress: not listening on 256.0.0.1:1"},
		{name: "a readiness address already in use", taken: true, logged: "readyz: listen tcp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := &logTail{}
			log.SetOutput(logs)
			t.Cleanup(func() { log.SetOutput(os.Stderr) })
			w := newWorker(t)
			listen := w.ingress
			if tc.ingress != "" {
				listen = tc.ingress
			}
			if tc.taken {
				l, err := net.Listen("tcp", w.ready)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = l.Close() })
			}
			done := make(chan error, 1)
			go func() {
				done <- run("p-1", listen, "", "", ingress.DefaultAllowedClientID, w.ready, herder.Paths{Base: w.base})
			}()
			for deadline := time.Now().Add(30 * time.Second); !strings.Contains(logs.String(), "serving atelet") || !strings.Contains(logs.String(), tc.logged); time.Sleep(20 * time.Millisecond) {
				if time.Now().After(deadline) {
					t.Fatalf("want the worker serving atelet and %q logged\n%s", tc.logged, logs)
				}
			}
			if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("run = %v, want nil on SIGTERM", err)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("the worker kept running after SIGTERM")
			}
		})
	}
}

// TestMainExit runs main in a child process and checks its exit status.
// It is 0 for -h, 2 for a bad command line and 1 for any other failure.
func TestMainExit(t *testing.T) {
	if args, ok := os.LookupEnv("ATEOM_FIBERD_TEST_ARGS"); ok {
		os.Args = append([]string{"ateom-fiberd"}, strings.Fields(args)...)
		main()
		os.Exit(0)
	}
	cases := []struct {
		name   string
		args   string
		env    []string
		code   int
		stderr string
	}{
		{name: "-h exits 0", args: "-h", code: 0, stderr: "-pod-uid"},
		{name: "a bad flag exits 2", args: "-nope", code: 2, stderr: "flag provided but not defined: -nope"},
		{name: "no pod uid exits 1", env: []string{"POD_UID="}, code: 1, stderr: "-pod-uid (or POD_UID) is required"},
		{name: "a run that fails exits 1", args: "-pod-uid p-1", env: []string{"ATEOM_FIBERD_ISOLATION=SOMEWHAT"}, code: 1,
			stderr: "ateom-fiberd: ATEOM_FIBERD_ISOLATION"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestMainExit$")
			cmd.Env = append(append(os.Environ(), "ATEOM_FIBERD_TEST_ARGS="+tc.args), tc.env...)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			err := cmd.Run()
			code := 0
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				code = exit.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != tc.code || !strings.Contains(stderr.String(), tc.stderr) {
				t.Fatalf("exit %d with %q, want %d with %q", code, stderr.String(), tc.code, tc.stderr)
			}
		})
	}
}
