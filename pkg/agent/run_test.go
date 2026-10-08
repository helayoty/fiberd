package agent_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/agent"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/home"
	"github.com/helayoty/fiberd/pkg/tlsconf"
	"github.com/helayoty/fiberd/pkg/tlsconf/tlsconftest"
)

const nodeID = "node-a"

// stateDir is a fresh -state directory. It is short, since the admin
// socket lives under it and macOS caps a socket path at 104 bytes.
func stateDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "fz")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// newConfig parses args the way a binary does, after a base that starts
// a plaintext stub agent on loopback ":0" ports. Later flags win.
func newConfig(t *testing.T, state string, args ...string) *agent.Config {
	t.Helper()
	fs := flag.NewFlagSet("fiberd", flag.ContinueOnError)
	var c agent.Config
	c.Bind(fs)
	base := []string{"-state", state, "-listen", "127.0.0.1:0", "-insecure-plaintext", "-verifier", "insecure-json",
		"-node-id", nodeID, "-runtime", "stub", "-status-interval", "10ms", "-pressure-interval", "10ms"}
	if err := fs.Parse(append(base, args...)); err != nil {
		t.Fatal(err)
	}
	c.Finish()
	return &c
}

// running is one Run in the background.
type running struct {
	c                   *agent.Config
	grpc, http, handoff net.Addr
	cancel              context.CancelFunc
	done                chan error
	stopped             bool
}

// start runs the agent and waits until every listener is bound. It fails
// the test when Run returns first.
func start(t *testing.T, c *agent.Config, newHome agent.HomeFactory) *running {
	t.Helper()
	r, err := launch(t, context.Background(), c, newHome)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return r
}

// launch runs the agent and returns once it is ready, or Run's error when
// it returns before that.
func launch(t *testing.T, ctx context.Context, c *agent.Config, newHome agent.HomeFactory) (*running, error) {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	r := &running{c: c, cancel: cancel, done: make(chan error, 1)}
	ready := make(chan struct{})
	agent.SetReady(c, func(g, h, ho net.Addr) {
		r.grpc, r.http, r.handoff = g, h, ho
		close(ready)
	})
	go func() { r.done <- agent.RunContext(ctx, c, newHome) }()
	select {
	case <-ready:
		t.Cleanup(func() {
			if !r.stopped {
				_ = r.stop(t)
			}
		})
		return r, nil
	case err := <-r.done:
		cancel()
		return nil, err
	case <-time.After(20 * time.Second):
		cancel()
		t.Fatal("Run neither became ready nor returned")
		return nil, nil
	}
}

// stop cancels Run and returns what it returned.
func (r *running) stop(t *testing.T) error {
	t.Helper()
	r.stopped = true
	r.cancel()
	select {
	case err := <-r.done:
		return err
	case <-time.After(20 * time.Second):
		t.Fatal("Run did not return after its context ended")
		return nil
	}
}

// noRunGoroutines waits until every goroutine RunContext started has
// returned, and fails when one outlives the deadline.
func noRunGoroutines(t *testing.T) {
	t.Helper()
	const mark = "created by github.com/helayoty/fiberd/pkg/agent.RunContext"
	deadline := time.Now().Add(10 * time.Second)
	for {
		buf := make([]byte, 8<<20)
		buf = buf[:runtime.Stack(buf, true)]
		if !bytes.Contains(buf, []byte(mark)) {
			return
		}
		if time.Now().After(deadline) {
			var leaked []string
			for _, g := range strings.Split(string(buf), "\n\n") {
				if strings.Contains(g, mark) {
					leaked = append(leaked, g)
				}
			}
			t.Fatalf("goroutines Run started outlived it:\n%s", strings.Join(leaked, "\n\n"))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// adminGet calls the admin socket.
func adminDo(t *testing.T, c *agent.Config, method, path, body string) (int, map[string]any) {
	t.Helper()
	cl := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", c.AdminSocket())
		},
	}}
	req, err := http.NewRequest(method, "http://admin"+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatalf("admin %s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// epochOf is the epoch the admin socket reports.
func epochOf(t *testing.T, c *agent.Config) uint64 {
	t.Helper()
	code, h := adminDo(t, c, http.MethodGet, "/healthz", "")
	if code != http.StatusOK {
		t.Fatalf("admin healthz: %d", code)
	}
	e, ok := h["epoch"].(float64)
	if !ok {
		t.Fatalf("admin healthz has no epoch: %v", h)
	}
	return uint64(e)
}

// jsonGrant is g as an insecure-json token.
func jsonGrant(t *testing.T, g core.Grant) string {
	t.Helper()
	b, err := protojson.Marshal(grant.ToProto(g))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func testGrant(uid string) core.Grant {
	return core.Grant{UID: uid, Audience: nodeID, FiberMax: 2, MinTier: core.TierBasic,
		LeaseExpiry: time.Now().Add(10 * time.Minute)}
}

// dial is a Fibers client for the agent's gRPC address.
func dial(t *testing.T, addr net.Addr, tc *tls.Config) grantv1.FibersClient {
	t.Helper()
	creds := insecure.NewCredentials()
	if tc != nil {
		creds = credentials.NewTLS(tc)
	}
	conn, err := grpc.NewClient(addr.String(), grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return grantv1.NewFibersClient(conn)
}

// getJSON fetches url and decodes its JSON body into out.
func getJSON(t *testing.T, cl *http.Client, url string, out any) int {
	t.Helper()
	resp, err := cl.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("GET %s: decode: %v", url, err)
	}
	return resp.StatusCode
}

// statusUIDs polls the gateway's status until it lists want, and returns
// the grant UIDs it lists.
func waitStatus(t *testing.T, cl *http.Client, base, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var sts []map[string]any
		if code := getJSON(t, cl, base+"/v1/status", &sts); code != http.StatusOK {
			t.Fatalf("status: %d", code)
		}
		for _, st := range sts {
			if st["grantUid"] == want {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("status never listed %s: %v", want, sts)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// mode is the permission bits of path, failing the test when it is
// missing.
func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// Homes that implement Run's optional interfaces. Embedding home.Home
// promotes only the interface's methods.
type (
	hostedHome struct {
		home.Home
		host, advertised string
	}
	scopedHome struct {
		home.Home
		lost chan func(context.Context, string)
	}
)

func (h hostedHome) EndpointHost() string       { return h.host }
func (h hostedHome) AdvertisedEndpoint() string { return h.advertised }
func (h scopedHome) OnScopeLost(f func(context.Context, string)) {
	h.lost <- f
}

func hosted(host, advertised string) agent.HomeFactory {
	return func(c *agent.Config, jwks *grant.Cache) (home.Home, error) {
		h, err := agent.Standalone(c, jwks)
		return hostedHome{Home: h, host: host, advertised: advertised}, err
	}
}

// fixture is what a case's setup made, such as more flags and what a
// caller needs to reach the agent.
type fixture struct {
	args   []string
	state  string
	client *tls.Config // the caller's mutual TLS, nil for plaintext
	thumb  string      // the caller certificate's thumbprint
	issuer *grant.Issuer
	cwd    string
}

// newIssuer is a signing issuer served over HTTP for -verifier=jwks.
func newIssuer(t *testing.T) *grant.Issuer {
	t.Helper()
	key, err := grant.GenerateKey(jose.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	is := &grant.Issuer{Key: key}
	srv := httptest.NewServer(is.Handler())
	t.Cleanup(srv.Close)
	is.URL = srv.URL
	return is
}

func mint(t *testing.T, is *grant.Issuer, g core.Grant) string {
	t.Helper()
	tok, err := is.Mint(g)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestRunServes starts the agent in-process the way cmd/fiberd does and
// talks to it over its real listeners, which are gRPC, the JSON gateway
// and the admin socket. Each case ends with a clean stop. Run returns nil,
// the admin socket is gone and nothing Run started is left running.
func TestRunServes(t *testing.T) {
	cases := []struct {
		name string
		args []string
		home agent.HomeFactory
		// setup prepares the state directory and returns more flags.
		setup func(t *testing.T, state string) fixture
		check func(t *testing.T, r *running, f fixture)
	}{
		{
			name: "plaintext clone, status over the gateway, state files private",
			args: []string{"-http", "127.0.0.1:0"},
			check: func(t *testing.T, r *running, f fixture) {
				ctx := context.Background()
				resp, err := dial(t, r.grpc, nil).Clone(ctx, &grantv1.CloneRequest{GrantJwt: jsonGrant(t, testGrant("g1")), Session: "s1"})
				if err != nil {
					t.Fatalf("Clone: %v", err)
				}
				if resp.GetFiberId() == "" || resp.GetFence().GetGrantUid() != "g1" {
					t.Fatalf("Clone = %v, want a fiber of g1", resp)
				}
				base := "http://" + r.http.String()
				waitStatus(t, http.DefaultClient, base, "g1")
				var hz map[string]any
				if code := getJSON(t, http.DefaultClient, base+"/healthz", &hz); code != http.StatusOK || hz["tier"] != "FIBER_CHECKPOINT" {
					t.Fatalf("gateway healthz = %d %v, want 200 with the stub's tier", code, hz)
				}
				// The epoch the agent serves under is the one on disk.
				priv := filepath.Join(f.state, "private")
				b, err := os.ReadFile(filepath.Join(priv, "epoch"))
				if err != nil {
					t.Fatal(err)
				}
				if got := strconv.FormatUint(epochOf(t, r.c), 10); string(b) != got {
					t.Fatalf("epoch file %q, admin says %s", b, got)
				}
				for path, want := range map[string]os.FileMode{
					priv: 0o700, filepath.Join(priv, "epoch"): 0o600,
					filepath.Join(priv, "audit-key.json"): 0o600, filepath.Join(priv, "audit.jsonl"): 0o600,
				} {
					if got := mode(t, path); got != want {
						t.Errorf("%s mode = %v, want %v", path, got, want)
					}
				}
			},
		},
		{
			name: "mutual TLS binds the grant to the caller's certificate",
			setup: func(t *testing.T, _ string) fixture {
				dir := t.TempDir()
				ca := tlsconftest.NewCA(t, "ca")
				caFile, _ := ca.Write(t, dir, "ca")
				cert, key := ca.Server(t).Write(t, dir, "server")
				ccert, ckey := ca.Client(t, "caller").Write(t, dir, "client")
				tc, err := tlsconf.Client(caFile, ccert, ckey)
				if err != nil {
					t.Fatal(err)
				}
				thumb, err := tlsconf.ThumbprintFile(ccert)
				if err != nil {
					t.Fatal(err)
				}
				is := newIssuer(t)
				return fixture{client: tc, thumb: thumb, issuer: is, args: []string{"-insecure-plaintext=false",
					"-tls-cert", cert, "-tls-key", key, "-client-ca", caFile, "-http", "127.0.0.1:0",
					"-verifier", "jwks", "-issuer", is.URL}}
			},
			check: func(t *testing.T, r *running, f fixture) {
				ctx := context.Background()
				g := testGrant("bound")
				// Over TLS the agent requires bound grants.
				_, err := dial(t, r.grpc, f.client).Clone(ctx, &grantv1.CloneRequest{GrantJwt: mint(t, f.issuer, g)})
				if status.Code(err) != codes.Unauthenticated {
					t.Fatalf("an unbound grant over TLS: %v, want Unauthenticated", err)
				}
				g.CallerThumbprint = f.thumb
				bound := mint(t, f.issuer, g)
				if _, err := dial(t, r.grpc, f.client).Clone(ctx, &grantv1.CloneRequest{GrantJwt: bound}); err != nil {
					t.Fatalf("Clone with a bound grant: %v", err)
				}
				// A plaintext caller gets no answer.
				pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				if _, err := dial(t, r.grpc, nil).Clone(pctx, &grantv1.CloneRequest{GrantJwt: bound}); err == nil {
					t.Fatal("a plaintext caller was served")
				}
				cl := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: f.client}}
				waitStatus(t, cl, "https://"+r.http.String(), "bound")
			},
		},
		{
			name: "jwks verifier admits a grant the issuer signed and nothing else",
			setup: func(t *testing.T, _ string) fixture {
				is := newIssuer(t)
				tok := mint(t, is, testGrant("signed"))
				// The token rides in -grants-dir. The home pre-admits it
				// through the verifier.
				gd := t.TempDir()
				if err := os.WriteFile(filepath.Join(gd, "signed.jwt"), []byte(tok), 0o600); err != nil {
					t.Fatal(err)
				}
				return fixture{args: []string{"-verifier", "jwks", "-issuer", is.URL, "-grants-dir", gd, "-http", "127.0.0.1:0"}}
			},
			check: func(t *testing.T, r *running, _ fixture) {
				waitStatus(t, http.DefaultClient, "http://"+r.http.String(), "signed")
				_, err := dial(t, r.grpc, nil).Clone(context.Background(),
					&grantv1.CloneRequest{GrantJwt: jsonGrant(t, testGrant("forged"))})
				if status.Code(err) != codes.Unauthenticated {
					t.Fatalf("an unsigned grant: %v, want Unauthenticated", err)
				}
			},
		},
		{
			name: "a relative -state is made absolute",
			setup: func(t *testing.T, state string) fixture {
				t.Chdir(state)
				cwd, err := os.Getwd()
				if err != nil {
					t.Fatal(err)
				}
				return fixture{cwd: cwd, args: []string{"-state", "rel"}}
			},
			check: func(t *testing.T, r *running, f fixture) {
				if want := filepath.Join(f.cwd, "rel"); r.c.StateDir != want {
					t.Fatalf("StateDir = %s, want %s", r.c.StateDir, want)
				}
				if got := mode(t, filepath.Join(f.cwd, "rel", "private")); got != 0o700 {
					t.Fatalf("private dir mode %v, want 0700", got)
				}
			},
		},
		{
			name: "the home fills the endpoint host and the advertised address",
			args: []string{"-endpoint-family", "inet4"},
			home: hosted("10.1.2.3", "home.example:8484"),
			check: func(t *testing.T, r *running, _ fixture) {
				if r.c.EndpointHost != "10.1.2.3" || r.c.Advertise != "home.example:8484" {
					t.Fatalf("endpoint host %q advertise %q, want the home's", r.c.EndpointHost, r.c.Advertise)
				}
			},
		},
		{
			name: "an explicit endpoint host and advertise address win over the home",
			args: []string{"-endpoint-family", "inet4", "-endpoint-host", "10.9.9.9", "-advertise", "mine:1"},
			home: hosted("10.1.2.3", "home.example:8484"),
			check: func(t *testing.T, r *running, _ fixture) {
				if r.c.EndpointHost != "10.9.9.9" || r.c.Advertise != "mine:1" {
					t.Fatalf("endpoint host %q advertise %q, want the flags'", r.c.EndpointHost, r.c.Advertise)
				}
			},
		},
		{
			name: "no pressure ladder still serves",
			args: []string{"-pressure-interval", "0"},
			check: func(t *testing.T, r *running, _ fixture) {
				if _, err := dial(t, r.grpc, nil).Clone(context.Background(),
					&grantv1.CloneRequest{GrantJwt: jsonGrant(t, testGrant("g2"))}); err != nil {
					t.Fatalf("Clone: %v", err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := stateDir(t)
			var f fixture
			if tc.setup != nil {
				f = tc.setup(t, state)
			}
			f.state = state
			nh := tc.home
			if nh == nil {
				nh = agent.Standalone
			}
			r := start(t, newConfig(t, state, append(append([]string{}, tc.args...), f.args...)...), nh)
			if _, err := os.Stat(r.c.AdminSocket()); err != nil {
				t.Fatalf("admin socket: %v", err)
			}
			tc.check(t, r, f)
			if err := r.stop(t); err != nil {
				t.Fatalf("Run after cancel = %v, want nil", err)
			}
			if _, err := os.Stat(r.c.AdminSocket()); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("admin socket left behind: %v", err)
			}
			noRunGoroutines(t)
		})
	}
}

// TestRunStopsWhenAskedBeforeServing checks that a stop that lands while Run is
// still starting up is a clean stop, not a serve error.
func TestRunStopsWhenAskedBeforeServing(t *testing.T) {
	c := newConfig(t, stateDir(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	agent.SetReady(c, func(net.Addr, net.Addr, net.Addr) {
		// Ask to stop, and hold Run back until the shutdown has closed
		// the admin socket, so the gRPC server is stopped before it
		// serves.
		cancel()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			conn, err := net.Dial("unix", c.AdminSocket())
			if err != nil {
				return
			}
			_ = conn.Close()
			time.Sleep(5 * time.Millisecond)
		}
	})
	done := make(chan error, 1)
	go func() { done <- agent.RunContext(ctx, c, agent.Standalone) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v, want nil", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Run did not return")
	}
	noRunGoroutines(t)
}

// TestRunStopsOnSignal checks that Run, which has no context, stops cleanly on
// SIGINT or SIGTERM.
func TestRunStopsOnSignal(t *testing.T) {
	cases := []struct {
		name string
		sig  syscall.Signal
	}{
		{name: "SIGINT", sig: syscall.SIGINT},
		{name: "SIGTERM", sig: syscall.SIGTERM},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newConfig(t, stateDir(t))
			ready := make(chan struct{})
			agent.SetReady(c, func(net.Addr, net.Addr, net.Addr) { close(ready) })
			done := make(chan error, 1)
			go func() { done <- agent.Run(c, agent.Standalone) }()
			select {
			case <-ready:
			case err := <-done:
				t.Fatalf("Run = %v before serving", err)
			}
			// Run is listening for the signal from before it is ready.
			if err := syscall.Kill(os.Getpid(), tc.sig); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("Run = %v, want nil", err)
				}
			case <-time.After(20 * time.Second):
				t.Fatal("Run did not stop on the signal")
			}
			noRunGoroutines(t)
		})
	}
}

// TestRunScopeLost checks that a home that loses its scope bumps the agent's
// epoch through the callback Run hands it. A bump that cannot be persisted
// leaves the epoch where it was.
func TestRunScopeLost(t *testing.T) {
	cases := []struct {
		name     string
		breakDir bool // make the epoch file unwritable first
		want     uint64
	}{
		{name: "the epoch moves on", want: 1},
		{name: "an unwritable epoch stays", breakDir: true, want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lost := make(chan func(context.Context, string), 1)
			nh := func(c *agent.Config, jwks *grant.Cache) (home.Home, error) {
				h, err := agent.Standalone(c, jwks)
				return scopedHome{Home: h, lost: lost}, err
			}
			state := stateDir(t)
			r := start(t, newConfig(t, state), nh)
			onLost := <-lost
			before := epochOf(t, r.c)
			if tc.breakDir {
				epoch := filepath.Join(state, "private", "epoch")
				if err := os.Remove(epoch); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Join(epoch, "x"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			onLost(context.Background(), "test")
			if got := epochOf(t, r.c); got != before+tc.want {
				t.Fatalf("epoch %d -> %d, want +%d", before, got, tc.want)
			}
			if err := r.stop(t); err != nil {
				t.Fatal(err)
			}
			noRunGoroutines(t)
		})
	}
}

// TestRunRefuses checks that every misconfiguration Run can see fails it with
// an error naming the problem, and leaves nothing running behind.
func TestRunRefuses(t *testing.T) {
	busy := func(t *testing.T) string {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		return l.Addr().String()
	}
	under := func(t *testing.T, state, name string, dir bool) {
		p := filepath.Join(state, "private", name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		var err error
		if dir {
			err = os.MkdirAll(filepath.Join(p, "x"), 0o700)
		} else {
			err = os.WriteFile(p, []byte("{"), 0o600)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	missing := "/nonexistent/fiberd-test"
	proc := []string{"-runtime", "proc", "-template", "default=/bin/true"}
	cases := []struct {
		name  string
		args  []string
		setup func(t *testing.T, state string) []string
		home  agent.HomeFactory
		want  string // in the error
		// wantLinux replaces want on Linux, where the host runtime is
		// real.
		wantLinux string
		wantIs    error
	}{
		{name: "no transport", args: []string{"-insecure-plaintext=false"}, wantIs: tlsconf.ErrNoTransport},
		{name: "TLS files missing", args: []string{"-insecure-plaintext=false", "-tls-cert", missing, "-tls-key", missing, "-client-ca", missing},
			want: "server certificate"},
		{name: "state dir is a file", want: "state dir", setup: func(t *testing.T, state string) []string {
			f := filepath.Join(state, "file")
			if err := os.WriteFile(f, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return []string{"-state", filepath.Join(f, "state")}
		}},
		{name: "jwks without an issuer", args: []string{"-verifier", "jwks"}, want: "-verifier=jwks needs -issuer"},
		{name: "no verifier", args: []string{"-verifier="}, want: "-verifier is required"},
		{name: "unknown verifier", args: []string{"-verifier", "trust-me"}, want: `unknown verifier "trust-me"`},
		{name: "home fails", home: func(*agent.Config, *grant.Cache) (home.Home, error) { return nil, errors.New("home is down") },
			want: "home is down"},
		{name: "home has no address of the family", args: []string{"-endpoint-family", "inet6"}, home: hosted("", ""),
			want: "-endpoint-family inet6: home standalone has no address of that family"},
		{name: "bad runtime tier", args: []string{"-runtime-tier", "FIBER_WARP"}, want: "runtime-tier"},
		{name: "host runtime without a template", args: []string{"-runtime", "proc"}, want: "-runtime=proc needs a -template"},
		{name: "hyperlight without a helper", args: []string{"-runtime", "hyperlight", "-template", "default=/g"},
			want: "-runtime=hyperlight needs -hyperlight-helper"},
		{name: "runc without a rootfs", args: []string{"-runtime", "runc", "-registry", "r.example/z"}, want: "-runtime=runc needs -runc-rootfs"},
		{name: "runc with a bad userns pool", args: []string{"-runtime", "runc", "-registry", "r.example/z", "-runc-rootfs", "/r", "-userns-pool", "1:1"},
			want: "-userns-pool"},
		{name: "runc state dir is a file", args: []string{"-runtime", "runc", "-template", "default=/z", "-runc-rootfs", "/r"},
			setup: func(t *testing.T, state string) []string {
				if err := os.WriteFile(filepath.Join(state, "runc"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
				return nil
			},
			want: "runc runtime: ", wantLinux: "runc: state directory"},
		{name: "gvisor without a rootfs", args: []string{"-runtime", "gvisor", "-template", "default=/z"}, want: "-runtime=gvisor needs -gvisor-rootfs"},
		// Confinement fails closed: a backend whose tools are missing
		// offers no tier, and the agent does not start over it.
		{name: "gvisor whose runsc is missing", args: []string{"-runtime", "gvisor", "-template", "default=/z", "-gvisor-rootfs", "/r", "-runsc", missing},
			want: "gvisor runtime: ", wantLinux: "gvisor runtime: host: backend gvisor offers no tier: runsc " + missing + " unavailable"},
		{name: "hyperlight whose helper is missing", args: []string{"-runtime", "hyperlight", "-template", "default=/g", "-hyperlight-helper", missing},
			want: "hyperlight runtime: ", wantLinux: "hyperlight runtime: host: backend hyperlight offers no tier: helper " + missing + " unusable"},
		{name: "bad parity", args: append([]string{"-parity", "kernel=sometimes"}, proc...), want: "parity"},
		{name: "unknown endpoint family", args: append([]string{"-endpoint-family", "pigeon"}, proc...), want: `endpoint family "pigeon"`},
		{name: "endpoint host of the wrong family", args: append([]string{"-endpoint-family", "inet4", "-endpoint-host", "::1"}, proc...),
			want: "is not an inet4 address"},
		{name: "delta key missing", args: append([]string{"-delta-registry", "r.example/d", "-delta-key", missing}, proc...),
			want: "-delta-key/-delta-trust"},
		{name: "handoff key missing", args: append([]string{"-handoff-listen", "127.0.0.1:0", "-handoff-key", missing}, proc...),
			want: "-handoff-key"},
		{name: "handoff address taken", args: proc, want: "-handoff-listen",
			setup: func(t *testing.T, _ string) []string { return []string{"-handoff-listen", busy(t)} }},
		{name: "bad handoff advertise", args: append([]string{"-handoff-listen", "127.0.0.1:0", "-handoff-advertise", "no-port"}, proc...),
			want: "-handoff-advertise"},
		{name: "host runtime cannot start", want: "proc runtime: ",
			setup: func(t *testing.T, state string) []string {
				f := filepath.Join(state, "file")
				if err := os.WriteFile(f, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				return append([]string{"-cgroup-root", filepath.Join(f, "cg")}, proc...)
			}},
		{name: "unknown runtime", args: []string{"-runtime", "vmware"}, want: `runtime "vmware" is not available yet`},
		{name: "epoch cannot be persisted", want: "epoch:",
			setup: func(t *testing.T, state string) []string { under(t, state, "epoch", true); return nil }},
		{name: "audit key missing", args: []string{"-audit-key", missing}, want: "-audit-key"},
		{name: "audit spool unreadable", want: "audit:",
			setup: func(t *testing.T, state string) []string { under(t, state, "audit.jsonl", true); return nil }},
		{name: "deny-list unreadable", want: "deny-list:",
			setup: func(t *testing.T, state string) []string { under(t, state, "revoked.json", false); return nil }},
		{name: "snapshot unreadable", want: "snapshot:",
			setup: func(t *testing.T, state string) []string { under(t, state, "ledger.json", true); return nil }},
		{name: "admin socket path taken", want: "admin socket:",
			setup: func(t *testing.T, state string) []string { under(t, state, "admin.sock", true); return nil }},
		{name: "gRPC address taken", want: "listen ",
			setup: func(t *testing.T, _ string) []string { return []string{"-listen", busy(t)} }},
		{name: "gateway address taken", want: "-http ",
			setup: func(t *testing.T, _ string) []string { return []string{"-http", busy(t)} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := stateDir(t)
			args := tc.args
			if tc.setup != nil {
				args = append(append([]string{}, args...), tc.setup(t, state)...)
			}
			nh := tc.home
			if nh == nil {
				nh = agent.Standalone
			}
			r, err := launch(t, context.Background(), newConfig(t, state, args...), nh)
			if r != nil {
				_ = r.stop(t)
				t.Fatal("Run started, want an error")
			}
			want := tc.want
			if runtime.GOOS == "linux" && tc.wantLinux != "" {
				want = tc.wantLinux
			}
			switch {
			case err == nil:
				t.Fatal("Run returned nil, want an error")
			case tc.wantIs != nil && !errors.Is(err, tc.wantIs):
				t.Fatalf("Run = %v, want %v", err, tc.wantIs)
			case !strings.Contains(err.Error(), want):
				t.Fatalf("Run = %v, want it to mention %q", err, want)
			}
			noRunGoroutines(t)
		})
	}
}
