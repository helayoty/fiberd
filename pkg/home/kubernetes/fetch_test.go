package kubernetes_test

import (
	"cmp"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	testingclock "k8s.io/utils/clock/testing"

	"github.com/Azure/fiberd/pkg/core"
	"github.com/Azure/fiberd/pkg/endpoint"
	"github.com/Azure/fiberd/pkg/grant"
	"github.com/Azure/fiberd/pkg/home"
	"github.com/Azure/fiberd/pkg/home/grantdir"
	"github.com/Azure/fiberd/pkg/home/kubernetes"
	"github.com/Azure/fiberd/pkg/home/kubernetes/fake"
)

const (
	// testBearer and testBearer2 are the Pod's token before and after the
	// kubelet rotates it.
	testBearer  = "pod-sa-token-one"
	testBearer2 = "pod-sa-token-two"
	// testLease is a 200's lease unless the answer names another.
	testLease = 60 * time.Second
)

// answer is one scripted reply of the grant endpoint.
type answer struct {
	status     int
	lease      time.Duration // a 200's lease, testLease when zero
	uid        string        // a 200's uid, the Pod's when empty
	jti        string        // the minted grant's jti, the Pod's when empty
	endsEarly  bool          // a 200 whose lease ends as it starts
	oversize   bool          // a 200 whose token is over grant.MaxTokenBytes
	noExpiry   bool          // a 200 without expiresAt
	body       string        // a 200 with this body and no grant
	retryAfter string        // the Retry-After header, none when empty
	retryIn    time.Duration // a Retry-After date this far past the clock's now
	location   string        // the Location header of a redirect
	reason     string        // a failure's error reason
	hang       bool          // no answer until the request is cancelled
}

// seen is one request the endpoint received.
type seen struct {
	at          time.Time // the clock's now when it arrived
	method      string
	path        string
	auth        string
	contentType string
	accept      string
	raw         string
	body        map[string]string
}

// controller is a grant endpoint answering from a script. Request n gets
// answer n, and the last answer repeats.
type controller struct {
	t      *testing.T
	clock  *testingclock.FakeClock
	key    *jose.JSONWebKey
	script []answer

	mu     sync.Mutex
	seen   []seen
	issued []string
}

func (c *controller) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	body := map[string]string{}
	_ = json.Unmarshal(raw, &body)
	now := c.clock.Now()
	c.mu.Lock()
	c.seen = append(c.seen, seen{at: now, method: r.Method, path: r.URL.Path, auth: r.Header.Get("Authorization"),
		contentType: r.Header.Get("Content-Type"), accept: r.Header.Get("Accept"), raw: string(raw), body: body})
	a := c.script[min(len(c.seen), len(c.script))-1]
	c.mu.Unlock()
	switch {
	case a.hang:
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	case a.status == http.StatusOK:
		c.grant(w, a, now)
	default:
		if a.location != "" {
			w.Header().Set("Location", a.location)
		}
		if a.retryAfter != "" {
			w.Header().Set("Retry-After", a.retryAfter)
		}
		if a.retryIn != 0 {
			w.Header().Set("Retry-After", now.Add(a.retryIn).UTC().Format(http.TimeFormat))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(a.status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": a.reason})
	}
}

// grant answers a 200 with a freshly minted grant, or with a.body.
func (c *controller) grant(w http.ResponseWriter, a answer, now time.Time) {
	if a.body != "" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, a.body)
		return
	}
	lease := cmp.Or(a.lease, testLease)
	c.mu.Lock()
	tok, err := c.mint(cmp.Or(a.jti, testPodUID), fmt.Sprintf("t-%d", len(c.issued)+1), now, now.Add(lease))
	if err == nil {
		c.issued = append(c.issued, tok)
	}
	c.mu.Unlock()
	if err != nil {
		c.t.Errorf("mint: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	exp := now.Add(lease)
	if a.endsEarly {
		exp = now
	}
	if a.oversize {
		// The minted grant stays a prefix, so noSecrets still finds it.
		tok += strings.Repeat("x", grant.MaxTokenBytes)
	}
	out := map[string]string{
		"token": tok, "uid": cmp.Or(a.uid, testPodUID), "audience": testPod,
		"issuedAt": now.Format(time.RFC3339), "expiresAt": exp.Format(time.RFC3339),
	}
	if a.noExpiry {
		delete(out, "expiresAt")
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// mint signs a grant with the controller's key. The tenant keeps every
// grant distinct.
func (c *controller) mint(jti, tenant string, iat, exp time.Time) (string, error) {
	return grant.Sign(core.Grant{UID: jti, Issuer: "https://issuer.test", Audience: testPod, Tenant: tenant, LeaseExpiry: exp}, c.key, iat)
}

func (c *controller) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}

func (c *controller) requests() []seen {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]seen(nil), c.seen...)
}

func (c *controller) tokens() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.issued...)
}

// fetchEnv is a home configured to fetch its grant from a scripted
// controller over TLS, on a fake clock.
type fetchEnv struct {
	ctl       *controller
	clock     *testingclock.FakeClock
	logs      *logBuffer
	root      string
	dir       string // the grants directory, missing until a grant is written
	tokenFile string
	cfg       kubernetes.Config
	preset    string // the grant file found at the start, empty for none
	// built, when set, is handed the home before the first fetch.
	built func(h *kubernetes.Home)
	// ctx, when set, is New's context. Else New gets the test's context.
	ctx context.Context
	// home is what newHome built, nil when New failed.
	home *kubernetes.Home
}

func newFetchEnv(t *testing.T, script ...answer) *fetchEnv {
	t.Helper()
	key, err := grant.GenerateKey(jose.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	fc := testingclock.NewFakeClock(testStart)
	ctl := &controller{t: t, clock: fc, key: key, script: script}
	srv := httptest.NewTLSServer(ctl)
	t.Cleanup(srv.Close)
	root := t.TempDir()
	logs := &logBuffer{}
	e := &fetchEnv{ctl: ctl, clock: fc, logs: logs, root: root,
		dir: filepath.Join(root, "grants"), tokenFile: filepath.Join(root, "token")}
	e.setBearer(t, testBearer+"\n")
	caFile := filepath.Join(root, "ca.pem")
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	k := fake.New(testNamespace)
	k.SetPod(livePod())
	k.SetClaim(testClaim, false)
	e.cfg = kubernetes.Config{
		Kube: k, PodName: testPod, PodNamespace: testNamespace, PodUID: testPodUID,
		StaleTTL: testStaleTTL, Poll: testPoll, Family: endpoint.Inet4,
		CgroupRoot: t.TempDir(), Clock: fc, Logger: logs.logger(),
		GrantsDir: e.dir, GrantTokenFile: e.tokenFile, GrantIssuerURL: srv.URL + "/", GrantCAFile: caFile,
	}
	return e
}

// setBearer replaces the Pod's token file in one rename, as the kubelet
// does.
func (e *fetchEnv) setBearer(t *testing.T, tok string) {
	t.Helper()
	tmp := e.tokenFile + ".new"
	if err := os.WriteFile(tmp, []byte(tok), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, e.tokenFile); err != nil {
		t.Fatal(err)
	}
}

// presetGrant puts a grant file of the Pod in the directory, with left
// lease from the start of the clock.
func (e *fetchEnv) presetGrant(t *testing.T, left time.Duration) {
	t.Helper()
	exp := testStart.Add(left)
	tok, err := e.ctl.mint(testPodUID, "preset", exp.Add(-time.Hour), exp)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(e.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.grantFile(), []byte(tok), 0o600); err != nil {
		t.Fatal(err)
	}
	e.preset = tok
}

func (e *fetchEnv) grantFile() string { return filepath.Join(e.dir, testPodUID+".jwt") }

// secrets is every token in play, the Pod's and the grants'.
func (e *fetchEnv) secrets() []string {
	s := append(e.ctl.tokens(), testBearer, testBearer2)
	if e.preset != "" {
		s = append(s, e.preset)
	}
	return s
}

// which names v among the secrets without showing it, for a failure
// message.
func (e *fetchEnv) which(v string) string {
	switch v {
	case "":
		return "nothing"
	case e.preset:
		return "the preset grant"
	case "Bearer " + testBearer:
		return "the first bearer"
	case "Bearer " + testBearer2:
		return "the second bearer"
	}
	for i, tok := range e.ctl.tokens() {
		if v == tok {
			return fmt.Sprintf("grant %d", i+1)
		}
	}
	return fmt.Sprintf("an unknown value of %d bytes", len(v))
}

// noSecrets fails the test when text holds any of secrets. The message
// names the secret by its place only.
func noSecrets(t *testing.T, where, text string, secrets []string) {
	t.Helper()
	for i, s := range secrets {
		if s != "" && strings.Contains(text, s) {
			t.Fatalf("%s holds secret %d of %d", where, i+1, len(secrets))
		}
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// drive moves the clock a second at a time whenever something waits on
// it, until cond holds or ten seconds pass.
func (e *fetchEnv) drive(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("waited for %s", what)
		}
		if e.clock.HasWaiters() {
			e.clock.Step(time.Second)
		}
		time.Sleep(time.Millisecond)
	}
}

// newHome runs New on another goroutine and drives the clock while New
// waits on it, until New returns. The jitter draw is fixed at the middle,
// so it moves no backoff.
func (e *fetchEnv) newHome(t *testing.T) (*kubernetes.Home, error) {
	t.Helper()
	type result struct {
		h   *kubernetes.Home
		err error
	}
	ctx := e.ctx
	if ctx == nil {
		ctx = t.Context()
	}
	done := make(chan result, 1)
	go func() {
		h, err := kubernetes.NewWithHook(ctx, e.cfg, func(h *kubernetes.Home) {
			h.SetJitter(0.5)
			if e.built != nil {
				e.built(h)
			}
		})
		done <- result{h, err}
	}()
	var r result
	e.drive(t, "New to return", func() bool {
		select {
		case r = <-done:
			return true
		default:
			return false
		}
	})
	if r.h != nil {
		t.Cleanup(r.h.Close)
	}
	e.home = r.h
	return r.h, r.err
}

// runFetch runs the grant renewal alone until the test ends.
func (e *fetchEnv) runFetch(t *testing.T, h *kubernetes.Home) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); h.RunFetch(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("the renewal did not stop after its context ended")
		}
	})
}

// stepUntil moves the clock a second at a time, each step taken while
// the fetcher waits on it, until cond holds. cond is checked only while
// the fetcher waits, so what a request wrote is in place. The clock moves
// at most limit.
func (e *fetchEnv) stepUntil(t *testing.T, what string, limit time.Duration, cond func() bool) {
	t.Helper()
	start := e.clock.Now()
	for {
		waitFor(t, "the fetcher to wait on the clock", e.clock.HasWaiters)
		if cond() {
			return
		}
		if e.clock.Since(start) >= limit {
			t.Fatalf("the clock moved %s without %s", limit, what)
		}
		e.clock.Step(time.Second)
	}
}

// wantGrantFile fails the test unless the Pod's grant file holds want,
// readable by its owner only.
func (e *fetchEnv) wantGrantFile(t *testing.T, want string) {
	t.Helper()
	b, err := os.ReadFile(e.grantFile())
	if err != nil {
		t.Fatalf("read the grant file: %v", err)
	}
	if string(b) != want {
		t.Fatalf("the grant file holds %s, want %s", e.which(string(b)), e.which(want))
	}
	info, err := os.Stat(e.grantFile())
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("the grant file's mode is %o, want 600", perm)
	}
}

// wantOnlyGrantFile fails the test when the grants directory holds
// anything but the Pod's grant file, a temporary file above all.
func (e *fetchEnv) wantOnlyGrantFile(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(e.dir)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range entries {
		if en.Name() != testPodUID+".jwt" {
			t.Fatalf("the grants directory holds %q", en.Name())
		}
	}
}

// wantPolled fails the test unless the directory's poll delivers the
// Pod's grant file as one GrantAdded carrying want.
func (e *fetchEnv) wantPolled(t *testing.T, want string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := grantdir.Poll(ctx, e.dir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-ch:
		if ev.Kind != home.GrantAdded || string(ev.Token) != want {
			t.Fatalf("the poll delivered kind %d with %s, want GrantAdded with %s", ev.Kind, e.which(string(ev.Token)), e.which(want))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the poll delivered nothing")
	}
}

// wantRequests fails the test unless every request was a JSON POST to
// the grant path that accepts JSON.
func (e *fetchEnv) wantRequests(t *testing.T) {
	t.Helper()
	for i, r := range e.ctl.requests() {
		if r.method != http.MethodPost || r.path != "/v1/grant" {
			t.Fatalf("request %d is %s %s, want POST /v1/grant", i+1, r.method, r.path)
		}
		if r.contentType != "application/json" || r.accept != "application/json" {
			t.Fatalf("request %d has Content-Type %q and Accept %q, want application/json for both", i+1, r.contentType, r.accept)
		}
	}
}

// TestFetchStart checks what New does with the first fetch: one request
// when the controller answers, retries until the timeout when it does
// not, and the grant file it finds or leaves.
func TestFetchStart(t *testing.T) {
	ok := answer{status: http.StatusOK}
	failing := answer{status: http.StatusInternalServerError, reason: "controller down"}
	cases := []struct {
		name   string
		script []answer
		// preset puts a grant file of the Pod with this much lease left
		// in the directory first. Zero puts none.
		preset time.Duration
		change func(t *testing.T, e *fetchEnv)
		// wantErr are what New's error must name. Empty wants no error.
		wantErr      []string
		wantRequests int
		// wantFile is the grant n the Pod's file must hold. Zero wants
		// the preset grant, or no file without one.
		wantFile int
		check    func(t *testing.T, e *fetchEnv)
	}{
		{name: "New fetches the grant once before it returns", script: []answer{ok}, wantRequests: 1, wantFile: 1},
		{name: "a failed first fetch is retried", script: []answer{failing, ok}, wantRequests: 2, wantFile: 1,
			check: func(t *testing.T, e *fetchEnv) {
				if at := e.ctl.requests()[1].at; !at.Equal(testStart.Add(time.Second)) {
					t.Fatalf("the retry came at %s, want a second after the start", at)
				}
			}},
		{name: "a 503 at the start waits its Retry-After",
			script:       []answer{{status: http.StatusServiceUnavailable, retryAfter: "3"}, ok},
			wantRequests: 2, wantFile: 1,
			check: func(t *testing.T, e *fetchEnv) {
				if at := e.ctl.requests()[1].at; !at.Equal(testStart.Add(3 * time.Second)) {
					t.Fatalf("the retry came at %s, want three seconds after the start", at)
				}
			}},
		{name: "a grant for another uid is retried and writes nothing",
			script: []answer{{status: http.StatusOK, uid: "other-pod"}, ok}, wantRequests: 2, wantFile: 2},
		{name: "a grant whose jti is not its uid is retried",
			script: []answer{{status: http.StatusOK, jti: "other-pod"}, ok}, wantRequests: 2, wantFile: 2},
		{name: "a grant whose lease ends as it starts is retried",
			script: []answer{{status: http.StatusOK, endsEarly: true}, ok}, wantRequests: 2, wantFile: 2},
		{name: "a grant over the token size limit is retried and writes nothing",
			script: []answer{{status: http.StatusOK, oversize: true}, ok}, wantRequests: 2, wantFile: 2,
			check: func(t *testing.T, e *fetchEnv) {
				if e.logs.count("Grant fetch failed", "bytes, over the") != 1 {
					t.Fatalf("the log does not say once that the grant is too long:\n%s", e.logs)
				}
			}},
		{name: "a 200 whose body is not JSON is retried and writes nothing",
			script: []answer{{status: http.StatusOK, body: "not json"}, ok}, wantRequests: 2, wantFile: 1,
			check: func(t *testing.T, e *fetchEnv) {
				if e.logs.count("Grant fetch failed", "decode the controller's grant") != 1 {
					t.Fatalf("the log does not say once that the answer did not decode:\n%s", e.logs)
				}
			}},
		{name: "a 200 without expiresAt is retried and writes nothing",
			script: []answer{{status: http.StatusOK, noExpiry: true}, ok}, wantRequests: 2, wantFile: 2,
			check: func(t *testing.T, e *fetchEnv) {
				if e.logs.count("Grant fetch failed", "not after it starts") != 1 {
					t.Fatalf("the log does not say once that the lease has no end:\n%s", e.logs)
				}
			}},
		{name: "a failed directory sync still holds the grant", script: []answer{ok}, wantRequests: 1, wantFile: 1,
			change: func(_ *testing.T, e *fetchEnv) {
				e.built = func(h *kubernetes.Home) {
					h.SetSyncDir(func(string) error { return errors.New("sync refused") })
				}
			},
			check: func(t *testing.T, e *fetchEnv) {
				if e.logs.count("directory sync failed", "sync refused") != 1 {
					t.Fatalf("the log does not say once that the directory sync failed:\n%s", e.logs)
				}
				e.runFetch(t, e.home)
				e.stepUntil(t, "the renewal", 2*time.Minute, func() bool { return e.ctl.count() > 1 })
				if got := e.ctl.requests()[1].body["previous"]; got != e.ctl.tokens()[0] {
					t.Fatalf("the renewal's previous is %s, want grant 1", e.which(got))
				}
				noSecrets(t, "the log", e.logs.String(), e.secrets())
			}},
		{name: "a redirect at the start is not followed",
			script: []answer{{status: http.StatusTemporaryRedirect, location: "/v1/grant/elsewhere"}, ok}, wantRequests: 2, wantFile: 1},
		{name: "a long error reason is logged cut to 200 bytes",
			script: []answer{{status: http.StatusInternalServerError, reason: strings.Repeat("r", 300)}, ok}, wantRequests: 2, wantFile: 1,
			check: func(t *testing.T, e *fetchEnv) {
				if e.logs.count(strings.Repeat("r", 200)) == 0 || e.logs.count(strings.Repeat("r", 201)) != 0 {
					t.Fatal("the log does not hold the reason cut to 200 bytes")
				}
			}},
		{name: "the timeout without a grant file fails", script: []answer{failing},
			wantErr: []string{"no grant from", "within 1m0s", "500", "controller down"}, wantRequests: 7},
		{name: "the timeout with an unexpired grant file starts on it", script: []answer{failing}, preset: 10 * time.Minute,
			wantRequests: 7,
			check: func(t *testing.T, e *fetchEnv) {
				if e.logs.count("Started on the unexpired grant file") != 1 {
					t.Fatalf("the log does not say the start was on the grant file:\n%s", e.logs)
				}
			}},
		{name: "the timeout with an expired grant file fails", script: []answer{failing}, preset: -time.Minute,
			wantErr: []string{"within 1m0s"}, wantRequests: 7},
		// The preset grant is expired, so the timeout fails New rather than
		// starting on the file.
		{name: "a read-only grants directory fails at the timeout and keeps the file",
			script: []answer{ok}, preset: -time.Minute,
			change: func(t *testing.T, e *fetchEnv) {
				if os.Geteuid() == 0 {
					t.Skip("root writes into a read-only directory")
				}
				if err := os.Chmod(e.dir, 0o500); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(e.dir, 0o700) })
			},
			wantErr: []string{"within 1m0s", "write the grant"}, wantRequests: 7},
		{name: "a 409 without a grant file fails at once",
			script:  []answer{{status: http.StatusConflict, reason: "pod terminating"}},
			wantErr: []string{"409", "pod terminating"}, wantRequests: 1},
		{name: "a 409 with a grant file starts with renewal stopped",
			script: []answer{{status: http.StatusConflict}}, preset: 10 * time.Minute, wantRequests: 1,
			check: func(t *testing.T, e *fetchEnv) {
				if e.logs.count("stopped the grant") != 1 {
					t.Fatalf("the log does not say once that renewal stopped:\n%s", e.logs)
				}
			}},
		{name: "a 409 with an expired grant file fails",
			script: []answer{{status: http.StatusConflict, reason: "pod terminating"}}, preset: -time.Minute,
			wantErr: []string{"409", "pod terminating"}, wantRequests: 1},
		{name: "a server outside the CA bundle fails at the timeout", script: []answer{ok},
			change:  func(_ *testing.T, e *fetchEnv) { e.cfg.GrantCAFile = "" },
			wantErr: []string{"within 1m0s"}},
		{name: "a missing CA file fails New", script: []answer{ok},
			change:  func(_ *testing.T, e *fetchEnv) { e.cfg.GrantCAFile = filepath.Join(e.root, "missing.pem") },
			wantErr: []string{"read the grant CA file"}},
		{name: "a CA file without a certificate fails New", script: []answer{ok},
			change: func(t *testing.T, e *fetchEnv) {
				if err := os.WriteFile(e.cfg.GrantCAFile, []byte("not a certificate"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: []string{"holds no PEM certificate"}},
		{name: "a missing token file is retried until the timeout", script: []answer{ok},
			change:  func(_ *testing.T, e *fetchEnv) { e.cfg.GrantTokenFile = filepath.Join(e.root, "missing") },
			wantErr: []string{"within 1m0s", "read the Pod's token"}},
		{name: "an empty token file is retried until the timeout", script: []answer{ok},
			change:  func(t *testing.T, e *fetchEnv) { e.setBearer(t, " \n") },
			wantErr: []string{"within 1m0s", "is empty"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newFetchEnv(t, c.script...)
			if c.preset != 0 {
				e.presetGrant(t, c.preset)
			}
			if c.change != nil {
				c.change(t, e)
			}
			_, err := e.newHome(t)
			noSecrets(t, "New's error", errText(err), e.secrets())
			if len(c.wantErr) == 0 && err != nil {
				t.Fatalf("New: %v", err)
			}
			if len(c.wantErr) > 0 && err == nil {
				t.Fatalf("New returned no error, want one naming %q", c.wantErr)
			}
			for _, s := range c.wantErr {
				if !strings.Contains(err.Error(), s) {
					t.Fatalf("New = %v, want it to name %q", err, s)
				}
			}
			if got := e.ctl.count(); got != c.wantRequests {
				t.Fatalf("the controller saw %d requests, want %d", got, c.wantRequests)
			}
			e.wantRequests(t)
			for i, r := range e.ctl.requests() {
				if r.auth != "Bearer "+testBearer {
					t.Fatalf("request %d carried %s, want the first bearer", i+1, e.which(r.auth))
				}
			}
			if c.wantRequests > 0 {
				first := e.ctl.requests()[0]
				if c.preset != 0 && first.body["previous"] != e.preset {
					t.Fatalf("the first request's previous is %s, want the preset grant", e.which(first.body["previous"]))
				}
				if c.preset == 0 && first.raw != "{}" {
					t.Fatalf("the first request's body is %d bytes, want {}", len(first.raw))
				}
			}
			switch {
			case c.wantFile > 0:
				want := e.ctl.tokens()[c.wantFile-1]
				e.wantGrantFile(t, want)
				e.wantPolled(t, want)
			case c.preset != 0:
				e.wantGrantFile(t, e.preset)
			default:
				if _, err := os.Stat(e.grantFile()); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("the grant file is there, or unreadable: %v", err)
				}
			}
			e.wantOnlyGrantFile(t)
			noSecrets(t, "the log", e.logs.String(), e.secrets())
			if c.check != nil {
				c.check(t, e)
			}
		})
	}
}

// TestFetchRenewal checks the renewal after a start on a fresh grant:
// when each request goes out, with which token and body, and which grant
// the file holds after.
func TestFetchRenewal(t *testing.T) {
	ok := answer{status: http.StatusOK}
	rotate := func(t *testing.T, e *fetchEnv) { e.setBearer(t, testBearer2+"\n") }
	cases := []struct {
		name   string
		script []answer
		// after runs once request n was answered, while the fetcher waits.
		after map[int]func(t *testing.T, e *fetchEnv)
		// wantGaps is the clock between request n and request n+1.
		wantGaps []time.Duration
		// wantFile is the grant n the Pod's file holds at the end.
		wantFile int
		check    func(t *testing.T, e *fetchEnv)
	}{
		{name: "the grant renews at half its lease with the grant it holds", script: []answer{ok, ok},
			wantGaps: []time.Duration{30 * time.Second}, wantFile: 2,
			check: func(t *testing.T, e *fetchEnv) {
				first, second := e.ctl.requests()[0], e.ctl.requests()[1]
				if first.raw != "{}" {
					t.Fatalf("the first request's body is %d bytes, want {}", len(first.raw))
				}
				if got, want := second.body["previous"], e.ctl.tokens()[0]; got != want {
					t.Fatalf("the renewal's previous is %s, want grant 1", e.which(got))
				}
			}},
		{name: "a renewed grant renews at half its own lease",
			script:   []answer{ok, {status: http.StatusOK, lease: 20 * time.Second}, ok},
			wantGaps: []time.Duration{30 * time.Second, 10 * time.Second}, wantFile: 3,
			check: func(t *testing.T, e *fetchEnv) {
				if got := e.ctl.requests()[2].body["previous"]; got != e.ctl.tokens()[1] {
					t.Fatalf("the second renewal's previous is %s, want grant 2", e.which(got))
				}
			}},
		{name: "the token file is read on every request", script: []answer{ok, ok},
			after:    map[int]func(*testing.T, *fetchEnv){1: rotate},
			wantGaps: []time.Duration{30 * time.Second}, wantFile: 2,
			check: func(t *testing.T, e *fetchEnv) {
				reqs := e.ctl.requests()
				if reqs[0].auth != "Bearer "+testBearer || reqs[1].auth != "Bearer "+testBearer2 {
					t.Fatalf("the requests carried %s then %s, want the first bearer then the second",
						e.which(reqs[0].auth), e.which(reqs[1].auth))
				}
			}},
		{name: "a 401 retries in 30 seconds with the token read again",
			script:   []answer{ok, {status: http.StatusUnauthorized}, ok},
			after:    map[int]func(*testing.T, *fetchEnv){2: rotate},
			wantGaps: []time.Duration{30 * time.Second, 30 * time.Second}, wantFile: 2,
			check: func(t *testing.T, e *fetchEnv) {
				reqs := e.ctl.requests()
				if reqs[1].auth != "Bearer "+testBearer || reqs[2].auth != "Bearer "+testBearer2 {
					t.Fatalf("the refused request carried %s and the retry %s, want the first bearer then the second",
						e.which(reqs[1].auth), e.which(reqs[2].auth))
				}
				if e.logs.count("refused the Pod's token") != 1 {
					t.Fatalf("the log does not say once that the token was refused:\n%s", e.logs)
				}
			}},
		{name: "a 403 retries in 30 seconds",
			script:   []answer{ok, {status: http.StatusForbidden}, ok},
			wantGaps: []time.Duration{30 * time.Second, 30 * time.Second}, wantFile: 2},
		{name: "a 422 retries in five minutes and logs the reason",
			script:   []answer{ok, {status: http.StatusUnprocessableEntity, reason: "the grant asks for too much"}, ok},
			wantGaps: []time.Duration{30 * time.Second, 5 * time.Minute}, wantFile: 2,
			check: func(t *testing.T, e *fetchEnv) {
				if e.logs.count("the grant asks for too much") != 1 {
					t.Fatalf("the log does not hold the reason once:\n%s", e.logs)
				}
			}},
		{name: "a 503 waits its Retry-After seconds",
			script:   []answer{ok, {status: http.StatusServiceUnavailable, retryAfter: "7"}, ok},
			wantGaps: []time.Duration{30 * time.Second, 7 * time.Second}, wantFile: 2},
		{name: "a 429 waits its Retry-After date",
			script:   []answer{ok, {status: http.StatusTooManyRequests, retryIn: 5 * time.Second}, ok},
			wantGaps: []time.Duration{30 * time.Second, 5 * time.Second}, wantFile: 2},
		{name: "a Retry-After past a quarter of the lease left is cut to it",
			script:   []answer{{status: http.StatusOK, lease: 2 * time.Minute}, {status: http.StatusServiceUnavailable, retryAfter: "600"}, ok},
			wantGaps: []time.Duration{time.Minute, 15 * time.Second}, wantFile: 2},
		{name: "a 500 backs off doubling and recovers",
			script: []answer{ok, {status: http.StatusInternalServerError}, {status: http.StatusInternalServerError},
				{status: http.StatusInternalServerError}, ok},
			wantGaps: []time.Duration{30 * time.Second, time.Second, 2 * time.Second, 4 * time.Second}, wantFile: 2},
		{name: "a redirect is backed off and not followed",
			script:   []answer{ok, {status: http.StatusTemporaryRedirect, location: "/v1/grant/elsewhere"}, ok},
			wantGaps: []time.Duration{30 * time.Second, time.Second}, wantFile: 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newFetchEnv(t, c.script...)
			h, err := e.newHome(t)
			noSecrets(t, "New's error", errText(err), e.secrets())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			e.runFetch(t, h)
			for n := 1; n <= len(c.wantGaps); n++ {
				if f := c.after[n]; f != nil {
					waitFor(t, "the fetcher to wait on the clock", e.clock.HasWaiters)
					f(t, e)
				}
				e.stepUntil(t, fmt.Sprintf("request %d", n+1), 10*time.Minute, func() bool { return e.ctl.count() > n })
				reqs := e.ctl.requests()
				if gap := reqs[n].at.Sub(reqs[n-1].at); gap != c.wantGaps[n-1] {
					t.Fatalf("request %d came %s after request %d, want %s", n+1, gap, n, c.wantGaps[n-1])
				}
			}
			if got, want := e.ctl.count(), len(c.wantGaps)+1; got != want {
				t.Fatalf("the controller saw %d requests, want %d", got, want)
			}
			e.wantRequests(t)
			e.wantGrantFile(t, e.ctl.tokens()[c.wantFile-1])
			e.wantOnlyGrantFile(t)
			noSecrets(t, "the log", e.logs.String(), e.secrets())
			if c.check != nil {
				c.check(t, e)
			}
		})
	}
}

// TestFetchConflict checks that a 409 stops the renewal for good: no
// request follows, however far the clock moves, and the file stays.
func TestFetchConflict(t *testing.T) {
	ok := answer{status: http.StatusOK}
	failing := answer{status: http.StatusInternalServerError}
	conflict := answer{status: http.StatusConflict, reason: "grant deleted"}
	cases := []struct {
		name         string
		script       []answer
		wantRequests int
	}{
		{name: "a 409 at the renewal stops it", script: []answer{ok, conflict}, wantRequests: 2},
		{name: "a 409 after failed renewals stops it", script: []answer{ok, failing, failing, conflict}, wantRequests: 4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newFetchEnv(t, c.script...)
			h, err := e.newHome(t)
			noSecrets(t, "New's error", errText(err), e.secrets())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			e.runFetch(t, h)
			e.drive(t, "the renewal to stop", func() bool { return e.logs.count("stopped the grant") > 0 })
			noSecrets(t, "the log", e.logs.String(), e.secrets())
			e.clock.Step(10 * testLease)
			if e.clock.HasWaiters() {
				t.Fatal("the fetcher waits on the clock after the 409")
			}
			if got := e.ctl.count(); got != c.wantRequests {
				t.Fatalf("the controller saw %d requests, want %d", got, c.wantRequests)
			}
			if e.logs.count("stopped the grant", "grant deleted") != 1 {
				t.Fatalf("the log does not say once that renewal stopped, with the reason:\n%s", e.logs)
			}
			e.wantGrantFile(t, e.ctl.tokens()[0])
			e.wantOnlyGrantFile(t)
		})
	}
}

// TestFetchOutageKeepsTheFile checks that a controller failing after one
// grant never removes or empties the grant file, even once its lease has
// lapsed.
func TestFetchOutageKeepsTheFile(t *testing.T) {
	ok := answer{status: http.StatusOK}
	cases := []struct {
		name   string
		script []answer
	}{
		{name: "a controller that fails after one grant", script: []answer{ok, {status: http.StatusInternalServerError}}},
		{name: "a controller that refuses the token after one grant", script: []answer{ok, {status: http.StatusUnauthorized}}},
		{name: "a controller that is busy after one grant", script: []answer{ok, {status: http.StatusServiceUnavailable, retryAfter: "120"}}},
		{name: "a controller that answers for another uid after one grant", script: []answer{ok, {status: http.StatusOK, uid: "other-pod"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newFetchEnv(t, c.script...)
			h, err := e.newHome(t)
			noSecrets(t, "New's error", errText(err), e.secrets())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			first := e.ctl.tokens()[0]
			e.runFetch(t, h)
			e.stepUntil(t, "the lease to lapse three times over", 4*testLease, func() bool {
				e.wantGrantFile(t, first)
				return e.clock.Since(testStart) >= 3*testLease
			})
			if e.ctl.count() < 3 {
				t.Fatalf("the controller saw %d requests, want the renewal to keep retrying", e.ctl.count())
			}
			e.wantOnlyGrantFile(t)
			noSecrets(t, "the log", e.logs.String(), e.secrets())
		})
	}
}

// TestFetchAfterStartOnFile checks that a start on an unexpired grant
// file keeps retrying from the backoff New left, with that file's grant
// as previous.
func TestFetchAfterStartOnFile(t *testing.T) {
	failing := answer{status: http.StatusInternalServerError}
	cases := []struct {
		name    string
		script  []answer
		wantGap time.Duration // between the last request of New and the first of the renewal
	}{
		{name: "the renewal fetches a grant once the controller answers",
			script:  []answer{failing, failing, failing, failing, failing, failing, failing, {status: http.StatusOK}},
			wantGap: 30 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newFetchEnv(t, c.script...)
			e.presetGrant(t, 10*time.Minute)
			h, err := e.newHome(t)
			noSecrets(t, "New's error", errText(err), e.secrets())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			started := e.ctl.count()
			e.runFetch(t, h)
			e.stepUntil(t, "the renewal's first request", 2*time.Minute, func() bool { return e.ctl.count() > started })
			reqs := e.ctl.requests()
			if gap := reqs[started].at.Sub(reqs[started-1].at); gap != c.wantGap {
				t.Fatalf("the renewal's first request came %s after New's last, want %s", gap, c.wantGap)
			}
			if got := reqs[started].body["previous"]; got != e.preset {
				t.Fatalf("the renewal's previous is %s, want the preset grant", e.which(got))
			}
			e.wantGrantFile(t, e.ctl.tokens()[0])
			e.wantOnlyGrantFile(t)
			noSecrets(t, "the log", e.logs.String(), e.secrets())
		})
	}
}

// TestNewClosed checks that Close, or the end of New's context, ends a
// New still retrying its first fetch. New returns the cancellation, leaves
// no grant file and closes the home.
func TestNewClosed(t *testing.T) {
	cases := []struct {
		name    string
		script  []answer
		waiting bool // stop while New waits on the clock, else while a request is in flight
		// cancel ends New's context instead of calling Close.
		cancel bool
		// deadline ends New's context with context.DeadlineExceeded as
		// its cause instead.
		deadline bool
		// wantErr is what New's error must wrap. Nil means the context's
		// cancellation.
		wantErr error
		// wantFailLogs is how many lines log a failed fetch. A cancelled
		// request is no failure.
		wantFailLogs int
	}{
		{name: "Close while New waits to retry", script: []answer{{status: http.StatusInternalServerError}}, waiting: true,
			wantFailLogs: 1},
		{name: "Close while a request is in flight", script: []answer{{hang: true}}},
		{name: "a cancelled context ends New while it waits to retry", script: []answer{{status: http.StatusInternalServerError}},
			waiting: true, cancel: true, wantFailLogs: 1},
		{name: "a cancelled context ends New during a request", script: []answer{{hang: true}}, cancel: true},
		{name: "a context ended with a deadline cause ends New with that cause", script: []answer{{hang: true}}, deadline: true,
			wantErr: context.DeadlineExceeded},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newFetchEnv(t, c.script...)
			var ctx context.Context
			var cancel context.CancelFunc
			var cancelCause context.CancelCauseFunc
			if c.deadline {
				ctx, cancelCause = context.WithCancelCause(t.Context())
				cancel = func() { cancelCause(nil) }
			} else {
				ctx, cancel = context.WithCancel(t.Context())
			}
			defer cancel()
			built := make(chan *kubernetes.Home, 1)
			done := make(chan error, 1)
			go func() {
				_, err := kubernetes.NewWithHook(ctx, e.cfg, func(h *kubernetes.Home) {
					h.SetJitter(0.5)
					built <- h
				})
				done <- err
			}()
			var h *kubernetes.Home
			select {
			case h = <-built:
			case <-time.After(10 * time.Second):
				t.Fatal("New built no home")
			}
			waitFor(t, "the first request", func() bool { return e.ctl.count() >= 1 })
			if c.waiting {
				waitFor(t, "New to wait on the clock", e.clock.HasWaiters)
			}
			switch {
			case c.cancel:
				cancel()
			case c.deadline:
				cancelCause(context.DeadlineExceeded)
			default:
				h.Close()
			}
			wantErr := c.wantErr
			if wantErr == nil {
				wantErr = context.Canceled
			}
			select {
			case err := <-done:
				noSecrets(t, "New's error", errText(err), e.secrets())
				if !errors.Is(err, wantErr) {
					t.Fatalf("New = %v, want %v", err, wantErr)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("New did not return after it was stopped")
			}
			// A closed home reads nothing from the cluster, so it finds
			// no address for the Pod.
			if got := h.EndpointHost(); got != "" {
				t.Fatalf("EndpointHost = %q after New failed, want the home closed", got)
			}
			if got := e.ctl.count(); got != 1 {
				t.Fatalf("the controller saw %d requests, want 1", got)
			}
			if _, err := os.Stat(e.grantFile()); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the grant file is there, or unreadable: %v", err)
			}
			e.wantOnlyGrantFile(t)
			if got := e.logs.count("Grant fetch failed"); got != c.wantFailLogs {
				t.Fatalf("the log says %d times that a fetch failed, want %d:\n%s", got, c.wantFailLogs, e.logs)
			}
			noSecrets(t, "the log", e.logs.String(), e.secrets())
		})
	}
}

// TestRunRenewsTheGrant checks that Run drives the renewal beside the
// polls, and that New's context is not the home's lifetime.
func TestRunRenewsTheGrant(t *testing.T) {
	ok := answer{status: http.StatusOK}
	cases := []struct {
		name   string
		script []answer
		// endNewCtx ends New's context once New has returned.
		endNewCtx bool
	}{
		{name: "Run renews the grant", script: []answer{ok, ok}},
		{name: "a context ended after New returned does not stop the home", script: []answer{ok, ok}, endNewCtx: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newFetchEnv(t, c.script...)
			newCtx, endNew := context.WithCancel(t.Context())
			defer endNew()
			e.ctx = newCtx
			h, err := e.newHome(t)
			noSecrets(t, "New's error", errText(err), e.secrets())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if c.endNewCtx {
				endNew()
				// A stopped home reads nothing from the cluster, so the
				// Pod's address shows the home still runs.
				if got := h.EndpointHost(); got != "10.0.0.1" {
					t.Fatalf("EndpointHost = %q after New's context ended, want the Pod's address", got)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { defer close(done); h.Run(ctx) }()
			defer func() {
				cancel()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					t.Error("Run did not return after its context ended")
				}
			}()
			e.drive(t, "the renewal", func() bool { return e.ctl.count() >= 2 })
			waitFor(t, "the renewed grant in the file", func() bool {
				b, err := os.ReadFile(e.grantFile())
				tokens := e.ctl.tokens()
				return err == nil && len(tokens) >= 2 && string(b) == tokens[1]
			})
			e.wantRequests(t)
			e.wantOnlyGrantFile(t)
			noSecrets(t, "the log", e.logs.String(), e.secrets())
		})
	}
}

// TestNextDelay checks the bounds of every wait between two requests.
func TestNextDelay(t *testing.T) {
	const even = 0.5 // the jitter draw that moves nothing
	cases := []struct {
		name string
		in   kubernetes.DelayInput
		// want is the wait. Zero checks wantMin and wantMax instead.
		want             time.Duration
		wantMin, wantMax time.Duration
	}{
		{name: "a written grant renews at half its lease",
			in: kubernetes.DelayInput{Wrote: true, Remaining: time.Minute}, want: 30 * time.Second},
		{name: "a written grant about to lapse renews after a second",
			in: kubernetes.DelayInput{Wrote: true, Remaining: time.Second}, want: time.Second},
		{name: "a written grant already lapsed renews after a second",
			in: kubernetes.DelayInput{Wrote: true, Remaining: -time.Minute}, want: time.Second},
		{name: "the first failure waits a second",
			in: kubernetes.DelayInput{Status: 500, Failures: 1, Jitter: even}, want: time.Second},
		{name: "each failure doubles the wait",
			in: kubernetes.DelayInput{Status: 500, Failures: 3, Jitter: even}, want: 4 * time.Second},
		{name: "the wait stops at 30 seconds",
			in: kubernetes.DelayInput{Status: 500, Failures: 6, Jitter: even}, want: 30 * time.Second},
		{name: "a long run of failures stays at 30 seconds",
			in: kubernetes.DelayInput{Status: 500, Failures: 1000, Jitter: even}, want: 30 * time.Second},
		{name: "a held lease caps the wait at a quarter of it",
			in: kubernetes.DelayInput{Status: 500, Failures: 10, Remaining: time.Minute, Jitter: even}, want: 15 * time.Second},
		{name: "a long held lease leaves the 30 second cap",
			in: kubernetes.DelayInput{Status: 500, Failures: 10, Remaining: time.Hour, Jitter: even}, want: 30 * time.Second},
		{name: "a quarter of the lease under a second is floored at a second",
			in: kubernetes.DelayInput{Status: 500, Failures: 3, Remaining: 2 * time.Second, Jitter: even}, want: time.Second},
		{name: "a lapsed lease leaves the 30 second cap",
			in: kubernetes.DelayInput{Status: 500, Failures: 10, Remaining: -5 * time.Second, Jitter: even}, want: 30 * time.Second},
		{name: "a transport error backs off like a 500",
			in: kubernetes.DelayInput{Failures: 2, Jitter: even}, want: 2 * time.Second},
		{name: "a redirect backs off like a 500",
			in: kubernetes.DelayInput{Status: 307, Failures: 2, Jitter: even}, want: 2 * time.Second},
		{name: "a 429 without Retry-After backs off",
			in: kubernetes.DelayInput{Status: 429, Failures: 2, Jitter: even}, want: 2 * time.Second},
		{name: "a 401 waits 30 seconds flat",
			in: kubernetes.DelayInput{Status: 401, Failures: 7, Remaining: 8 * time.Second}, want: 30 * time.Second},
		{name: "a 403 waits 30 seconds flat",
			in: kubernetes.DelayInput{Status: 403, Failures: 1}, want: 30 * time.Second},
		{name: "a 422 waits five minutes flat",
			in: kubernetes.DelayInput{Status: 422, Failures: 9, Remaining: time.Minute}, want: 5 * time.Minute},
		{name: "a 503 waits its Retry-After",
			in: kubernetes.DelayInput{Status: 503, RetryAfter: 7 * time.Second, HasRetryAfter: true, Failures: 4}, want: 7 * time.Second},
		{name: "a 429 waits its Retry-After",
			in: kubernetes.DelayInput{Status: 429, RetryAfter: 20 * time.Second, HasRetryAfter: true, Failures: 1}, want: 20 * time.Second},
		{name: "a Retry-After over five minutes is cut to five without a held grant",
			in: kubernetes.DelayInput{Status: 503, RetryAfter: time.Hour, HasRetryAfter: true, Failures: 1}, want: 5 * time.Minute},
		{name: "a Retry-After over a quarter of the held lease is cut to it",
			in: kubernetes.DelayInput{Status: 503, RetryAfter: time.Minute, HasRetryAfter: true, Failures: 1, Remaining: 2 * time.Minute}, want: 30 * time.Second},
		{name: "a Retry-After in the past waits a second",
			in: kubernetes.DelayInput{Status: 503, RetryAfter: -10 * time.Second, HasRetryAfter: true, Failures: 1}, want: time.Second},
		{name: "a Retry-After of zero waits a second",
			in: kubernetes.DelayInput{Status: 429, HasRetryAfter: true, Failures: 1}, want: time.Second},
		{name: "a Retry-After on a 500 is not honoured",
			in: kubernetes.DelayInput{Status: 500, RetryAfter: time.Minute, HasRetryAfter: true, Failures: 1, Jitter: even}, want: time.Second},
		{name: "the lowest jitter draw takes a quarter off",
			in: kubernetes.DelayInput{Status: 500, Failures: 10, Jitter: 0}, want: 22500 * time.Millisecond},
		{name: "the highest jitter draw adds under a quarter",
			in:      kubernetes.DelayInput{Status: 500, Failures: 10, Jitter: 0.999999},
			wantMin: 37 * time.Second, wantMax: 37500 * time.Millisecond},
		{name: "jitter applies after the lease cap",
			in:      kubernetes.DelayInput{Status: 500, Failures: 10, Remaining: 40 * time.Second, Jitter: 0.999999},
			wantMin: 12 * time.Second, wantMax: 12500 * time.Millisecond},
		{name: "jitter never goes under the floor",
			in: kubernetes.DelayInput{Status: 500, Failures: 1, Jitter: 0}, want: time.Second},
		{name: "jitter leaves the flat waits alone",
			in: kubernetes.DelayInput{Status: 401, Failures: 1, Jitter: 0}, want: 30 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := kubernetes.NextDelay(c.in)
			if c.want != 0 && got != c.want {
				t.Fatalf("NextDelay = %s, want %s", got, c.want)
			}
			if c.want == 0 && (got < c.wantMin || got >= c.wantMax) {
				t.Fatalf("NextDelay = %s, want in [%s, %s)", got, c.wantMin, c.wantMax)
			}
		})
	}
}
