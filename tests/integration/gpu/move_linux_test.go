//go:build linux && integration && gpu

// Package gputest holds the GPU PoC's move test, TestMoveAcrossGPUs
// (docs/proposals/gpu-poc.md, "The move test"). A fiber's CPU state and
// its device slice leave one home and resume on another through a delta
// registry. hack/gpu/move.sh runs its halves on the two VMs, and
// FIBERD_GPU_MOVE=local runs both here, on simulated engines when no
// device is named.
package gputest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/core"
	fiberendpoint "github.com/helayoty/fiberd/pkg/endpoint"
	"github.com/helayoty/fiberd/pkg/fiberd"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/tests/internal/testenv"
)

// The slice a fiber fills, its grant's device budget and the engine
// pools in MiB. The small pool cannot hold the slice. stateRoot holds
// every home's state, and the park and resume homes use the same path
// under it on both VMs.
const (
	sliceBytes   = 16 << 20
	deviceBudget = 32 << 20
	poolMB       = 64
	smallPoolMB  = 8
	fillSeed     = 20261022
	otherLayout  = "other"
	zygoteArgs   = "--heap-mb 32 --http"
	stateRoot    = "/var/lib/fiberd/gpu-move"
)

// cgRoot is the cgroup subtree the dev container delegates to the tests.
var cgRoot string

func TestMain(m *testing.M) {
	testenv.OwnMountNamespace()
	cgRoot = testenv.RequireCgroupRoot("gpu")
	os.Exit(m.Run())
}

// move is one run of the test.
type move struct {
	env  moveEnv
	logs *tap
	keys keyFiles
	is   *grant.Issuer
	tpl  tmpl
}

// TestMoveAcrossGPUs moves a named session with a device slice between
// two homes through the delta registry. FIBERD_GPU_MOVE picks the half.
// park clones the session on one home, fills its slice and parks it.
// resume claims it on another, checks its counter and its slice, and runs
// the refusals. local runs both in this process, a home per device.
func TestMoveAcrossGPUs(t *testing.T) {
	env := readEnv(t)
	logs := tapLogs(t, env.phase)
	if err := os.RemoveAll(stateRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	var keys keyFiles
	if env.keys != "" {
		keys = keysIn(env.keys)
	} else {
		keys = makeKeys(t, t.TempDir())
	}
	m := &move{env: env, logs: logs, keys: keys, is: startIssuer(t, keys.issuer)}
	switch env.phase {
	case "park":
		m.tpl = m.template(t, true)
		m.park(t, homeSpec{name: "a1", dir: "home", device: env.devA1, poolMB: poolMB})
	case "resume":
		m.tpl = m.template(t, false)
		m.resume(t, homeSpec{name: "b", dir: "home", device: env.devB, poolMB: poolMB})
	case "local":
		m.tpl = m.template(t, true)
		m.park(t, homeSpec{name: "a1", dir: "a1", device: env.devA1, poolMB: poolMB})
		m.resume(t, homeSpec{name: "a2", dir: "a2", device: env.devA2, poolMB: poolMB})
	}
}

// moveEnv is what hack/gpu/move.sh passes, as FIBERD_GPU_* variables.
type moveEnv struct {
	phase    string
	registry string
	keys     string
	session  string
	engine   string
	devA1    string
	devA2    string
	devB     string
}

// readEnv reads the run's settings. Without FIBERD_GPU_MOVE the test
// skips, since it runs only when asked.
func readEnv(t *testing.T) moveEnv {
	t.Helper()
	e := moveEnv{
		phase:   os.Getenv("FIBERD_GPU_MOVE"),
		keys:    os.Getenv("FIBERD_GPU_MOVE_KEYS"),
		session: os.Getenv("FIBERD_GPU_MOVE_SESSION"),
		engine:  os.Getenv("FIBERD_GPU_ENGINE"),
		devA1:   os.Getenv("FIBERD_GPU_MOVE_DEVICES_A1"),
		devA2:   os.Getenv("FIBERD_GPU_MOVE_DEVICES_A2"),
		devB:    os.Getenv("FIBERD_GPU_MOVE_DEVICES_B"),
	}
	if e.phase == "" {
		t.Skip("FIBERD_GPU_MOVE is not set. hack/gpu/move.sh sets it on the VMs, and FIBERD_GPU_MOVE=local runs both halves here")
	}
	if r := os.Getenv("FIBERD_GPU_MOVE_REGISTRY"); r != "" {
		e.registry = "http://" + r
	}
	if e.session == "" {
		e.session = "gpu-move"
	}
	if e.engine == "" {
		e.engine = filepath.Join(testenv.RepoRoot(), "bin", "refengine")
	}
	if _, err := os.Stat(e.engine); err != nil {
		t.Fatalf("no device engine at %s (make engine builds it): %v", e.engine, err)
	}
	switch e.phase {
	case "park", "resume":
		if e.registry == "" || e.keys == "" {
			t.Fatalf("the %s phase moves through a registry with shared keys. Set FIBERD_GPU_MOVE_REGISTRY and FIBERD_GPU_MOVE_KEYS", e.phase)
		}
	case "local":
		if (e.devA1 == "") != (e.devA2 == "") {
			t.Fatal("the local phase needs both FIBERD_GPU_MOVE_DEVICES_A1 and _A2, or neither for simulated engines")
		}
	default:
		t.Fatalf("FIBERD_GPU_MOVE=%q, want park, resume or local", e.phase)
	}
	return e
}

// keyFiles are the shared keys, named as hack/gpu/move.sh's keygen writes
// them.
type keyFiles struct{ issuer, delta, seal, fleet string }

func keysIn(dir string) keyFiles {
	return keyFiles{issuer: filepath.Join(dir, "issuer-key.json"), delta: filepath.Join(dir, "delta-key.json"),
		seal: filepath.Join(dir, "delta-seal-key.json"), fleet: filepath.Join(dir, "fleet-pub.json")}
}

// makeKeys writes a fresh set into dir, as that keygen does, for a local
// run given none.
func makeKeys(t *testing.T, dir string) keyFiles {
	t.Helper()
	k := keysIn(dir)
	for _, path := range []string{k.issuer, k.delta} {
		key, err := grant.GenerateKey(jose.EdDSA)
		if err != nil {
			t.Fatal(err)
		}
		if err := grant.SaveKey(path, key); err != nil {
			t.Fatal(err)
		}
	}
	master, err := artifact.GenerateSealKey()
	if err != nil {
		t.Fatal(err)
	}
	seal, err := artifact.SealKeyFromJWK(master)
	if err != nil {
		t.Fatal(err)
	}
	wrap, err := artifact.DeriveWrapKey(seal)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := wrap.PublicJWK()
	if err != nil {
		t.Fatal(err)
	}
	if err := grant.SaveKey(k.seal, master); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(k.fleet, append(pub, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	return k
}

// startIssuer serves the issuer key's discovery document and key set on
// loopback, as grant-issuer serve does, so every home verifies the grants
// it mints.
func startIssuer(t *testing.T, keyPath string) *grant.Issuer {
	t.Helper()
	key, err := grant.LoadKey(keyPath)
	if err != nil {
		t.Fatalf("issuer key: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	is := &grant.Issuer{Key: key, URL: "http://" + ln.Addr().String()}
	srv := &http.Server{Handler: is.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return is
}

// tap holds everything fiberd logs, so the test finds the engine's GPU
// facts and the park and resume lines in it.
type tap struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *tap) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

// mark is where the next line will start.
func (l *tap) mark() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Len()
}

// since is what was logged from mark at on.
func (l *tap) since(at int) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()[at:]
}

// wait polls for a line from mark at on that re matches, and returns its
// submatches.
func (l *tap) wait(t *testing.T, at int, re *regexp.Regexp, what string) []string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if m := re.FindStringSubmatch(l.since(at)); m != nil {
			return m
		}
		if time.Now().After(deadline) {
			t.Fatalf("fiberd logged no line for %s in 30s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// tail is the last n lines logged.
func (l *tap) tail(n int) string {
	lines := strings.Split(strings.TrimRight(l.since(0), "\n"), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}

// tapLogs sends fiberd's log to a tap and to bin/gpu-move/fiberd-<phase>.log
// in the checkout, which stays on the VM after the dev container ends.
func tapLogs(t *testing.T, phase string) *tap {
	t.Helper()
	dir := filepath.Join(testenv.RepoRoot(), "bin", "gpu-move")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "fiberd-"+phase+".log")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	l := &tap{}
	log.SetOutput(io.MultiWriter(f, l))
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		_ = f.Close()
		if t.Failed() {
			t.Logf("the last lines fiberd logged, all of them in %s:\n%s", path, l.tail(60))
			return
		}
		t.Logf("fiberd's log is in %s", path)
	})
	return l
}

// The fiberd lines the test reads, for one grant uid and session. The
// GPU fields may be empty, for an engine that names no GPU.
func factsLine(uid string) *regexp.Regexp {
	return regexp.MustCompile(`host: device engine of ` + regexp.QuoteMeta(uid) + ` is (\S+) on (\S*) cc (\S*) driver (\S*)`)
}

func parkedLine(uid string) *regexp.Regexp {
	return regexp.MustCompile(`host: parked device slice of ` + regexp.QuoteMeta(uid) + `/\S+: delta=(\d+) slice=(\d+) bytes, saved in (\S+)`)
}

func publishedLine(uid, session string) *regexp.Regexp {
	return regexp.MustCompile(`host: published ` + regexp.QuoteMeta(uid+"/"+session) + ` as (\S+)@sha256:`)
}

func fitsLine(uid, session string) *regexp.Regexp {
	return regexp.MustCompile(`host: ` + regexp.QuoteMeta(uid+"/"+session) + ` fits engine (\S+) (\S+) here: ` +
		`saved by version (\S*) on (\S*) cc (\S*) driver (\S*), here version (\S*) on (\S*) cc (\S*) driver (\S*)`)
}

func restoredLine(uid string) *regexp.Regexp {
	return regexp.MustCompile(`host: restored device slice of ` + regexp.QuoteMeta(uid) + `/\S+: (\d+) bytes in (\S+)`)
}

func returnedLine(uid, session string) *regexp.Regexp {
	return regexp.MustCompile(`host: returned ` + regexp.QuoteMeta(uid+"/"+session) + ` to the registry`)
}

// tmpl is the zygote every home serves, under one digest, which with the
// tenant is the session's domain. repo is the -registry it is pulled
// from, or empty for a -template command.
type tmpl struct {
	digest  string
	repo    string
	command string
}

// template makes the zygote's template. With a registry the parking side
// builds the artifact, its images sealed to the fleet, and pushes it as
// hack/test/mobility.sh does, and the resuming side finds its digest
// under the same tag. A local run gets a tag of its own, so it never
// replaces the template a parked session needs. Without a registry the
// homes run the zygote as a -template command.
func (m *move) template(t *testing.T, build bool) tmpl {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if m.env.registry == "" {
		bin := buildZygote(t)
		b, err := os.ReadFile(bin)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		return tmpl{digest: "sha256:" + hex.EncodeToString(sum[:]), command: bin + " " + zygoteArgs}
	}
	repo := m.env.registry + "/zygotes/gpu-move"
	ref := repo + ":" + m.env.session
	if m.env.phase == "local" {
		ref += "-local"
	}
	if !build {
		loc, found, err := artifact.Resolve(ctx, ref)
		if err != nil || !found {
			t.Fatalf("template %s: found %v, %v. The park phase pushes it", ref, found, err)
		}
		t.Logf("template %s, from %s", loc.Digest, ref)
		return tmpl{digest: loc.Digest, repo: repo}
	}
	pub, err := artifact.LoadWrapPublicKey(m.keys.fleet)
	if err != nil {
		t.Fatalf("the fleet's wrap key: %v", err)
	}
	out := filepath.Join(t.TempDir(), "art")
	opts := artifact.BuildOptions{Zygote: buildZygote(t), Args: strings.Fields(zygoteArgs), Out: out, SealTo: pub}
	if _, err := artifact.Build(ctx, opts); err != nil {
		t.Fatalf("build the template: %v", err)
	}
	digest, err := artifact.Push(ctx, out, ref)
	if err != nil {
		t.Fatalf("push the template: %v", err)
	}
	t.Logf("template %s, pushed to %s", digest, ref)
	return tmpl{digest: digest, repo: repo}
}

// buildZygote compiles the reference zygote for this run.
func buildZygote(t *testing.T) string {
	t.Helper()
	bin, err := testenv.BuildZygote(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return bin
}

// homeSpec is one home of the move. name is its node id and its grant's
// audience, and dir its state directory under stateRoot. The park and
// resume homes share dir across the VMs, since a proc restore reopens
// the template where the parking home cached it. device is the GPU or
// MIG UUID its engine drives, empty for a simulated pool. layout, when
// set, replaces the engine's own.
type homeSpec struct {
	name   string
	dir    string
	device string
	poolMB int
	layout string
}

// home is a fiberd running in this process, and its grant.
type home struct {
	homeSpec
	uid    string
	token  string
	api    grantv1.FibersClient
	conn   *grpc.ClientConn
	cancel context.CancelFunc
	done   chan error
	once   sync.Once
}

// engineCommand is spec's -engine line. Without a device the pool is
// simulated, under a GPU name of the home's own.
func (m *move) engineCommand(spec homeSpec) string {
	cmd := fmt.Sprintf("%s --sim-mb %d --sim-name sim-%s", m.env.engine, spec.poolMB, spec.name)
	if spec.device != "" {
		cmd = fmt.Sprintf("%s --pool-mb %d", m.env.engine, spec.poolMB)
	}
	if spec.layout != "" {
		cmd += " --layout " + spec.layout
	}
	return cmd
}

// startHome runs a fiberd for spec on the proc runtime, with its device
// engine, the delta registry and the shared keys, as hack/test/mobility.sh
// starts its homes, and mints its grant. It returns once the API is
// bound. The home stops when the test ends, or earlier through stop.
func (m *move) startHome(t *testing.T, spec homeSpec) *home {
	t.Helper()
	state := filepath.Join(stateRoot, spec.dir)
	if err := os.MkdirAll(state, 0o755); err != nil {
		t.Fatal(err)
	}
	deltas := artifact.FileScheme + filepath.Join(stateRoot, "registry")
	if m.env.registry != "" {
		deltas = m.env.registry + "/deltas"
	}
	args := []string{"-state", state, "-node-id", spec.name, "-cgroup-root", homeCgroup(t, spec.name),
		"-listen", "127.0.0.1:0", "-insecure-plaintext", "-verifier", "jwks", "-issuer", m.is.URL, "-jwks-max-stale", "10m",
		"-runtime", "proc", "-engine", m.engineCommand(spec), "-delta-registry", deltas,
		"-delta-key", m.keys.delta, "-delta-seal-key", m.keys.seal}
	if m.tpl.repo != "" {
		args = append(args, "-registry", m.tpl.repo)
	} else {
		args = append(args, "-template", "default="+m.tpl.command)
	}
	if spec.device != "" {
		args = append(args, "-devices", spec.device)
	}
	flags := flag.NewFlagSet("fiberd", flag.ContinueOnError)
	var c fiberd.Config
	c.Bind(flags)
	if err := flags.Parse(args); err != nil {
		t.Fatal(err)
	}
	ready := make(chan net.Addr, 1)
	c.Ready = func(g, _, _ net.Addr) { ready <- g }
	ctx, cancel := context.WithCancel(context.Background())
	h := &home{homeSpec: spec, uid: "gpu-move-" + spec.name, cancel: cancel, done: make(chan error, 1)}
	go func() { h.done <- fiberd.RunContext(ctx, &c, fiberd.Standalone) }()
	t.Cleanup(func() { h.stop(t) })
	var addr net.Addr
	select {
	case addr = <-ready:
	case err := <-h.done:
		h.done <- err // stop reads it too
		t.Fatalf("%s: fiberd: %v", spec.name, err)
	case <-time.After(30 * time.Second):
		t.Fatalf("%s: fiberd did not come up in 30s", spec.name)
	}
	conn, err := grpc.NewClient(addr.String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	h.conn, h.api = conn, grantv1.NewFibersClient(conn)
	g := core.Grant{UID: h.uid, Audience: spec.name, Tenant: "acme", TemplateDigest: m.tpl.digest, FiberMax: 4,
		WBudgetBytes: 64 << 20, MinTier: core.TierCheckpoint, LeaseExpiry: time.Now().Add(time.Hour).Truncate(time.Second),
		Policy: core.Policy{Isolation: core.Trusted}, DeviceBudget: core.DeviceBudget{Bytes: deviceBudget}}
	if h.token, err = m.is.Mint(g); err != nil {
		t.Fatal(err)
	}
	drives := "a simulated pool"
	if spec.device != "" {
		drives = spec.device
	}
	t.Logf("%s: fiberd up, its engine on %s: %s", spec.name, drives, m.engineCommand(spec))
	return h
}

// stop ends the home's fiberd and waits for it. Its state stays, since a
// later home may resume what it parked or returned.
func (h *home) stop(t *testing.T) {
	t.Helper()
	h.once.Do(func() {
		h.cancel()
		select {
		case err := <-h.done:
			if err != nil {
				t.Logf("%s: fiberd returned %v", h.name, err)
			}
		case <-time.After(30 * time.Second):
			t.Errorf("%s: fiberd did not stop in 30s", h.name)
		}
		if h.conn != nil {
			_ = h.conn.Close()
		}
	})
}

// homeCgroup is a fresh delegated cgroup for one home, removed leaves
// first when the test ends.
func homeCgroup(t *testing.T, name string) string {
	t.Helper()
	root := filepath.Join(cgRoot, fmt.Sprintf("gpu-move-%s-%d", name, os.Getpid()))
	t.Cleanup(func() {
		var dirs []string
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				dirs = append(dirs, p)
			}
			return nil
		})
		slices.Reverse(dirs)
		for _, d := range dirs {
			_ = os.Remove(d)
		}
	})
	return root
}

// clone asks the home for a fiber of the session.
func (h *home) clone(session string) (*grantv1.CloneResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return h.api.Clone(ctx, &grantv1.CloneRequest{GrantJwt: h.token, Session: session})
}

// park parks the fiber and waits for its delta.
func (h *home) park(t *testing.T, fiberID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := h.api.Park(ctx, &grantv1.ParkRequest{FiberId: fiberID, Sync: true}); err != nil {
		t.Fatalf("%s: park %s: %v", h.name, fiberID, err)
	}
}

// release ends the fiber and discards its session.
func (h *home) release(t *testing.T, fiberID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := h.api.Release(ctx, &grantv1.ReleaseRequest{FiberId: fiberID, Discard: true}); err != nil {
		t.Errorf("%s: release %s: %v", h.name, fiberID, err)
	}
}

// park is the parking home's half. It clones the session, fills its slice
// from a seed, counts to 3, parks and publishes. The fiber keeps the
// slice's hash in its own memory, so a later check proves the CPU state
// and the slice arrived as one session.
func (m *move) park(t *testing.T, spec homeSpec) {
	t.Helper()
	at := m.logs.mark()
	h := m.startHome(t, spec)
	r, err := h.clone(m.env.session)
	if err != nil {
		t.Fatalf("%s: clone %s: %v", spec.name, m.env.session, err)
	}
	if r.GetKind() != grantv1.CloneKind_CREATE {
		t.Fatalf("%s: clone %s is %v, want CREATE of a new session", spec.name, m.env.session, r.GetKind())
	}
	t.Logf("%s: fiber %s, its engine %s", spec.name, r.GetFiberId(), m.engineFacts(t, h, at))
	ep := r.GetEndpoint()
	st, body := fiberHTTP(t, ep, "POST", fmt.Sprintf("/gpu/fill?seed=%d&bytes=%d", fillSeed, sliceBytes))
	if st != http.StatusOK || !strings.HasPrefix(body, "ok ") {
		t.Fatalf("%s: POST /gpu/fill = %d %q, want ok and a hash", spec.name, st, body)
	}
	t.Logf("%s: filled %d bytes from seed %d, and the fiber keeps hash %s", spec.name, sliceBytes, fillSeed, strings.TrimPrefix(body, "ok "))
	for range 3 {
		fiberHTTP(t, ep, "POST", "/incr")
	}
	wantCount(t, h, ep, 3)
	wantSlice(t, h, ep)
	at = m.logs.mark()
	h.park(t, r.GetFiberId())
	p := m.logs.wait(t, at, parkedLine(h.uid), spec.name+" saving the slice")
	t.Logf("%s: parked, a delta of %s bytes and a slice of %s bytes, SAVE took %s", spec.name, p[1], p[2], p[3])
	ref, loc := m.published(t, h, at)
	t.Logf("%s: published to %s, %s", spec.name, ref, facts(loc))
	h.stop(t)
}

// resume is the resuming home's half, spec's home. It claims and resumes
// the session parked elsewhere and compares the GPUs. Then it counts to 4
// and parks the session again, so the refusal homes have a delta to
// refuse, and takes it back once they are done.
func (m *move) resume(t *testing.T, spec homeSpec) {
	t.Helper()
	at := m.logs.mark()
	h := m.startHome(t, spec)
	fid, ep := m.wantResume(t, h, 3)
	t.Logf("%s: its engine %s", spec.name, m.engineFacts(t, h, at))
	f := m.logs.wait(t, at, fitsLine(h.uid, m.env.session), spec.name+" comparing the engines")
	t.Logf("%s: engine %s %s. Saved by version %s on GPU %s cc %s driver %s, resumed by version %s on GPU %s cc %s driver %s",
		spec.name, f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8], f[9], f[10])
	switch {
	case !slices.Equal(f[4:7], f[8:11]):
		t.Logf("%s: the GPU facts differ", spec.name)
	case m.env.phase == "resume" || spec.device == "":
		t.Errorf("%s: the GPU facts are the same on both homes, want another GPU", spec.name)
	default:
		t.Logf("%s: the GPU facts are the same, as two MIG instances of one GPU report. The devices were %s and %s", spec.name, m.env.devA1, spec.device)
	}

	fiberHTTP(t, ep, "POST", "/incr")
	wantCount(t, h, ep, 4)
	at = m.logs.mark()
	h.park(t, fid)
	m.logs.wait(t, at, parkedLine(h.uid), spec.name+" saving the slice again")
	ref, loc := m.published(t, h, at)
	t.Logf("%s: parked again and published to %s, %s", spec.name, ref, facts(loc))

	m.wrongLayout(t, spec.device, ref, loc)
	m.smallPool(t, spec.device, ref)

	fid, _ = m.wantResume(t, h, 4)
	h.release(t, fid)
	t.Logf("%s: resumed again after the refusals, with its counter and its slice", spec.name)
}

// wantResume clones the session on h and fails unless it resumes with the
// counter at count and the slice as the fiber filled it. It logs the
// RESTORE.
func (m *move) wantResume(t *testing.T, h *home, count int) (fiberID, endpoint string) {
	t.Helper()
	at := m.logs.mark()
	r, err := h.clone(m.env.session)
	if err != nil {
		t.Fatalf("%s: clone %s: %v", h.name, m.env.session, err)
	}
	if r.GetKind() != grantv1.CloneKind_RESUME {
		t.Fatalf("%s: clone %s is %v, want RESUME of the parked session", h.name, m.env.session, r.GetKind())
	}
	rs := m.logs.wait(t, at, restoredLine(h.uid), h.name+" restoring the slice")
	t.Logf("%s: resumed as %s, RESTORE of %s bytes took %s", h.name, r.GetFiberId(), rs[1], rs[2])
	wantCount(t, h, r.GetEndpoint(), count)
	wantSlice(t, h, r.GetEndpoint())
	return r.GetFiberId(), r.GetEndpoint()
}

// wrongLayout starts a home whose engine declares another layout. Its
// Clone of the session must be refused before the claim, naming both
// layouts, and the session must stay in the registry as it was.
func (m *move) wrongLayout(t *testing.T, device, ref string, parked artifact.Located) {
	t.Helper()
	layout := parked.Annotations[artifact.AnnotationEngineLayout]
	if layout == "" {
		t.Fatalf("the delta at %s names no engine layout", ref)
	}
	h := m.startHome(t, homeSpec{name: "layout", dir: "layout", device: device, poolMB: poolMB, layout: otherLayout})
	defer h.stop(t)
	r, err := h.clone(m.env.session)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("layout: clone on an engine of layout %s is %v, %v, want FailedPrecondition", otherLayout, r.GetKind(), err)
	}
	msg := status.Convert(err).Message()
	if !strings.Contains(msg, "layout "+otherLayout+" here") || !strings.Contains(msg, layout+" in the delta") {
		t.Fatalf("layout: refused with %q, want both layouts named, %s here and %s in the delta", msg, otherLayout, layout)
	}
	t.Logf("layout: refused before the claim: %s", msg)
	m.inRegistry(t, ref, parked.Digest)
	t.Logf("layout: the session stays in the registry at %s", ref)
}

// smallPool starts a home whose engine's pool is smaller than the slice.
// The claim goes through, the RESTORE fails for capacity, and the failed
// resume returns the session to the registry.
func (m *move) smallPool(t *testing.T, device, ref string) {
	t.Helper()
	h := m.startHome(t, homeSpec{name: "small", dir: "small", device: device, poolMB: smallPoolMB})
	defer h.stop(t)
	at := m.logs.mark()
	r, err := h.clone(m.env.session)
	if err == nil {
		t.Fatalf("small: clone on a %d MiB pool is %v, want the resume of a %d byte slice to fail", smallPoolMB, r.GetKind(), sliceBytes)
	}
	m.logs.wait(t, at, returnedLine(h.uid, m.env.session), "small returning the session")
	if !strings.Contains(err.Error()+m.logs.since(at), "capacity") {
		t.Errorf("small: the failed resume names no capacity: %v", err)
	}
	t.Logf("small: the resume failed: %v", err)
	m.inRegistry(t, ref, "")
	t.Logf("small: the session is back in the registry at %s", ref)
}

// engineFacts waits for the facts h's engine declared at its start, from
// mark at on.
func (m *move) engineFacts(t *testing.T, h *home, at int) string {
	t.Helper()
	f := m.logs.wait(t, at, factsLine(h.uid), h.name+"'s engine facts")
	return fmt.Sprintf("class %s, GPU %s cc %s driver %s", f[1], f[2], f[3], f[4])
}

// published waits for h's publish of the session and returns the ref it
// went to, with what the registry holds there.
func (m *move) published(t *testing.T, h *home, at int) (string, artifact.Located) {
	t.Helper()
	ref := m.logs.wait(t, at, publishedLine(h.uid, m.env.session), h.name+" publishing the session")[1]
	return ref, m.inRegistry(t, ref, "")
}

// inRegistry fails unless the registry holds the session at ref, at
// digest when one is named, and returns what is there.
func (m *move) inRegistry(t *testing.T, ref, digest string) artifact.Located {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	loc, found, err := artifact.Resolve(ctx, ref)
	switch {
	case err != nil:
		t.Fatalf("resolve %s: %v", ref, err)
	case !found:
		t.Fatalf("the registry holds no session at %s", ref)
	case digest != "" && loc.Digest != digest:
		t.Fatalf("%s holds %s, want %s", ref, loc.Digest, digest)
	}
	return loc
}

// facts is the engine facts a delta's annotations carry.
func facts(loc artifact.Located) string {
	a := loc.Annotations
	return fmt.Sprintf("engine class %s layout %s version %s, GPU %s cc %s driver %s", a[artifact.AnnotationEngineClass],
		a[artifact.AnnotationEngineLayout], a[artifact.AnnotationEngineVersion], a[artifact.AnnotationGPUName],
		a[artifact.AnnotationGPUCC], a[artifact.AnnotationGPUDriver])
}

// fiberHTTP sends one request to a fiber's --http endpoint and returns the
// status and the body without its newline.
func fiberHTTP(t *testing.T, endpoint, method, path string) (int, string) {
	t.Helper()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return fiberendpoint.Dial(ctx, endpoint)
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: time.Minute}
	req, err := http.NewRequest(method, "http://fiber"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp.StatusCode, strings.TrimSpace(string(b))
}

// wantCount fails unless the fiber's counter is want.
func wantCount(t *testing.T, h *home, endpoint string, want int) {
	t.Helper()
	if st, body := fiberHTTP(t, endpoint, "GET", "/count"); st != http.StatusOK || body != fmt.Sprint(want) {
		t.Fatalf("%s: GET /count = %d %q, want %d", h.name, st, body, want)
	}
}

// wantSlice fails unless the fiber finds its slice as it filled it.
func wantSlice(t *testing.T, h *home, endpoint string) {
	t.Helper()
	if st, body := fiberHTTP(t, endpoint, "GET", "/gpu/check"); st != http.StatusOK || body != "ok" {
		t.Fatalf("%s: GET /gpu/check = %d %q, want ok", h.name, st, body)
	}
}
