//go:build linux

package proctest

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/registry"

	"github.com/helayoty/fiberd/pkg/artifact"
	procbackend "github.com/helayoty/fiberd/pkg/backend/proc"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/runtime/host"
)

// newHost opens the host runtime over the fork backend, as fiberd
// -runtime proc does.
func newHost(c host.Config) (core.Runtime, error) {
	c.Backend = procbackend.New(procbackend.Options{})
	return host.New(c)
}

var (
	zygoteBin string
	cgRoot    = os.Getenv("FIBERD_CGROUP_ROOT")
)

func TestMain(m *testing.M) {
	if cgRoot == "" {
		cgRoot = "/sys/fs/cgroup/fiberd"
	}
	if f, err := os.OpenFile(filepath.Join(cgRoot, "cgroup.subtree_control"), os.O_WRONLY, 0); err != nil {
		fmt.Fprintf(os.Stderr, "skipping proc tests: %s not writable (run under make linux-test)\n", cgRoot)
		os.Exit(0)
	} else {
		_ = f.Close()
	}
	dir, err := os.MkdirTemp("", "refzygote")
	if err != nil {
		panic(err)
	}
	zygoteBin = filepath.Join(dir, "refzygote")
	build := exec.Command("gcc", "-O2", "-o", zygoteBin, "../../hack/zygote/refzygote.c", "../../hack/zygote/libfiberzygote.c")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "skipping proc tests: cannot build refzygote: %v\n", err)
		os.Exit(0)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func newRuntime(t *testing.T) core.Runtime {
	t.Helper()
	run := filepath.Join("/tmp", "fz-"+fmt.Sprint(os.Getpid()))
	rt, err := newHost(host.Config{
		Templates:  map[string]string{"default": zygoteBin + " --heap-mb 32"},
		CgroupRoot: filepath.Join(cgRoot, "t"+fmt.Sprint(time.Now().UnixNano()%1_000_000)),
		RunDir:     run,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if c, ok := rt.(interface{ Close() }); ok {
			c.Close()
		}
		_ = os.RemoveAll(run)
	})
	return rt
}

// talk sends one line to a fiber's endpoint and returns the reply.
func talk(t *testing.T, endpoint, line string) string {
	t.Helper()
	c, err := net.DialTimeout("unix", strings.TrimPrefix(endpoint, "unix://"), 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", endpoint, err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintln(c, line); err != nil {
		t.Fatal(err)
	}
	reply, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("read reply to %q: %v", line, err)
	}
	return strings.TrimSpace(reply)
}

func TestCloneServeStatsRelease(t *testing.T) {
	rt := newRuntime(t)
	ctx := context.Background()
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatalf("second prepare must be idempotent: %v", err)
	}
	fence := core.Fence{GrantUID: "g1", Epoch: 1, Seq: 1}
	t0 := time.Now()
	h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: fence, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("fork-to-ready: %s", time.Since(t0))
	if h.ID != "g1/1/1" || !strings.HasPrefix(h.Endpoint, "unix://") {
		t.Fatalf("handle = %+v", h)
	}
	if got := talk(t, h.Endpoint, "ping"); got != "pong" {
		t.Fatalf("ping = %q", got)
	}
	if got := talk(t, h.Endpoint, "fence"); got != "g1/1/1" {
		t.Fatalf("fence = %q, want the identity assigned after the fork", got)
	}
	// Identity lives only in the child: the environment was scrubbed and
	// the fence set afterwards. (Asked of the process itself: the kernel's
	// /proc/<pid>/environ shows the exec-time block, not what clearenv did.)
	if got := talk(t, h.Endpoint, "getenv FIBERD_FENCE"); got != "g1/1/1" {
		t.Fatalf("FIBERD_FENCE in child = %q", got)
	}
	for _, name := range []string{"PATH", "FIBERD_GRANT", "HOME"} {
		if got := talk(t, h.Endpoint, "getenv "+name); got != "-" {
			t.Fatalf("%s survived the scrub: %q", name, got)
		}
	}

	before, _ := rt.Stats(ctx, h.ID)
	if got := talk(t, h.Endpoint, "dirty 8388608"); got != "ok 8388608" {
		t.Fatalf("dirty = %q", got)
	}
	after, _ := rt.Stats(ctx, h.ID)
	if after.WUsedBytes < before.WUsedBytes+7<<20 {
		t.Fatalf("W before=%d after=%d, want >= 8 MiB growth from dirtying (CoW charged to the leaf)", before.WUsedBytes, after.WUsedBytes)
	}
	t.Logf("W before=%d after=%d", before.WUsedBytes, after.WUsedBytes)

	if got := talk(t, h.Endpoint, "incr"); got != "1" {
		t.Fatalf("incr = %q", got)
	}
	list, err := rt.List(ctx)
	if err != nil || len(list) != 1 || list[0].ID != h.ID {
		t.Fatalf("list = %+v %v", list, err)
	}
	if err := rt.Release(ctx, h.ID, false); err != nil {
		t.Fatal(err)
	}
	select {
	case ex := <-rt.Exits():
		t.Fatalf("release must not report an exit, got %+v", ex)
	case <-time.After(200 * time.Millisecond):
	}
	if list, _ := rt.List(ctx); len(list) != 0 {
		t.Fatalf("after release list = %+v", list)
	}
	if _, err := os.Stat(strings.TrimPrefix(h.Endpoint, "unix://")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("endpoint not cleaned: %v", err)
	}
}

func TestParkResumeKeepsState(t *testing.T) {
	rt := newRuntime(t)
	if rt.Tier() < core.TierCheckpoint {
		t.Skip("criu not usable here; runtime offers", rt.Tier())
	}
	ctx := context.Background()
	g := core.Grant{UID: "g5", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	f1 := core.Fence{GrantUID: "g5", Epoch: 1, Seq: 1}
	h1, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: f1, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	talk(t, h1.Endpoint, "incr")
	if got := talk(t, h1.Endpoint, "incr"); got != "2" {
		t.Fatalf("incr = %q", got)
	}

	// Sync park: images durable, then the incarnation ends. No exit is
	// reported (it was ours), the leaf and endpoint are gone.
	t0 := time.Now()
	ref, err := rt.Park(ctx, h1.ID, true)
	if err != nil {
		t.Fatalf("park: %v", err)
	}
	t.Logf("park (sync): %s -> %s", time.Since(t0), ref)
	select {
	case ex := <-rt.Exits():
		t.Fatalf("park must not report an exit, got %+v", ex)
	case <-time.After(200 * time.Millisecond):
	}
	if list, _ := rt.List(ctx); len(list) != 0 {
		t.Fatalf("after park list = %+v", list)
	}
	if _, err := os.Stat(filepath.Join(ref, "manifest.json")); err != nil {
		t.Fatalf("manifest missing: %v", err)
	}

	// Resume under a new fence: the counter survived, the endpoint is the
	// one the process bound, the new fence is published beside it.
	f2 := core.Fence{GrantUID: "g5", Epoch: 1, Seq: 2}
	t0 = time.Now()
	h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: f2, Deadline: 5 * time.Second})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	t.Logf("resume: %s", time.Since(t0))
	if h2.ID != "g5/1/2" || h2.Endpoint != h1.Endpoint {
		t.Fatalf("resumed handle = %+v (first %+v)", h2, h1)
	}
	if got := talk(t, h2.Endpoint, "get"); got != "2" {
		t.Fatalf("counter after resume = %q, want 2 (state must survive park/resume)", got)
	}
	if got := talk(t, h2.Endpoint, "incr"); got != "3" {
		t.Fatalf("incr after resume = %q", got)
	}
	pub, _ := os.ReadFile(strings.TrimPrefix(h2.Endpoint, "unix://") + ".fence")
	if strings.TrimSpace(string(pub)) != "g5/1/2" {
		t.Fatalf("published fence = %q", pub)
	}
	if st, err := rt.Stats(ctx, h2.ID); err != nil || st.WUsedBytes == 0 {
		t.Fatalf("stats after resume = %+v %v", st, err)
	}

	// Park again without sync, resume again, then release with discard.
	ref2, err := rt.Park(ctx, h2.ID, false)
	if err != nil {
		t.Fatalf("second park: %v", err)
	}
	f3 := core.Fence{GrantUID: "g5", Epoch: 1, Seq: 3}
	h3, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref2, Fence: f3, Deadline: 5 * time.Second})
	if err != nil {
		t.Fatalf("second resume: %v", err)
	}
	if got := talk(t, h3.Endpoint, "get"); got != "3" {
		t.Fatalf("counter after second resume = %q, want 3", got)
	}
	if err := rt.Release(ctx, h3.ID, true); err != nil {
		t.Fatal(err)
	}
	if list, _ := rt.List(ctx); len(list) != 0 {
		t.Fatalf("after release list = %+v", list)
	}
}

func TestOrphanAdoptionAcrossRuntimes(t *testing.T) {
	// A fiber left by a previous agent: a second runtime over the same
	// cgroup root must see it in List and be able to kill it by id.
	root := filepath.Join(cgRoot, "t"+fmt.Sprint(time.Now().UnixNano()%1_000_000))
	run := filepath.Join("/tmp", "fz-orphan")
	mk := func() core.Runtime {
		rt, err := newHost(host.Config{Templates: map[string]string{"default": zygoteBin + " --heap-mb 16"}, CgroupRoot: root, RunDir: run})
		if err != nil {
			t.Fatal(err)
		}
		return rt
	}
	ctx := context.Background()
	g := core.Grant{UID: "g6", TemplateDigest: "sha256:ref"}
	rt1 := mk()
	if err := rt1.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	h, err := rt1.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g6", Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	// Second runtime, same root, no knowledge of rt1's fibers.
	rt2 := mk()
	list, err := rt2.List(ctx)
	if err != nil || len(list) != 1 || list[0].ID != h.ID {
		t.Fatalf("second runtime list = %+v %v, want the orphan %s", list, err, h.ID)
	}
	if err := rt2.Release(ctx, h.ID, false); err != nil {
		t.Fatalf("release orphan: %v", err)
	}
	if list, _ := rt2.List(ctx); len(list) != 0 {
		t.Fatalf("orphan still listed: %+v", list)
	}
	if dc, ok := rt2.(core.DeltaChecker); !ok || dc.HasDelta("/nonexistent") {
		t.Fatal("HasDelta must report a missing delta as missing")
	}
	if c, ok := rt1.(interface{ Close() }); ok {
		c.Close()
	}
	_ = os.RemoveAll(run)
}

func TestParkIsWSizedDelta(t *testing.T) {
	rt := newRuntime(t)
	if rt.Tier() < core.TierCheckpoint {
		t.Skip("criu not usable here")
	}
	ctx := context.Background()
	g := core.Grant{UID: "g9", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g9", Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if got := talk(t, h.Endpoint, "pid"); got != "1" {
		t.Fatalf("fiber pid = %s, want 1 (own pid namespace)", got)
	}
	const dirty = 8 << 20
	talk(t, h.Endpoint, fmt.Sprintf("dirty %d", dirty))
	talk(t, h.Endpoint, "incr")
	t0 := time.Now()
	ref, err := rt.Park(ctx, h.ID, true)
	if err != nil {
		t.Fatalf("park: %v", err)
	}
	parkTook := time.Since(t0)
	var m struct {
		WBytes uint64 `json:"w_bytes"`
		Delta  bool   `json:"delta"`
	}
	b, _ := os.ReadFile(filepath.Join(ref, "manifest.json"))
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if !m.Delta {
		t.Fatal("park did not produce a delta")
	}
	// The delta is the dirtied working set: 8 MiB plus a few pages of
	// stack, libc state and socket buffers, well within the plan's 20%.
	lo, hi := uint64(dirty), uint64(dirty+dirty/5)
	if m.WBytes < lo || m.WBytes > hi {
		t.Fatalf("delta W = %d bytes, want within [%d, %d] for %d dirtied", m.WBytes, lo, hi, dirty)
	}
	pages, _ := os.Stat(filepath.Join(ref, "pages-1.img"))
	t.Logf("park (sync) %s: delta %d bytes for %d dirtied (pages file %d bytes, zygote heap 32 MiB)", parkTook.Round(time.Millisecond), m.WBytes, dirty, pages.Size())

	// Resume merges the delta with this home's zygote pages.
	h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: "g9", Epoch: 1, Seq: 2}, Deadline: 5 * time.Second})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if got := talk(t, h2.Endpoint, "get"); got != "1" {
		t.Fatalf("counter after resume = %q, want 1", got)
	}
	if got := talk(t, h2.Endpoint, "pid"); got != "1" {
		t.Fatalf("resumed fiber pid = %s, want 1", got)
	}
	_ = rt.Release(ctx, h2.ID, true)
}

func TestResumeOnAnotherRuntimeFromSameArtifact(t *testing.T) {
	// Two homes warmed from the same artifact: a session parked on A
	// resumes on B with its state, because B's zygote pages hash the same
	// as the parent the delta was taken over.
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "art")
	digest, err := artifact.Build(ctx, artifact.BuildOptions{Zygote: zygoteBin, Args: []string{"--heap-mb", "16"}, Out: out})
	if err != nil {
		t.Fatalf("build artifact: %v", err)
	}
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	reg := strings.TrimPrefix(srv.URL, "http://")
	if _, err := artifact.Push(ctx, out, reg+"/zygotes/ref:v1", true); err != nil {
		t.Fatal(err)
	}
	mk := func(name string) core.Runtime {
		rt, err := newHost(host.Config{
			Registry: reg + "/zygotes/ref", RegistryPlainHTTP: true, TemplateCache: t.TempDir(),
			CgroupRoot: filepath.Join(cgRoot, name+fmt.Sprint(time.Now().UnixNano()%1_000_000)),
			RunDir:     filepath.Join("/tmp", "fz-"+name), DeltaDir: t.TempDir(),
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if c, ok := rt.(interface{ Close() }); ok {
				c.Close()
			}
		})
		return rt
	}
	a, b := mk("ha"), mk("hb")
	if a.Tier() < core.TierCheckpoint {
		t.Skip("criu not usable here")
	}
	g := core.Grant{UID: "g10", TemplateDigest: digest, WBudgetBytes: 64 << 20}
	if err := a.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	if err := b.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	h, err := a.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g10", Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		talk(t, h.Endpoint, "incr")
	}
	talk(t, h.Endpoint, "dirty 2097152")
	ref, err := a.Park(ctx, h.ID, true)
	if err != nil {
		t.Fatalf("park on A: %v", err)
	}
	var m struct {
		WBytes uint64 `json:"w_bytes"`
		Delta  bool   `json:"delta"`
	}
	mb, _ := os.ReadFile(filepath.Join(ref, "manifest.json"))
	_ = json.Unmarshal(mb, &m)
	t.Logf("parked on A: delta=%v W=%d bytes", m.Delta, m.WBytes)

	h2, err := b.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: "g10", Epoch: 7, Seq: 1}, Deadline: 5 * time.Second})
	if err != nil {
		t.Fatalf("resume on B: %v", err)
	}
	if got := talk(t, h2.Endpoint, "get"); got != "3" {
		t.Fatalf("counter on B = %q, want 3 (state must move with the delta)", got)
	}
	if got := talk(t, h2.Endpoint, "incr"); got != "4" {
		t.Fatalf("incr on B = %q", got)
	}
	_ = b.Release(ctx, h2.ID, true)
}

// tokenVerifier hands back the grant named by the token: the agents in
// the mobility test share one grant and need no signatures.
type tokenVerifier map[string]core.Grant

func (v tokenVerifier) Verify(_ context.Context, tok []byte) (core.Grant, error) {
	g, ok := v[string(tok)]
	if !ok {
		return core.Grant{}, fmt.Errorf("unknown token %q", tok)
	}
	return g, nil
}

// TestSessionMovesThroughRegistry is the standalone acceptance of phase
// 6: two agents on one host, each with its own runtime warmed from the
// same artifact, a delta registry between them. Count to three on A, park,
// Clone(S) on B resumes with the count, and A no longer believes it holds
// the session.
func TestSessionMovesThroughRegistry(t *testing.T) {
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "art")
	digest, err := artifact.Build(ctx, artifact.BuildOptions{Zygote: zygoteBin, Args: []string{"--heap-mb", "16"}, Out: out})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	reg := strings.TrimPrefix(srv.URL, "http://")
	if _, err := artifact.Push(ctx, out, reg+"/zygotes/ref:v1", true); err != nil {
		t.Fatal(err)
	}
	// One grant per home (its own uid and audience), the same template:
	// that template is the domain the session moves within.
	grantFor := func(home string) core.Grant {
		return core.Grant{UID: "mob-" + home, Audience: home, TemplateDigest: digest, FiberMax: 4, WBudgetBytes: 32 << 20, LeaseExpiry: time.Now().Add(time.Hour)}
	}
	mk := func(home string) (*core.Agent, core.Runtime) {
		rt, err := newHost(host.Config{
			Registry: reg + "/zygotes/ref", RegistryPlainHTTP: true, TemplateCache: t.TempDir(),
			DeltaRegistry: reg + "/deltas", HomeID: home,
			CgroupRoot: filepath.Join(cgRoot, home+fmt.Sprint(time.Now().UnixNano()%1_000_000)),
			RunDir:     filepath.Join("/tmp", "fz-"+home), DeltaDir: t.TempDir(),
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if c, ok := rt.(interface{ Close() }); ok {
				c.Close()
			}
		})
		a := &core.Agent{NodeID: home, Ledger: core.NewLedger(1), Budget: core.NewBudget(1000, 1<<20),
			Runtime: rt, Audit: core.NopAuditor{}, Verify: tokenVerifier{"g": grantFor(home)},
			Health: core.NewSourceHealth(time.Minute, time.Now())}
		return a, rt
	}
	a, _ := mk("home-a")
	b, _ := mk("home-b")
	if b.Runtime.Tier() < core.TierCheckpoint {
		t.Skip("criu not usable here")
	}
	req := core.CloneRequest{GrantJWT: []byte("g"), Session: "S", Deadline: 5 * time.Second}
	domainRepo := reg + "/deltas/" + strings.TrimPrefix(digest, "sha256:")[:40] + "-" + shortHash(digest)

	r1, code, err := a.Clone(ctx, req)
	if err != nil || code != core.OK || r1.Kind != core.ActCreate {
		t.Fatalf("A create: %v %d %v", err, code, r1.Kind)
	}
	for i := 0; i < 3; i++ {
		talk(t, r1.Endpoint, "incr")
	}
	talk(t, r1.Endpoint, "dirty 1048576")
	if _, code, err := a.Park(ctx, r1.FiberID, true); err != nil || code != core.OK {
		t.Fatalf("A park: %v %d", err, code)
	}
	if _, found, err := artifact.Resolve(ctx, domainRepo+":"+sessionTag("S"), true); err != nil || !found {
		t.Fatalf("delta not published at %s: found=%v err=%v", domainRepo, found, err)
	}

	t0 := time.Now()
	r2, code, err := b.Clone(ctx, req)
	if err != nil || code != core.OK {
		t.Fatalf("B clone: %v %d", err, code)
	}
	if r2.Kind != core.ActResume {
		t.Fatalf("B clone kind = %v, want RESUME", r2.Kind)
	}
	t.Logf("B claimed and resumed S in %s", time.Since(t0).Round(time.Millisecond))
	if got := talk(t, r2.Endpoint, "get"); got != "3" {
		t.Fatalf("counter on B = %q, want 3", got)
	}
	if got := talk(t, r2.Endpoint, "incr"); got != "4" {
		t.Fatalf("incr on B = %q", got)
	}

	// The tag is gone: A's parked copy is stale. A must not resume it.
	r3, code, err := a.Clone(ctx, req)
	if err != nil || code != core.OK {
		t.Fatalf("A clone after claim: %v %d", err, code)
	}
	if r3.Kind != core.ActCreate {
		t.Fatalf("A served a session B holds: kind %v", r3.Kind)
	}
	if got := talk(t, r3.Endpoint, "get"); got != "0" {
		t.Fatalf("A's fresh session counter = %q, want 0", got)
	}
	if code, err := a.Release(ctx, r3.FiberID, true); err != nil || code != core.OK {
		t.Fatalf("A release: %v %d", err, code)
	}

	// Too large to move: B parks (4 -> published with W), A is told to
	// prefer home-b.
	if _, code, err := b.Park(ctx, r2.FiberID, true); err != nil || code != core.OK {
		t.Fatalf("B park: %v %d", err, code)
	}
	a.MobilityBudget = func(core.Grant) uint64 { return 4096 }
	_, code, err = a.Clone(ctx, req)
	var rm *core.RemoteMiss
	if code != core.DeferredFallback || !errors.As(err, &rm) || rm.PreferredHome != "home-b" {
		t.Fatalf("A clone of a too-large session = %d %v, want DeferredFallback preferring home-b", code, err)
	}
	// And with the budget back, A pulls it and finds the count at 4.
	a.MobilityBudget = nil
	r4, code, err := a.Clone(ctx, req)
	if err != nil || code != core.OK || r4.Kind != core.ActResume {
		t.Fatalf("A resume from B: %v %d %v", err, code, r4.Kind)
	}
	if got := talk(t, r4.Endpoint, "get"); got != "4" {
		t.Fatalf("counter back on A = %q, want 4", got)
	}
	_, _ = a.Release(ctx, r4.FiberID, true)
}

// TestTemplateParityGate: an artifact's images are only warmed on a host
// they were made on, at the configured strictness. The runtime's own
// platform is overridden to stand in for a different host.
func TestTemplateParityGate(t *testing.T) {
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "art")
	digest, err := artifact.Build(ctx, artifact.BuildOptions{Zygote: zygoteBin, Args: []string{"--heap-mb", "16"}, Out: out})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	reg := strings.TrimPrefix(srv.URL, "http://")
	if _, err := artifact.Push(ctx, out, reg+"/zygotes/ref:v1", true); err != nil {
		t.Fatal(err)
	}
	here := artifact.Host()
	cases := []struct {
		name     string
		platform artifact.Platform
		parity   artifact.Parity
		wantErr  bool
	}{
		{"same host, strict", artifact.Platform{}, artifact.Strict, false},
		{"other patch release, strict", artifact.Platform{Kernel: here.Kernel + "-other"}, artifact.Strict, true},
		{"other series, series", artifact.Platform{Kernel: "9.9.9"}, artifact.Parity{Kernel: artifact.ParitySeries}, true},
		{"other series, kernel off", artifact.Platform{Kernel: "9.9.9"}, artifact.Parity{Kernel: artifact.ParityOff}, false},
		{"other libc, strict", artifact.Platform{Libc: "(gnu libc) 0.1"}, artifact.Strict, true},
		{"other libc, libc off", artifact.Platform{Libc: "(gnu libc) 0.1"}, artifact.Parity{Libc: artifact.ParityOff}, false},
		{"other arch, everything off", artifact.Platform{Arch: "riscv64"}, artifact.Parity{Kernel: artifact.ParityOff, Libc: artifact.ParityOff}, true},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rt, err := newHost(host.Config{
				Registry: reg + "/zygotes/ref", RegistryPlainHTTP: true, TemplateCache: t.TempDir(),
				CgroupRoot: filepath.Join(cgRoot, fmt.Sprintf("par%d-%d", i, time.Now().UnixNano()%1_000_000)),
				RunDir:     filepath.Join("/tmp", fmt.Sprintf("fz-par%d", i)),
				Parity:     c.parity, Platform: c.platform,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer rt.(interface{ Close() }).Close()
			g := core.Grant{UID: fmt.Sprintf("gp%d", i), TemplateDigest: digest}
			err = rt.PrepareTemplate(ctx, g)
			if c.wantErr {
				if !errors.Is(err, host.ErrParity) || !errors.Is(err, artifact.ErrParity) {
					t.Fatalf("prepare = %v, want ErrParity", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("prepare: %v", err)
			}
			h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			if got := talk(t, h.Endpoint, "ping"); got != "pong" {
				t.Fatalf("ping = %q", got)
			}
			_ = rt.Release(ctx, h.ID, false)
		})
	}
}

// TestMobilityParityGate: a session parked on a host with another kernel
// is found but not taken; the miss names where it is. Relaxing the level
// lets it through.
func TestMobilityParityGate(t *testing.T) {
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "art")
	digest, err := artifact.Build(ctx, artifact.BuildOptions{Zygote: zygoteBin, Args: []string{"--heap-mb", "16"}, Out: out})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	reg := strings.TrimPrefix(srv.URL, "http://")
	if _, err := artifact.Push(ctx, out, reg+"/zygotes/ref:v1", true); err != nil {
		t.Fatal(err)
	}
	mk := func(home string, parity artifact.Parity, platform artifact.Platform) *core.Agent {
		rt, err := newHost(host.Config{
			Registry: reg + "/zygotes/ref", RegistryPlainHTTP: true, TemplateCache: t.TempDir(),
			DeltaRegistry: reg + "/deltas", HomeID: home, Parity: parity, Platform: platform,
			CgroupRoot: filepath.Join(cgRoot, home+fmt.Sprint(time.Now().UnixNano()%1_000_000)),
			RunDir:     filepath.Join("/tmp", "fz-"+home), DeltaDir: t.TempDir(),
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { rt.(interface{ Close() }).Close() })
		g := core.Grant{UID: "par-" + home, Audience: home, TemplateDigest: digest, FiberMax: 4, WBudgetBytes: 32 << 20, LeaseExpiry: time.Now().Add(time.Hour)}
		return &core.Agent{NodeID: home, Ledger: core.NewLedger(1), Budget: core.NewBudget(1000, 1<<20),
			Runtime: rt, Audit: core.NopAuditor{}, Verify: tokenVerifier{"g": g},
			Health: core.NewSourceHealth(time.Minute, time.Now())}
	}
	// home-a believes it runs another kernel (and does not care that its
	// template was built on this one); its deltas say so.
	a := mk("home-a", artifact.Parity{Kernel: artifact.ParityOff}, artifact.Platform{Kernel: "9.9.9-elsewhere"})
	if a.Runtime.Tier() < core.TierCheckpoint {
		t.Skip("criu not usable here")
	}
	req := core.CloneRequest{GrantJWT: []byte("g"), Session: "S", Deadline: 5 * time.Second}
	r1, code, err := a.Clone(ctx, req)
	if err != nil || code != core.OK {
		t.Fatalf("A create: %v %d", err, code)
	}
	for i := 0; i < 3; i++ {
		talk(t, r1.Endpoint, "incr")
	}
	if _, code, err := a.Park(ctx, r1.FiberID, true); err != nil || code != core.OK {
		t.Fatalf("A park: %v %d", err, code)
	}

	// A strict home-b finds S, refuses it, and points at home-a.
	b := mk("home-b", artifact.Strict, artifact.Platform{})
	_, code, err = b.Clone(ctx, req)
	var rm *core.RemoteMiss
	if code != core.DeferredFallback || !errors.Is(err, core.ErrIncompatible) || !errors.As(err, &rm) || rm.PreferredHome != "home-a" {
		t.Fatalf("strict B clone = %d %v, want DeferredFallback ErrIncompatible preferring home-a", code, err)
	}
	// Series parity is not enough either: 9.9 is not this kernel's series.
	bs := mk("home-bs", artifact.Parity{Kernel: artifact.ParitySeries}, artifact.Platform{})
	if _, code, err := bs.Clone(ctx, req); code != core.DeferredFallback || !errors.Is(err, core.ErrIncompatible) {
		t.Fatalf("series B clone = %d %v, want DeferredFallback ErrIncompatible", code, err)
	}
	// The tag is still there: nobody claimed it.
	domainRepo := reg + "/deltas/" + strings.TrimPrefix(digest, "sha256:")[:40] + "-" + shortHash(digest)
	if _, found, err := artifact.Resolve(ctx, domainRepo+":"+sessionTag("S"), true); err != nil || !found {
		t.Fatalf("refused session must stay published: found=%v err=%v", found, err)
	}
	// With the kernel check off, home-c takes it and the count is intact.
	c := mk("home-c", artifact.Parity{Kernel: artifact.ParityOff}, artifact.Platform{})
	r2, code, err := c.Clone(ctx, req)
	if err != nil || code != core.OK || r2.Kind != core.ActResume {
		t.Fatalf("relaxed C clone = %v %d %v, want RESUME", err, code, r2.Kind)
	}
	if got := talk(t, r2.Endpoint, "get"); got != "3" {
		t.Fatalf("counter on C = %q, want 3", got)
	}
	_, _ = c.Release(ctx, r2.FiberID, true)
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}

func sessionTag(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "s-" + hex.EncodeToString(sum[:12])
}

func TestTemplateFromRegistryArtifact(t *testing.T) {
	ctx := context.Background()
	// Build the reference zygote into an artifact, with its CRIU images.
	out := filepath.Join(t.TempDir(), "art")
	digest, err := artifact.Build(ctx, artifact.BuildOptions{Zygote: zygoteBin, Args: []string{"--heap-mb", "16"}, Out: out})
	if err != nil {
		t.Fatalf("build artifact: %v", err)
	}
	cfg, _ := artifact.ReadConfig(out)
	if !cfg.HasImages {
		t.Fatal("artifact has no images")
	}
	if _, err := os.Stat(filepath.Join(artifact.ImagesDir(out), "inventory.img")); err != nil {
		t.Fatalf("zygote images missing: %v", err)
	}
	t.Logf("artifact %s kernel=%s libc=%s", digest, cfg.Kernel, cfg.Libc)

	// Push to an in-process registry, then let the runtime pull it by the
	// grant's template digest.
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	reg := strings.TrimPrefix(srv.URL, "http://")
	if _, err := artifact.Push(ctx, out, reg+"/zygotes/ref:v1", true); err != nil {
		t.Fatalf("push: %v", err)
	}
	cache := t.TempDir()
	rt, err := newHost(host.Config{
		Registry: reg + "/zygotes/ref", RegistryPlainHTTP: true, TemplateCache: cache,
		CgroupRoot: filepath.Join(cgRoot, "t"+fmt.Sprint(time.Now().UnixNano()%1_000_000)),
		RunDir:     filepath.Join("/tmp", "fz-art"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if c, ok := rt.(interface{ Close() }); ok {
			c.Close()
		}
	}()
	g := core.Grant{UID: "g7", TemplateDigest: digest}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatalf("prepare from registry: %v", err)
	}
	pulled := filepath.Join(cache, strings.TrimPrefix(digest, "sha256:"))
	if _, err := os.Stat(artifact.ZygotePath(pulled)); err != nil {
		t.Fatalf("template not in cache: %v", err)
	}
	if _, err := os.Stat(filepath.Join(artifact.ImagesDir(pulled), "inventory.img")); err != nil {
		t.Fatalf("images not unpacked in cache: %v", err)
	}
	h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g7", Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if got := talk(t, h.Endpoint, "ping"); got != "pong" {
		t.Fatalf("ping = %q", got)
	}
	_ = rt.Release(ctx, h.ID, false)

	// An unknown digest with no registry entry is refused, not defaulted.
	bogus := core.Grant{UID: "g8", TemplateDigest: "sha256:" + strings.Repeat("1", 64)}
	if err := rt.PrepareTemplate(ctx, bogus); err == nil {
		t.Fatal("unknown digest prepared")
	}
}

func TestCeilingAndPressureSource(t *testing.T) {
	rt := newRuntime(t)
	ctx := context.Background()
	g := core.Grant{UID: "g4", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 8 << 20}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	src, ok := rt.(core.PressureSource)
	if !ok {
		t.Fatal("proc runtime must be a PressureSource")
	}
	psi, err := src.Pressure("g4")
	if err != nil {
		t.Fatalf("pressure: %v", err)
	}
	t.Logf("grant PSI some avg10 = %.2f%%", psi)
	// The block ceiling landed on the grant cgroup: memory.high is at
	// least fibers.max * w_budget.
	matches, _ := filepath.Glob(filepath.Join(cgRoot, "t*", "g4", "memory.high"))
	if len(matches) != 1 {
		t.Fatalf("grant cgroup memory.high not found: %v", matches)
	}
	b, _ := os.ReadFile(matches[0])
	var high uint64
	if _, err := fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &high); err != nil || high < 4*(8<<20) {
		t.Fatalf("memory.high = %q, want >= %d", strings.TrimSpace(string(b)), 4*(8<<20))
	}
	t.Logf("grant ceiling memory.high = %d MiB", high>>20)
}

func TestOverBudgetIsOOMKilled(t *testing.T) {
	rt := newRuntime(t)
	ctx := context.Background()
	g := core.Grant{UID: "g2", TemplateDigest: "sha256:ref", WBudgetBytes: 4 << 20}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	fence := core.Fence{GrantUID: "g2", Epoch: 1, Seq: 1}
	h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: fence, Deadline: 2 * time.Second,
		Payload: []byte(`{"dirty_bytes": 16777216}`)})
	if err != nil {
		t.Fatalf("clone should succeed (ready is reported before the fiber grows): %v", err)
	}
	select {
	case ex := <-rt.Exits():
		if ex.FiberID != h.ID || ex.Reason != "oom" {
			t.Fatalf("exit = %+v, want oom for %s", ex, h.ID)
		}
		t.Logf("kernel killed it: %s", ex.Detail)
	case <-time.After(10 * time.Second):
		t.Fatal("no exit reported for the over-budget fiber")
	}
	if _, err := rt.Stats(ctx, h.ID); err == nil {
		t.Fatal("stats on a dead fiber must fail")
	}
}

func TestDeadlineIsEnforced(t *testing.T) {
	rt := newRuntime(t)
	ctx := context.Background()
	g := core.Grant{UID: "g3", TemplateDigest: "sha256:ref"}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	fence := core.Fence{GrantUID: "g3", Epoch: 1, Seq: 1}
	dctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	_, err := rt.Clone(dctx, core.CloneSpec{Grant: g, Fence: fence, Deadline: 300 * time.Millisecond,
		Payload: []byte(`{"ready_delay_ms": 2000}`)})
	if err == nil {
		t.Fatal("late fiber was delivered")
	}
	t.Logf("late fiber refused: %v", err)
	time.Sleep(200 * time.Millisecond)
	if list, _ := rt.List(ctx); len(list) != 0 {
		t.Fatalf("late fiber left running: %+v", list)
	}
}
