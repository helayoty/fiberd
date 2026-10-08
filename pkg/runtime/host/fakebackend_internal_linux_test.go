//go:build linux

package host

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/sys/cgroup"
)

// A fake backend.Backend. It forks nothing. It records every call the
// runtime makes, answers with what a test configured, and reports exits
// when asked, while the runtime's own logic runs for real over it.
// Optional backend interfaces are mixins a test composes in.

// fakeFiber is one fiber the fake backend was asked for.
type fakeFiber struct {
	spec   backend.FiberSpec
	resume *backend.ResumeSpec
	alive  bool
	// identity is the message the fiber read from its handoff channel
	// before any connection, nil when none was queued.
	identity []byte
	// handoff is the fiber's end of its handoff channel, kept open past
	// Clone (the runtime closes its copy), or -1.
	handoff int
	// ln is the unix listener a serving fake fiber answers on (serve).
	ln net.Listener
}

type fakeBackend struct {
	name  string
	tier  core.Tier
	exits chan backend.Exit

	mu       sync.Mutex
	warms    map[string]backend.WarmSpec
	fibers   map[string]*fakeFiber
	parks    []backend.ParkSpec
	killed   []string
	unwarmed []string
	closed   bool
	nextPID  int
	// warmCalls counts Warm calls, idempotent prepares included.
	warmCalls int

	// Knobs a test sets before calling the runtime.
	warmErr, cloneErr, parkErr, resumeErr error
	warm                                  backend.Warm
	// parkFiles is what Park writes into its directory. Nil writes a
	// page file and a dump log.
	parkFiles map[string]string
	// parkNoDir makes Park succeed without making its directory, as a
	// backend that dumped nothing would.
	parkNoDir bool
	// parkDangling makes Park leave a dangling symlink in its directory,
	// which no fsync can open.
	parkDangling bool
	// noExit makes Kill and an async Park end nothing, so no exit is ever
	// reported for the fiber.
	noExit bool
	// endpointFile makes Clone leave a file at the unix endpoint path, as
	// the bound socket of a real fiber would.
	endpointFile bool
	// serve makes Clone and Resume listen on the fiber's unix endpoint
	// and answer every line with "<fence>:<line>", as a fiber would. The
	// listener ends with the fiber.
	serve bool
}

func newFakeBackend(tier core.Tier) *fakeBackend {
	return &fakeBackend{name: "fake", tier: tier, exits: make(chan backend.Exit, 64),
		warms: map[string]backend.WarmSpec{}, fibers: map[string]*fakeFiber{}, nextPID: 1000}
}

func (b *fakeBackend) Name() string    { return b.name }
func (b *fakeBackend) Tier() core.Tier { return b.tier }

func (b *fakeBackend) Warm(_ context.Context, spec backend.WarmSpec) (backend.Warm, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.warmCalls++
	if b.warmErr != nil {
		return backend.Warm{}, b.warmErr
	}
	b.warms[spec.GrantUID] = spec
	b.nextPID++
	w := b.warm
	w.ID, w.PID = spec.GrantUID, b.nextPID
	return w, nil
}

func (b *fakeBackend) Unwarm(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.unwarmed = append(b.unwarmed, id)
}

// takeHandoff keeps the fiber's end of a handoff channel open and reads
// the identity message queued on it, if any.
func takeHandoff(f *os.File) (fd int, identity []byte) {
	if f == nil {
		return -1, nil
	}
	fd, err := syscall.Dup(int(f.Fd()))
	if err != nil {
		return -1, nil
	}
	buf := make([]byte, 64<<10)
	n, _, _, _, err := syscall.Recvmsg(fd, buf, nil, syscall.MSG_DONTWAIT)
	if err != nil || n == 0 {
		return fd, nil
	}
	return fd, buf[:n]
}

func (b *fakeBackend) Clone(_ context.Context, warmID string, spec backend.FiberSpec) (backend.Fiber, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cloneErr != nil {
		return backend.Fiber{}, b.cloneErr
	}
	if _, ok := b.warms[warmID]; !ok {
		return backend.Fiber{}, fmt.Errorf("fake: no warm instance %q", warmID)
	}
	if b.endpointFile && filepath.IsAbs(spec.Endpoint) {
		if err := os.WriteFile(spec.Endpoint, nil, 0o600); err != nil {
			return backend.Fiber{}, err
		}
	}
	ln, err := b.listen(spec.Fence, spec.Endpoint)
	if err != nil {
		return backend.Fiber{}, err
	}
	fd, identity := takeHandoff(spec.Handoff)
	b.nextPID++
	b.fibers[spec.Fence] = &fakeFiber{spec: spec, alive: true, identity: identity, handoff: fd, ln: ln}
	return backend.Fiber{ID: spec.Fence, PID: b.nextPID}, nil
}

// listen serves a fake fiber's unix endpoint when serve is set.
func (b *fakeBackend) listen(fence, ep string) (net.Listener, error) {
	if !b.serve || !filepath.IsAbs(ep) {
		return nil, nil
	}
	ln, err := net.Listen("unix", ep)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				sc := bufio.NewScanner(c)
				for sc.Scan() {
					if _, err := fmt.Fprintf(c, "%s:%s\n", fence, sc.Text()); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln, nil
}

// end marks a fiber dead and closes what it served on.
func (f *fakeFiber) end() {
	f.alive = false
	if f.ln != nil {
		_ = f.ln.Close()
		f.ln = nil
	}
}

func (b *fakeBackend) Park(_ context.Context, fiberID string, spec backend.ParkSpec) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.parks = append(b.parks, spec)
	f := b.fibers[fiberID]
	if f == nil || !f.alive {
		return fmt.Errorf("fake: no running fiber %q", fiberID)
	}
	if b.parkErr != nil {
		// A failed dump still leaves its log behind.
		_ = os.MkdirAll(spec.Dir, 0o755)
		_ = os.WriteFile(filepath.Join(spec.Dir, "dump.log"), []byte("failed\n"), 0o644)
		return b.parkErr
	}
	if !b.parkNoDir {
		files := b.parkFiles
		if files == nil {
			files = map[string]string{"pages-1.img": "dirty pages of " + fiberID, "dump.log": "ok\n"}
		}
		if err := os.MkdirAll(spec.Dir, 0o755); err != nil {
			return err
		}
		for n, c := range files {
			if err := os.WriteFile(filepath.Join(spec.Dir, n), []byte(c), 0o644); err != nil {
				return err
			}
		}
		if b.parkDangling {
			if err := os.Symlink("/nonexistent/ghost", filepath.Join(spec.Dir, "ghost")); err != nil {
				return err
			}
		}
	}
	if !spec.Sync && !b.noExit {
		f.end()
		b.exits <- backend.Exit{FiberID: fiberID, Status: "exit:0"}
	}
	return nil
}

func (b *fakeBackend) Resume(_ context.Context, spec backend.ResumeSpec) (backend.Fiber, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.resumeErr != nil {
		return backend.Fiber{}, b.resumeErr
	}
	ln, err := b.listen(spec.Fence, spec.Endpoint)
	if err != nil {
		return backend.Fiber{}, err
	}
	fd, identity := takeHandoff(spec.Handoff)
	rs := spec
	b.nextPID++
	b.fibers[spec.Fence] = &fakeFiber{resume: &rs, alive: true, identity: identity, handoff: fd, ln: ln}
	return backend.Fiber{ID: spec.Fence, PID: b.nextPID}, nil
}

func (b *fakeBackend) Kill(fiberID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.killed = append(b.killed, fiberID)
	f := b.fibers[fiberID]
	if f == nil || !f.alive || b.noExit {
		return nil
	}
	f.end()
	b.exits <- backend.Exit{FiberID: fiberID, Status: "signal:SIGKILL"}
	return nil
}

func (b *fakeBackend) Exits() <-chan backend.Exit { return b.exits }

func (b *fakeBackend) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	for _, f := range b.fibers {
		if f.handoff >= 0 {
			_ = syscall.Close(f.handoff)
			f.handoff = -1
		}
		f.end()
	}
	close(b.exits)
}

// die reports a fiber's death on its own, with the given status.
func (b *fakeBackend) die(fiberID, status string) {
	b.mu.Lock()
	if f := b.fibers[fiberID]; f != nil {
		f.end()
	}
	b.mu.Unlock()
	b.exits <- backend.Exit{FiberID: fiberID, Status: status}
}

// warmGone reports the end of a grant's warm instance.
func (b *fakeBackend) warmGone(grantUID string) {
	b.exits <- backend.Exit{WarmID: grantUID}
}

func (b *fakeBackend) fiber(id string) *fakeFiber {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.fibers[id]
}

// closeHandoff ends the fiber's side of its handoff channel, as a dead
// fiber would.
func (b *fakeBackend) closeHandoff(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if f := b.fibers[id]; f != nil && f.handoff >= 0 {
		_ = syscall.Close(f.handoff)
		f.handoff = -1
	}
}

func (b *fakeBackend) killedIDs() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.killed...)
}

func (b *fakeBackend) warmed() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.warmCalls
}

func (b *fakeBackend) parked() []backend.ParkSpec {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]backend.ParkSpec(nil), b.parks...)
}

func (b *fakeBackend) warmSpec(grantUID string) (backend.WarmSpec, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.warms[grantUID]
	return s, ok
}

// Each mixin adds one optional backend interface.

type overheadMixin struct{}

func (overheadMixin) FiberOverheadBytes() uint64 { return 0 }

type wReporterMixin struct {
	wmu sync.Mutex
	w   map[string]uint64
}

func (m *wReporterMixin) setW(fiberID string, w uint64) {
	m.wmu.Lock()
	defer m.wmu.Unlock()
	if m.w == nil {
		m.w = map[string]uint64{}
	}
	m.w[fiberID] = w
}

func (m *wReporterMixin) FiberW(fiberID string) (uint64, bool) {
	m.wmu.Lock()
	defer m.wmu.Unlock()
	w, ok := m.w[fiberID]
	return w, ok
}

type wMeterMixin struct{ counter string }

func (m wMeterMixin) WCounter() string { return m.counter }

type deviceMixin struct {
	dmu            sync.Mutex
	fiberUse       map[string]uint64
	used, capacity uint64
	reported       bool
	evicted        []string
	evictErr       error
}

func (m *deviceMixin) setDevice(fiberID string, used uint64) {
	m.dmu.Lock()
	defer m.dmu.Unlock()
	if m.fiberUse == nil {
		m.fiberUse = map[string]uint64{}
	}
	m.fiberUse[fiberID] = used
}

func (m *deviceMixin) FiberDevice(fiberID string) (uint64, bool) {
	m.dmu.Lock()
	defer m.dmu.Unlock()
	u, ok := m.fiberUse[fiberID]
	return u, ok
}

func (m *deviceMixin) WarmDevice(string) (uint64, uint64, bool) {
	m.dmu.Lock()
	defer m.dmu.Unlock()
	return m.used, m.capacity, m.reported
}

func (m *deviceMixin) EvictDevice(fiberID string) error {
	m.dmu.Lock()
	defer m.dmu.Unlock()
	m.evicted = append(m.evicted, fiberID)
	return m.evictErr
}

func (m *deviceMixin) evictedIDs() []string {
	m.dmu.Lock()
	defer m.dmu.Unlock()
	return append([]string(nil), m.evicted...)
}

type isolatorMixin struct{ isolates bool }

func (m isolatorMixin) IsolatesTenants() bool { return m.isolates }

type handoffMixin struct{ handoff bool }

func (m handoffMixin) Handoff() bool { return m.handoff }

type channelMixin struct {
	err   error
	pairs atomic.Int32
}

func (m *channelMixin) Socketpair(_ string, typ int) ([2]int, error) {
	if m.err != nil {
		return [2]int{}, m.err
	}
	m.pairs.Add(1)
	return syscall.Socketpair(syscall.AF_UNIX, typ|syscall.SOCK_CLOEXEC, 0)
}

type idMapperMixin struct {
	uid uint32
	err error
}

func (m *idMapperMixin) MappedRoot(string) (uint32, error) { return m.uid, m.err }
func (m *idMapperMixin) mapper() *idMapperMixin            { return m }

type platformMixin struct{ p artifact.Platform }

func (m platformMixin) Platform() artifact.Platform { return m.p }

type deadlineMixin struct{ create, resume time.Duration }

func (m deadlineMixin) DefaultDeadlines() (time.Duration, time.Duration) { return m.create, m.resume }

type schemesMixin struct{ schemes []string }

func (m schemesMixin) EndpointSchemes() []string { return m.schemes }

// A fake delta codec. A parent checkpoint is a directory with a "pages"
// file, hashed by content. A delta is a "delta.json" naming its parent.
const (
	fakePagesFile = "pages"
	fakeDeltaFile = "delta.json"
)

type fakeParent struct {
	sha    string
	closed atomic.Int32
}

func (p *fakeParent) SHA256() string { return p.sha }
func (p *fakeParent) Close()         { p.closed.Add(1) }

type fakeDelta struct {
	Parent string `json:"parent"`
	Bytes  uint64 `json:"bytes"`
}

type codecMixin struct {
	cmu        sync.Mutex
	loads      int
	failLoadAt int // 1-based index of the LoadParent call that fails (0 = never)
	loadErr    error
	computeErr error
	mergeErr   error
	infoErr    error
	imageBytes uint64
	imageErr   error
	deltaBytes uint64
	parents    []*fakeParent
	merged     []string
}

func pagesSHA(dir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, fakePagesFile))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func (c *codecMixin) ImageBytes(string) (uint64, error) { return c.imageBytes, c.imageErr }

func (c *codecMixin) LoadParent(dir string) (backend.Parent, error) {
	c.cmu.Lock()
	defer c.cmu.Unlock()
	c.loads++
	if c.loadErr != nil || c.loads == c.failLoadAt {
		err := c.loadErr
		if err == nil {
			err = errors.New("fake codec: load refused")
		}
		return nil, err
	}
	sha, err := pagesSHA(dir)
	if err != nil {
		return nil, err
	}
	p := &fakeParent{sha: sha}
	c.parents = append(c.parents, p)
	return p, nil
}

func (c *codecMixin) Compute(dir string, parent backend.Parent) (backend.DeltaInfo, error) {
	if c.computeErr != nil {
		return backend.DeltaInfo{}, c.computeErr
	}
	n := c.deltaBytes
	if n == 0 {
		n = 7
	}
	d := fakeDelta{Parent: parent.SHA256(), Bytes: n}
	b, _ := json.Marshal(d)
	if err := os.WriteFile(filepath.Join(dir, fakeDeltaFile), b, 0o644); err != nil {
		return backend.DeltaInfo{}, err
	}
	return backend.DeltaInfo{ParentSHA256: d.Parent, Bytes: d.Bytes}, nil
}

func (c *codecMixin) HasDelta(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, fakeDeltaFile))
	return err == nil
}

func (c *codecMixin) ReadDeltaInfo(dir string) (backend.DeltaInfo, error) {
	if c.infoErr != nil {
		return backend.DeltaInfo{}, c.infoErr
	}
	b, err := os.ReadFile(filepath.Join(dir, fakeDeltaFile))
	if err != nil {
		return backend.DeltaInfo{}, err
	}
	var d fakeDelta
	if err := json.Unmarshal(b, &d); err != nil {
		return backend.DeltaInfo{}, err
	}
	return backend.DeltaInfo{ParentSHA256: d.Parent, Bytes: d.Bytes}, nil
}

func (c *codecMixin) Merge(dir string, parent backend.Parent) error {
	c.cmu.Lock()
	defer c.cmu.Unlock()
	if c.mergeErr != nil {
		return c.mergeErr
	}
	c.merged = append(c.merged, dir)
	return os.WriteFile(filepath.Join(dir, "merged"), []byte(parent.SHA256()), 0o644)
}

func (c *codecMixin) loadedParents() []*fakeParent {
	c.cmu.Lock()
	defer c.cmu.Unlock()
	return append([]*fakeParent(nil), c.parents...)
}

type selfCheckpointMixin struct {
	err   error
	pages string // what the checkpoint's pages hold ("" = derived from the warm id)
	calls atomic.Int32
}

func (m *selfCheckpointMixin) CheckpointWarm(_ context.Context, warmID, dir string) error {
	m.calls.Add(1)
	if m.err != nil {
		return m.err
	}
	pages := m.pages
	if pages == "" {
		pages = "zygote pages of " + warmID
	}
	return writeParentDir(dir, pages)
}

// writeParentDir makes a fake parent checkpoint and returns its hash.
func writeParentDir(dir, pages string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, fakePagesFile), []byte(pages), 0o644)
}

func shaOf(pages string) string {
	sum := sha256.Sum256([]byte(pages))
	return hex.EncodeToString(sum[:])
}

// Compositions used across the tests.

// codecBackend is a fork backend with a delta codec and a self
// checkpoint, as proc is.
type codecBackend struct {
	*fakeBackend
	*codecMixin
	*selfCheckpointMixin
}

func newCodecBackend(tier core.Tier) *codecBackend {
	return &codecBackend{newFakeBackend(tier), &codecMixin{}, &selfCheckpointMixin{}}
}

// sandboxBackend is a backend whose fibers are sandboxes. It has a fixed
// footprint, reports W and devices itself, isolates tenants, and offers
// handoff and tcp endpoints.
type sandboxBackend struct {
	*fakeBackend
	overheadMixin
	*wReporterMixin
	*deviceMixin
	isolatorMixin
	handoffMixin
	*channelMixin
	schemesMixin
	platformMixin
	deadlineMixin
}

func newSandboxBackend(tier core.Tier) *sandboxBackend {
	return &sandboxBackend{fakeBackend: newFakeBackend(tier), wReporterMixin: &wReporterMixin{}, deviceMixin: &deviceMixin{},
		isolatorMixin: isolatorMixin{true}, handoffMixin: handoffMixin{true}, channelMixin: &channelMixin{},
		schemesMixin: schemesMixin{[]string{"unix", "tcp"}}}
}

// Test plumbing.

var cgroupSeq atomic.Int64

// testCgroupRoot is a fresh delegated subtree for one runtime, removed
// with everything under it when the test ends. Tests needing one skip
// where the home's cgroup root is not writable.
func testCgroupRoot(t *testing.T) string {
	t.Helper()
	root := os.Getenv("FIBERD_CGROUP_ROOT")
	if root == "" {
		root = "/sys/fs/cgroup/fiberd"
	}
	f, err := os.OpenFile(filepath.Join(root, "cgroup.subtree_control"), os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("cgroup root %s not writable: %v", root, err)
	}
	_ = f.Close()
	dir := filepath.Join(root, fmt.Sprintf("host-%d-%d", os.Getpid(), cgroupSeq.Add(1)))
	t.Cleanup(func() { removeCgroupTree(cgroup.Dir{Path: dir}) })
	return dir
}

// removeCgroupTree kills and removes d and every cgroup under it.
func removeCgroupTree(d cgroup.Dir) {
	if !d.Exists() {
		return
	}
	_ = d.Kill()
	children, _ := d.Children("")
	for _, c := range children {
		removeCgroupTree(c)
	}
	for i := 0; i < 50; i++ {
		if err := d.Remove(); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// testConfig is a runtime configuration over be with every path under
// the test's temp dir and a fresh cgroup subtree.
func testConfig(t *testing.T, be backend.Backend) Config {
	t.Helper()
	root := t.TempDir()
	return Config{Backend: be, Templates: map[string]string{"default": "/bin/true --template"},
		CgroupRoot: testCgroupRoot(t), RunDir: filepath.Join(root, "run"), DeltaDir: filepath.Join(root, "deltas"),
		TemplateCache: filepath.Join(root, "cache")}
}

// newTestRuntime opens a runtime over be, closed when the test ends.
func newTestRuntime(t *testing.T, be backend.Backend, mod func(*Config)) *Runtime {
	t.Helper()
	cfg := testConfig(t, be)
	if mod != nil {
		mod(&cfg)
	}
	r, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(r.Close)
	return r
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitExit takes the next fiber exit the runtime reports.
func waitExit(t *testing.T, r *Runtime) core.FiberExit {
	t.Helper()
	select {
	case e := <-r.Exits():
		return e
	case <-time.After(3 * time.Second):
		t.Fatal("no fiber exit reported")
		return core.FiberExit{}
	}
}

// noExit asserts the runtime reports no exit for a short while. An exit
// wrongly sent would arrive within microseconds of the event it follows.
func noExit(t *testing.T, r *Runtime) {
	t.Helper()
	select {
	case e := <-r.Exits():
		t.Fatalf("unexpected fiber exit %+v", e)
	case <-time.After(100 * time.Millisecond):
	}
}

// cgFile reads one file of a cgroup.
func cgFile(t *testing.T, d cgroup.Dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(d.Path, name))
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(d.Path, name), err)
	}
	return string(b[:len(b)-1]) // trailing newline
}

func cgUint(t *testing.T, d cgroup.Dir, name string) uint64 {
	t.Helper()
	n, err := strconv.ParseUint(cgFile(t, d, name), 10, 64)
	if err != nil {
		t.Fatalf("%s/%s: %v", d.Path, name, err)
	}
	return n
}

// startSleeper runs a process of the test's own inside leaf, so the leaf
// has a live task charged to it. The shell moves itself into the leaf
// before it execs, so what the task maps is the leaf's. It is killed and
// reaped when the test ends.
func startSleeper(t *testing.T, leaf cgroup.Dir) int {
	t.Helper()
	return startInLeaf(t, leaf, "exec sleep 300")
}

// startInLeaf runs a shell command of the test's own inside leaf.
func startInLeaf(t *testing.T, leaf cgroup.Dir, command string) int {
	t.Helper()
	cmd := exec.Command("sh", "-c", "echo $$ > "+filepath.Join(leaf.Path, "cgroup.procs")+" && "+command)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start task: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	waitFor(t, "the task to enter "+leaf.Path, func() bool {
		pids, _ := leaf.Procs()
		for _, p := range pids {
			if p == cmd.Process.Pid {
				return true
			}
		}
		return false
	})
	return cmd.Process.Pid
}

// fileOwner is the uid owning path.
func fileOwner(t *testing.T, path string) uint32 {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Sys().(*syscall.Stat_t).Uid
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// readManifest reads a parked delta's manifest.
func readManifest(t *testing.T, dir string) manifest {
	t.Helper()
	var m manifest
	if err := readJSON(filepath.Join(dir, "manifest.json"), &m); err != nil {
		t.Fatalf("manifest of %s: %v", dir, err)
	}
	return m
}

// The compositions offer the interfaces the tests rely on.
var (
	_ backend.Backend          = (*fakeBackend)(nil)
	_ backend.DeltaCodec       = (*codecBackend)(nil)
	_ backend.SelfCheckpointer = (*codecBackend)(nil)
	_ backend.Overheader       = (*sandboxBackend)(nil)
	_ backend.WReporter        = (*sandboxBackend)(nil)
	_ backend.DeviceReporter   = (*sandboxBackend)(nil)
	_ backend.Isolator         = (*sandboxBackend)(nil)
	_ backend.Handoffer        = (*sandboxBackend)(nil)
	_ backend.ChannelMaker     = (*sandboxBackend)(nil)
	_ backend.EndpointSchemer  = (*sandboxBackend)(nil)
	_ backend.Platformer       = (*sandboxBackend)(nil)
	_ backend.DeadlineAdvisor  = (*sandboxBackend)(nil)
)

// refuseLeaves caps d at the descendants it has now, so the kernel refuses
// the next leaf with EAGAIN. Every cgroup v2 kernel enforces this, unlike a
// tiny memory.max, which only some kernels refuse a child under.
func refuseLeaves(t *testing.T, d cgroup.Dir) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(d.Path, "cgroup.stat"))
	if err != nil {
		t.Fatal(err)
	}
	n := ""
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "nr_descendants "); ok {
			n = v
		}
	}
	if n == "" {
		t.Fatal("no nr_descendants in cgroup.stat")
	}
	if err := os.WriteFile(filepath.Join(d.Path, "cgroup.max.descendants"), []byte(n), 0o644); err != nil {
		t.Fatal(err)
	}
}
