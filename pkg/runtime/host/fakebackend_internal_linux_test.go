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
	// identity is the record the fiber read from its channel before
	// any connection, nil when none was queued (a resume).
	identity []byte
	// handoff is the fiber's end of its channel, kept open for a
	// handoff fiber's life, or -1 once a direct fiber read its record.
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
	// events is the order of unwarms and pool discards, for tests that
	// check what goes first.
	events []string

	// Knobs a test sets before calling the runtime.
	warmErr, cloneErr, parkErr, resumeErr error
	warm                                  backend.Warm
	// footprint is what Clone, Bind and Resume report as the leaf's own
	// count before the hand-out.
	footprint uint64
	// parkFiles is what Park writes into its directory. Nil writes a
	// page file and a dump log.
	parkFiles map[string]string
	// parkNoDir makes Park succeed without making its directory, as a
	// backend that dumped nothing would.
	parkNoDir bool
	// channels makes every fiber take a channel, as a Handoffer's do,
	// with its record queued by the fake. pairs counts them, and
	// channelErr refuses to make one.
	channels   bool
	channelErr error
	pairs      atomic.Int32
	// parkDangling makes Park leave a dangling symlink in its directory,
	// which no fsync can open.
	parkDangling bool
	// noExit makes Kill and an async Park end nothing, so no exit is ever
	// reported for the fiber.
	noExit bool
	// parkGate, when set, holds every Park after it has begun until the
	// channel is closed, so a test can end the fiber under the dump.
	parkGate chan struct{}
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
	enter(spec.CgroupFD)
	enter(spec.ProbeCgroupFD)
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
	b.events = append(b.events, "unwarm "+id)
}

func (b *fakeBackend) eventLog() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.events...)
}

// channel makes a fiber's channel as a Handoffer does, the record for
// spec queued on it (none when spec names no fence, a resume), reads
// the record back off the fiber's end as the library would, and returns
// the host's end with the fiber's end and the record. A direct fiber
// reads its record and both ends close, as the library and the backend
// do, so only a handoff fiber keeps a channel. The fiber's end is -1 on
// a backend whose fibers take none.
func (b *fakeBackend) channel(spec backend.FiberSpec, handoff bool) (host *os.File, fd int, identity []byte, err error) {
	if !b.channels {
		return nil, -1, nil, nil
	}
	if b.channelErr != nil {
		return nil, -1, nil, b.channelErr
	}
	inc := backend.Incarnation{Generation: spec.Generation, Kind: "fork", Fence: spec.Fence, Endpoint: spec.Endpoint, Payload: spec.Payload, Session: spec.Session, Identity: spec.Identity}
	host, fiber, err := backend.Channel(nil, inc)
	if err != nil {
		return nil, -1, nil, err
	}
	b.pairs.Add(1)
	fd = int(fiber.Fd())
	// Keep the descriptor past the *os.File, as the fiber keeps its end.
	fd, err = syscall.Dup(fd)
	_ = fiber.Close()
	if err != nil {
		_ = host.Close()
		return nil, -1, nil, err
	}
	if spec.Fence == "" {
		return host, fd, nil, nil
	}
	buf := make([]byte, 64<<10)
	n, _, _, _, err := syscall.Recvmsg(fd, buf, nil, syscall.MSG_DONTWAIT)
	if err != nil || n == 0 {
		return host, fd, nil, nil
	}
	if !handoff {
		_ = syscall.Close(fd)
		_ = host.Close()
		return nil, -1, buf[:n], nil
	}
	return host, fd, buf[:n], nil
}

func (b *fakeBackend) Clone(_ context.Context, warmID string, spec backend.FiberSpec) (backend.Fiber, error) {
	enter(spec.CgroupFD)
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
	host, fd, identity, err := b.channel(spec, spec.Identity != nil)
	if err != nil {
		if ln != nil {
			_ = ln.Close()
		}
		return backend.Fiber{}, err
	}
	b.nextPID++
	b.fibers[spec.Fence] = &fakeFiber{spec: spec, alive: true, identity: identity, handoff: fd, ln: ln}
	return backend.Fiber{ID: spec.Fence, PID: b.nextPID, Footprint: b.footprint, Channel: host}, nil
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
	if gate := b.parkGate; gate != nil {
		// The dump takes a while, and the fiber may die meanwhile (die).
		b.mu.Unlock()
		<-gate
		b.mu.Lock()
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
			// A name with a slash is a nested file, as a sandbox's blobs are.
			if err := os.MkdirAll(filepath.Dir(filepath.Join(spec.Dir, n)), 0o755); err != nil {
				return err
			}
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
	enter(spec.CgroupFD)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.resumeErr != nil {
		return backend.Fiber{}, b.resumeErr
	}
	ln, err := b.listen(spec.Fence, spec.Endpoint)
	if err != nil {
		return backend.Fiber{}, err
	}
	// A handoff resume's channel carries no record.
	host, fd, identity := (*os.File)(nil), -1, []byte(nil)
	if spec.Handoff {
		host, fd, identity, err = b.channel(backend.FiberSpec{}, true)
	}
	if err != nil {
		if ln != nil {
			_ = ln.Close()
		}
		return backend.Fiber{}, err
	}
	rs := spec
	b.nextPID++
	b.fibers[spec.Fence] = &fakeFiber{resume: &rs, alive: true, identity: identity, handoff: fd, ln: ln}
	return backend.Fiber{ID: spec.Fence, PID: b.nextPID, Footprint: b.footprint, Channel: host}, nil
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

// report delivers an exit unless the backend is closed, for exits that
// come from a goroutine of the fake's own.
func (b *fakeBackend) report(e backend.Exit) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.closed {
		b.exits <- e
	}
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

// alive reports whether the fake still runs the fiber.
func (b *fakeBackend) alive(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	f := b.fibers[id]
	return f != nil && f.alive
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

func (b *fakeBackend) unwarmedIDs() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.unwarmed...)
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

// poolMixin pools restored sandboxes, as gvisor does. A pooled sandbox
// becomes a fake fiber at Bind, under the fence it is handed, with the
// pid it was restored with.
type poolMixin struct {
	fb     *fakeBackend
	pmu    sync.Mutex
	pooled map[string]*fakePooled
	n      int
	// Knobs a test sets before calling the runtime.
	poolErr, bindErr error
	noPool           bool          // the template does not bind late
	bindDelay        time.Duration // how long a Bind takes before it answers
	bindExitDelay    time.Duration // how long after a failed Bind the sandbox's end is reported
	bindExits        atomic.Int32  // those ends, once reported
	poolGate         chan struct{} // holds every Pool until closed
	discarded        []string
}

type fakePooled struct {
	id   string
	pid  int
	spec backend.PoolSpec
}

func newPoolMixin(fb *fakeBackend) *poolMixin {
	return &poolMixin{fb: fb, pooled: map[string]*fakePooled{}}
}

func (m *poolMixin) Pool(_ context.Context, warmID string, spec backend.PoolSpec) (backend.Pooled, error) {
	enter(spec.CgroupFD)
	if gate := m.poolGate; gate != nil {
		<-gate
	}
	if m.poolErr != nil {
		return backend.Pooled{}, m.poolErr
	}
	if m.noPool {
		return backend.Pooled{}, backend.ErrNoPool
	}
	if _, ok := m.fb.warmSpec(warmID); !ok {
		return backend.Pooled{}, fmt.Errorf("fake: no warm instance %q", warmID)
	}
	m.fb.mu.Lock()
	m.fb.nextPID++
	pid := m.fb.nextPID
	m.fb.mu.Unlock()
	m.pmu.Lock()
	defer m.pmu.Unlock()
	m.n++
	p := &fakePooled{id: fmt.Sprintf("p-%s-%d", warmID, m.n), pid: pid, spec: spec}
	m.pooled[p.id] = p
	return backend.Pooled{ID: p.id, PID: p.pid}, nil
}

func (m *poolMixin) Bind(_ context.Context, pooledID string, spec backend.FiberSpec) (backend.Fiber, error) {
	m.pmu.Lock()
	p := m.pooled[pooledID]
	delete(m.pooled, pooledID)
	m.pmu.Unlock()
	if p == nil {
		return backend.Fiber{}, fmt.Errorf("fake: no pooled sandbox %q", pooledID)
	}
	time.Sleep(m.bindDelay)
	if m.bindErr != nil {
		// A failed hand-out kills the sandbox under its pooled id, and
		// its reaper reports that later, as a real one does.
		go func() {
			time.Sleep(max(m.bindExitDelay, 10*time.Millisecond))
			m.fb.report(backend.Exit{PooledID: pooledID, Status: "signal:SIGKILL"})
			m.bindExits.Add(1)
		}()
		return backend.Fiber{}, m.bindErr
	}
	m.fb.mu.Lock()
	defer m.fb.mu.Unlock()
	ln, err := m.fb.listen(spec.Fence, spec.Endpoint)
	if err != nil {
		return backend.Fiber{}, err
	}
	host, fd, identity, err := m.fb.channel(spec, spec.Identity != nil)
	if err != nil {
		return backend.Fiber{}, err
	}
	m.fb.fibers[spec.Fence] = &fakeFiber{spec: spec, alive: true, identity: identity, handoff: fd, ln: ln}
	return backend.Fiber{ID: spec.Fence, PID: p.pid, Footprint: m.fb.footprint, Channel: host}, nil
}

func (m *poolMixin) Discard(pooledID string) {
	m.pmu.Lock()
	_, ok := m.pooled[pooledID]
	delete(m.pooled, pooledID)
	m.discarded = append(m.discarded, pooledID)
	m.pmu.Unlock()
	m.fb.mu.Lock()
	m.fb.events = append(m.fb.events, "discard "+pooledID)
	m.fb.mu.Unlock()
	if ok {
		m.fb.exits <- backend.Exit{PooledID: pooledID, Status: "signal:SIGKILL"}
	}
}

// pooledDie reports a pooled sandbox's death on its own.
func (m *poolMixin) pooledDie(pooledID, status string) {
	m.pmu.Lock()
	delete(m.pooled, pooledID)
	m.pmu.Unlock()
	m.fb.exits <- backend.Exit{PooledID: pooledID, Status: status}
}

func (m *poolMixin) pooledIDs() []string {
	m.pmu.Lock()
	defer m.pmu.Unlock()
	var ids []string
	for id := range m.pooled {
		ids = append(ids, id)
	}
	return ids
}

func (m *poolMixin) discardedIDs() []string {
	m.pmu.Lock()
	defer m.pmu.Unlock()
	return append([]string(nil), m.discarded...)
}

type isolatorMixin struct{ isolates bool }

func (m isolatorMixin) IsolatesTenants() bool { return m.isolates }

// handoffMixin says the backend's fibers take a channel. The fake it
// wraps must make them (channels), so a test composing it sets that.
type handoffMixin struct{ handoff bool }

func (m handoffMixin) Handoff() bool { return m.handoff }

type idMapperMixin struct {
	uid uint32
	err error
}

func (m *idMapperMixin) MappedRoot(string) (uint32, error) { return m.uid, m.err }
func (m *idMapperMixin) mapper() *idMapperMixin            { return m }

type platformMixin struct{ p artifact.Platform }

func (m platformMixin) Platform() artifact.Platform { return m.p }

// deadlineMixin advises create and resume, or what byWarm holds for the
// warm instance asked about, as a backend that measured it at warm.
type deadlineMixin struct {
	create, resume time.Duration
	byWarm         map[string][2]time.Duration
}

func (m deadlineMixin) DefaultDeadlines(warmID string) (time.Duration, time.Duration) {
	if d, ok := m.byWarm[warmID]; ok {
		return d[0], d[1]
	}
	return m.create, m.resume
}

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
	schemesMixin
	platformMixin
	deadlineMixin
}

func newSandboxBackend(tier core.Tier) *sandboxBackend {
	fb := newFakeBackend(tier)
	fb.channels = true
	return &sandboxBackend{fakeBackend: fb, wReporterMixin: &wReporterMixin{}, deviceMixin: &deviceMixin{},
		isolatorMixin: isolatorMixin{true}, handoffMixin: handoffMixin{true},
		schemesMixin: schemesMixin{[]string{"unix", "tcp"}}}
}

// poolBackend is a sandbox backend that pools restored sandboxes, as
// gvisor is: a fixed footprint, isolated tenants, and a pool.
type poolBackend struct {
	*fakeBackend
	overheadMixin
	isolatorMixin
	*poolMixin
}

func newPoolBackend(tier core.Tier) *poolBackend {
	fb := newFakeBackend(tier)
	fb.warm = backend.Warm{Bytes: 4 * mib, TotalBytes: 8 * mib}
	return &poolBackend{fakeBackend: fb, isolatorMixin: isolatorMixin{true}, poolMixin: newPoolMixin(fb)}
}

// Test plumbing.

// plainTree is whether the runtime runs over a plain directory standing
// in for its cgroup subtree, the default. FIBERD_CGROUP_ROOT names a
// real delegated subtree instead, for a root run in the dev container.
var plainTree = os.Getenv("FIBERD_CGROUP_ROOT") == ""

func init() {
	if plainTree {
		rmdir = plainRmdir
	}
}

// plainRmdir removes a cgroup of the plain tree. The kernel drops an
// empty cgroup whatever control files it shows, so the files go first.
// A child cgroup keeps it, as the kernel would.
func plainRmdir(d cgroup.Dir) error {
	entries, err := os.ReadDir(d.Path)
	if err != nil {
		return d.Remove()
	}
	for _, e := range entries {
		if !e.IsDir() {
			_ = os.Remove(filepath.Join(d.Path, e.Name()))
		}
	}
	return d.Remove()
}

var cgroupSeq atomic.Int64

// testCgroupRoot is a fresh cgroup subtree for one runtime. On the
// plain tree it is a directory under the test's temp dir showing the
// controllers a delegated root offers. On a real tree it is a child of
// FIBERD_CGROUP_ROOT, removed with everything under it when the test
// ends, and the test skips where that root is not writable.
func testCgroupRoot(t *testing.T) string {
	t.Helper()
	if plainTree {
		dir := filepath.Join(t.TempDir(), "cg")
		seedCgroup(t, cgroup.Root(dir), map[string]string{"cgroup.controllers": "memory pids\n"})
		return dir
	}
	root := os.Getenv("FIBERD_CGROUP_ROOT")
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

// seedCgroup makes d with the given files, on the plain tree the files
// the kernel would show before the runtime touches d. On a real tree it
// only makes d, which then has every file.
func seedCgroup(t *testing.T, d cgroup.Dir, files map[string]string) {
	t.Helper()
	if err := os.MkdirAll(d.Path, 0o755); err != nil {
		t.Fatal(err)
	}
	if !plainTree {
		return
	}
	for name, v := range files {
		if err := os.WriteFile(filepath.Join(d.Path, name), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// delegated seeds d as a cgroup made under a root that delegated the
// pids controller, which shows pids.max and cgroup.procs from the start.
// A test calls it before the runtime makes d, for the task limits and
// the cgroup.procs hand-over the runtime writes on the way.
func delegated(t *testing.T, d cgroup.Dir) {
	t.Helper()
	seedCgroup(t, d, map[string]string{"pids.max": "max\n", "cgroup.procs": ""})
}

// delegatedUnder is delegated for cgroups named relative to root, from
// a Config modifier that has no test to fail.
func delegatedUnder(root string, names ...string) {
	for _, n := range names {
		d := cgroup.Root(root).Child(n)
		if err := os.MkdirAll(d.Path, 0o755); err != nil {
			panic(err)
		}
		if !plainTree {
			continue
		}
		for name, v := range map[string]string{"pids.max": "max\n", "cgroup.procs": ""} {
			if err := os.WriteFile(filepath.Join(d.Path, name), []byte(v), 0o644); err != nil {
				panic(err)
			}
		}
	}
}

// liveFiles is what a cgroup shows once a task runs in it, as far as the
// runtime reads. Nothing is charged, no task is listed, no event yet.
var liveFiles = map[string]string{
	"cgroup.procs":    "",
	"memory.current":  "0\n",
	"memory.stat":     "anon 0\nshmem 0\n",
	"memory.events":   "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
	"pids.events":     "max 0\n",
	"memory.pressure": "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
}

// enter is what the fake does with a cgroup descriptor it is handed.
// On the plain tree it writes the files a live cgroup shows, which the
// kernel keeps for a real one. Files already there are kept.
func enter(fd int) {
	if !plainTree || fd < 0 {
		return
	}
	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return
	}
	for name, v := range liveFiles {
		p := filepath.Join(path, name)
		if _, err := os.Lstat(p); err == nil {
			continue
		}
		_ = os.WriteFile(p, []byte(v), 0o644)
	}
}

// plainOnly skips a test on a real tree, whose kernel-owned files no
// test can write.
func plainOnly(t *testing.T) {
	t.Helper()
	if !plainTree {
		t.Skip("the kernel owns this file on a real cgroup tree")
	}
}

// cgSet writes one file of a cgroup, a value the kernel would show.
func cgSet(t *testing.T, d cgroup.Dir, name, v string) {
	t.Helper()
	plainOnly(t)
	if err := os.WriteFile(filepath.Join(d.Path, name), []byte(v+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// charge is what the leaf's tasks have made private, its memory.current.
func charge(t *testing.T, d cgroup.Dir, n uint64) {
	t.Helper()
	cgSet(t, d, "memory.current", strconv.FormatUint(n, 10))
}

// unwritable makes name under d a directory, so the runtime's write of
// that control file fails, as the kernel refuses some values.
func unwritable(t *testing.T, d cgroup.Dir, name string) {
	t.Helper()
	plainOnly(t)
	if err := os.MkdirAll(d.Path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(d.Path, name), 0o755); err != nil {
		t.Fatal(err)
	}
}

// inTheWay leaves a file where the runtime would make the cgroup name
// under d, so the kernel cannot make it. The kernel's own refusal of
// one leaf more is tests/integration/host TestLeafRefused.
func inTheWay(t *testing.T, d cgroup.Dir, name string) {
	t.Helper()
	plainOnly(t)
	if err := os.WriteFile(filepath.Join(d.Path, name), nil, 0o644); err != nil {
		t.Fatal(err)
	}
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

// testConfig is a runtime configuration over be with every path under
// the test's temp dir and a fresh cgroup subtree.
// testPlatform is the host every test runtime believes it runs on. It
// names all three facts, so New detects nothing (the libc comes from
// ldd).
var testPlatform = artifact.Platform{Arch: "riscv64", Kernel: "6.1.0-test", Libc: "(gnu libc) 2.36"}

func testConfig(t *testing.T, be backend.Backend) Config {
	t.Helper()
	root := t.TempDir()
	return Config{Backend: be, Templates: map[string]string{"default": "/bin/true --template"},
		CgroupRoot: testCgroupRoot(t), RunDir: filepath.Join(root, "run"), DeltaDir: filepath.Join(root, "deltas"),
		TemplateCache: filepath.Join(root, "cache"), Platform: testPlatform}
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
	return strings.TrimSpace(string(b))
}

// cgOr reads one file of a cgroup. On the plain tree a file the runtime
// never wrote is absent, and reads as the kernel's default absent.
func cgOr(t *testing.T, d cgroup.Dir, name, absent string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(d.Path, name))
	if errors.Is(err, os.ErrNotExist) && plainTree {
		return absent
	}
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(d.Path, name), err)
	}
	return strings.TrimSpace(string(b))
}

// limit reads one limit of a cgroup, "max" when the runtime never set it.
func limit(t *testing.T, d cgroup.Dir, name string) string {
	t.Helper()
	return cgOr(t, d, name, "max")
}

func cgUint(t *testing.T, d cgroup.Dir, name string) uint64 {
	t.Helper()
	n, err := strconv.ParseUint(cgFile(t, d, name), 10, 64)
	if err != nil {
		t.Fatalf("%s/%s: %v", d.Path, name, err)
	}
	return n
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
	_ backend.EndpointSchemer  = (*sandboxBackend)(nil)
	_ backend.Platformer       = (*sandboxBackend)(nil)
	_ backend.DeadlineAdvisor  = (*sandboxBackend)(nil)
	_ backend.Pooler           = (*poolBackend)(nil)
	_ backend.Overheader       = (*poolBackend)(nil)
)
