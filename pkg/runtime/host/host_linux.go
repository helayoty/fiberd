//go:build linux

package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/endpoint"
	"github.com/helayoty/fiberd/pkg/sys/cgroup"
)

var (
	ErrNoTemplate  = errors.New("host: no template command for digest")
	ErrNotPrepared = errors.New("host: template not prepared for this grant")
	// ErrParity: an artifact's images or a published delta were made on
	// a host this one cannot restore them on (see artifact.Parity).
	ErrParity = errors.New("host: platform parity")
	// ErrNoHandoff means the grant's fibers are reached by handoff but
	// this home cannot pass them connections. Its backend cannot, or it
	// routes none (no Config.Handoff).
	ErrNoHandoff = errors.New("host: this home does not hand connections to fibers")
	// ErrNotHandoff means a connection was handed to a fiber that does not
	// take them (unknown, gone, or reached directly).
	ErrNotHandoff = errors.New("host: fiber does not take handed-off connections")
	// ErrHandoffBusy means the fiber's queue of handed-off connections is
	// full, so it is not accepting.
	ErrHandoffBusy = errors.New("host: fiber is not accepting handed-off connections")
)

// Runtime implements core.Runtime over one warm template instance per
// grant, provided by the backend.
type Runtime struct {
	cfg  Config
	be   backend.Backend
	root cgroup.Dir
	tier core.Tier         // what the backend offers
	host artifact.Platform // what checkpoints made here record, and what pulled ones must match
	hide []string          // directories fibers must not see
	// ownRootfs is set when the backend runs templates inside a root
	// filesystem of its own (it stated a libc of its own: gvisor, runc,
	// hyperlight). The host's loader never sees such a template, so a
	// dynamically linked one is refused rather than tried (resolveTemplate).
	ownRootfs bool

	// relay is set when the family is tcp and the backend serves unix
	// sockets only: fiberd listens on each fiber's port and splices
	// to its socket (relay.go). relaySlots is the home's cap on relayed
	// connections, shared by every fiber's relay.
	relay      bool
	relaySlots chan struct{}

	mu      sync.Mutex
	warms   map[string]*warm  // grant uid
	fibers  map[string]*fiber // fiber id (fence string)
	poolSeq uint64            // names pool leaves, p-<n>, across every grant
	ports   map[int]string    // tcp endpoints: port -> fiber id holding it
	// socks maps each unix socket path a live fiber serves under the run
	// directory to that fiber. A resumed fiber binds the name it was
	// parked with, which another home minted, so names can collide with
	// a local fiber's. The holder keeps the name until its end.
	socks map[string]string
	exits chan core.FiberExit
	// poolExits names the grant of every pooled sandbox that dies before
	// its hand-out.
	poolExits chan string
	// stop is closed by Close, so the W executioner ends with the
	// runtime instead of outliving it.
	stop     chan struct{}
	stopOnce sync.Once
	// identities maps a grant uid to the handoff identity its fibers get.
	identities map[string]handoffIdentity

	// parents is the content-addressed store of template checkpoints:
	// <TemplateCache>/parents/<sha256>/ (a self-checkpoint, or a symlink
	// to an artifact's images). A delta names its parent by hash, so a
	// parent kept here stays usable across template restarts and, when
	// the same artifact warmed another home, across homes, for as long as
	// a warm instance or a delta here names it (parents_linux.go).
	parentsMu sync.Mutex
	parents   map[string]backend.Parent
	// storeMu is held for reading by every section that uses the store
	// (useParents) and for writing by the prune. storeUses counts the
	// sections that ended. prune pokes the pruner, which closes
	// pruneDone when it ends.
	storeMu   sync.RWMutex
	storeUses atomic.Uint64
	prune     chan struct{}
	pruneDone chan struct{}

	// templateMu serialises pulls and re-verification of the template
	// cache, which replace files other warms of the same digest read.
	// imagesHeld counts, per unpacked images directory, the warms in
	// the making between their resolve and the link that names the
	// images, so the prune leaves those images (parents_linux.go).
	templateMu sync.Mutex
	imagesHeld map[string]int

	devicesMu      sync.Mutex
	deviceChannels map[string]core.DeviceChannel // grant uid -> what the home provisioned
}

// AttachDevices implements core.DeviceAware: the grant's devices reach
// its warm instance's environment at PrepareTemplate.
func (r *Runtime) AttachDevices(grantUID string, fc core.DeviceChannel) {
	r.devicesMu.Lock()
	defer r.devicesMu.Unlock()
	if r.deviceChannels == nil {
		r.deviceChannels = map[string]core.DeviceChannel{}
	}
	r.deviceChannels[grantUID] = fc
}

func (r *Runtime) devicesOf(grantUID string) core.DeviceChannel {
	r.devicesMu.Lock()
	defer r.devicesMu.Unlock()
	return r.deviceChannels[grantUID]
}

type warm struct {
	grantUID string
	digest   string
	template backend.Template
	id       string // backend handle
	pid      int
	bytes    uint64 // one fiber's fixed footprint in the W counter (0: none)
	total    uint64 // one fiber's whole footprint, for its leaf's memory.max
	// parentSHA names the checkpoint of this instance's pages that fiber
	// deltas are computed against, in the parent store: the artifact's
	// images, or a self-checkpoint taken after READY.
	parentSHA string
	cg        cgroup.Dir // <root>/<grant>
	zcg       cgroup.Dir // <root>/<grant>/zygote
	minBytes  uint64     // memory.min held for the instance's pages
	pool      []*pooled  // sandboxes restored ahead of their fibers, oldest first
	noPool    bool       // the backend said this template cannot pool
}

type fiber struct {
	id       string
	grantUID string
	pid      int
	cg       cgroup.Dir
	endpoint string // the URL Clone returned
	port     int    // tcp endpoints: the port held while running or parked
	sock     string // the unix socket path the backend serves under the run directory, "" for none
	birth    string // the fence the fiber was born under, which it holds in memory across resumes
	// generation counts the fiber's lineage: 1 when born from the warm
	// instance, the parked generation plus one when resumed. A park
	// writes it into the manifest, so the count survives a move.
	generation int
	budget     uint64 // w_budget_bytes; 0 = unlimited
	devMax     uint64 // device_budget bytes; 0 = none
	quota      uint64 // the grant's parked-delta bytes on this home (0 = none)
	base       uint64 // the leaf's own count before the hand-out, subtracted from W (0 = the template's probe)
	overWhy    string // why the host killed it, for the exit's detail
	released   bool   // Release or Park in progress: do not report the exit
	parked     bool   // the end in progress is a park: the port stays with the delta
	overW      bool   // killed by the host for exceeding its W budget
	ready      bool   // the backend has answered: before that, W is a restore in flight, not the fiber's
	pooled     bool   // handed out of the pool, in the leaf it was restored in
	// channel is the host's end of a handoff fiber's channel, which the
	// backend made and carried its incarnation record at birth, and the
	// host passes connections over. It is nil for every other fiber.
	// handoff says the fiber serves those connections rather than an
	// endpoint.
	channel *os.File
	handoff bool
	// relay is the tcp listener in front of a fiber that serves a unix
	// socket on a tcp home. It is nil for every other fiber.
	relay *relay
	done  chan struct{}
	// exit is what finish would have reported, kept when a park or
	// release withheld it, so a park that fails after the fiber died can
	// still report the death.
	exit *core.FiberExit
}

// New opens the runtime over cfg.Backend. It refuses a backend that
// offers no tier (ErrNoTier), since confinement fails closed.
func New(cfg Config) (*Runtime, error) {
	if cfg.Backend == nil {
		return nil, errors.New("host: Backend is required")
	}
	if cfg.CgroupRoot == "" {
		return nil, errors.New("host: CgroupRoot is required")
	}
	if cfg.Handoff != nil && len(cfg.HandoffKey) < 32 {
		return nil, errors.New("host: Handoff needs a HandoffKey of at least 32 bytes")
	}
	if cfg.RunDir == "" {
		cfg.RunDir = "/run/fiberd"
	}
	if cfg.DeltaDir == "" {
		cfg.DeltaDir = "/var/lib/fiberd/deltas"
	}
	if cfg.TemplateCache == "" {
		cfg.TemplateCache = "/var/lib/fiberd/templates"
	}
	// Restores change directory, so every path handed down must be
	// absolute; RunDir too, since endpoints are recorded in manifests.
	for _, p := range []*string{&cfg.RunDir, &cfg.DeltaDir, &cfg.CgroupRoot, &cfg.TemplateCache, &cfg.PrivateDir} {
		if *p == "" {
			continue // PrivateDir is optional, and the others have defaults above
		}
		abs, err := filepath.Abs(*p)
		if err != nil {
			return nil, err
		}
		*p = abs
	}
	tier := cfg.Backend.Tier()
	if tier == core.TierUnspecified {
		return nil, noTier(cfg.Backend)
	}
	root := cgroup.Root(cfg.CgroupRoot)
	if err := root.Ensure("memory", "pids"); err != nil {
		return nil, err
	}
	capGrants(root)
	for _, d := range []string{cfg.RunDir, cfg.DeltaDir, cfg.TemplateCache} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	// Template memory in the clear, fiberd's alone, also when an earlier
	// fiberd left the stores open.
	for _, d := range []string{filepath.Join(cfg.TemplateCache, "parents"), filepath.Join(cfg.TemplateCache, "zygote-images")} {
		if err := ownerDir(d); err != nil {
			return nil, err
		}
	}
	// What this home believes about its host. The configuration's facts
	// win, then the backend's, and what neither names is detected.
	host := artifact.Platform{Arch: cfg.Platform.Arch, Kernel: cfg.Platform.Kernel, Libc: cfg.Platform.Libc}
	ownRootfs := false
	if p, ok := cfg.Backend.(backend.Platformer); ok {
		// The backend knows what its checkpoints depend on.
		bp := p.Platform()
		for dst, v := range map[*string]string{&host.Arch: bp.Arch, &host.Kernel: bp.Kernel, &host.Libc: bp.Libc} {
			if *dst == "" {
				*dst = v
			}
		}
		ownRootfs = bp.Libc != ""
	}
	host = host.Complete()
	host.Backend = cfg.Backend.Name()
	if host.Backend == "proc" {
		// CRIU reopens a cached template executable by its path. runc
		// binds a copy of its own, and gVisor and Hyperlight restore
		// inside their sandbox.
		host.Templates = cfg.TemplateCache
	}
	if err := cfg.Endpoints.Validate(); err != nil {
		return nil, fmt.Errorf("host: %w", err)
	}
	if cfg.DeltaRegistry != "" {
		if err := cfg.checkDeltaRegistry(); err != nil {
			return nil, err
		}
	}
	// Every backend serves unix sockets under the run directory. Under a
	// tcp family, a backend that can bind the port itself (proc) is told
	// the tcp address; any other is told the unix path and fiberd
	// relays the port to it (relay.go).
	relay := cfg.Endpoints.Family.Scheme() != "unix" && !serves(cfg.Backend, "tcp")
	hide, skipped, err := cfg.fiberHide()
	if err != nil {
		return nil, err
	}
	if len(skipped) > 0 {
		log.Printf("host: not hiding %v from fibers: relative, or holding the run directory %s", skipped, cfg.RunDir)
	}
	served := cfg.Endpoints.Family.Scheme()
	if relay {
		served += " (relayed to unix sockets)"
	}
	log.Printf("host: backend %s tier %s platform %s parity %s endpoints %s", host.Backend, tier, host, cfg.Parity, served)
	r := &Runtime{
		cfg: cfg, be: cfg.Backend, root: root, tier: tier, host: host, hide: hide, ownRootfs: ownRootfs,
		relay: relay, relaySlots: make(chan struct{}, relayMaxTotal),
		warms: map[string]*warm{}, fibers: map[string]*fiber{}, ports: map[int]string{}, socks: map[string]string{},
		exits:     make(chan core.FiberExit, 1024),
		poolExits: make(chan string, 64),
		stop:      make(chan struct{}),
		parents:   map[string]backend.Parent{},
		prune:     make(chan struct{}, 1),
		pruneDone: make(chan struct{}),
	}
	r.sweepPools()
	r.sweepStores()
	go r.pump()
	// What an earlier fiberd left in the store that no delta names.
	go r.pruneLoop()
	r.pokePrune()
	_, overhead := cfg.Backend.(backend.Overheader)
	_, reports := cfg.Backend.(backend.WReporter)
	_, devices := cfg.Backend.(backend.DeviceReporter)
	if overhead || reports || devices {
		go r.enforceW()
	}
	return r, nil
}

// noTier is New's error for a backend that offers no tier. It names the
// backend and, when the backend can say, why.
func noTier(be backend.Backend) error {
	if p, ok := be.(backend.Prober); ok && p.ProbeErr() != nil {
		return fmt.Errorf("host: backend %s %w: %w", be.Name(), ErrNoTier, p.ProbeErr())
	}
	return fmt.Errorf("host: backend %s %w", be.Name(), ErrNoTier)
}

// serves reports whether the backend lists scheme among the endpoint
// schemes it can bind. A backend without an EndpointSchemer speaks unix
// only.
func serves(be backend.Backend, scheme string) bool {
	s, ok := be.(backend.EndpointSchemer)
	if !ok {
		return scheme == "unix"
	}
	for _, sc := range s.EndpointSchemes() {
		if sc == scheme {
			return true
		}
	}
	return false
}

// Relays reports whether this home's tcp endpoints are relayed by the
// fiberd to fibers' unix sockets.
func (r *Runtime) Relays() bool { return r.relay }

// IsolatesTenants implements core.Isolator with the backend's answer.
func (r *Runtime) IsolatesTenants() bool {
	iso, ok := r.be.(backend.Isolator)
	return ok && iso.IsolatesTenants()
}

// OffersDevice implements core.DeviceCapable: the grant's warm instance
// is an engine that has reported a device (the class is not checked
// beyond that; one engine, one device class).
func (r *Runtime) OffersDevice(grantUID, _ string) bool {
	dr, ok := r.be.(backend.DeviceReporter)
	if !ok {
		return false
	}
	_, capacity, ok := dr.WarmDevice(grantUID)
	return ok && capacity > 0
}

// DevicePressure is the ladder's second input: the engine's occupancy in
// percent of its capacity, for grants whose template is an engine; 0 for
// the rest. Combine with the PSI source through core.MaxPressure.
func (r *Runtime) DevicePressure() core.PressureSource { return devicePressure{r} }

type devicePressure struct{ r *Runtime }

func (d devicePressure) Pressure(grantUID string) (float64, error) {
	dr, ok := d.r.be.(backend.DeviceReporter)
	if !ok {
		return 0, nil
	}
	used, capacity, ok := dr.WarmDevice(grantUID)
	if !ok || capacity == 0 {
		return 0, nil
	}
	return 100 * float64(used) / float64(capacity), nil
}

// enforceW is the executioner for backends whose fibers carry a fixed
// footprint, or report W themselves because they are not processes in a
// leaf. Their leaves get memory.max = budget + footprint + slack for the
// sandbox's own variance, so the kernel only catches gross overruns; the
// budget itself is held here: W is sampled, and a fiber over its budget
// is killed and reported as oom, exactly as the kernel would for a fork.
func (r *Runtime) enforceW() {
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-tick.C:
		}
		r.mu.Lock()
		fs := make([]*fiber, 0, len(r.fibers))
		for _, f := range r.fibers {
			if (f.budget > 0 || f.devMax > 0) && !f.released && f.ready {
				fs = append(fs, f)
			}
		}
		r.mu.Unlock()
		dr, _ := r.be.(backend.DeviceReporter)
		_, overhead := r.be.(backend.Overheader)
		_, reports := r.be.(backend.WReporter)
		for _, f := range fs {
			why := ""
			if overhead || reports || dr == nil {
				if w, err := r.wBytes(f); err == nil && f.budget > 0 && w > f.budget {
					why = fmt.Sprintf("W=%d over budget %d", w, f.budget)
				}
			}
			if why == "" && dr != nil && f.devMax > 0 {
				if d, ok := dr.FiberDevice(f.id); ok && d > f.devMax {
					why = fmt.Sprintf("device %d over budget %d", d, f.devMax)
				}
			}
			if why == "" {
				continue
			}
			r.mu.Lock()
			f.overW, f.overWhy = true, why
			r.mu.Unlock()
			log.Printf("host: %s %s: killed", f.id, why)
			_ = r.be.Kill(f.id)
			_ = f.cg.Kill()
		}
	}
}

func (r *Runtime) codec() backend.DeltaCodec {
	c, _ := r.be.(backend.DeltaCodec)
	return c
}

func (r *Runtime) parentsDir() string { return filepath.Join(r.cfg.TemplateCache, "parents") }

// registerParent loads a checkpoint directory, files it under its hash in
// the parent store (moving a self-checkpoint, made fiberd's alone first,
// linking an artifact's images) and returns the hash. The caller holds a
// section (useParents) until the parent's use is recorded.
func (r *Runtime) registerParent(dir string, move bool) (string, error) {
	codec := r.codec()
	if codec == nil {
		return "", errors.New("host: backend has no delta codec")
	}
	p, err := codec.LoadParent(dir)
	if err != nil {
		return "", err
	}
	sha := p.SHA256()
	dst := filepath.Join(r.parentsDir(), sha)
	if err := ownerDir(r.parentsDir()); err != nil {
		p.Close()
		return "", err
	}
	if move {
		if err := ownerOnly(dir); err != nil {
			p.Close()
			return "", err
		}
	}
	if _, err := os.Lstat(dst); err != nil {
		if move {
			err = os.Rename(dir, dst)
		} else {
			err = os.Symlink(dir, dst)
		}
		// Another warm of the same artifact filed it meanwhile: the same
		// content, loaded below as the store's.
		if err != nil && !errors.Is(err, os.ErrExist) {
			p.Close()
			return "", err
		}
		if err != nil && move {
			_ = os.RemoveAll(dir)
		}
		// Re-map from the store path so the parent survives the source
		// directory going away.
		p.Close()
		if p, err = codec.LoadParent(dst); err != nil {
			return "", err
		}
	} else if move {
		_ = os.RemoveAll(dir) // identical content already stored
		p.Close()
		if p, err = codec.LoadParent(dst); err != nil {
			return "", err
		}
	}
	r.parentsMu.Lock()
	if _, ok := r.parents[sha]; ok {
		p.Close() // already loaded by someone else; keep theirs
	} else {
		r.parents[sha] = p
	}
	r.parentsMu.Unlock()
	return sha, nil
}

// ErrParentMissing: a delta names a parent this home's store lacks.
var ErrParentMissing = errors.New("host: parent checkpoint not in the store")

// parent finds a checkpoint by hash: in memory, or on disk in the store.
func (r *Runtime) parent(sha string) (backend.Parent, error) {
	if !isHex64(sha) {
		return nil, fmt.Errorf("host: parent hash %q is not a sha256", sha)
	}
	codec := r.codec()
	if codec == nil {
		return nil, errors.New("host: backend has no delta codec")
	}
	r.parentsMu.Lock()
	p, ok := r.parents[sha]
	r.parentsMu.Unlock()
	if ok {
		return p, nil
	}
	dir := filepath.Join(r.parentsDir(), sha)
	if _, err := os.Stat(dir); err != nil {
		return nil, fmt.Errorf("%w (%s)", ErrParentMissing, sha[:12])
	}
	p, err := codec.LoadParent(dir)
	if err != nil {
		return nil, err
	}
	if p.SHA256() != sha {
		p.Close()
		return nil, fmt.Errorf("host: parent store entry %s hashes to %s", sha[:12], p.SHA256()[:12])
	}
	r.parentsMu.Lock()
	if old, ok := r.parents[sha]; ok {
		p.Close()
		p = old
	} else {
		r.parents[sha] = p
	}
	r.parentsMu.Unlock()
	return p, nil
}

func (r *Runtime) Tier() core.Tier { return r.tier }

// CgroupRoot is where the runtime carves grant and fiber cgroups.
func (r *Runtime) CgroupRoot() string { return r.cfg.CgroupRoot }

// DefaultDeadlines implements core.DeadlineAdvisor from the backend, for
// the grant's warm instance. A grant with none warm asks for no
// instance, which the backend answers with its floors.
func (r *Runtime) DefaultDeadlines(grantUID string) (create, resume time.Duration) {
	adv, ok := r.be.(backend.DeadlineAdvisor)
	if !ok {
		return 0, 0
	}
	id := ""
	if z := r.warmOf(grantUID); z != nil {
		id = z.id
	}
	return adv.DefaultDeadlines(id)
}

// overhead is the fixed per-fiber footprint for a grant's fibers, added
// to every leaf's memory.max and subtracted from the measured W of a
// fiber whose backend did not report its own. Only a backend that is an
// Overheader gets it. It is the warm template's resident size, measured
// once ready, because a sandbox restored from the template pays for
// those pages itself.
func (r *Runtime) overhead(grantUID string) uint64 {
	if _, ok := r.be.(backend.Overheader); !ok {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if z := r.warms[grantUID]; z != nil {
		return z.bytes
	}
	return 0
}

// wBytes reads a fiber's working set: what the backend reports when its
// fibers have no leaf of their own, else the leaf's memory.current or
// the memory.stat counter the backend names, less the fixed footprint.
// The footprint is the leaf's own count before the hand-out when the
// backend read one, since restores of one image settle MiB apart, and
// the template's probe otherwise.
func (r *Runtime) wBytes(f *fiber) (uint64, error) {
	if rep, ok := r.be.(backend.WReporter); ok {
		if w, known := rep.FiberW(f.id); known {
			return w, nil
		}
		return 0, nil
	}
	var cur uint64
	var err error
	if m, ok := r.be.(backend.WMeter); ok && m.WCounter() != "" {
		cur, err = f.cg.Stat(m.WCounter())
	} else {
		cur, err = f.cg.MemoryCurrent()
	}
	if err != nil {
		return 0, err
	}
	o := f.base
	if o == 0 {
		o = r.overhead(f.grantUID)
	}
	if cur > o {
		return cur - o, nil
	}
	return 0, nil
}

// leafMax is memory.max for a fiber of this grant: the W budget plus the
// fiber's whole fixed footprint, with half of that and 32 MiB of slack.
// The slack covers what is not the fiber's working set but is charged
// to its leaf: the sandbox's own kernel heap (which varies by tens of
// MiB between sandboxes and between hosts) and the runtime client that
// starts it in the leaf and lives there until the restore completes.
// The kernel limit therefore only catches gross overruns; the budget
// itself is held by enforceW on the W counter. 0 (no budget) stays
// unlimited.
func (r *Runtime) leafMax(g core.Grant) uint64 {
	if g.WBudgetBytes == 0 {
		return 0
	}
	if _, ok := r.be.(backend.Overheader); !ok {
		return g.WBudgetBytes
	}
	var total uint64
	r.mu.Lock()
	if z := r.warms[g.UID]; z != nil {
		total = z.total
	}
	r.mu.Unlock()
	if total == 0 {
		return g.WBudgetBytes
	}
	return g.WBudgetBytes + total + total/2 + 32<<20
}

// grantCgroup makes the grant's cgroup with its controllers and its
// task limit.
func (r *Runtime) grantCgroup(g core.Grant) (cgroup.Dir, error) {
	gcg := r.root.Child(g.UID)
	if err := gcg.Ensure("memory", "pids"); err != nil {
		return cgroup.Dir{}, err
	}
	if r.limitsTasks() {
		if err := gcg.SetPidsMax(grantPids(g)); err != nil {
			return cgroup.Dir{}, err
		}
	}
	if err := r.delegateProcs(g.UID, gcg); err != nil {
		return cgroup.Dir{}, err
	}
	return gcg, nil
}

// fiberLeaf makes a fiber's leaf under parent, with its memory ceiling,
// group OOM and task limit.
func (r *Runtime) fiberLeaf(parent cgroup.Dir, g core.Grant, fence core.Fence) (cgroup.Dir, error) {
	return r.leaf(parent, g, leafName(fence))
}

// leaf makes a leaf with a fiber's limits under parent: for a fiber, or
// for a sandbox restored ahead of one.
func (r *Runtime) leaf(parent cgroup.Dir, g core.Grant, name string) (cgroup.Dir, error) {
	leaf := parent.Child(name)
	if err := leaf.Create(r.leafMax(g), true); err != nil {
		return leaf, err
	}
	if r.limitsTasks() {
		if err := leaf.SetPidsMax(fiberPidsMax); err != nil {
			_ = rmdir(leaf)
			return leaf, err
		}
	}
	if err := r.delegateProcs(g.UID, leaf); err != nil {
		_ = rmdir(leaf)
		return leaf, err
	}
	return leaf, nil
}

// delegateProcs hands the grant's mapped root, when the backend maps
// one, the cgroup.procs of d and nothing else. A birth into a leaf needs
// write access to it and to the grant cgroup's. The limits stay root's,
// so a grant cannot raise its own memory.max or make cgroups.
func (r *Runtime) delegateProcs(grantUID string, d cgroup.Dir) error {
	m, ok := r.be.(backend.IDMapper)
	if !ok {
		return nil
	}
	uid, err := m.MappedRoot(grantUID)
	if err != nil {
		return err
	}
	if err := os.Chown(filepath.Join(d.Path, "cgroup.procs"), int(uid), -1); err != nil {
		return fmt.Errorf("host: delegate cgroup.procs of %s to uid %d: %w", d.Path, uid, err)
	}
	return nil
}

// limitsTasks reports whether task limits apply. They bound a fork
// backend's fiber, the processes it forks. A sandbox's fiber is the
// sandbox, whose own threads (gVisor's Sentry and Gofer) such a limit
// would count and starve.
func (r *Runtime) limitsTasks() bool { return !r.IsolatesTenants() }

// pidsHits counts the forks refused at pids.max by the grant's cgroup
// and by the subtree root, whose cap (capGrants) every grant shares.
func (r *Runtime) pidsHits(gcg cgroup.Dir) uint64 {
	g, _ := gcg.PidsMaxHits()
	s, _ := r.root.PidsMaxHits()
	return g + s
}

// pidsPressure names a failed birth as the home's own pressure when the
// grant's cgroup or the subtree root refused a fork since before was
// read (pidsHits). The caller is then shed, not sent to another home.
func (r *Runtime) pidsPressure(gcg cgroup.Dir, before uint64, grantUID string, err error) error {
	if r.pidsHits(gcg) > before {
		return fmt.Errorf("%w: grant %s or its home is at pids.max: %w", core.ErrPressure, grantUID, err)
	}
	return err
}

// fiberd's share of the home's limits: an eighth, at least this much,
// at most half.
const (
	reserveMinBytes = 64 << 20
	reserveMinTasks = 64
)

// reserve is fiberd's share of a limit.
func reserve(limit, floor uint64) uint64 {
	return min(max(limit/8, floor), limit/2)
}

// capGrants caps the fibers' subtree a reserve below the home's own
// memory and task limits, which fiberd shares with it. Fibers that
// fill a shared limit would stop fiberd creating a thread, a Go fatal
// error that ends every fiber. memory.high sits an eighth lower so the
// ladder sees pressure first. A home with no visible limit is left alone.
func capGrants(root cgroup.Dir) {
	if c := root.Ceiling("memory.max"); c > 0 {
		top := c - reserve(c, reserveMinBytes)
		if err := root.SetCeiling(top-top/8, top); err != nil {
			log.Printf("host: cap the subtree's memory: %v", err)
		} else {
			log.Printf("host: subtree memory.max=%dMiB, %dMiB kept for fiberd under the home's %dMiB", top>>20, (c-top)>>20, c>>20)
		}
	}
	if c := root.Ceiling("pids.max"); c > 0 {
		top := c - reserve(c, reserveMinTasks)
		if err := root.SetPidsMax(top); err != nil {
			log.Printf("host: cap the subtree's tasks: %v", err)
		} else {
			log.Printf("host: subtree pids.max=%d, %d kept for fiberd under the home's %d", top, c-top, c)
		}
	}
}

// protectTemplates keeps every warm template's pages out of reclaim.
// memory.min on the delegation root is the sum of the warm instances',
// because the kernel caps a child's protection at its parent's.
func (r *Runtime) protectTemplates() {
	r.mu.Lock()
	var sum uint64
	for _, z := range r.warms {
		sum += z.minBytes
	}
	r.mu.Unlock()
	if err := r.root.SetMemoryMin(sum); err != nil {
		log.Printf("host: protect warm templates: %v", err)
	}
}

// PrepareTemplate warms the grant's template: its cgroup, the backend's
// warm instance, the delta parent, the block ceiling. Idempotent per grant.
func (r *Runtime) PrepareTemplate(ctx context.Context, g core.Grant) error {
	if g.Policy.EndpointMode == core.EndpointHandoff {
		if !r.canHandoff() {
			return fmt.Errorf("%w: grant %s on backend %s", ErrNoHandoff, g.UID, r.be.Name())
		}
		if err := r.prepareIdentity(g.UID, g.CallerThumbprint); err != nil {
			return err
		}
	}
	r.mu.Lock()
	if _, ok := r.warms[g.UID]; ok {
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()
	if m, ok := r.be.(backend.IDMapper); ok {
		// Before anything is made for the grant. A grant whose id range
		// another admitted grant holds cannot run on this home.
		if _, err := m.MappedRoot(g.UID); err != nil {
			return err
		}
	}
	tpl, err := r.resolveTemplate(ctx, g.TemplateDigest)
	if err != nil {
		return err
	}
	// The images a resolve unpacked are held until the warm names them
	// through a store link. Images a warm never came to name are left
	// for the prune.
	linked := false
	defer func() {
		if tpl.ImagesDir != "" {
			r.releaseImages(tpl.ImagesDir)
			if !linked {
				r.pokePrune()
			}
		}
	}()

	gcg, err := r.grantCgroup(g)
	if err != nil {
		return err
	}
	zcg := gcg.Child("zygote")
	if err := zcg.Create(0, false); err != nil {
		return err
	}
	zfd, err := zcg.Open()
	if err != nil {
		return err
	}
	defer func() { _ = zfd.Close() }()

	// An empty leaf a backend may measure one fiber's footprint in.
	pcg := gcg.Child("probe")
	probeFD := -1
	if err := pcg.Create(0, false); err == nil {
		if pf, err := pcg.Open(); err == nil {
			probeFD = int(pf.Fd())
			defer func() { _ = pf.Close() }()
		}
	}
	defer func() { _ = removeSoon(pcg) }()

	workDir := filepath.Join(r.cfg.RunDir, g.UID)
	w, err := r.be.Warm(ctx, backend.WarmSpec{GrantUID: g.UID, Template: tpl, CgroupFD: int(zfd.Fd()), WorkDir: workDir, ProbeCgroupFD: probeFD,
		Devices: r.devicesOf(g.UID).Devices, Hide: r.hide})
	if err != nil {
		return err
	}
	z := &warm{grantUID: g.UID, digest: g.TemplateDigest, template: tpl, id: w.ID, pid: w.PID, cg: gcg, zcg: zcg}

	// The parent pages for deltas: the artifact's checkpoint when there
	// is one; otherwise checkpoint the warm instance now, leaving it
	// running. Deltas over a self-checkpoint are exact on this home and
	// portable to any home whose template pages hash the same. Filing
	// the parent and publishing the warm that names it are one section,
	// so the prune never sees the entry without its name.
	parentsDone := func() {}
	defer func() { parentsDone() }()
	if r.usesImages() {
		if tpl.ImagesDir != "" {
			parentsDone = r.useParents()
			sha, err := r.registerParent(tpl.ImagesDir, false)
			if err != nil {
				log.Printf("host: artifact images for %s unusable as a parent; parks will be full images: %v", g.UID, err)
			} else {
				z.parentSHA = sha
			}
		} else if sc, ok := r.be.(backend.SelfCheckpointer); ok {
			// Whatever is left of a checkpoint that is not filed goes,
			// since it is the template's memory in the clear.
			dir := filepath.Join(r.zygoteImagesDir(), g.UID)
			_ = os.RemoveAll(dir)
			if err := ownerDir(r.zygoteImagesDir()); err != nil {
				log.Printf("host: self-checkpoint for %s has no store; parks will be full images: %v", g.UID, err)
			} else if err := sc.CheckpointWarm(ctx, w.ID, dir); err != nil {
				_ = os.RemoveAll(dir)
				log.Printf("host: self-checkpoint for %s failed; parks will be full images: %v", g.UID, err)
			} else {
				parentsDone = r.useParents()
				if sha, err := r.registerParent(dir, true); err != nil {
					_ = os.RemoveAll(dir)
					log.Printf("host: self-checkpoint for %s unusable; parks will be full images: %v", g.UID, err)
				} else {
					z.parentSHA = sha
				}
			}
		}
	}

	zbytes, _ := zcg.MemoryCurrent() // the warm instance's whole footprint, for the ceiling
	if _, ok := r.be.(backend.Overheader); ok {
		// One fiber's fixed footprint: what the backend measured, else
		// the warm instance's own count.
		z.bytes, z.total = w.Bytes, w.TotalBytes
		if z.bytes == 0 {
			z.bytes = zbytes
		}
		if z.total == 0 {
			z.total = z.bytes
		}
	}
	// The template's pages are shared by every fiber. Reclaiming them
	// would make each fiber fault them back in.
	for _, d := range []cgroup.Dir{zcg, gcg} {
		if err := d.SetMemoryMin(zbytes); err != nil {
			log.Printf("host: protect template of %s: %v", g.UID, err)
		}
	}
	z.minBytes = zbytes
	r.mu.Lock()
	r.warms[g.UID] = z
	r.mu.Unlock()
	parentsDone() // the warm names its parent now
	parentsDone = func() {}
	linked = z.parentSHA != ""
	r.protectTemplates()

	// The block ceiling, now that the warm instance's footprint is known.
	ceiling := r.cfg.Ceiling
	if ceiling == nil {
		ceiling = DefaultCeiling
	}
	gc := g
	gc.WBudgetBytes = r.leafMax(g) // each fiber's leaf is this large
	if c := ceiling(gc, zbytes); c > 0 {
		if err := gcg.SetCeiling(c, c+gc.WBudgetBytes); err != nil {
			log.Printf("host: ceiling on grant %s: %v", g.UID, err)
		}
	}
	log.Printf("host: template ready grant=%s template=%s backend=%s pid=%d warm=%dMiB fiber=%dKiB", g.UID, g.TemplateDigest, r.be.Name(), w.PID, zbytes>>20, z.bytes>>10)
	return nil
}

// resolveTemplate finds the template for a digest: the Templates map
// first (a bare command line, no images), else the artifact pulled from
// the registry into the cache, one directory per digest.
func (r *Runtime) resolveTemplate(ctx context.Context, digest string) (backend.Template, error) {
	if argv, ok := r.cfg.Command(digest); ok {
		return backend.Template{Argv: argv, Digest: digest}, nil
	}
	if r.cfg.Registry == "" {
		return backend.Template{}, fmt.Errorf("%w %q (no -template entry and no registry)", ErrNoTemplate, digest)
	}
	hex, ok := sha256Hex(digest)
	if !ok {
		return backend.Template{}, fmt.Errorf("%w %q: registry templates are addressed by sha256: and 64 lowercase hex characters", ErrNoTemplate, digest)
	}
	dir := filepath.Join(r.cfg.TemplateCache, hex)
	r.templateMu.Lock()
	defer r.templateMu.Unlock()
	cfg, err := artifact.ReadConfig(dir)
	if err == nil {
		if cfg, err = artifact.Reverify(ctx, dir, digest); err != nil {
			log.Printf("host: cached template %s failed verification, pulling it again: %v", digest, err)
			_ = os.RemoveAll(dir)
		}
	}
	if err != nil {
		log.Printf("host: pulling template %s from %s", digest, r.cfg.Registry)
		cfg, err = artifact.Pull(ctx, r.cfg.Registry+"@"+digest, dir)
		if err != nil {
			_ = os.RemoveAll(dir)
			return backend.Template{}, fmt.Errorf("%w %q: %w", ErrNoTemplate, digest, err)
		}
	}
	// Author images are sealed to the fleet. A home that makes parents
	// from them opens them with the master, checks their hash, and
	// unpacks them owner-only, afresh on every resolve. Other homes leave
	// them sealed. The unpacked images are held for the caller, since
	// the prune takes images nothing names (releaseImages).
	unpacked := false
	if cfg.HasImages() && r.usesImages() {
		if err := artifact.UnpackImages(dir, cfg, r.cfg.DeltaKeys.Seal); err != nil {
			return backend.Template{}, fmt.Errorf("%w %q: cannot open its images: %w", ErrNoTemplate, digest, err)
		}
		unpacked = true
		if r.imagesHeld == nil {
			r.imagesHeld = map[string]int{}
		}
		r.imagesHeld[artifact.ImagesDir(dir)]++
	}
	// The parity gate. The executable must be for this instruction set,
	// and if the artifact carries images (the template's pages, which
	// every delta is computed against and every restore starts from) they
	// must be from a host this one can restore them on.
	want := cfg.Platform()
	if !cfg.HasImages() {
		// A bare template brings an executable and no pages, so the
		// kernel does not matter. Neither does libc when the executable
		// runs on this host: the loader here loads it or fails plainly.
		// A backend with a root filesystem of its own loads it against
		// that filesystem's libraries, which the home cannot inspect. A
		// static executable needs none. Anything else is refused unless
		// libc parity is off.
		want.Kernel, want.Libc = "", ""
		if r.ownRootfs && cfg.Linking != artifact.LinkStatic && r.cfg.Parity.Libc != artifact.ParityOff {
			return backend.Template{}, fmt.Errorf("%w: template %s is not a static executable (linking %q, built against %q), and backend %s runs templates inside its own root filesystem (%s), which may lack that libc; build the template static, or run with -parity libc=off",
				ErrParity, digest[:19], cfg.Linking, cfg.Libc, r.host.Backend, r.host.Libc)
		}
	}
	if err := r.cfg.Parity.Check(r.host, want); err != nil {
		return backend.Template{}, fmt.Errorf("%w: template %s built on %s: %w", ErrParity, digest[:19], cfg.Platform(), err)
	}
	tpl := backend.Template{Argv: append([]string{artifact.ZygotePath(dir)}, cfg.Args...), Digest: digest, Dir: dir, ZygoteSHA256: cfg.ZygoteSHA256}
	if unpacked {
		tpl.ImagesDir = artifact.ImagesDir(dir)
	}
	return tpl, nil
}

// usesImages reports whether this home makes parents for deltas, from an
// artifact's images or by checkpointing its warm instance.
func (r *Runtime) usesImages() bool {
	return r.codec() != nil && r.tier >= core.TierCheckpoint
}

// sha256Hex returns the hex of a digest that is exactly "sha256:" and 64
// lowercase hex characters. Anything else could name a path outside the
// template cache once joined to it.
func sha256Hex(digest string) (string, bool) {
	hex, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || !isHex64(hex) {
		return "", false
	}
	return hex, true
}

// isHex64 reports whether s is 64 lowercase hex characters, the only form
// of a hash that is safe to join into a path.
func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Pressure implements core.PressureSource: PSI memory "some avg10" on the
// grant's cgroup (warm instance and every fiber leaf).
func (r *Runtime) Pressure(grantUID string) (float64, error) {
	p, err := r.root.Child(grantUID).PSI()
	if err != nil {
		return 0, err
	}
	return p.SomeAvg10, nil
}

// pump turns backend exits into fiber exits: classify (OOM if the leaf
// recorded a kill), clean up, and report unless the fiber was released
// on purpose. A warm instance's end takes its fibers with it. A pooled
// sandbox's end only removes its leaf.
func (r *Runtime) pump() {
	for e := range r.be.Exits() {
		switch {
		case e.PooledID != "":
			r.pooledGone(e.PooledID, e.Status)
			continue
		case e.FiberID == "":
			r.warmGone(e.WarmID)
			continue
		}
		r.mu.Lock()
		f := r.fibers[e.FiberID]
		r.mu.Unlock()
		if f == nil {
			continue
		}
		reason, detail := "exit", e.Status
		if strings.HasPrefix(e.Status, "signal:") {
			reason = "signal"
		}
		if n, err := f.cg.OOMKills(); err == nil && n > 0 {
			reason, detail = "oom", fmt.Sprintf("%s oom_kill=%d", e.Status, n)
		}
		r.mu.Lock()
		overW, why := f.overW, f.overWhy
		r.mu.Unlock()
		if overW {
			reason, detail = "oom", e.Status+" "+why
		}
		r.finish(f, reason, detail)
	}
}

func (r *Runtime) warmGone(grantUID string) {
	r.mu.Lock()
	var ps []*pooled
	if z := r.warms[grantUID]; z != nil {
		ps = z.drainAll()
	}
	delete(r.warms, grantUID)
	var orphans []*fiber
	for _, f := range r.fibers {
		if f.grantUID == grantUID {
			orphans = append(orphans, f)
		}
	}
	r.mu.Unlock()
	r.forgetIdentity(grantUID)
	r.protectTemplates()
	r.discard(ps)
	for _, f := range orphans {
		_ = f.cg.Kill()
		r.finish(f, "signal", "template instance exited")
	}
	r.pokePrune() // its parent, unless a delta names it
	log.Printf("host: warm instance gone grant=%s", grantUID)
}

// DropTemplate implements core.TemplateDropper. The yielded grant's pool
// drains, its warm instance ends and its pages lose their protection.
func (r *Runtime) DropTemplate(grantUID string) {
	r.mu.Lock()
	z := r.warms[grantUID]
	delete(r.warms, grantUID)
	var ps []*pooled
	if z != nil {
		ps = z.drainAll()
	}
	r.mu.Unlock()
	r.forgetIdentity(grantUID)
	if z == nil {
		return
	}
	r.discard(ps)
	r.be.Unwarm(z.id)
	for _, d := range []cgroup.Dir{z.zcg, z.cg} {
		if err := d.SetMemoryMin(0); err != nil {
			log.Printf("host: unprotect template of %s: %v", grantUID, err)
		}
	}
	r.protectTemplates()
	r.pokePrune() // its parent, unless a delta names it
	log.Printf("host: warm instance dropped grant=%s", grantUID)
}

func (r *Runtime) finish(f *fiber, reason, detail string) {
	r.mu.Lock()
	if r.fibers[f.id] != f {
		r.mu.Unlock()
		return
	}
	delete(r.fibers, f.id)
	released := f.released
	f.exit = &core.FiberExit{FiberID: f.id, Reason: reason, Detail: detail}
	ep := f.endpoint
	r.mu.Unlock()
	// The relay goes first: its open connections end with the fiber, and
	// its socket is removed below with the fiber's.
	if f.relay != nil {
		f.relay.Close()
		_ = os.Remove(f.relay.sock)
	}
	if p := endpoint.UnixPath(ep); p != "" {
		_ = os.Remove(p)
	}
	r.freeSocket(f.sock, f.id)
	r.unroute(f)
	if f.channel != nil {
		_ = f.channel.Close()
	}
	// The leaf may still be tearing down, so retry briefly.
	_ = removeSoon(f.cg)
	// A parked fiber keeps its port: the restored listener needs the same
	// one. Every other end frees it.
	r.mu.Lock()
	parked := f.parked
	r.mu.Unlock()
	if !parked {
		r.freePort(f.port, f.id)
	}
	close(f.done)
	if !released {
		r.exits <- core.FiberExit{FiberID: f.id, Reason: reason, Detail: detail}
	}
}

// unixPath is where a unix endpoint for the fence lives.
func (r *Runtime) unixPath(fence core.Fence) string {
	return filepath.Join(r.cfg.RunDir, fence.GrantUID, fmt.Sprintf("%d-%d.sock", fence.Epoch, fence.Seq))
}

// mintEndpoint chooses a fiber's endpoint under the runtime's policy:
// the unix socket path for its fence, or the declared address with a
// port taken from the range. bind is what the backend is told to serve
// on; url is what Clone returns. On a relaying home the two differ: the
// backend serves the unix path and the url names the relayed port.
func (r *Runtime) mintEndpoint(fence core.Fence) (url, bind string, port int, err error) {
	if r.cfg.Endpoints.Family.Scheme() == "unix" {
		p := r.unixPath(fence)
		return "unix://" + p, p, 0, nil
	}
	port, err = r.allocPort(fence.String(), 0)
	if err != nil {
		return "", "", 0, err
	}
	url = r.tcpURL(port)
	if r.relay {
		return url, r.unixPath(fence), port, nil
	}
	return url, url, port, nil
}

// tcpURL is the endpoint of a port on this home's address.
func (r *Runtime) tcpURL(port int) string {
	return endpoint.Endpoint{Scheme: "tcp", Host: r.cfg.Endpoints.Host, Port: port}.String()
}

// openRelay listens on the fiber's port in fiberd's network namespace
// and splices to sock, the unix path the backend serves. The listener is
// up before the backend is asked for the fiber, so a port fiberd
// cannot bind fails the Clone before a sandbox is restored for it.
func (r *Runtime) openRelay(port int, sock string) (*relay, error) {
	network := "tcp4"
	if r.cfg.Endpoints.Family == endpoint.Inet6 {
		network = "tcp6"
	}
	e := endpoint.Endpoint{Scheme: "tcp", Host: r.cfg.Endpoints.Host, Port: port}
	_, addr := e.Network()
	rl, err := listenRelay(network, addr, sock, relayMaxConns, r.relaySlots)
	if err != nil {
		return nil, fmt.Errorf("host: relay for %s: %w", sock, err)
	}
	return rl, nil
}

// allocPort hands out a free port from the range, or reserves want
// when it is given and free (a resumed fiber's listener is restored on
// the port it was parked with).
func (r *Runtime) allocPort(fiberID string, want int) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	lo, hi := r.cfg.Endpoints.Ports()
	if want != 0 {
		if holder, taken := r.ports[want]; taken && holder != fiberID {
			return 0, fmt.Errorf("host: endpoint port %d is held by %s", want, holder)
		}
		r.ports[want] = fiberID
		return want, nil
	}
	for p := lo; p <= hi; p++ {
		if _, taken := r.ports[p]; !taken {
			r.ports[p] = fiberID
			return p, nil
		}
	}
	return 0, fmt.Errorf("host: no free endpoint port in %d-%d", lo, hi)
}

// freePorts gives back every port a fiber id holds: a parked delta's,
// when the delta goes.
func (r *Runtime) freePorts(fiberID string) {
	r.mu.Lock()
	for p, holder := range r.ports {
		if holder == fiberID {
			delete(r.ports, p)
		}
	}
	r.mu.Unlock()
}

func (r *Runtime) freePort(port int, fiberID string) {
	if port == 0 {
		return
	}
	r.mu.Lock()
	if r.ports[port] == fiberID {
		delete(r.ports, port)
	}
	r.mu.Unlock()
}

// claimSocket reserves a unix socket path for a fiber, or refuses it
// while a live fiber of the grant holds it. A resume binds the name its
// fiber was parked with on another home, and a fresh clone the name of
// its fence, so either can meet the other's.
func (r *Runtime) claimSocket(path, fiberID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if holder, taken := r.socks[path]; taken && holder != fiberID {
		return fmt.Errorf("host: socket %s is held by %s", path, holder)
	}
	r.socks[path] = fiberID
	return nil
}

func (r *Runtime) freeSocket(path, fiberID string) {
	if path == "" {
		return
	}
	r.mu.Lock()
	if r.socks[path] == fiberID {
		delete(r.socks, path)
	}
	r.mu.Unlock()
}

func leafName(f core.Fence) string { return fmt.Sprintf("f-%d-%d", f.Epoch, f.Seq) }

// Clone births one fiber from the grant's pool or warm instance, or
// restores a parked delta.
func (r *Runtime) Clone(ctx context.Context, spec core.CloneSpec) (core.FiberHandle, error) {
	if spec.Source == core.SourceDelta {
		return r.resume(ctx, spec)
	}
	r.mu.Lock()
	z, ok := r.warms[spec.Grant.UID]
	r.mu.Unlock()
	if !ok {
		// The warm instance is gone (an engine crash takes its fibers but
		// not the grant): warm it again on demand, so the grant recovers
		// without a re-admission.
		if err := r.PrepareTemplate(ctx, spec.Grant); err != nil {
			return core.FiberHandle{}, fmt.Errorf("%w: %s: %w", ErrNotPrepared, spec.Grant.UID, err)
		}
		r.mu.Lock()
		z, ok = r.warms[spec.Grant.UID]
		r.mu.Unlock()
		if !ok {
			return core.FiberHandle{}, fmt.Errorf("%w: %s", ErrNotPrepared, spec.Grant.UID)
		}
	}
	if p := r.takePooled(z); p != nil {
		t0 := time.Now()
		h, err := r.start(ctx, z, spec, p)
		if err == nil || !p.spent {
			return h, err
		}
		// The hand-out failed and the sandbox is gone. Restore on demand
		// with the time left.
		log.Printf("host: hand-out of %s to %s failed, restoring on demand: %v", p.id, spec.Fence, err)
		if spec.Deadline > 0 {
			if spec.Deadline -= time.Since(t0); spec.Deadline <= 0 {
				return core.FiberHandle{}, err
			}
		}
		if ctx.Err() != nil {
			return core.FiberHandle{}, err
		}
	}
	return r.start(ctx, z, spec, nil)
}

// start births spec's fiber by binding p, or by a fresh restore when p
// is nil. A failure before the backend is asked returns p to the pool.
func (r *Runtime) start(ctx context.Context, z *warm, spec core.CloneSpec, p *pooled) (core.FiberHandle, error) {
	var leaf cgroup.Dir
	var err error
	if p != nil {
		leaf = p.cg
	} else if leaf, err = r.fiberLeaf(z.cg, spec.Grant, spec.Fence); err != nil {
		return core.FiberHandle{}, err
	}
	// giveUp undoes the leaf when the birth fails before the backend is asked.
	giveUp := func() {
		if p != nil {
			r.returnPooled(z, p)
		} else {
			_ = rmdir(leaf)
		}
	}
	lfd, err := leaf.Open()
	if err != nil {
		giveUp()
		return core.FiberHandle{}, err
	}
	defer func() { _ = lfd.Close() }()

	if err := os.MkdirAll(filepath.Join(r.cfg.RunDir, spec.Grant.UID), 0o755); err != nil {
		giveUp()
		return core.FiberHandle{}, err
	}
	url, bind, port := "", handoffEndpoint, 0
	handoff := spec.Grant.Policy.EndpointMode == core.EndpointHandoff
	var identity *backend.Identity
	if handoff {
		// The record the backend queues for the fiber carries the
		// grant's TLS identity, with the caller it serves.
		if !r.canHandoff() {
			err = fmt.Errorf("%w: grant %s on backend %s", ErrNoHandoff, spec.Grant.UID, r.be.Name())
		} else {
			identity, err = r.identityFor(spec.Grant.UID, spec.CallerCert)
		}
	} else {
		url, bind, port, err = r.mintEndpoint(spec.Fence)
	}
	if err != nil {
		giveUp()
		return core.FiberHandle{}, err
	}
	sock := ""
	if port == 0 && url != "" || r.relay && port != 0 {
		sock = bind // a unix socket, served directly or behind the relay
		if err := r.claimSocket(sock, spec.Fence.String()); err != nil {
			r.freePort(port, spec.Fence.String())
			giveUp()
			return core.FiberHandle{}, err
		}
	}
	var rl *relay
	if r.relay && port != 0 {
		if rl, err = r.openRelay(port, bind); err != nil {
			r.freeSocket(sock, spec.Fence.String())
			r.freePort(port, spec.Fence.String())
			giveUp()
			return core.FiberHandle{}, err
		}
	}
	// A fiber born from the warm instance, forked or restored from its
	// image, starts its lineage at generation 1.
	f := &fiber{id: spec.Fence.String(), grantUID: spec.Grant.UID, cg: leaf, endpoint: url, port: port, sock: sock, birth: spec.Fence.String(),
		generation: 1, budget: spec.Grant.WBudgetBytes, devMax: spec.Grant.DeviceBudget.Bytes,
		quota: deltaQuota(spec.Grant), handoff: handoff, relay: rl, done: make(chan struct{}), pooled: p != nil}
	// Registered before the backend answers so an exit that races the
	// reply is not lost.
	r.mu.Lock()
	r.fibers[f.id] = f
	r.mu.Unlock()
	fspec := backend.FiberSpec{
		Fence: f.id, Endpoint: bind, CgroupFD: int(lfd.Fd()), Deadline: spec.Deadline,
		Payload: spec.Payload, Session: spec.Session, Generation: f.generation, OwnPIDNS: true, Identity: identity,
	}
	var fb backend.Fiber
	if p != nil {
		p.spent = true
		fb, err = r.pooler().Bind(ctx, p.id, fspec)
	} else {
		refused := r.pidsHits(z.cg)
		if fb, err = r.be.Clone(ctx, z.id, fspec); err != nil {
			err = r.pidsPressure(z.cg, refused, spec.Grant.UID, err)
		}
	}
	if err != nil {
		r.mu.Lock()
		if r.fibers[f.id] == f {
			delete(r.fibers, f.id)
		}
		r.mu.Unlock()
		if rl != nil {
			rl.Close()
		}
		r.freeSocket(sock, f.id)
		r.freePort(port, f.id)
		if p != nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			// The backend kills a sandbox it could not bind or start in
			// time, reporting a pooled one's end under its pooled id, and
			// the leaf empties once it is gone.
			_ = leaf.Kill()
			removeDead(leaf)
		} else {
			_ = rmdir(leaf)
		}
		return core.FiberHandle{}, err
	}
	// The host's end of the fiber's channel is the host's from here, and
	// finish closes it with the fiber.
	r.mu.Lock()
	f.channel = fb.Channel
	r.mu.Unlock()
	ep, err := r.route(f)
	if err != nil {
		_ = r.Release(ctx, f.id, false)
		return core.FiberHandle{}, err
	}
	r.mu.Lock()
	f.pid = fb.PID
	f.base = fb.Footprint
	f.endpoint = ep
	f.ready = true
	r.mu.Unlock()
	return core.FiberHandle{ID: f.id, Endpoint: f.endpoint, Pooled: f.pooled}, nil
}

// manifest sits beside the images so a delta is self-describing.
type manifest struct {
	Fence    string `json:"fence"`
	GrantUID string `json:"grant_uid"`
	// Birth is the fence the fiber was born under, which names the
	// socket it serves however often it is resumed.
	Birth    string `json:"birth_fence,omitempty"`
	Endpoint string `json:"endpoint"`
	// Handoff marks a fiber that served handed-off connections, not Endpoint.
	Handoff bool `json:"handoff,omitempty"`
	// Relay is the unix socket a fiber served behind a relayed tcp
	// Endpoint. The resumed listener binds its name again under the
	// resuming grant's run directory, and the home relays a port to it.
	Relay    string `json:"relay_socket,omitempty"`
	Template string `json:"template_digest"`
	Backend  string `json:"backend"`
	// Generation is the parked fiber's place in its lineage. A resume of
	// this park is the next one, on this home or another.
	Generation int `json:"generation"`
	// WBytes is what the park costs to move: the delta's bytes when the
	// checkpoint is a delta, else the full image bytes.
	WBytes uint64 `json:"w_bytes"`
	// WUsed is the fiber's W when it was parked, which a resume of the
	// image continues counting from.
	WUsed    uint64 `json:"w_used_bytes,omitempty"`
	Delta    bool   `json:"delta"`
	Parent   string `json:"parent_sha256,omitempty"`
	ParkedAt string `json:"parked_at"`
}

func (r *Runtime) deltaDir(f core.Fence) string {
	return filepath.Join(r.cfg.DeltaDir, f.GrantUID, fmt.Sprintf("%d-%d", f.Epoch, f.Seq))
}

// Park checkpoints the fiber into its delta directory and ends its running
// incarnation. sync: the fiber keeps running until the delta, its manifest
// and every file under the directory are durable (fsync), then it is
// killed. Otherwise the checkpoint ends it. Returns the delta directory as
// the ref.
func (r *Runtime) Park(ctx context.Context, fiberID string, sync bool) (string, error) {
	if r.tier < core.TierCheckpoint {
		return "", fmt.Errorf("host: park needs %s (backend %s offers %s)", core.TierCheckpoint, r.be.Name(), r.tier)
	}
	r.mu.Lock()
	f, ok := r.fibers[fiberID]
	var ep string
	var channel *os.File
	if ok {
		f.released = true // the coming exit is ours, not a death
		f.parked = true   // and its port stays with the delta
		ep = f.endpoint
		channel = f.channel
	}
	r.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("host: unknown fiber %q", fiberID)
	}
	fence, err := core.ParseFence(f.id)
	if err != nil {
		return "", fmt.Errorf("host: %w", err)
	}
	dir := r.deltaDir(fence)
	_ = os.RemoveAll(dir)
	w, _ := r.wBytes(f)
	// Checked before the dump. An async park ends the fiber, so a delta
	// refused afterwards would take the session with it. W is roughly what
	// the delta will weigh.
	if f.quota > 0 {
		if used := treeBytes(filepath.Join(r.cfg.DeltaDir, f.grantUID)); used+w > f.quota {
			r.unpark(f)
			return "", fmt.Errorf("%w: grant %s holds %d bytes, parking %s adds about %d, quota %d",
				core.ErrDeltaQuota, f.grantUID, used, fiberID, w, f.quota)
		}
	}
	// Devices are renegotiated on resume: the engine drops the slice
	// before the CPU side is checkpointed (the continuity contract).
	if dr, ok := r.be.(backend.DeviceReporter); ok && f.devMax > 0 {
		if err := dr.EvictDevice(f.id); err != nil {
			log.Printf("host: evict device slice of %s: %v", f.id, err)
		}
	}
	// giveBack undoes a park whose fiber still runs, keeping the failed
	// images and dump log aside for diagnosis.
	giveBack := func(err error) (string, error) {
		r.unpark(f)
		_ = os.RemoveAll(dir + ".failed")
		_ = os.Rename(dir, dir+".failed")
		return "", err
	}
	// The fiber is asked to stop serving and dumped once it has. The
	// wait is bounded by the grant's resume deadline, the one per-grant
	// number for a wait on a fiber, and a handoff fiber answers on the
	// channel the host holds.
	_, deadline := core.GrantDeadlines(r, f.grantUID)
	if err := r.be.Park(ctx, f.id, backend.ParkSpec{Dir: dir, Sync: sync, Deadline: deadline, Channel: channel}); err != nil {
		return giveBack(err)
	}
	// A sync park's fiber runs until the delta is durable, so a failure
	// gives it back. An async park's fiber is gone, so the ref goes back
	// with any error, and the ledger parks the session rather than count a
	// dead fiber.
	m := manifest{Fence: f.id, GrantUID: f.grantUID, Birth: f.birth, Endpoint: ep, Handoff: f.handoff, Backend: r.be.Name(),
		Generation: f.generation, WUsed: w, ParkedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if f.relay != nil {
		m.Relay = f.relay.sock
	}
	// From the warm that names the parent to the manifest that names it
	// next, one section, so the prune cannot take the parent between.
	parentsDone := r.useParents()
	z := r.warmOf(f.grantUID)
	if z != nil {
		m.Template = z.digest
	}
	full := dirBytes(dir)
	if codec := r.codec(); codec != nil {
		if b, err := codec.ImageBytes(dir); err == nil {
			full = b
		}
	}
	m.WBytes = full
	if codec := r.codec(); codec != nil && z != nil && z.parentSHA != "" {
		// Strip every page the template already holds: what is left is
		// the dirtied working set, and its size is what a move costs.
		parent, err := r.parent(z.parentSHA)
		if err == nil {
			var info backend.DeltaInfo
			if info, err = codec.Compute(dir, parent); err == nil {
				m.Delta, m.Parent, m.WBytes = true, info.ParentSHA256, info.Bytes
			}
		}
		if err != nil {
			log.Printf("host: delta for %s failed, keeping the full image: %v", fiberID, err)
		}
	}
	err = writeJSON(filepath.Join(dir, "manifest.json"), m)
	parentsDone()
	if err != nil {
		err = fmt.Errorf("host: %s parked to %s, but its manifest: %w", fiberID, dir, err)
		if sync {
			return giveBack(err)
		}
		return dir, err
	}
	if sync {
		// Everything is written. Make it durable, then end the fiber.
		if err := syncDir(dir); err != nil {
			return giveBack(err)
		}
		_ = r.be.Kill(f.id)
		_ = f.cg.Kill()
	}
	// The exit is on its way or already handled, so wait for cleanup. The
	// park is complete either way, and a wait that ends early is logged,
	// not failed.
	select {
	case <-f.done:
	case <-ctx.Done():
		log.Printf("host: parked %s -> %s; not waiting for its exit: %v", fiberID, dir, ctx.Err())
		return dir, nil
	case <-time.After(5 * time.Second):
		log.Printf("host: parked %s -> %s; it has not exited after 5s, cleanup continues", fiberID, dir)
		return dir, nil
	}
	log.Printf("host: parked %s cgroup W=%d full image=%d delta=%v W bytes=%d -> %s", fiberID, w, full, m.Delta, m.WBytes, dir)
	return dir, nil
}

// unpark takes back a park that failed: the fiber runs again, its exit
// no longer ours. One that died meanwhile had its exit withheld by finish
// under the park's flag, so it is reported now rather than lost.
func (r *Runtime) unpark(f *fiber) {
	r.mu.Lock()
	f.released, f.parked = false, false
	exit := f.exit
	r.mu.Unlock()
	if exit != nil {
		r.exits <- *exit
	}
}

// resume restores a parked delta into a fresh leaf under the new fence.
// The restored fiber serves on the endpoint it had when parked.
func (r *Runtime) resume(ctx context.Context, spec core.CloneSpec) (core.FiberHandle, error) {
	if r.tier < core.TierCheckpoint {
		return core.FiberHandle{}, fmt.Errorf("host: resume needs %s (backend %s offers %s)", core.TierCheckpoint, r.be.Name(), r.tier)
	}
	dir := spec.Ref
	var m manifest
	if err := readJSON(filepath.Join(dir, "manifest.json"), &m); err != nil {
		return core.FiberHandle{}, fmt.Errorf("host: delta %s: %w", dir, err)
	}
	if m.Backend != "" && m.Backend != r.be.Name() {
		return core.FiberHandle{}, fmt.Errorf("%w: delta %s was parked by backend %s, this home runs %s", ErrParity, dir, m.Backend, r.be.Name())
	}
	if codec := r.codec(); m.Delta && codec != nil && codec.HasDelta(dir) {
		// Rebuild the full checkpoint from the delta and the parent it
		// names, looked up by hash in this home's store: the artifact's
		// images, or a self-checkpoint kept from an earlier instance.
		info, err := codec.ReadDeltaInfo(dir)
		if err != nil {
			return core.FiberHandle{}, err
		}
		if err := r.merge(codec, dir, info.ParentSHA256); err != nil {
			return core.FiberHandle{}, err
		}
	}
	gcg, err := r.grantCgroup(spec.Grant)
	if err != nil {
		return core.FiberHandle{}, err
	}
	leaf, err := r.fiberLeaf(gcg, spec.Grant, spec.Fence)
	if err != nil {
		return core.FiberHandle{}, err
	}
	lfd, err := leaf.Open()
	if err != nil {
		_ = rmdir(leaf)
		return core.FiberHandle{}, err
	}
	defer func() { _ = lfd.Close() }()
	workDir := filepath.Join(r.cfg.RunDir, spec.Grant.UID)
	_ = os.MkdirAll(workDir, 0o755)
	// Every fiber of a channel backend gets a new channel in place of its
	// parked one (below). A handoff fiber serves on it. Any other
	// restored listener serves on its parked endpoint. That is a unix
	// socket that binds its path again, or the tcp port, which must still
	// be this fiber's (or free) on this home.
	var parked endpoint.Endpoint
	if m.Handoff {
		// The restored fiber holds its identity in memory. The pin is
		// recorded here for HandoffRoute, and the new channel carries
		// only connections.
		if !r.canHandoff() {
			_ = rmdir(leaf)
			return core.FiberHandle{}, fmt.Errorf("%w: grant %s on backend %s", ErrNoHandoff, spec.Grant.UID, r.be.Name())
		}
		if err := r.prepareIdentity(spec.Grant.UID, spec.Grant.CallerThumbprint); err != nil {
			_ = rmdir(leaf)
			return core.FiberHandle{}, err
		}
	} else {
		if parked, err = endpoint.Parse(m.Endpoint); err != nil {
			_ = rmdir(leaf)
			return core.FiberHandle{}, fmt.Errorf("host: delta %s: %w", dir, err)
		}
		if parked.Scheme != r.cfg.Endpoints.Family.Scheme() {
			_ = rmdir(leaf)
			return core.FiberHandle{}, fmt.Errorf("host: delta %s was parked on a %s endpoint, this home serves %s", dir, parked.Scheme, r.cfg.Endpoints.Family.Scheme())
		}
		if parked.Scheme == "tcp" && (m.Relay != "") != r.relay {
			// The same backend relays or not, so only a hand-edited
			// manifest gets here.
			_ = rmdir(leaf)
			if m.Relay != "" {
				return core.FiberHandle{}, fmt.Errorf("host: delta %s was parked behind a relay, this home's backend %s binds tcp itself", dir, r.be.Name())
			}
			return core.FiberHandle{}, fmt.Errorf("host: delta %s was parked on a tcp listener of its own, this home's backend %s needs a relay", dir, r.be.Name())
		}
	}
	bind, port := m.Endpoint, 0
	switch {
	case m.Handoff:
		bind = handoffEndpoint
	case parked.Scheme == "unix":
		// The restored listener binds the path it was parked with, in
		// a mount namespace where that path's directory is the run
		// directory of the grant resuming it (the backend binds this
		// grant's workDir there), so the socket surfaces under workDir
		// by its parked name.
		bind = filepath.Join(workDir, filepath.Base(parked.Path))
		parked.Path = bind
	default:
		// The port the parked listener holds. The fiber id changes on
		// resume; the manifest's fence held it while parked. A delta
		// claimed from another home names a fence that may be a live
		// fiber's here, whose port is its own.
		if port, err = r.allocPort(spec.Fence.String(), parked.Port); err != nil {
			r.mu.Lock()
			_, live := r.fibers[m.Fence]
			r.mu.Unlock()
			if !live {
				r.freePort(parked.Port, m.Fence)
				port, err = r.allocPort(spec.Fence.String(), parked.Port)
			}
		}
		if err != nil && m.Relay != "" {
			// Nothing in a relayed checkpoint pins the port: the fiber
			// binds its socket by name, so any free port serves it.
			port, err = r.allocPort(spec.Fence.String(), 0)
		}
		if err != nil {
			_ = rmdir(leaf)
			return core.FiberHandle{}, err
		}
		if m.Relay != "" {
			// The backend binds the parked socket name under the run
			// directory, as a unix resume does, and the relay in front
			// of it is this home's.
			bind = filepath.Join(workDir, filepath.Base(m.Relay))
		}
	}
	// The fiber resumes with its birth fence in memory and learns the
	// new one from the record the backend sends it on its channel.
	birth, err := core.ParseFence(m.Birth)
	if err != nil {
		birth, err = core.ParseFence(m.Fence) // parked once, never resumed: born under the parked fence
	}
	if err != nil {
		r.freePort(port, spec.Fence.String())
		_ = rmdir(leaf)
		return core.FiberHandle{}, fmt.Errorf("host: delta %s: %w", dir, err)
	}
	// The parked name was minted by whichever home parked the fiber, so
	// it is this home's to bind again only while no live fiber of the
	// grant serves it. Then the restored socket binds it afresh.
	sock := ""
	if parked.Scheme == "unix" || m.Relay != "" {
		sock = bind
		if err := r.claimSocket(sock, spec.Fence.String()); err != nil {
			r.freePort(port, spec.Fence.String())
			_ = rmdir(leaf)
			return core.FiberHandle{}, err
		}
		_ = os.Remove(sock)
	}

	served := m.Endpoint
	var rl *relay
	switch {
	case parked.Scheme == "unix":
		served = "unix://" + bind
	case m.Relay != "":
		served = r.tcpURL(port)
		if rl, err = r.openRelay(port, bind); err != nil {
			r.freeSocket(sock, spec.Fence.String())
			r.freePort(port, spec.Fence.String())
			_ = rmdir(leaf)
			return core.FiberHandle{}, err
		}
	}
	// The resumed fiber is the next generation of the parked one's
	// lineage, whichever home parked it. The backend tells it so on its
	// channel, and a handoff fiber gets a fresh channel from the backend
	// in place of its parked one, with that record first on it.
	f := &fiber{id: spec.Fence.String(), grantUID: spec.Grant.UID, cg: leaf, port: port, sock: sock, birth: birth.String(),
		generation: m.Generation + 1, endpoint: served, budget: spec.Grant.WBudgetBytes, devMax: spec.Grant.DeviceBudget.Bytes,
		quota: deltaQuota(spec.Grant), handoff: m.Handoff, relay: rl, done: make(chan struct{})}
	r.mu.Lock()
	r.fibers[f.id] = f
	r.mu.Unlock()
	refused := r.pidsHits(gcg)
	fb, err := r.be.Resume(ctx, backend.ResumeSpec{Dir: dir, Fence: f.id, Endpoint: bind, CgroupFD: int(lfd.Fd()), Deadline: spec.Deadline,
		WarmID: spec.Grant.UID, WorkDir: workDir, Session: spec.Session, Generation: f.generation, Handoff: m.Handoff})
	if err != nil {
		err = r.pidsPressure(gcg, refused, spec.Grant.UID, err)
		r.mu.Lock()
		if r.fibers[f.id] == f {
			delete(r.fibers, f.id)
		}
		r.mu.Unlock()
		if rl != nil {
			rl.Close()
		}
		r.freeSocket(sock, f.id)
		r.freePort(port, f.id)
		_ = leaf.Kill()
		_ = rmdir(leaf)
		// Nothing serves on the socket a failed restore may have bound.
		if sock != "" {
			_ = os.Remove(sock)
		}
		return core.FiberHandle{}, err
	}
	r.mu.Lock()
	f.channel = fb.Channel
	r.mu.Unlock()
	ep, err := r.route(f)
	if err != nil {
		_ = r.Release(ctx, f.id, false)
		return core.FiberHandle{}, err
	}
	r.mu.Lock()
	f.pid = fb.PID
	if fb.Footprint > m.WUsed {
		// The image restored holds the pages the fiber dirtied before
		// its park, so its W carries on from there rather than from 0.
		f.base = fb.Footprint - m.WUsed
	}
	f.endpoint = ep
	f.ready = true
	r.mu.Unlock()
	log.Printf("host: resumed %s from %s pid=%d", f.id, dir, fb.PID)
	return core.FiberHandle{ID: f.id, Endpoint: f.endpoint}, nil
}

// merge rebuilds the full checkpoint in dir from its delta and the
// parent sha, in one section, so the prune does not close the parent
// while the codec reads it.
func (r *Runtime) merge(codec backend.DeltaCodec, dir, sha string) error {
	defer r.useParents()()
	parent, err := r.parent(sha)
	if err != nil {
		return fmt.Errorf("host: resume of a delta: %w", err)
	}
	if err := codec.Merge(dir, parent); err != nil {
		return fmt.Errorf("host: merge delta %s: %w", dir, err)
	}
	return nil
}

// HasDelta implements core.DeltaChecker: a parked ref is usable while its
// manifest exists.
func (r *Runtime) HasDelta(ref string) bool {
	_, err := os.Stat(filepath.Join(ref, "manifest.json"))
	return err == nil
}

// Release kills the fiber's leaf and waits for it to be reaped. discard
// also deletes any parked delta stored under this fiber id. A fiber this
// runtime does not know (an orphan from a previous fiberd, found through
// List) is killed through its leaf as well.
func (r *Runtime) Release(ctx context.Context, fiberID string, discard bool) error {
	r.mu.Lock()
	f, ok := r.fibers[fiberID]
	if ok {
		f.released = true
		if discard {
			f.parked = false // a park in progress is discarded too, so finish frees the port
		}
	}
	r.mu.Unlock()
	fence, ferr := core.ParseFence(fiberID)
	if discard && ferr == nil {
		_ = os.RemoveAll(r.deltaDir(fence))
		r.pokePrune() // its parent, unless something else names it
		// A discarded delta gives its port back. A running fiber's port
		// is freed by finish, once its listener or relay has closed, so
		// a clone meanwhile cannot be handed a port still bound.
		if !ok {
			r.freePorts(fiberID)
		}
	}
	if !ok {
		if ferr != nil {
			return nil
		}
		return r.killOrphan(ctx, fence)
	}
	_ = r.be.Kill(f.id)
	_ = f.cg.Kill()
	select {
	case <-f.done:
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
		return fmt.Errorf("host: %s did not exit after kill", fiberID)
	}
	return nil
}

// killOrphan ends a leaf left by a previous fiberd: kill everything in it,
// wait for it to empty, remove it and the endpoint it served on.
func (r *Runtime) killOrphan(ctx context.Context, fence core.Fence) error {
	leaf := r.root.Child(fence.GrantUID).Child(leafName(fence))
	if !leaf.Exists() {
		return nil
	}
	_ = leaf.Kill()
	deadline := time.After(5 * time.Second)
	for {
		pids, err := leaf.Procs()
		if err != nil || len(pids) == 0 {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("host: orphan %s did not die", fence)
		case <-time.After(10 * time.Millisecond):
		}
	}
	// A resumed orphan served the socket it was parked under, named by
	// another fence, which nothing here records. That name is unlinked
	// before the next fiber binds it.
	_ = os.Remove(r.unixPath(fence))
	return rmdir(leaf)
}

// PruneGrants removes leftover cgroups of grants not in keep: the warm
// instance's cgroup (its process is gone or killed here) and its fiber
// leaves. A task killed here is still exiting when its cgroup is
// removed, so each removal is retried briefly.
func (r *Runtime) PruneGrants(keep map[string]bool) {
	grants, err := r.root.Children("")
	if err != nil {
		return
	}
	for _, g := range grants {
		if keep[g.Name()] {
			continue
		}
		_ = g.Kill()
		leaves, _ := g.Children("")
		for _, l := range leaves {
			_ = l.Kill()
			_ = removeSoon(l)
		}
		if err := removeSoon(g); err == nil {
			log.Printf("host: pruned stale grant cgroup %s", g.Name())
		} else {
			log.Printf("host: stale grant cgroup %s not pruned: %v", g.Name(), err)
		}
	}
}

func (r *Runtime) warmOf(grantUID string) *warm {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.warms[grantUID]
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// dirBytes is the size of every regular file in dir: what a full
// checkpoint costs to move when the backend cannot say better.
func dirBytes(dir string) uint64 {
	var n uint64
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if info, err := e.Info(); err == nil && info.Mode().IsRegular() {
			n += uint64(info.Size())
		}
	}
	return n
}

// treeBytes is the size of every regular file under dir, at any depth.
// It measures what a grant's parked deltas take, each in its own directory.
func treeBytes(dir string) uint64 {
	var n uint64
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // what cannot be read weighs nothing
		}
		if info, err := d.Info(); err == nil && info.Mode().IsRegular() {
			n += uint64(info.Size())
		}
		return nil
	})
	return n
}

// rmdir removes a cgroup the runtime is done with. The kernel drops an
// empty cgroup whatever control files it shows, where a plain directory
// standing in for one holds the files the runtime wrote, so this is a
// seam for tests, like fsync.
var rmdir = cgroup.Dir.Remove

// removeSoon removes a cgroup whose tasks were just killed and may still
// be tearing down, retrying briefly.
func removeSoon(d cgroup.Dir) error {
	var err error
	for i := 0; i < 20; i++ {
		if err = rmdir(d); err == nil {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return err
}

// fsync is what syncDir calls on every file and directory. A seam for tests.
var fsync = func(f *os.File) error { return f.Sync() }

// syncDir fsyncs every file under dir at any depth, then every directory,
// children before parents. It runs once the delta and its manifest are
// written, so the whole checkpoint is durable before the running
// incarnation is ended.
func syncDir(dir string) error {
	var dirs []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			dirs = append(dirs, path)
			return nil
		}
		return syncPath(path)
	})
	if err != nil {
		return err
	}
	// The walk lists a directory before what is under it, so the reverse
	// order syncs every directory after its subdirectories.
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := syncPath(dirs[i]); err != nil {
			return err
		}
	}
	return nil
}

func syncPath(path string) error {
	fh, err := os.Open(path)
	if err != nil {
		return err
	}
	err = fsync(fh)
	_ = fh.Close()
	return err
}

// List reports every fiber leaf with live processes under the root,
// known to this runtime or not: reality for the ledger to reconcile.
func (r *Runtime) List(context.Context) ([]core.FiberHandle, error) {
	grants, err := r.root.Children("")
	if err != nil {
		return nil, err
	}
	var out []core.FiberHandle
	for _, g := range grants {
		leaves, err := g.Children("f-")
		if err != nil {
			continue
		}
		for _, l := range leaves {
			pids, err := l.Procs()
			if err != nil || len(pids) == 0 {
				continue
			}
			var epoch, seq uint64
			if _, err := fmt.Sscanf(l.Name(), "f-%d-%d", &epoch, &seq); err != nil {
				continue
			}
			fence := core.Fence{GrantUID: g.Name(), Epoch: epoch, Seq: seq}
			// An orphan's tcp port is not recoverable from its leaf; the
			// reconcile only needs the fence to kill or adopt it.
			ep := ""
			if r.cfg.Endpoints.Family.Scheme() == "unix" {
				ep = "unix://" + r.unixPath(fence)
			}
			out = append(out, core.FiberHandle{ID: fence.String(), Endpoint: ep})
		}
	}
	return out, nil
}

func (r *Runtime) Stats(_ context.Context, fiberID string) (core.FiberStats, error) {
	r.mu.Lock()
	f, ok := r.fibers[fiberID]
	r.mu.Unlock()
	if !ok {
		return core.FiberStats{}, fmt.Errorf("host: unknown fiber %q", fiberID)
	}
	w, err := r.wBytes(f)
	if err != nil {
		return core.FiberStats{}, err
	}
	st := core.FiberStats{WUsedBytes: w}
	if dr, ok := r.be.(backend.DeviceReporter); ok {
		st.DeviceUsedBytes, _ = dr.FiberDevice(f.id)
	}
	return st, nil
}

func (r *Runtime) Exits() <-chan core.FiberExit { return r.exits }

// Close drains every pool, ends every warm instance and its fibers, and
// fiberd's relays.
func (r *Runtime) Close() {
	r.stopOnce.Do(func() { close(r.stop) })
	if r.pruneDone != nil {
		<-r.pruneDone
	}
	r.mu.Lock()
	var ps []*pooled
	for _, z := range r.warms {
		ps = append(ps, z.drainAll()...)
	}
	r.mu.Unlock()
	r.discard(ps)
	r.be.Close()
	r.mu.Lock()
	var relays []*relay
	for _, f := range r.fibers {
		if f.relay != nil {
			relays = append(relays, f.relay)
		}
	}
	r.mu.Unlock()
	for _, rl := range relays {
		rl.Close()
	}
}
