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
	"time"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/sys/cgroup"
)

var (
	ErrNoTemplate  = errors.New("host: no template command for digest")
	ErrNotPrepared = errors.New("host: template not prepared for this grant")
	// ErrParity: an artifact's images or a published delta were made on
	// a host this one cannot restore them on (see artifact.Parity).
	ErrParity = errors.New("host: platform parity")
)

// Runtime implements core.Runtime over one warm template instance per
// grant, provided by the backend.
type Runtime struct {
	cfg  Config
	be   backend.Backend
	root cgroup.Dir
	host artifact.Platform // what checkpoints made here record, and what pulled ones must match

	mu     sync.Mutex
	warms  map[string]*warm  // grant uid
	fibers map[string]*fiber // fiber id (fence string)
	exits  chan core.FiberExit

	// parents is the content-addressed store of template checkpoints:
	// <TemplateCache>/parents/<sha256>/ (a self-checkpoint, or a symlink
	// to an artifact's images). A delta names its parent by hash, so a
	// parent kept here stays usable across template restarts and, when
	// the same artifact warmed another home, across homes.
	parentsMu sync.Mutex
	parents   map[string]backend.Parent
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
}

type fiber struct {
	id       string
	grantUID string
	pid      int
	cg       cgroup.Dir
	endpoint string
	started  time.Time
	budget   uint64 // w_budget_bytes; 0 = unlimited
	released bool   // Release or Park in progress: do not report the exit
	overW    bool   // killed by the host for exceeding its W budget
	ready    bool   // the backend has answered: before that, W is a restore in flight, not the fiber's
	done     chan struct{}
}

func New(cfg Config) (core.Runtime, error) {
	if cfg.Backend == nil {
		return nil, errors.New("host: Backend is required")
	}
	if cfg.CgroupRoot == "" {
		return nil, errors.New("host: CgroupRoot is required")
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
	for _, p := range []*string{&cfg.RunDir, &cfg.DeltaDir, &cfg.CgroupRoot, &cfg.TemplateCache} {
		abs, err := filepath.Abs(*p)
		if err != nil {
			return nil, err
		}
		*p = abs
	}
	detected := cfg.Backend.Tier()
	if cfg.Tier == core.TierUnspecified || cfg.Tier > detected {
		cfg.Tier = detected
	}
	root := cgroup.Root(cfg.CgroupRoot)
	if err := root.Ensure("memory", "pids"); err != nil {
		return nil, err
	}
	for _, d := range []string{cfg.RunDir, cfg.DeltaDir, cfg.TemplateCache} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	host := artifact.Host()
	if p, ok := cfg.Backend.(backend.Platformer); ok {
		// The backend knows what its checkpoints depend on.
		bp := p.Platform()
		for dst, v := range map[*string]string{&host.Arch: bp.Arch, &host.Kernel: bp.Kernel, &host.Libc: bp.Libc} {
			if v != "" {
				*dst = v
			}
		}
	}
	for dst, override := range map[*string]string{&host.Arch: cfg.Platform.Arch, &host.Kernel: cfg.Platform.Kernel, &host.Libc: cfg.Platform.Libc} {
		if override != "" {
			*dst = override
		}
	}
	host.Backend = cfg.Backend.Name()
	log.Printf("host: backend %s tier %s platform %s parity %s", host.Backend, cfg.Tier, host, cfg.Parity)
	r := &Runtime{
		cfg: cfg, be: cfg.Backend, root: root, host: host,
		warms: map[string]*warm{}, fibers: map[string]*fiber{},
		exits:   make(chan core.FiberExit, 1024),
		parents: map[string]backend.Parent{},
	}
	go r.pump()
	_, overhead := cfg.Backend.(backend.Overheader)
	_, reports := cfg.Backend.(backend.WReporter)
	if overhead || reports {
		go r.enforceW()
	}
	return r, nil
}

// enforceW is the executioner for backends whose fibers carry a fixed
// footprint, or report W themselves because they are not processes in a
// leaf. Their leaves get memory.max = budget + footprint + slack for the
// sandbox's own variance, so the kernel only catches gross overruns; the
// budget itself is held here: W is sampled, and a fiber over its budget
// is killed and reported as oom, exactly as the kernel would for a fork.
func (r *Runtime) enforceW() {
	for {
		time.Sleep(25 * time.Millisecond)
		r.mu.Lock()
		fs := make([]*fiber, 0, len(r.fibers))
		for _, f := range r.fibers {
			if f.budget > 0 && !f.released && f.ready {
				fs = append(fs, f)
			}
		}
		r.mu.Unlock()
		for _, f := range fs {
			w, err := r.wBytes(f)
			if err != nil || w <= f.budget {
				continue
			}
			r.mu.Lock()
			f.overW = true
			r.mu.Unlock()
			log.Printf("host: %s W=%d over budget %d: killed", f.id, w, f.budget)
			_ = r.be.Kill(f.id)
			_ = f.cg.Kill()
		}
	}
}

func (r *Runtime) codec() backend.DeltaCodec {
	if r.cfg.NoDeltas {
		return nil
	}
	c, _ := r.be.(backend.DeltaCodec)
	return c
}

func (r *Runtime) parentsDir() string { return filepath.Join(r.cfg.TemplateCache, "parents") }

// registerParent loads a checkpoint directory, files it under its hash in
// the parent store (moving a self-checkpoint, linking an artifact's
// images) and returns the hash.
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
	if err := os.MkdirAll(r.parentsDir(), 0o755); err != nil {
		p.Close()
		return "", err
	}
	if _, err := os.Lstat(dst); err != nil {
		if move {
			err = os.Rename(dir, dst)
		} else {
			err = os.Symlink(dir, dst)
		}
		if err != nil {
			p.Close()
			return "", err
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

func (r *Runtime) Tier() core.Tier { return r.cfg.Tier }

// CgroupRoot is where the runtime carves grant and fiber cgroups.
func (r *Runtime) CgroupRoot() string { return r.cfg.CgroupRoot }

// DefaultDeadlines implements core.DeadlineAdvisor from the backend.
func (r *Runtime) DefaultDeadlines() (create, resume time.Duration) {
	if adv, ok := r.be.(backend.DeadlineAdvisor); ok {
		return adv.DefaultDeadlines()
	}
	return 0, 0
}

// overhead is the fixed per-fiber footprint for a grant's fibers, added
// to every leaf's memory.max and subtracted from measured W: what the
// backend declares, or, when it declares 0 while saying it has one, the
// warm template's own resident size as measured after it became ready
// (a sandbox restored from the template pays for those pages itself).
func (r *Runtime) overhead(grantUID string) uint64 {
	o, ok := r.be.(backend.Overheader)
	if !ok {
		return 0
	}
	if n := o.FiberOverheadBytes(); n > 0 {
		return n
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
	if o := r.overhead(f.grantUID); cur > o {
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
	if o, ok := r.be.(backend.Overheader); ok && o.FiberOverheadBytes() > 0 {
		total = o.FiberOverheadBytes()
	} else {
		r.mu.Lock()
		if z := r.warms[g.UID]; z != nil {
			total = z.total
		}
		r.mu.Unlock()
	}
	if total == 0 {
		return g.WBudgetBytes
	}
	return g.WBudgetBytes + total + total/2 + 32<<20
}

// PrepareTemplate warms the grant's template: its cgroup, the backend's
// warm instance, the delta parent, the block ceiling. Idempotent per grant.
func (r *Runtime) PrepareTemplate(ctx context.Context, g core.Grant) error {
	r.mu.Lock()
	if _, ok := r.warms[g.UID]; ok {
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()
	tpl, err := r.resolveTemplate(ctx, g.TemplateDigest)
	if err != nil {
		return err
	}

	gcg := r.root.Child(g.UID)
	if err := gcg.Ensure("memory", "pids"); err != nil {
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
	defer func() {
		for i := 0; i < 20; i++ {
			if err := pcg.Remove(); err == nil {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	workDir := filepath.Join(r.cfg.RunDir, g.UID)
	w, err := r.be.Warm(ctx, backend.WarmSpec{GrantUID: g.UID, Template: tpl, CgroupFD: int(zfd.Fd()), WorkDir: workDir, ProbeCgroupFD: probeFD})
	if err != nil {
		return err
	}
	z := &warm{grantUID: g.UID, digest: g.TemplateDigest, template: tpl, id: w.ID, pid: w.PID, cg: gcg, zcg: zcg}

	// The parent pages for deltas: the artifact's checkpoint when there
	// is one; otherwise checkpoint the warm instance now, leaving it
	// running. Deltas over a self-checkpoint are exact on this home and
	// portable to any home whose template pages hash the same.
	if r.codec() != nil && r.cfg.Tier >= core.TierCheckpoint {
		if tpl.ImagesDir != "" {
			sha, err := r.registerParent(tpl.ImagesDir, false)
			if err != nil {
				log.Printf("host: artifact images for %s unusable as a parent; parks will be full images: %v", g.UID, err)
			} else {
				z.parentSHA = sha
			}
		} else if sc, ok := r.be.(backend.SelfCheckpointer); ok {
			dir := filepath.Join(r.cfg.TemplateCache, "zygote-images", g.UID)
			_ = os.RemoveAll(dir)
			if err := sc.CheckpointWarm(ctx, w.ID, dir); err != nil {
				log.Printf("host: self-checkpoint for %s failed; parks will be full images: %v", g.UID, err)
			} else if sha, err := r.registerParent(dir, true); err != nil {
				log.Printf("host: self-checkpoint for %s unusable; parks will be full images: %v", g.UID, err)
			} else {
				z.parentSHA = sha
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
	r.mu.Lock()
	r.warms[g.UID] = z
	r.mu.Unlock()

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
	log.Printf("host: template ready grant=%s template=%s backend=%s pid=%d warm=%dMiB", g.UID, g.TemplateDigest, r.be.Name(), w.PID, zbytes>>20)
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
	if !strings.HasPrefix(digest, "sha256:") {
		return backend.Template{}, fmt.Errorf("%w %q: registry templates are addressed by sha256 digest", ErrNoTemplate, digest)
	}
	dir := filepath.Join(r.cfg.TemplateCache, strings.TrimPrefix(digest, "sha256:"))
	cfg, err := artifact.ReadConfig(dir)
	if err != nil {
		log.Printf("host: pulling template %s from %s", digest, r.cfg.Registry)
		cfg, err = artifact.Pull(ctx, r.cfg.Registry+"@"+digest, dir, r.cfg.RegistryPlainHTTP)
		if err != nil {
			_ = os.RemoveAll(dir)
			return backend.Template{}, fmt.Errorf("%w %q: %w", ErrNoTemplate, digest, err)
		}
	}
	// The parity gate. The executable must be for this instruction set,
	// and if the artifact carries images (the template's pages, which
	// every delta is computed against and every restore starts from) they
	// must be from a host this one can restore them on.
	want := cfg.Platform()
	if !cfg.HasImages {
		want.Kernel, want.Libc = "", ""
	}
	if err := r.cfg.Parity.Check(r.host, want); err != nil {
		return backend.Template{}, fmt.Errorf("%w: template %s built on %s: %w", ErrParity, digest[:19], cfg.Platform(), err)
	}
	tpl := backend.Template{Argv: append([]string{artifact.ZygotePath(dir)}, cfg.Args...), Digest: digest, Dir: dir}
	if cfg.HasImages {
		tpl.ImagesDir = artifact.ImagesDir(dir)
	}
	return tpl, nil
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
// on purpose. A warm instance's end takes its fibers with it.
func (r *Runtime) pump() {
	for e := range r.be.Exits() {
		if e.FiberID == "" {
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
		overW := f.overW
		r.mu.Unlock()
		if overW {
			reason, detail = "oom", e.Status+" w over budget"
		}
		r.finish(f, reason, detail)
	}
}

func (r *Runtime) warmGone(grantUID string) {
	r.mu.Lock()
	delete(r.warms, grantUID)
	var orphans []*fiber
	for _, f := range r.fibers {
		if f.grantUID == grantUID {
			orphans = append(orphans, f)
		}
	}
	r.mu.Unlock()
	for _, f := range orphans {
		_ = f.cg.Kill()
		r.finish(f, "signal", "template instance exited")
	}
	log.Printf("host: warm instance gone grant=%s", grantUID)
}

func (r *Runtime) finish(f *fiber, reason, detail string) {
	r.mu.Lock()
	if r.fibers[f.id] != f {
		r.mu.Unlock()
		return
	}
	delete(r.fibers, f.id)
	released := f.released
	r.mu.Unlock()
	_ = os.Remove(strings.TrimPrefix(f.endpoint, "unix://"))
	_ = os.Remove(strings.TrimPrefix(f.endpoint, "unix://") + ".fence")
	// The leaf may still be tearing down; retry briefly.
	for i := 0; i < 20; i++ {
		if err := f.cg.Remove(); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(f.done)
	if !released {
		r.exits <- core.FiberExit{FiberID: f.id, Reason: reason, Detail: detail}
	}
}

func (r *Runtime) endpoint(fence core.Fence) string {
	return filepath.Join(r.cfg.RunDir, fence.GrantUID, fmt.Sprintf("%d-%d.sock", fence.Epoch, fence.Seq))
}

func leafName(f core.Fence) string { return fmt.Sprintf("f-%d-%d", f.Epoch, f.Seq) }

// Clone births one fiber from the grant's warm instance into a fresh
// leaf, or restores a parked delta into one.
func (r *Runtime) Clone(ctx context.Context, spec core.CloneSpec) (core.FiberHandle, error) {
	if spec.Source == core.SourceDelta {
		return r.resume(ctx, spec)
	}
	r.mu.Lock()
	z, ok := r.warms[spec.Grant.UID]
	r.mu.Unlock()
	if !ok {
		return core.FiberHandle{}, fmt.Errorf("%w: %s", ErrNotPrepared, spec.Grant.UID)
	}

	leaf := z.cg.Child(leafName(spec.Fence))
	if err := leaf.Create(r.leafMax(spec.Grant), true); err != nil {
		return core.FiberHandle{}, err
	}
	lfd, err := leaf.Open()
	if err != nil {
		_ = leaf.Remove()
		return core.FiberHandle{}, err
	}
	defer func() { _ = lfd.Close() }()

	ep := r.endpoint(spec.Fence)
	if err := os.MkdirAll(filepath.Dir(ep), 0o755); err != nil {
		_ = leaf.Remove()
		return core.FiberHandle{}, err
	}
	f := &fiber{id: spec.Fence.String(), grantUID: spec.Grant.UID, cg: leaf, endpoint: "unix://" + ep,
		started: time.Now(), budget: spec.Grant.WBudgetBytes, done: make(chan struct{})}
	// Registered before the backend answers so an exit that races the
	// reply is not lost.
	r.mu.Lock()
	r.fibers[f.id] = f
	r.mu.Unlock()
	fb, err := r.be.Clone(ctx, z.id, backend.FiberSpec{
		Fence: f.id, Endpoint: ep, CgroupFD: int(lfd.Fd()), Deadline: spec.Deadline,
		Payload: spec.Payload, OwnPIDNS: !r.cfg.NoFiberPIDNS,
	})
	if err != nil {
		r.mu.Lock()
		if r.fibers[f.id] == f {
			delete(r.fibers, f.id)
		}
		r.mu.Unlock()
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			// The backend enforces the same deadline and kills the child.
			_ = leaf.Kill()
			go func() { time.Sleep(100 * time.Millisecond); _ = leaf.Remove() }()
		} else {
			_ = leaf.Remove()
		}
		return core.FiberHandle{}, err
	}
	r.mu.Lock()
	f.pid = fb.PID
	f.ready = true
	r.mu.Unlock()
	return core.FiberHandle{ID: f.id, Endpoint: f.endpoint, Started: f.started}, nil
}

// manifest sits beside the images so a delta is self-describing.
type manifest struct {
	Fence    string `json:"fence"`
	GrantUID string `json:"grant_uid"`
	Endpoint string `json:"endpoint"`
	Template string `json:"template_digest"`
	Backend  string `json:"backend"`
	// WBytes is what the park costs to move: the delta's bytes when the
	// checkpoint is a delta, else the full image bytes.
	WBytes   uint64 `json:"w_bytes"`
	Delta    bool   `json:"delta"`
	Parent   string `json:"parent_sha256,omitempty"`
	ParkedAt string `json:"parked_at"`
}

func (r *Runtime) deltaDir(f core.Fence) string {
	return filepath.Join(r.cfg.DeltaDir, f.GrantUID, fmt.Sprintf("%d-%d", f.Epoch, f.Seq))
}

// Park checkpoints the fiber into its delta directory and ends its running
// incarnation. sync: the fiber keeps running until the images are durable
// (fsync), then is killed; otherwise the checkpoint ends it. Returns the
// delta directory as the ref.
func (r *Runtime) Park(ctx context.Context, fiberID string, sync bool) (string, error) {
	if r.cfg.Tier < core.TierCheckpoint {
		return "", fmt.Errorf("host: park needs %s (backend %s offers %s)", core.TierCheckpoint, r.be.Name(), r.cfg.Tier)
	}
	r.mu.Lock()
	f, ok := r.fibers[fiberID]
	if ok {
		f.released = true // the coming exit is ours, not a death
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
	if err := r.be.Park(ctx, f.id, backend.ParkSpec{Dir: dir, Sync: sync}); err != nil {
		r.mu.Lock()
		f.released = false
		r.mu.Unlock()
		// Keep the failed dump's log for diagnosis; it is small.
		_ = os.RemoveAll(dir + ".failed")
		_ = os.Rename(dir, dir+".failed")
		return "", err
	}
	if sync {
		if err := syncDir(dir); err != nil {
			return "", err
		}
		_ = r.be.Kill(f.id)
		_ = f.cg.Kill()
	}
	m := manifest{Fence: f.id, GrantUID: f.grantUID, Endpoint: f.endpoint, Backend: r.be.Name(),
		ParkedAt: time.Now().UTC().Format(time.RFC3339Nano)}
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
	if err := writeJSON(filepath.Join(dir, "manifest.json"), m); err != nil {
		return "", err
	}
	// The exit is on its way (or already handled); wait for cleanup.
	select {
	case <-f.done:
	case <-ctx.Done():
		return dir, ctx.Err()
	case <-time.After(5 * time.Second):
		return dir, fmt.Errorf("host: %s did not exit after park", fiberID)
	}
	log.Printf("host: parked %s cgroup W=%d full image=%d delta=%v W bytes=%d -> %s", fiberID, w, full, m.Delta, m.WBytes, dir)
	return dir, nil
}

// resume restores a parked delta into a fresh leaf under the new fence.
// The restored fiber serves on the endpoint it had when parked.
func (r *Runtime) resume(ctx context.Context, spec core.CloneSpec) (core.FiberHandle, error) {
	if r.cfg.Tier < core.TierCheckpoint {
		return core.FiberHandle{}, fmt.Errorf("host: resume needs %s (backend %s offers %s)", core.TierCheckpoint, r.be.Name(), r.cfg.Tier)
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
		parent, err := r.parent(info.ParentSHA256)
		if err != nil {
			return core.FiberHandle{}, fmt.Errorf("host: resume of a delta: %w", err)
		}
		if err := codec.Merge(dir, parent); err != nil {
			return core.FiberHandle{}, fmt.Errorf("host: merge delta %s: %w", dir, err)
		}
	}
	gcg := r.root.Child(spec.Grant.UID)
	if err := gcg.Ensure("memory", "pids"); err != nil {
		return core.FiberHandle{}, err
	}
	leaf := gcg.Child(leafName(spec.Fence))
	if err := leaf.Create(r.leafMax(spec.Grant), true); err != nil {
		return core.FiberHandle{}, err
	}
	lfd, err := leaf.Open()
	if err != nil {
		_ = leaf.Remove()
		return core.FiberHandle{}, err
	}
	defer func() { _ = lfd.Close() }()
	ep := strings.TrimPrefix(m.Endpoint, "unix://")
	_ = os.MkdirAll(filepath.Dir(ep), 0o755)
	_ = os.Remove(ep) // the restored socket binds it again
	// The fiber resumes with its old fence in memory; the new one is
	// published beside the endpoint for applications that need it.
	_ = os.WriteFile(ep+".fence", []byte(spec.Fence.String()+"\n"), 0o644)

	f := &fiber{id: spec.Fence.String(), grantUID: spec.Grant.UID, cg: leaf,
		endpoint: m.Endpoint, started: time.Now(), budget: spec.Grant.WBudgetBytes, done: make(chan struct{})}
	r.mu.Lock()
	r.fibers[f.id] = f
	r.mu.Unlock()
	fb, err := r.be.Resume(ctx, backend.ResumeSpec{Dir: dir, Fence: f.id, Endpoint: ep, CgroupFD: int(lfd.Fd()), Deadline: spec.Deadline, WarmID: spec.Grant.UID})
	if err != nil {
		r.mu.Lock()
		if r.fibers[f.id] == f {
			delete(r.fibers, f.id)
		}
		r.mu.Unlock()
		_ = leaf.Kill()
		_ = leaf.Remove()
		return core.FiberHandle{}, err
	}
	r.mu.Lock()
	f.pid = fb.PID
	f.ready = true
	r.mu.Unlock()
	log.Printf("host: resumed %s from %s pid=%d", f.id, dir, fb.PID)
	return core.FiberHandle{ID: f.id, Endpoint: f.endpoint, Started: f.started}, nil
}

// HasDelta implements core.DeltaChecker: a parked ref is usable while its
// manifest exists.
func (r *Runtime) HasDelta(ref string) bool {
	_, err := os.Stat(filepath.Join(ref, "manifest.json"))
	return err == nil
}

// Release kills the fiber's leaf and waits for it to be reaped. discard
// also deletes any parked delta stored under this fiber id. A fiber this
// runtime does not know (an orphan from a previous agent, found through
// List) is killed through its leaf as well.
func (r *Runtime) Release(ctx context.Context, fiberID string, discard bool) error {
	r.mu.Lock()
	f, ok := r.fibers[fiberID]
	if ok {
		f.released = true
	}
	r.mu.Unlock()
	fence, ferr := core.ParseFence(fiberID)
	if discard && ferr == nil {
		_ = os.RemoveAll(r.deltaDir(fence))
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

// killOrphan ends a leaf left by a previous agent: kill everything in it,
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
	_ = os.Remove(r.endpoint(fence))
	_ = os.Remove(r.endpoint(fence) + ".fence")
	return leaf.Remove()
}

// PruneGrants removes leftover cgroups of grants not in keep: the warm
// instance's cgroup (its process is gone or killed here) and empty fiber
// leaves.
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
			_ = l.Remove()
		}
		if err := g.Remove(); err == nil {
			log.Printf("host: pruned stale grant cgroup %s", g.Name())
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

// syncDir fsyncs every file in dir and the directory itself: the delta is
// durable before the running incarnation is ended.
func syncDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		fh, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			return err
		}
		err = fh.Sync()
		_ = fh.Close()
		if err != nil {
			return err
		}
	}
	dh, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = dh.Close() }()
	return dh.Sync()
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
			out = append(out, core.FiberHandle{ID: fence.String(), Endpoint: "unix://" + r.endpoint(fence)})
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
	return core.FiberStats{WUsedBytes: w}, nil
}

func (r *Runtime) Exits() <-chan core.FiberExit { return r.exits }

// Close ends every warm instance (and with them every fiber).
func (r *Runtime) Close() { r.be.Close() }
