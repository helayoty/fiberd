//go:build linux

// Package cloudhv is the Cloud Hypervisor backend: every fiber is a
// cloud-hypervisor process holding one micro-VM, restored from a snapshot
// of the warm guest. fiberd drives each VMM over its API socket with plain
// HTTP, and talks to the guest init over the VM's hybrid vsock socket
// (hack/cloudhv/PROTOCOL.md). hack/cloudhv/fakevmm speaks the same API
// subset and plays the guest without KVM, for conformance in CI.
//
// How it maps onto the seam:
//
//   - Warm: start a VMM in the warm leaf, vm.create with the kernel, the
//     read-only rootfs and vsock, vm.boot, wait for the guest init's
//     ready line, vm.pause and vm.snapshot, end the VMM. The snapshot is
//     the warm instance. No process stays behind.
//   - Clone: start a VMM in the fiber's leaf restoring the warm snapshot,
//     vm.resume, send INCARNATE on the control port and wait for served.
//     The fiber's unix endpoint is spliced to guest port 1024.
//   - Park: the guest stops serving, vm.pause, vm.snapshot, the images
//     move to the park directory, and the VMM ends unless the park is Sync.
//   - Resume: as Clone, restoring the park instead.
//   - Kill: vmm.shutdown, then the host kills the leaf.
//
// Each VMM runs in its own mount namespace as an unprivileged uid with
// /dev/kvm alone (jail_linux.go), so every snapshot names the same paths
// and two restores of one snapshot never meet. A VMM sits in its fiber's
// leaf, so W is the leaf's memory.current less what the restore cost,
// which Fiber.Footprint reports. Tier FIBER_SNAPSHOT. No delta codec, no
// pool, no workspaces, and no handoff grants, since a passed TCP socket
// cannot cross into a VM.
package cloudhv

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
)

const (
	defaultMemoryMiB = 256
	defaultVCPUs     = 1

	// The deadlines a clone or resume without one of its own gets. A
	// restore copies the whole guest in, then the guest init answers
	// INCARNATE. Unmeasured until S4 logs it, so they are generous.
	createDeadline = 5 * time.Second  // spike S4
	resumeDeadline = 10 * time.Second // spike S4

	// warmTimeout bounds a warm whose caller set no deadline: a boot,
	// the template's own init, and a snapshot of the whole guest.
	warmTimeout = 2 * time.Minute
	// versionTimeout bounds `vmm --version` at open.
	versionTimeout = 5 * time.Second

	// vmmOverhead is what a VMM costs besides its guest's memory, its
	// own heap and the device threads. Unmeasured until S1 logs it.
	vmmOverhead = 64 << 20 // spike S1
)

// parkTimeout bounds a park whose caller set no deadline. A park that
// never comes back is worse than one that fails.
const parkTimeout = 30 * time.Second

// Backend implements backend.Backend, Isolator, Platformer, Prober,
// DeadlineAdvisor, Overheader and Handoffer (to refuse handoff by name).
type Backend struct {
	opt     Options
	starter starter
	tier    core.Tier
	why     error
	facts   facts

	mu     sync.Mutex
	warms  map[string]*warm
	fibers map[string]*fiber
	exits  chan backend.Exit
	closed bool
}

// warm is a grant's warm snapshot. No process holds it.
type warm struct {
	id      string
	dir     string
	workDir string
}

// fiber is one VMM serving one fence.
type fiber struct {
	id       string
	vm       *vm
	endpoint string

	mu sync.Mutex // one Park or Kill at a time
	ep *endpoint  // nil while parked
}

// New opens the backend. The tier is FIBER_SNAPSHOT when the VMM answers
// `--version`, the kernel and rootfs can be hashed and VMMs can be
// jailed here. Otherwise it offers none, and ProbeErr says why.
func New(o Options) backend.Backend { return newBackend(o, nil) }

// newBackend is New with the starter chosen, nil for the VMM executable.
func newBackend(o Options, st starter) *Backend {
	if o.MemoryMiB == 0 {
		o.MemoryMiB = defaultMemoryMiB
	}
	if o.VCPUs == 0 {
		o.VCPUs = defaultVCPUs
	}
	if st == nil {
		st = execStarter{o.VMM}
	}
	b := &Backend{opt: o, starter: st, warms: map[string]*warm{}, fibers: map[string]*fiber{}, exits: make(chan backend.Exit, 1024)}
	f, err := b.probe()
	if err != nil {
		b.why = err
		return b
	}
	b.facts = f
	b.tier = core.TierSnapshot
	return b
}

// probe checks everything a warm needs and reads the facts its
// snapshots depend on.
func (b *Backend) probe() (facts, error) {
	o := b.opt
	switch {
	case o.VMM == "":
		return facts{}, errors.New("no VMM executable (-cloudhv-vmm)")
	case o.Kernel == "" || o.Rootfs == "":
		return facts{}, errors.New("no guest kernel or rootfs (-cloudhv-kernel, -cloudhv-rootfs; hack/cloudhv/build.sh builds them)")
	case o.StateDir == "":
		return facts{}, errors.New("no state directory")
	case o.RestoreMode != "" && o.RestoreMode != "copy" && o.RestoreMode != "ondemand":
		return facts{}, fmt.Errorf("restore mode %q is neither copy nor ondemand", o.RestoreMode)
	}
	if err := checkIDs(o.UsernsPool, o.EngineUID); err != nil {
		return facts{}, err
	}
	if err := b.starter.Probe(); err != nil {
		return facts{}, fmt.Errorf("VMMs cannot be jailed here: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), versionTimeout)
	defer cancel()
	out, err := b.starter.Version(ctx)
	if err != nil {
		return facts{}, fmt.Errorf("VMM %s unusable: --version: %w", o.VMM, err)
	}
	f, err := readFacts(out, o.Kernel, o.Rootfs)
	if err != nil {
		return facts{}, err
	}
	for _, d := range []string{b.opt.StateDir, filepath.Join(b.opt.StateDir, "vm"), filepath.Join(b.opt.StateDir, "warm")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return facts{}, err
		}
	}
	// What an earlier fiberd left: its VMMs ended with their leaves, and
	// its warm snapshots are warmed again by grant.
	for _, d := range []string{"vm", "warm"} {
		ents, _ := os.ReadDir(filepath.Join(b.opt.StateDir, d))
		for _, e := range ents {
			_ = os.RemoveAll(filepath.Join(b.opt.StateDir, d, e.Name()))
		}
	}
	return f, nil
}

// ProbeErr is why New found no tier.
func (b *Backend) ProbeErr() error { return b.why }

func (b *Backend) Name() string    { return "cloudhv" }
func (b *Backend) Tier() core.Tier { return b.tier }

// IsolatesTenants is true because a fiber runs on a guest kernel of its
// own behind KVM.
func (b *Backend) IsolatesTenants() bool { return true }

// Handoff is false. A handoff fiber takes TCP sockets over SCM_RIGHTS,
// which cannot cross into a VM, so the host refuses a handoff grant on
// this backend and names it.
func (b *Backend) Handoff() bool { return false }

// DefaultDeadlines are fixed. Every restore copies the same guest size.
func (b *Backend) DefaultDeadlines(string) (time.Duration, time.Duration) {
	return createDeadline, resumeDeadline
}

// FiberOverheadBytes is the whole guest plus the VMM, since a restore
// that copies the snapshot pays for every page of it (spike S1). The
// host adds it to each leaf's memory.max. W itself is measured from the
// footprint each Clone reports.
func (b *Backend) FiberOverheadBytes() uint64 { return b.guestBytes() + vmmOverhead }

func (b *Backend) guestBytes() uint64 { return b.opt.MemoryMiB << 20 }

func (b *Backend) runDir(id string) string { return filepath.Join(b.opt.StateDir, "vm", id) }

// warmDir is where a grant's warm snapshot lives, named by a hash of the
// grant so any grant uid makes a path.
func (b *Backend) warmDir(grantUID string) string {
	sum := sha256.Sum256([]byte(grantUID))
	return filepath.Join(b.opt.StateDir, "warm", hex.EncodeToString(sum[:8]))
}

// newID names a VMM. It is short because the host path of its API and
// vsock sockets must fit a sockaddr_un.
func newID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (b *Backend) Exits() <-chan backend.Exit { return b.exits }

// Close ends every VMM. The warm snapshots stay until the next open.
func (b *Backend) Close() {
	b.mu.Lock()
	b.closed = true
	fs := make([]*fiber, 0, len(b.fibers))
	for _, f := range b.fibers {
		fs = append(fs, f)
	}
	b.mu.Unlock()
	for _, f := range fs {
		f.vm.end()
	}
}

// facts is what a snapshot depends on besides fiberd itself: the VMM's
// release, the exact guest kernel and rootfs, and the host CPU. A
// snapshot restores only on a home with the same facts. Which CPU facts
// KVM itself insists on is S5, so both the vendor and the model are kept
// until then.
type facts struct {
	vmm, kernel, rootfs, cpu string
}

// readFacts takes the VMM's release from the first line `--version`
// prints ("cloud-hypervisor v53.0"), hashes the kernel and the rootfs,
// and reads the CPU from /proc/cpuinfo.
func readFacts(version, kernel, rootfs string) (facts, error) {
	words := strings.Fields(strings.SplitN(version, "\n", 2)[0])
	if len(words) < 2 {
		return facts{}, fmt.Errorf("VMM --version printed %q, want \"cloud-hypervisor <release>\"", strings.TrimSpace(version))
	}
	kh, err := hashPath(kernel)
	if err != nil {
		return facts{}, fmt.Errorf("guest kernel: %w", err)
	}
	rh, err := hashPath(rootfs)
	if err != nil {
		return facts{}, fmt.Errorf("guest rootfs: %w", err)
	}
	return facts{vmm: words[1], kernel: kh, rootfs: rh, cpu: cpuFacts()}, nil
}

// hashPath is the hex SHA-256 of a file. A directory, which only the
// fake VMM takes as a rootfs, is named by its path instead, since the
// fake's snapshots hold no guest to depend on its contents.
func hashPath(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if st.IsDir() {
		sum := sha256.Sum256([]byte("dir:" + path))
		return hex.EncodeToString(sum[:]), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// cpuFacts is the first CPU's vendor and model name, spaces folded, or
// "unknown" when /proc/cpuinfo has neither.
func cpuFacts() string {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "unknown"
	}
	var vendor, model string
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "vendor_id":
			if vendor == "" {
				vendor = strings.TrimSpace(v)
			}
		case "model name":
			if model == "" {
				model = strings.TrimSpace(v)
			}
		}
	}
	if vendor == "" && model == "" {
		return "unknown"
	}
	return strings.Join(strings.Fields(vendor+" "+model), "_")
}

// Platform replaces the host's kernel facts with the VM's. The VMM
// release goes where a kernel release goes, so kernel=series relaxes it
// to a minor series. The images and the CPU go, exact, where libc goes.
// A backend that cannot warm says so here.
func (b *Backend) Platform() artifact.Platform {
	if b.tier < core.TierSnapshot {
		return artifact.Platform{Kernel: "cloudhv-unusable", Libc: "n/a"}
	}
	f := b.facts
	return artifact.Platform{Kernel: "cloudhv-" + f.vmm, Libc: "kernel-" + f.kernel[:16] + "+rootfs-" + f.rootfs[:16] + "+" + f.cpu}
}

// leafBytes is the leaf's memory.current, 0 when it cannot be read.
func leafBytes(cgroupFD int) uint64 {
	if cgroupFD < 0 {
		return 0
	}
	fd, err := unix.Openat(cgroupFD, "memory.current", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0
	}
	f := os.NewFile(uintptr(fd), "memory.current")
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, 64))
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	return n
}

// Warm boots the template's guest in the warm leaf, waits for the guest
// init to say the template is ready, and keeps a snapshot of it. The VMM
// ends either way. The template's command names a path in the rootfs,
// which is pinned by its hash, so a registry template is refused.
func (b *Backend) Warm(ctx context.Context, sp backend.WarmSpec) (backend.Warm, error) {
	if b.tier < core.TierSnapshot {
		return backend.Warm{}, fmt.Errorf("cloudhv: unusable: %w", b.why)
	}
	if sp.Template.Dir != "" {
		return backend.Warm{}, fmt.Errorf("cloudhv: template %s comes from a registry; a cloudhv home runs templates from its rootfs only", sp.Template.Digest)
	}
	cmdline, err := kernelCmdline(sp.Template.Argv)
	if err != nil {
		return backend.Warm{}, err
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, warmTimeout)
		defer cancel()
	}
	if err := os.MkdirAll(sp.WorkDir, 0o755); err != nil {
		return backend.Warm{}, err
	}
	v, err := b.launch(ctx, sp.GrantUID, "", logPath(sp.WorkDir), sp.CgroupFD, nil)
	if err != nil {
		return backend.Warm{}, err
	}
	defer v.end()
	if err := v.api.put(ctx, "vm.create", b.vmConfig(cmdline)); err != nil {
		return backend.Warm{}, err
	}
	if err := v.api.put(ctx, "vm.boot", nil); err != nil {
		return backend.Warm{}, err
	}
	// The guest init listens on its control port only once the template
	// has said READY, so the first answer is the warm state.
	c, _, state, err := v.control(ctx)
	if err != nil {
		return backend.Warm{}, fmt.Errorf("cloudhv: guest of %s never became ready: %w", sp.GrantUID, err)
	}
	_ = c.Close()
	if state != stateReady {
		return backend.Warm{}, fmt.Errorf("%w: a booted guest says %q, want %q", ErrGuest, state, stateReady)
	}
	dir := b.warmDir(sp.GrantUID)
	if err := b.snapshot(ctx, v, dir); err != nil {
		return backend.Warm{}, err
	}
	w := &warm{id: sp.GrantUID, dir: dir, workDir: sp.WorkDir}
	b.mu.Lock()
	old := b.warms[w.id]
	b.warms[w.id] = w
	b.mu.Unlock()
	if old != nil && old.dir != dir {
		_ = os.RemoveAll(old.dir)
	}
	// One fiber costs the whole guest, which its restore copies in, and
	// the VMM (spike S1).
	return backend.Warm{ID: w.id, PID: 0, Bytes: b.guestBytes(), TotalBytes: b.guestBytes() + vmmOverhead}, nil
}

// logPath is the grant's log, where every VMM of the grant writes its
// own output and its guest's console.
func logPath(workDir string) string { return filepath.Join(workDir, "zygote.log") }

// snapshot pauses the VM, has the VMM write its snapshot into its own
// run directory, and takes the images out of the VMM's reach into dir.
// The VM stays paused.
func (b *Backend) snapshot(ctx context.Context, v *vm, dir string) error {
	if err := v.api.put(ctx, "vm.pause", nil); err != nil {
		return err
	}
	if err := clearDir(v.snapshot()); err != nil {
		return err
	}
	if err := v.api.put(ctx, "vm.snapshot", map[string]string{"destination_url": "file://" + vmRun + "/" + snapDir}); err != nil {
		return err
	}
	if err := takeSnapshot(v.snapshot(), dir); err != nil {
		return fmt.Errorf("cloudhv: take the snapshot of VMM %s: %w", v.id, err)
	}
	return nil
}

// clearDir empties a directory, keeping it and its owner.
func clearDir(dir string) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// Unwarm drops the warm snapshot. Running fibers keep what they restored.
func (b *Backend) Unwarm(id string) {
	b.mu.Lock()
	w, ok := b.warms[id]
	if ok {
		delete(b.warms, id)
	}
	b.mu.Unlock()
	if ok {
		_ = os.RemoveAll(w.dir)
	}
}

// Clone restores the warm snapshot in the fiber's leaf and hands the
// guest its incarnation.
func (b *Backend) Clone(ctx context.Context, warmID string, sp backend.FiberSpec) (backend.Fiber, error) {
	b.mu.Lock()
	w, ok := b.warms[warmID]
	b.mu.Unlock()
	if !ok {
		return backend.Fiber{}, fmt.Errorf("cloudhv: no warm snapshot %q", warmID)
	}
	line, err := incarnationLine(sp.Fence, sp.Generation, sp.Payload, sp.Session)
	if err != nil {
		return backend.Fiber{}, err
	}
	// spike S1: copy is the default. v53.0 offers only copy and ondemand.
	// Copy-on-write needs v54.0, and its pin would move together in
	// hack/cloudhv/build.sh and hack/cloudhv/spike/env.sh.
	mode := b.opt.RestoreMode
	if mode == "" {
		mode = "copy"
	}
	return b.birth(ctx, w.id, w.dir, mode, logPath(w.workDir), sp.Fence, sp.Endpoint, sp.CgroupFD, sp.Deadline, createDeadline, line)
}

// Resume restores a park in the new leaf and hands the guest its new
// incarnation. The endpoint and engine paths are the same in every VM,
// so nothing in the guest is rewritten.
func (b *Backend) Resume(ctx context.Context, sp backend.ResumeSpec) (backend.Fiber, error) {
	if b.tier < core.TierSnapshot {
		return backend.Fiber{}, fmt.Errorf("cloudhv: unusable: %w", b.why)
	}
	line, err := incarnationLine(sp.Fence, sp.Generation, nil, sp.Session)
	if err != nil {
		return backend.Fiber{}, err
	}
	return b.birth(ctx, sp.WarmID, sp.Dir, "copy", logPath(sp.WorkDir), sp.Fence, sp.Endpoint, sp.CgroupFD, sp.Deadline, resumeDeadline, line)
}

// incarnationLine is what the guest init learns a fiber by:
//
//	INCARNATE <generation> <fence> <seed-hex> <payload-hex|-> <session-hex|->
//
// The seed is 32 fresh bytes drawn here, living in the line alone, which
// the sender zeroes once written. A generation the guest would be wrong
// to take, or a fence that would split the line, is refused by name.
func incarnationLine(fence string, generation int, payload []byte, session string) ([]byte, error) {
	if generation < 1 {
		return nil, fmt.Errorf("cloudhv: %s: generation %d is not an incarnation", fence, generation)
	}
	if fence == "" || strings.ContainsFunc(fence, func(r rune) bool { return r <= ' ' || r > '~' }) {
		return nil, fmt.Errorf("cloudhv: fence %q cannot ride on a control line", fence)
	}
	seed := make([]byte, backend.SeedBytes)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("cloudhv: seed of %s: %w", fence, err)
	}
	line := make([]byte, 0, 64+len(fence)+2*backend.SeedBytes+2*len(payload)+2*len(session))
	line = append(line, "INCARNATE "...)
	line = strconv.AppendInt(line, int64(generation), 10)
	line = append(line, ' ')
	line = append(line, fence...)
	line = append(line, ' ')
	line = hex.AppendEncode(line, seed)
	clear(seed)
	line = append(line, ' ')
	line = appendHexOrDash(line, payload)
	line = append(line, ' ')
	line = appendHexOrDash(line, []byte(session))
	return line, nil
}

func appendHexOrDash(line, b []byte) []byte {
	if len(b) == 0 {
		return append(line, '-')
	}
	return hex.AppendEncode(line, b)
}

// birth starts a VMM in the leaf restoring the snapshot in from, resumes
// it, records what the restore cost the leaf, and sends the incarnation.
// The fiber is returned once the guest says served and its endpoint is
// bound. A guest that never says so is ended.
func (b *Backend) birth(ctx context.Context, grantUID, from, mode, logp, fence, ep string, cgroupFD int, deadline, floor time.Duration, line []byte) (backend.Fiber, error) {
	defer clear(line)
	if deadline <= 0 {
		deadline = floor
	}
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	src := "source_url=file://" + vmFrom
	if mode != "copy" {
		src += ",memory_restore_mode=" + mode
	}
	v, err := b.launch(ctx, grantUID, from, logp, cgroupFD, []string{"--restore", src})
	if err != nil {
		return backend.Fiber{}, fmt.Errorf("cloudhv: %s: %w", fence, err)
	}
	fail := func(err error) (backend.Fiber, error) {
		v.end()
		return backend.Fiber{}, fmt.Errorf("cloudhv: %s: %w", fence, err)
	}
	if err := v.waitState(ctx, "Paused"); err != nil {
		return fail(err)
	}
	if err := v.api.put(ctx, "vm.resume", nil); err != nil {
		return fail(err)
	}
	// What the restore cost the leaf, before the fiber dirties anything:
	// the host takes W as the leaf's count less this.
	footprint := leafBytes(cgroupFD)
	if err := v.guest(ctx, line, "served", stateReady, stateParked); err != nil {
		return fail(err)
	}
	e, err := serveEndpoint(ep, v.vsock())
	if err != nil {
		return fail(err)
	}
	f := &fiber{id: fence, vm: v, endpoint: ep, ep: e}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		e.close()
		return fail(errors.New("backend closed"))
	}
	b.fibers[fence] = f
	b.mu.Unlock()
	go b.watch(f)
	return backend.Fiber{ID: fence, PID: v.proc.Pid(), Footprint: footprint}, nil
}

// watch reports the fiber's end once its VMM has ended, however it did.
func (b *Backend) watch(f *fiber) {
	// verify on KVM: a template's end powers the guest off, which ends
	// the VMM. A guest kernel panic reboots it instead (panic=-1), and
	// v53.0 has no option to exit on a guest reset, so a reboot is not
	// yet detected here and the fiber would come back as a fresh guest.
	<-f.vm.done
	f.mu.Lock()
	if f.ep != nil {
		f.ep.close()
		f.ep = nil
	}
	f.mu.Unlock()
	f.vm.cleanup()
	b.mu.Lock()
	known := b.fibers[f.id] == f
	if known {
		delete(b.fibers, f.id)
	}
	b.mu.Unlock()
	if known {
		b.exits <- backend.Exit{FiberID: f.id, Status: f.vm.exited()}
	}
}

func (b *Backend) fiberOf(id string) (*fiber, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	f, ok := b.fibers[id]
	if !ok {
		return nil, fmt.Errorf("cloudhv: unknown fiber %q", id)
	}
	return f, nil
}

// Park asks the guest to stop serving, as SIGUSR1 does for gVisor, and
// only then pauses and snapshots the VM into the park directory. Without
// Sync the VMM then ends, and its Exit follows. With Sync the VM runs on,
// not serving, until the host ends it. A park that fails after the guest
// stopped serving resumes the VM and has the guest serve again, so the
// fiber runs on as after any other failed park.
func (b *Backend) Park(ctx context.Context, fiberID string, sp backend.ParkSpec) error {
	f, err := b.fiberOf(fiberID)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ep == nil {
		return fmt.Errorf("cloudhv: %s is parked already or ending", fiberID)
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, parkTimeout)
		defer cancel()
	}
	if err := os.MkdirAll(sp.Dir, 0o700); err != nil {
		return err
	}
	// The guest stops serving within the grant's resume deadline. A
	// guest that never says so is not parked and serves on.
	sctx := ctx
	if sp.Deadline > 0 {
		var cancel context.CancelFunc
		sctx, cancel = context.WithTimeout(ctx, sp.Deadline)
		defer cancel()
	}
	if err := f.vm.guest(sctx, []byte("PARK"), "parked", stateServing); err != nil {
		return fmt.Errorf("cloudhv: %s did not stop serving for the park: %w", fiberID, err)
	}
	f.ep.close()
	f.ep = nil
	if err := b.snapshot(ctx, f.vm, sp.Dir); err != nil {
		return b.unpark(f, err)
	}
	if sp.Capture != nil {
		if err := sp.Capture(); err != nil {
			return b.unpark(f, fmt.Errorf("cloudhv: capture of %s: %w", fiberID, err))
		}
	}
	if sp.Sync {
		if err := f.vm.api.put(ctx, "vm.resume", nil); err != nil {
			return fmt.Errorf("cloudhv: %s parked, but its VM did not resume: %w", fiberID, err)
		}
		return nil
	}
	// The VMM ends here, and watch reports the fiber's end.
	go f.vm.end()
	return nil
}

// unpark undoes a park that failed after the guest stopped serving: the
// VM runs again, the guest serves again under the same incarnation, and
// the endpoint is bound again. A fiber that cannot be brought back is
// ended, and the error says so.
func (b *Backend) unpark(f *fiber, cause error) error {
	ctx, cancel := context.WithTimeout(context.Background(), resumeDeadline)
	defer cancel()
	err := f.vm.api.put(ctx, "vm.resume", nil)
	if err == nil {
		err = f.vm.guest(ctx, []byte("UNPARK"), "served", stateParked)
	}
	if err == nil {
		f.ep, err = serveEndpoint(f.endpoint, f.vm.vsock())
	}
	if err != nil {
		go f.vm.end()
		return fmt.Errorf("%w; the fiber could not serve again and was ended: %w", cause, err)
	}
	return cause
}

// Kill shuts the VMM down, and kills it when it does not go. The host
// kills the leaf as well.
func (b *Backend) Kill(fiberID string) error {
	f, err := b.fiberOf(fiberID)
	if err != nil {
		return nil
	}
	go f.vm.end()
	return nil
}

var (
	_ backend.Backend         = (*Backend)(nil)
	_ backend.Isolator        = (*Backend)(nil)
	_ backend.Platformer      = (*Backend)(nil)
	_ backend.Prober          = (*Backend)(nil)
	_ backend.DeadlineAdvisor = (*Backend)(nil)
	_ backend.Overheader      = (*Backend)(nil)
	_ backend.Handoffer       = (*Backend)(nil)
)
