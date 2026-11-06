//go:build linux

// Package hyperlight is the Hyperlight backend: every fiber is a
// Hyperlight micro-VM restored from a snapshot of the warm guest, held
// by a helper process that fiberd starts per grant and drives over the
// line protocol in hack/hyperlight/PROTOCOL.md. Hyperlight has a Rust
// host API only, so the mechanism lives in the helper
// (hack/hyperlight/helper); the same protocol is served without a
// hypervisor by hack/hyperlight/fakehelper, which conformance runs against
// and the unit tests run inside their own process through the starter.
//
// The helper's sandboxes are threads of one process, so a fiber has no
// process and no cgroup leaf of its own: the helper runs in the grant's
// cgroup (the ceiling still holds), exits are reported by fence, and W
// is what the helper reports the guest dirtied (backend.WReporter). Tier
// FIBER_SNAPSHOT. No delta codec: a park is what the helper wrote.
//
// A grant with a device engine hands the helper the engine's socket. A
// guest reaches it only through the helper, which puts the fiber's fence
// in each request, so the helper's cgroup speaks for every fiber and the
// host sends the engine RELAY for it (RelaysEngine).
package hyperlight

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Azure/fiberd/pkg/artifact"
	"github.com/Azure/fiberd/pkg/backend"
	"github.com/Azure/fiberd/pkg/core"
)

// Options configure the Hyperlight backend.
type Options struct {
	// Helper is the helper executable (the Rust helper, or fakehelper).
	// Required.
	Helper string
	// Guest is the guest binary the helper loads; template commands from
	// -template are appended to the helper's arguments after it.
	Guest string
}

const (
	// The deadlines a clone or resume without one of its own gets.
	// createDeadline and resumeDeadline are the floors. A warm instance
	// whose probe clone took longer raises them to deadlineFactor times
	// what the probe took (DefaultDeadlines), as gVisor does. A helper's
	// clone is more than a sandbox from memory: it may start the
	// template's program, and clones share the helper and the host's
	// CPUs, so one sized for a small guest on an idle host is too short
	// for a runtime's under load. deadlineCap bounds a probe that took
	// pathologically long, so no clone waits without end for a default
	// it never set.
	createDeadline = 500 * time.Millisecond
	resumeDeadline = 2 * time.Second
	deadlineFactor = 4
	deadlineCap    = 5 * time.Second
	// probeEndWait bounds Warm's wait for the probe's EXITED, so the
	// footprint the host reads once Warm returns is the warm instance's
	// alone and holds no probe sandbox.
	probeEndWait = 2 * time.Second
	// probeLate is how near deadlineCap a probe's ERROR counts as the
	// probe running out its time, from a helper that keeps the deadline
	// on its CLONE line and answers just before fiberd's own timer fires.
	probeLate      = 250 * time.Millisecond
	versionTimeout = 5 * time.Second
)

var ErrHelper = errors.New("hyperlight: helper error")

// facts is what a helper's snapshots depend on. The helper reports it on
// `--version` and on READY as one token each, in this order.
//
//	helper      the helper and its version ("fiberd-hyperlight-helper/0.3.0")
//	hyperlight  the hyperlight_host crate the helper was built with
//	hypervisor  the one in use on this host (kvm, mshv)
//	cpu         the CPU vendor string (GenuineIntel, AuthenticAMD)
//
// Hyperlight refuses to load a snapshot from another version, hypervisor
// or CPU vendor, and the park layout is the helper's own. Recording the
// facts as the platform refuses a mismatch before the resume instead of
// failing inside it.
type facts struct {
	helper, hyperlight, hypervisor, cpu string
}

// parseFacts reads the four tokens after READY or from `--version`.
func parseFacts(tokens []string) (facts, error) {
	if len(tokens) != 4 {
		return facts{}, fmt.Errorf("%w: want 4 facts (helper hyperlight hypervisor cpu), got %q", ErrHelper, strings.Join(tokens, " "))
	}
	for _, t := range tokens {
		if t == "" {
			return facts{}, fmt.Errorf("%w: empty fact in %q", ErrHelper, strings.Join(tokens, " "))
		}
	}
	return facts{helper: tokens[0], hyperlight: tokens[1], hypervisor: tokens[2], cpu: tokens[3]}, nil
}

// platform maps the facts onto the parity fields. The Hyperlight version
// goes where a kernel release goes, so kernel=series relaxes it to a
// minor series. Everything else goes, exact, where libc goes. The host
// keeps the architecture.
func (f facts) platform() artifact.Platform {
	return artifact.Platform{Kernel: "hyperlight-" + f.hyperlight, Libc: f.helper + "+" + f.hypervisor + "+" + f.cpu}
}

// starter starts helper processes. It is the one point where a process
// enters the backend, so the unit tests put a goroutine there.
type starter interface {
	// Version is what `helper --version` prints.
	Version(ctx context.Context) (string, error)
	// Start runs the helper with args in workDir, in the cgroup when
	// cgroupFD is not negative, with its output on logf and ctl as fd 3.
	Start(args []string, workDir string, cgroupFD int, logf, ctl *os.File) (process, error)
}

// process is a started helper.
type process interface {
	Pid() int
	Kill() error
	Wait() error
}

// execStarter starts the helper executable.
type execStarter struct{ helper string }

// command keeps the container's environment, unlike every other program
// fiberd starts (pkg/sys/helper). A deployment's settings reach the helper
// that way. It holds no capabilities beyond the ones a device engine adds.
func (s execStarter) command(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, s.helper, args...)
	cmd.Env = os.Environ()
	return cmd
}

func (s execStarter) Version(ctx context.Context) (string, error) {
	out, err := s.command(ctx, "--version").Output()
	return string(out), err
}

func (s execStarter) Start(args []string, workDir string, cgroupFD int, logf, ctl *os.File) (process, error) {
	cmd := s.command(context.Background(), args...)
	cmd.ExtraFiles = []*os.File{ctl}
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.Dir = workDir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if cgroupFD >= 0 {
		cmd.SysProcAttr.UseCgroupFD = true
		cmd.SysProcAttr.CgroupFD = cgroupFD
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return execProcess{cmd}, nil
}

type execProcess struct{ cmd *exec.Cmd }

func (p execProcess) Pid() int    { return p.cmd.Process.Pid }
func (p execProcess) Kill() error { return p.cmd.Process.Kill() }
func (p execProcess) Wait() error { return p.cmd.Wait() }

// Backend implements backend.Backend, Platformer, DeadlineAdvisor,
// WReporter and Prober.
type Backend struct {
	opt     Options
	starter starter // New sets it to the helper executable
	tier    core.Tier
	why     error // why tier is unspecified, nil when it is not
	facts   facts // from `helper --version` at open, and every READY must agree

	mu     sync.Mutex
	warms  map[string]*helper
	fibers map[string]*fiber // fence
	exits  chan backend.Exit
}

type helper struct {
	id   string
	proc process
	ctl  *net.UnixConn
	pmu  sync.Mutex
	pend map[string]chan reply // fence -> reply
	gone chan struct{}
	// cloneTook is how long the probe clone at warm took from CLONE to
	// CLONED, 0 when it measured nothing (DefaultDeadlines). published is
	// set once Warm hands the instance to the host, and only then does
	// helperGone report the helper's end. Both under Backend.mu.
	cloneTook time.Duration
	published bool
	// probeEnd is closed by the probe's EXITED while Warm waits on it,
	// under pmu.
	probeFence string
	probeEnd   chan struct{}
}

type reply struct {
	bytes uint64
	err   error
}

type fiber struct {
	id     string
	warmID string
	w      uint64
	// h is the helper holding the fiber. Two warms of one grant share
	// warmID, so a helper's end orphans only the fibers it held.
	h *helper
}

// New opens the backend. The tier is FIBER_SNAPSHOT when the helper
// answers `--version` and the guest exists. Otherwise it offers none,
// and ProbeErr says why.
func New(o Options) backend.Backend { return newBackend(o, nil) }

// newBackend is New with the starter chosen, nil for the helper
// executable.
func newBackend(o Options, start starter) *Backend {
	if start == nil {
		start = execStarter{o.Helper}
	}
	b := &Backend{opt: o, starter: start, warms: map[string]*helper{}, fibers: map[string]*fiber{}, exits: make(chan backend.Exit, 1024)}
	f, err := probeFacts(start)
	if err != nil {
		b.why = fmt.Errorf("helper %s unusable: %w", o.Helper, err)
		return b
	}
	if o.Guest != "" {
		if _, err := os.Stat(o.Guest); err != nil {
			b.why = fmt.Errorf("guest unusable: %w", err)
			return b
		}
	}
	b.facts = f
	b.tier = core.TierSnapshot
	return b
}

// ProbeErr is why New found no tier: the helper cannot state its facts,
// or the guest is missing.
func (b *Backend) ProbeErr() error { return b.why }

// probeFacts runs `helper --version` for the facts a snapshot through
// this helper depends on. They are known before any grant is warmed,
// because the host records them at open.
func probeFacts(start starter) (facts, error) {
	ctx, cancel := context.WithTimeout(context.Background(), versionTimeout)
	defer cancel()
	out, err := start.Version(ctx)
	if err != nil {
		return facts{}, fmt.Errorf("--version: %w", err)
	}
	return parseFacts(strings.Fields(strings.SplitN(out, "\n", 2)[0]))
}

func (b *Backend) Name() string    { return "hyperlight" }
func (b *Backend) Tier() core.Tier { return b.tier }

// IsolatesTenants is true because a fiber is a micro-VM guest behind the
// hypervisor.
func (b *Backend) IsolatesTenants() bool { return true }

// RelaysEngine is true because a fiber has no process of its own. Its
// engine requests come from the helper, in the warm instance's cgroup,
// with the fiber's fence put in by the helper, never by the guest.
func (b *Backend) RelaysEngine() bool { return true }

// Platform reports the helper's facts, because a snapshot depends on them
// and not on the host kernel or libc. A backend without a usable helper
// warms nothing, and says so here.
func (b *Backend) Platform() artifact.Platform {
	if b.tier < core.TierSnapshot {
		return artifact.Platform{Kernel: "hyperlight-unusable", Libc: "n/a"}
	}
	return b.facts.platform()
}

// DefaultDeadlines sizes the deadlines of a clone or resume without one
// of its own from the probe clone the warm instance made. They are the
// floors, raised to deadlineFactor times the probe and capped at
// deadlineCap. An instance whose probe measured nothing, or one this
// backend does not have, gets the floors.
func (b *Backend) DefaultDeadlines(warmID string) (create, resume time.Duration) {
	var took time.Duration
	b.mu.Lock()
	if h := b.warms[warmID]; h != nil {
		took = h.cloneTook
	}
	b.mu.Unlock()
	return sizeDeadline(took, createDeadline), sizeDeadline(took, resumeDeadline)
}

// sizeDeadline sizes one of the defaults (backend.SizeDeadline).
func sizeDeadline(measured, floor time.Duration) time.Duration {
	return backend.SizeDeadline(measured, floor, deadlineFactor, deadlineCap)
}

// FiberW implements backend.WReporter from the helper's W lines.
func (b *Backend) FiberW(fiberID string) (uint64, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	f, ok := b.fibers[fiberID]
	if !ok {
		return 0, false
	}
	return f.w, true
}

// Warm starts the helper in the grant's cgroup with fd 3 as the control
// socket and waits for READY.
func (b *Backend) Warm(ctx context.Context, sp backend.WarmSpec) (backend.Warm, error) {
	if b.tier < core.TierSnapshot {
		return backend.Warm{}, errors.New("hyperlight: helper or guest unavailable")
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return backend.Warm{}, fmt.Errorf("hyperlight: socketpair: %w", err)
	}
	parentF := os.NewFile(uintptr(fds[0]), "helper-ctl")
	childF := os.NewFile(uintptr(fds[1]), "helper-ctl-child")

	args := []string{}
	if b.opt.Guest != "" {
		args = append(args, "--guest", b.opt.Guest)
	}
	if sp.EnginePath != "" {
		args = append(args, "--engine", sp.EnginePath)
	}
	// The template command's own arguments, after the helper's; the
	// first word is the guest's name for the helper's benefit.
	if len(sp.Template.Argv) > 1 {
		args = append(args, sp.Template.Argv[1:]...)
	}
	if err := os.MkdirAll(sp.WorkDir, 0o755); err != nil {
		_ = parentF.Close()
		return backend.Warm{}, err
	}
	logf, err := os.OpenFile(filepath.Join(sp.WorkDir, "zygote.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		_ = parentF.Close()
		return backend.Warm{}, err
	}
	defer func() { _ = logf.Close() }()
	proc, err := b.starter.Start(args, sp.WorkDir, sp.CgroupFD, logf, childF)
	// The helper holds its own copy of its end. Ours closes, so a
	// helper that dies before READY is read as EOF below rather than
	// waited for until the caller's deadline.
	_ = childF.Close()
	if err != nil {
		_ = parentF.Close()
		return backend.Warm{}, fmt.Errorf("hyperlight: start helper: %w", err)
	}
	conn, err := net.FileConn(parentF)
	_ = parentF.Close()
	if err != nil {
		end(proc)
		return backend.Warm{}, err
	}
	uc, _ := conn.(*net.UnixConn)
	h := &helper{id: sp.GrantUID, proc: proc, ctl: uc, pend: map[string]chan reply{}, gone: make(chan struct{})}

	ready := make(chan error, 1)
	rd := bufio.NewReaderSize(uc, 64<<10)
	go func() {
		line, err := rd.ReadString('\n')
		if err != nil {
			ready <- err
			return
		}
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "READY" {
			ready <- fmt.Errorf("%w: expected READY, got %q", ErrHelper, strings.TrimSpace(line))
			return
		}
		// This warm's snapshots are filed under the facts recorded at
		// open, so a helper replaced since then must not warm.
		got, err := parseFacts(f[1:])
		if err != nil {
			ready <- err
			return
		}
		if got != b.facts {
			ready <- fmt.Errorf("%w: READY reports %v, the helper reported %v at open", ErrHelper, got, b.facts)
			return
		}
		ready <- nil
	}()
	select {
	case err := <-ready:
		if err != nil {
			end(proc)
			_ = uc.Close()
			return backend.Warm{}, fmt.Errorf("hyperlight: helper for %s did not become ready: %w", sp.GrantUID, err)
		}
	case <-ctx.Done():
		end(proc)
		_ = uc.Close()
		return backend.Warm{}, ctx.Err()
	}
	b.mu.Lock()
	b.warms[h.id] = h
	b.mu.Unlock()
	go b.read(h, rd)
	go func() { _ = proc.Wait() }()
	took := b.probeClone(ctx, h, sp.WorkDir)
	// The instance is the host's once it is published. A helper that
	// ended before that fails the warm, and helperGone reports no end for
	// an instance the host never had. A caller that gave up during the
	// probe still gets it, sized from how long the probe ran: it was
	// READY, and the host warms on demand under a clone's deadline, so a
	// probe that does not fit that deadline must not cost the grant its
	// warm instance.
	b.mu.Lock()
	current := b.warms[h.id]
	if current == h {
		h.cloneTook, h.published = took, true
	}
	b.mu.Unlock()
	if current != h {
		_ = uc.Close()
		_ = proc.Kill()
		if current != nil {
			// Another warm of the grant took its place while it probed.
			return backend.Warm{}, fmt.Errorf("hyperlight: another warm of %s took this one's place during its probe clone", sp.GrantUID)
		}
		return backend.Warm{}, fmt.Errorf("%w: helper for %s exited during its probe clone", ErrHelper, sp.GrantUID)
	}
	if took > 0 {
		log.Printf("hyperlight: template of %s sized from a probe of %s, default deadlines create=%s resume=%s", h.id, took.Round(time.Millisecond),
			sizeDeadline(took, createDeadline), sizeDeadline(took, resumeDeadline))
	}
	return backend.Warm{ID: h.id, PID: proc.Pid()}, nil
}

// probeClone makes one fiber from the warm snapshot, ends it, and returns
// how long it took from CLONE to CLONED, what a clone costs and what
// sizes the instance's default deadlines (DefaultDeadlines). A probe the
// helper refused returns 0, which leaves the floors and is logged: a
// helper that cannot clone fails its first real clone just the same, and
// says why there. A probe that ran out its time returns deadlineCap, the
// most any default may be, since a template that slow needs every bit of
// it. One the caller cut short returns how long it ran, which the clone
// took at least. The probe runs under the caller's context, as gVisor's
// does, so a clone that warms the grant on demand pays for it. Its fence is the grant's own and no real fence (grant/epoch/seq)
// can take it, and it is never a fiber of the backend's, so its W and
// EXITED go nowhere.
func (b *Backend) probeClone(ctx context.Context, h *helper, workDir string) time.Duration {
	fence := h.id + "/probe"
	endpoint := filepath.Join(workDir, "probe.sock")
	_ = os.Remove(endpoint)
	line, err := incarnationLine(fmt.Sprintf("CLONE %s %s %d -", fence, endpoint, deadlineMS(deadlineCap)), fence, 1)
	if err != nil {
		log.Printf("hyperlight: probe clone of %s: %v", h.id, err)
		return 0
	}
	end := make(chan struct{})
	h.pmu.Lock()
	h.probeFence, h.probeEnd = fence, end
	h.pmu.Unlock()
	defer func() {
		h.pmu.Lock()
		h.probeEnd = nil
		h.pmu.Unlock()
		_ = os.Remove(endpoint)
	}()
	// The probe's answer is awaited by hand rather than through ask, so
	// its pending entry outlives the probe's time: an answer that comes
	// as the time runs out is still heard below, never dropped.
	answer := make(chan reply, 1)
	h.pmu.Lock()
	h.pend[fence] = answer
	h.pmu.Unlock()
	defer h.reply(fence, reply{})
	pctx, cancel := context.WithTimeout(ctx, deadlineCap)
	defer cancel()
	t0 := time.Now()
	_, err = h.ctl.Write(append(line, '\n'))
	clear(line)
	if err != nil {
		// A control socket that takes no line belongs to a helper that is
		// going: its end is let register, so Warm fails rather than
		// publish an instance already dead.
		select {
		case <-h.gone:
		case <-time.After(probeEndWait):
		}
	} else {
		select {
		case r := <-answer:
			err = r.err
		case <-pctx.Done():
			err = pctx.Err()
		case <-h.gone:
			err = fmt.Errorf("%w: helper exited", ErrHelper)
		}
	}
	took := time.Since(t0)
	timedOut := errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
	if err != nil && !timedOut {
		// An ERROR: the helper made no sandbox, or freed it before it
		// said so, so there is nothing to end or wait on, and a helper
		// that is gone took everything with it. One that came as the
		// probe's time ran out is a helper keeping the CLONE's deadline,
		// and counts as running it out.
		if took >= deadlineCap-probeLate {
			log.Printf("hyperlight: probe clone of %s ran out its %s: %v; default deadlines go to the cap", h.id, deadlineCap, err)
			return deadlineCap
		}
		log.Printf("hyperlight: probe clone of %s: %v; default deadlines stay at the floors", h.id, err)
		return 0
	}
	// A probe that cloned, or one still cloning, is ended, and a helper
	// ends one that clones after its KILL. Its sandbox is charged to the
	// warm instance's cgroup until the helper frees it, so its EXITED is
	// awaited, within probeEndWait.
	// A late answer to the CLONE may still come on the same entry: an
	// ERROR, from a helper keeping the CLONE's own deadline, means no
	// sandbox to wait on.
	late := answer
	_, _ = h.ctl.Write([]byte("KILL " + fence + "\n"))
	// The wait holds even for a caller that gave up: the host reads the
	// warm instance's footprint as Warm returns, and a probe sandbox
	// still alive would be counted in it for the instance's whole life.
	wait := time.After(probeEndWait)
	for done := false; !done; {
		select {
		case r := <-late:
			done = r.err != nil // a late CLONED still has its EXITED to come
		case <-end:
			done = true
		case <-h.gone:
			done = true
		case <-wait:
			log.Printf("hyperlight: probe clone of %s did not exit within %s of its KILL; the footprint read now may count it", h.id, probeEndWait)
			done = true
		}
	}
	switch {
	case timedOut && took < deadlineCap && ctx.Err() != nil:
		// Cut short by the caller: the clone took at least this long,
		// which still sizes the defaults better than the floors do.
		log.Printf("hyperlight: probe clone of %s cut short after %s; default deadlines sized from that", h.id, took.Round(time.Millisecond))
		return took
	case timedOut:
		log.Printf("hyperlight: probe clone of %s did not clone within %s; default deadlines go to the cap", h.id, deadlineCap)
		return deadlineCap
	}
	return took
}

// end kills a helper that did not come up and reaps it, so a failed
// warm leaves no zombie behind. A helper that did come up is reaped by
// the goroutine Warm starts for it.
func end(p process) {
	_ = p.Kill()
	_ = p.Wait()
}

func (b *Backend) read(h *helper, rd *bufio.Reader) {
	defer close(h.gone)
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			b.helperGone(h)
			return
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "CLONED":
			h.reply(f[1], reply{})
		case "PARKED":
			// The bytes are what the park costs to move. A line without
			// them is still the answer to the park, not a reason to stop
			// reading the helper.
			var n uint64
			if len(f) >= 3 {
				n, _ = strconv.ParseUint(f[2], 10, 64)
			}
			h.reply(f[1], reply{bytes: n})
		case "ERROR":
			h.reply(f[1], reply{err: fmt.Errorf("%w: %s", ErrHelper, strings.Join(f[2:], " "))})
		case "W":
			if len(f) >= 3 {
				n, _ := strconv.ParseUint(f[2], 10, 64)
				b.mu.Lock()
				if fb := b.fibers[f[1]]; fb != nil {
					fb.w = n
				}
				b.mu.Unlock()
			}
		case "EXITED":
			status := "exit:?"
			if len(f) >= 3 {
				status = f[2]
			}
			b.mu.Lock()
			fb := b.fibers[f[1]]
			if fb != nil {
				delete(b.fibers, f[1])
			}
			b.mu.Unlock()
			if fb != nil {
				b.exits <- backend.Exit{FiberID: f[1], Status: status}
			} else {
				h.probeExited(f[1])
			}
		}
	}
}

func (h *helper) reply(fence string, r reply) {
	h.pmu.Lock()
	ch, ok := h.pend[fence]
	delete(h.pend, fence)
	h.pmu.Unlock()
	if ok {
		ch <- r
	}
}

// probeExited ends Warm's wait for the probe when fence is the probe's.
func (h *helper) probeExited(fence string) {
	h.pmu.Lock()
	if h.probeEnd != nil && fence == h.probeFence {
		close(h.probeEnd)
		h.probeEnd = nil
	}
	h.pmu.Unlock()
}

func (b *Backend) helperGone(h *helper) {
	b.mu.Lock()
	if b.warms[h.id] == h {
		delete(b.warms, h.id)
	}
	published := h.published
	var orphans []string
	for id, f := range b.fibers {
		if f.h == h {
			orphans = append(orphans, id)
			delete(b.fibers, id)
		}
	}
	b.mu.Unlock()
	h.pmu.Lock()
	for fence, ch := range h.pend {
		ch <- reply{err: fmt.Errorf("%w: helper exited", ErrHelper)}
		delete(h.pend, fence)
	}
	h.pmu.Unlock()
	for _, id := range orphans {
		b.exits <- backend.Exit{FiberID: id, Status: "signal:helper"}
	}
	if published {
		b.exits <- backend.Exit{WarmID: h.id, Status: "helper exited"}
	}
}

// ask sends one line, which it zeroes once written since a CLONE or a
// RESUME carries the fiber's seed, and waits for the helper's reply on
// that fence. Replies carry only the fence, so one command per fence
// may be in flight: a second would take the first's place in pend and
// leave it waiting for a reply that has already been delivered.
func (b *Backend) ask(ctx context.Context, h *helper, fence string, line []byte) (reply, error) {
	ch := make(chan reply, 1)
	h.pmu.Lock()
	if _, busy := h.pend[fence]; busy {
		h.pmu.Unlock()
		return reply{}, fmt.Errorf("hyperlight: another command for %s is still in flight", fence)
	}
	h.pend[fence] = ch
	h.pmu.Unlock()
	_, err := h.ctl.Write(append(line, '\n'))
	clear(line)
	if err != nil {
		h.reply(fence, reply{})
		return reply{}, fmt.Errorf("hyperlight: send: %w", err)
	}
	select {
	case r := <-ch:
		return r, r.err
	case <-ctx.Done():
		h.reply(fence, reply{})
		return reply{}, ctx.Err()
	case <-h.gone:
		return reply{}, fmt.Errorf("%w: helper exited", ErrHelper)
	}
}

func (b *Backend) helperOf(fiberID string) (*helper, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	f, ok := b.fibers[fiberID]
	if !ok {
		return nil, fmt.Errorf("hyperlight: unknown fiber %q", fiberID)
	}
	// The helper that holds it, not whichever warm of the grant is newest.
	h := f.h
	if h == nil {
		return nil, fmt.Errorf("hyperlight: no helper for %q", fiberID)
	}
	return h, nil
}

func (b *Backend) Unwarm(id string) {
	b.mu.Lock()
	h, ok := b.warms[id]
	if ok {
		delete(b.warms, id)
	}
	b.mu.Unlock()
	if ok {
		_ = h.ctl.Close()
		_ = h.proc.Kill()
	}
}

// Clone asks the helper for a fiber from the warm snapshot, told its
// generation and a fresh seed before it serves.
func (b *Backend) Clone(ctx context.Context, warmID string, sp backend.FiberSpec) (backend.Fiber, error) {
	b.mu.Lock()
	h, ok := b.warms[warmID]
	b.mu.Unlock()
	if !ok {
		return backend.Fiber{}, fmt.Errorf("hyperlight: no warm helper %q", warmID)
	}
	line, err := incarnationLine(fmt.Sprintf("CLONE %s %s %d %s", sp.Fence, sp.Endpoint, deadlineMS(sp.Deadline), payloadHex(sp.Payload)), sp.Fence, sp.Generation)
	if err != nil {
		return backend.Fiber{}, err
	}
	return b.start(ctx, h, sp.Fence, line, sp.Deadline)
}

// incarnationLine ends a CLONE or RESUME with what the guest learns
// through Incarnate: the host's generation and 32 bytes of fresh
// entropy, hex. The seed is drawn here and lives in the line alone,
// which ask zeroes once it is written. A generation the guest would be
// wrong to take is refused here by name rather than shown as a helper
// error.
func incarnationLine(head, fence string, generation int) ([]byte, error) {
	if generation < 1 {
		return nil, fmt.Errorf("hyperlight: %s: generation %d is not an incarnation", fence, generation)
	}
	seed := make([]byte, backend.SeedBytes)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("hyperlight: seed of %s: %w", fence, err)
	}
	line := make([]byte, 0, len(head)+1+20+1+2*backend.SeedBytes)
	line = append(line, head...)
	line = append(line, ' ')
	line = strconv.AppendInt(line, int64(generation), 10)
	line = append(line, ' ')
	line = hex.AppendEncode(line, seed)
	clear(seed)
	return line, nil
}

func (b *Backend) start(ctx context.Context, h *helper, fence string, line []byte, deadline time.Duration) (backend.Fiber, error) {
	if deadline > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, deadline)
		defer cancel()
	}
	f := &fiber{id: fence, warmID: h.id, h: h}
	b.mu.Lock()
	b.fibers[fence] = f // before the reply: a W or EXITED that races it is kept
	b.mu.Unlock()
	if _, err := b.ask(ctx, h, fence, line); err != nil {
		b.mu.Lock()
		if b.fibers[fence] == f {
			delete(b.fibers, fence)
		}
		b.mu.Unlock()
		// The helper may still bring it up late; make sure it is gone.
		_, _ = h.ctl.Write([]byte("KILL " + fence + "\n"))
		return backend.Fiber{}, err
	}
	return backend.Fiber{ID: fence, PID: 0}, nil
}

// Park asks the helper to write the fiber's state into the directory.
func (b *Backend) Park(ctx context.Context, fiberID string, sp backend.ParkSpec) error {
	h, err := b.helperOf(fiberID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(sp.Dir, 0o755); err != nil {
		return err
	}
	sync := "0"
	if sp.Sync {
		sync = "1"
	}
	// A park that never comes back is worse than a park that fails: the
	// caller (a consumer parking an idle session) has no deadline of its
	// own, and a helper that misses the command, or is stuck serving the
	// fiber's endpoint, would hold it forever. Snapshotting is hundreds
	// of milliseconds; this is generous and still an answer.
	_, callers := ctx.Deadline()
	if !callers {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, parkTimeout)
		defer cancel()
	}
	if _, err = b.ask(ctx, h, fiberID, fmt.Appendf(nil, "PARK %s %s %s", fiberID, sp.Dir, sync)); err != nil {
		// Name the deadline that fired, the caller's or this one.
		if errors.Is(err, context.DeadlineExceeded) {
			if callers {
				return fmt.Errorf("%w: no answer to PARK %s before the caller's deadline: %w", ErrHelper, fiberID, err)
			}
			return fmt.Errorf("%w: no answer to PARK %s within %s", ErrHelper, fiberID, parkTimeout)
		}
		return err
	}
	return nil
}

// parkTimeout bounds a park whose caller set no deadline. A variable so
// a test can shorten it.
var parkTimeout = 15 * time.Second

// Resume asks the helper for a fiber from a park directory, told the
// parked generation plus one and a fresh seed before it serves again.
func (b *Backend) Resume(ctx context.Context, sp backend.ResumeSpec) (backend.Fiber, error) {
	b.mu.Lock()
	h, ok := b.warms[sp.WarmID]
	b.mu.Unlock()
	if !ok {
		return backend.Fiber{}, fmt.Errorf("hyperlight: no warm helper %q to resume under", sp.WarmID)
	}
	line, err := incarnationLine(fmt.Sprintf("RESUME %s %s %s %d", sp.Fence, sp.Dir, sp.Endpoint, deadlineMS(sp.Deadline)), sp.Fence, sp.Generation)
	if err != nil {
		return backend.Fiber{}, err
	}
	return b.start(ctx, h, sp.Fence, line, sp.Deadline)
}

func (b *Backend) Kill(fiberID string) error {
	h, err := b.helperOf(fiberID)
	if err != nil {
		return nil
	}
	_, err = h.ctl.Write([]byte("KILL " + fiberID + "\n"))
	return err
}

func (b *Backend) Exits() <-chan backend.Exit { return b.exits }

func (b *Backend) Close() {
	b.mu.Lock()
	hs := make([]*helper, 0, len(b.warms))
	for _, h := range b.warms {
		hs = append(hs, h)
	}
	b.mu.Unlock()
	for _, h := range hs {
		_ = h.ctl.Close()
		_ = h.proc.Kill()
	}
}

func deadlineMS(d time.Duration) int64 {
	if d <= 0 {
		return int64(createDeadline / time.Millisecond)
	}
	return d.Milliseconds()
}

func payloadHex(p []byte) string {
	if len(p) == 0 {
		return "-"
	}
	return hex.EncodeToString(p)
}

// FiberOverheadBytes: a fiber here is a whole sandbox restored from the
// template's snapshot, not a copy-on-write child, so it costs about what
// the warm instance costs however little of it the guest dirties. W stays
// the dirtied bytes the helper reports; this is what the grant's block
// ceiling must leave room for, and 0 asks the host to measure it from the
// warm instance rather than guess. Without it the ceiling is sized as if
// a fiber cost only its W budget, and the first clone puts the grant
// cgroup over memory.high: the ladder then sheds and yields while the
// helper crawls, which is what a park that never came back looked like.
func (b *Backend) FiberOverheadBytes() uint64 { return 0 }

var (
	_ backend.Backend         = (*Backend)(nil)
	_ backend.Platformer      = (*Backend)(nil)
	_ backend.DeadlineAdvisor = (*Backend)(nil)
	_ backend.WReporter       = (*Backend)(nil)
	_ backend.Overheader      = (*Backend)(nil)
)
