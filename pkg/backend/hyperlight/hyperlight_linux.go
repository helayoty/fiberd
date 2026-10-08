//go:build linux

// Package hyperlight is the Hyperlight backend: every fiber is a
// Hyperlight micro-VM restored from a snapshot of the warm guest, held
// by a helper process that fiberd starts per grant and drives over the
// line protocol in hack/hyperlight/PROTOCOL.md. Hyperlight has a Rust
// host API only, so the mechanism lives in the helper
// (hack/hyperlight/helper); the same protocol is served without a
// hypervisor by hack/hyperlight/fakehelper, which is what the container
// tests and conformance run against.
//
// The helper's sandboxes are threads of one process, so a fiber has no
// process and no cgroup leaf of its own: the helper runs in the grant's
// cgroup (the ceiling still holds), exits are reported by fence, and W
// is what the helper reports the guest dirtied (backend.WReporter). Tier
// FIBER_SNAPSHOT. No delta codec: a park is what the helper wrote.
package hyperlight

import (
	"bufio"
	"context"
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

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
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
	createDeadline = 500 * time.Millisecond
	resumeDeadline = 2 * time.Second
	versionTimeout = 5 * time.Second
)

var ErrHelper = errors.New("hyperlight: helper error")

// facts is what a helper's snapshots depend on, as the helper reports
// it on `--version` and on READY: one token each, in this order.
//
//	helper      the helper and its version ("fiberd-hyperlight-helper/0.1.0")
//	hyperlight  the hyperlight_host crate the helper was built with
//	hypervisor  the one in use on this host (kvm, mshv)
//	cpu         the CPU vendor string (GenuineIntel, AuthenticAMD)
//
// Hyperlight refuses to load a snapshot from another version,
// hypervisor or CPU vendor, and the helper's park layout is the
// helper's; recorded as the platform, a mismatch is refused before the
// resume instead of failing inside it.
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

// platform maps the facts onto the parity fields: the Hyperlight
// version where a kernel release goes (kernel=series relaxes it to a
// minor series), everything else exact, where libc goes. The host keeps
// the architecture.
func (f facts) platform() artifact.Platform {
	return artifact.Platform{Kernel: "hyperlight-" + f.hyperlight, Libc: f.helper + "+" + f.hypervisor + "+" + f.cpu}
}

// Backend implements backend.Backend, Platformer, DeadlineAdvisor and
// WReporter.
type Backend struct {
	opt   Options
	tier  core.Tier
	facts facts // from `helper --version` at open; every READY must agree

	mu     sync.Mutex
	warms  map[string]*helper
	fibers map[string]*fiber // fence
	exits  chan backend.Exit
}

type helper struct {
	id   string
	cmd  *exec.Cmd
	ctl  *net.UnixConn
	pmu  sync.Mutex
	pend map[string]chan reply // fence -> reply
	gone chan struct{}
}

type reply struct {
	bytes uint64
	err   error
}

type fiber struct {
	id     string
	warmID string
	w      uint64
}

// New opens the backend; the tier is FIBER_SNAPSHOT when the helper
// answers `--version` and the guest exists.
func New(o Options) backend.Backend {
	b := &Backend{opt: o, warms: map[string]*helper{}, fibers: map[string]*fiber{}, exits: make(chan backend.Exit, 1024)}
	f, err := probeFacts(o.Helper)
	if err != nil {
		log.Printf("hyperlight: helper %q unusable: %v", o.Helper, err)
		return b
	}
	if o.Guest != "" {
		if _, err := os.Stat(o.Guest); err != nil {
			log.Printf("hyperlight: guest %q unusable: %v", o.Guest, err)
			return b
		}
	}
	b.facts = f
	b.tier = core.TierSnapshot
	return b
}

// probeFacts runs `helper --version`: the facts a snapshot made through
// this helper depends on, known before any grant is warmed because the
// host records them at open.
func probeFacts(helper string) (facts, error) {
	ctx, cancel := context.WithTimeout(context.Background(), versionTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, helper, "--version").Output()
	if err != nil {
		return facts{}, fmt.Errorf("--version: %w", err)
	}
	return parseFacts(strings.Fields(strings.SplitN(string(out), "\n", 2)[0]))
}

func (b *Backend) Name() string    { return "hyperlight" }
func (b *Backend) Tier() core.Tier { return b.tier }

// IsolatesTenants: a fiber is a micro-VM guest behind the hypervisor.
func (b *Backend) IsolatesTenants() bool { return true }

// Platform: a snapshot depends on the helper's facts, not on the host
// kernel or libc. A backend without a usable helper warms nothing, and
// says so here.
func (b *Backend) Platform() artifact.Platform {
	if b.tier < core.TierSnapshot {
		return artifact.Platform{Kernel: "hyperlight-unusable", Libc: "n/a"}
	}
	return b.facts.platform()
}

func (b *Backend) DefaultDeadlines() (time.Duration, time.Duration) {
	return createDeadline, resumeDeadline
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
	cmd := exec.Command(b.opt.Helper, args...)
	cmd.ExtraFiles = []*os.File{childF}
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.Dir = sp.WorkDir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if sp.CgroupFD >= 0 {
		cmd.SysProcAttr.UseCgroupFD = true
		cmd.SysProcAttr.CgroupFD = sp.CgroupFD
	}
	err = cmd.Start()
	// The helper holds its own copy of its end now. Ours goes, so a
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
		end(cmd)
		return backend.Warm{}, err
	}
	uc, _ := conn.(*net.UnixConn)
	h := &helper{id: sp.GrantUID, cmd: cmd, ctl: uc, pend: map[string]chan reply{}, gone: make(chan struct{})}

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
		// The facts recorded at open are what this warm's snapshots
		// are filed under: a helper replaced since then must not warm.
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
			end(cmd)
			_ = uc.Close()
			return backend.Warm{}, fmt.Errorf("hyperlight: helper for %s did not become ready: %w", sp.GrantUID, err)
		}
	case <-ctx.Done():
		end(cmd)
		_ = uc.Close()
		return backend.Warm{}, ctx.Err()
	}
	b.mu.Lock()
	b.warms[h.id] = h
	b.mu.Unlock()
	go b.read(h, rd)
	go func() { _ = cmd.Wait() }()
	return backend.Warm{ID: h.id, PID: cmd.Process.Pid}, nil
}

// end kills a helper that did not come up and reaps it, so a failed
// warm leaves no zombie behind. A helper that did come up is reaped by
// the goroutine Warm starts for it.
func end(cmd *exec.Cmd) {
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
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

func (b *Backend) helperGone(h *helper) {
	b.mu.Lock()
	if b.warms[h.id] == h {
		delete(b.warms, h.id)
	}
	var orphans []string
	for id, f := range b.fibers {
		if f.warmID == h.id {
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
	b.exits <- backend.Exit{WarmID: h.id, Status: "helper exited"}
}

// ask sends one line and waits for the helper's reply on that fence.
// Replies carry only the fence, so one command per fence may be in
// flight: a second would take the first's place in pend and leave it
// waiting for a reply that has already been delivered.
func (b *Backend) ask(ctx context.Context, h *helper, fence, line string) (reply, error) {
	ch := make(chan reply, 1)
	h.pmu.Lock()
	if _, busy := h.pend[fence]; busy {
		h.pmu.Unlock()
		return reply{}, fmt.Errorf("hyperlight: another command for %s is still in flight", fence)
	}
	h.pend[fence] = ch
	h.pmu.Unlock()
	if _, err := h.ctl.Write([]byte(line + "\n")); err != nil {
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
	h := b.warms[f.warmID]
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
		_ = h.cmd.Process.Kill()
	}
}

// Clone asks the helper for a fiber from the warm snapshot.
func (b *Backend) Clone(ctx context.Context, warmID string, sp backend.FiberSpec) (backend.Fiber, error) {
	b.mu.Lock()
	h, ok := b.warms[warmID]
	b.mu.Unlock()
	if !ok {
		return backend.Fiber{}, fmt.Errorf("hyperlight: no warm helper %q", warmID)
	}
	return b.start(ctx, h, sp.Fence, fmt.Sprintf("CLONE %s %s %d %s", sp.Fence, sp.Endpoint, deadlineMS(sp.Deadline), payloadHex(sp.Payload)), sp.Deadline)
}

func (b *Backend) start(ctx context.Context, h *helper, fence, line string, deadline time.Duration) (backend.Fiber, error) {
	if deadline > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, deadline)
		defer cancel()
	}
	f := &fiber{id: fence, warmID: h.id}
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
	if _, err = b.ask(ctx, h, fiberID, fmt.Sprintf("PARK %s %s %s", fiberID, sp.Dir, sync)); err != nil {
		// Name the deadline that fired: the caller's, or this one.
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

// Resume asks the helper for a fiber from a park directory.
func (b *Backend) Resume(ctx context.Context, sp backend.ResumeSpec) (backend.Fiber, error) {
	b.mu.Lock()
	h, ok := b.warms[sp.WarmID]
	b.mu.Unlock()
	if !ok {
		return backend.Fiber{}, fmt.Errorf("hyperlight: no warm helper %q to resume under", sp.WarmID)
	}
	return b.start(ctx, h, sp.Fence, fmt.Sprintf("RESUME %s %s %s %d", sp.Fence, sp.Dir, sp.Endpoint, deadlineMS(sp.Deadline)), sp.Deadline)
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
		_ = h.cmd.Process.Kill()
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
