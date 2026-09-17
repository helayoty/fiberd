//go:build linux

// Package proc is the fork backend: one zygote process per grant, linked
// with hack/zygote/libfiberzygote, asked to fork fibers over a socketpair
// inherited as fd 3, and checkpointed with CRIU. It is the reference
// backend and the one the conformance suite runs against.
//
// Line protocol on the control socket (zygote side in libfiberzygote.c):
//
//	zygote -> host   READY
//	host   -> zygote CLONE <fence> <endpoint> <deadline_ms> <payload-hex|-> <pidns|->   + SCM_RIGHTS cgroup fd
//	zygote -> host   CLONED <fence> <pid>  |  ERROR <fence> <text>
//	zygote -> host   EXITED <pid> exit:<n>|signal:<name>
package proc

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

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/sys/criu"
)

// Options configure the fork backend.
type Options struct {
	// CRIU names the criu binary (default "criu").
	CRIU string
	// Launcher, when set, starts the zygote some other way than a plain
	// exec: inside an OCI container (pkg/backend/runc). Fibers are still
	// forked by the zygote over the control socket, checkpointed with
	// criu and computed as deltas; the launcher supplies what criu needs
	// to dump and restore trees that live in its namespaces.
	Launcher Launcher
}

// Launcher starts the zygote for a Backend in an environment of its own.
type Launcher interface {
	// Name is the backend name this launcher gives the fork backend.
	Name() string
	// Command builds the command that starts argv as the warm instance
	// for spec with ctl as its fd 3, logging to logf. It is exec'd by the
	// backend inside spec's cgroup.
	Command(spec backend.WarmSpec, argv []string, ctl, logf *os.File) (*exec.Cmd, error)
	// PID is the zygote process itself (the container's init) once
	// Command has started, as the host sees it.
	PID(ctx context.Context, spec backend.WarmSpec, cmd *exec.Cmd) (int, error)
	// Release ends whatever Command created besides the process.
	Release(spec backend.WarmSpec)
	// Endpoint maps a host path in spec.WorkDir to where the zygote sees
	// it (the run directory is bind-mounted into its namespace).
	Endpoint(spec backend.WarmSpec, hostPath string) string
	// DumpExtra and RestoreExtra are criu arguments for a tree that
	// lives inside the launcher's namespaces.
	DumpExtra(spec backend.WarmSpec) []string
	RestoreExtra(spec backend.WarmSpec) []string
}

var ErrZygote = errors.New("proc: zygote error")

// Backend implements backend.Backend, backend.SelfCheckpointer and
// backend.DeltaCodec.
type Backend struct {
	opt  Options
	criu criu.Options
	tier core.Tier

	mu      sync.Mutex
	zygotes map[string]*zygote // warm id (grant uid)
	fibers  map[string]*fiber  // fence
	byPID   map[int]*fiber
	exits   chan backend.Exit
}

type zygote struct {
	id   string
	spec backend.WarmSpec
	cmd  *exec.Cmd
	pid  int // the zygote process as the host sees it (cmd's, or the container init's)
	ctl  *net.UnixConn
	pmu  sync.Mutex
	pend map[string]chan cloneResult // fence -> reply
	gone chan struct{}
}

type cloneResult struct {
	pid int
	err error
}

type fiber struct {
	id       string
	pid      int // as the host sees it
	zpid     int // as the zygote reported it (its own pid namespace); 0 for restored trees
	warmID   string
	restored *criu.Restored
}

// New opens the backend. It offers FIBER_CHECKPOINT when `criu check`
// passes and FIBER_WARM otherwise.
func New(o Options) backend.Backend { return NewBackend(o) }

// NewBackend is New with the concrete type, for launchers that wrap it.
func NewBackend(o Options) *Backend {
	b := &Backend{opt: o, criu: criu.Options{Bin: o.CRIU}, tier: core.TierWarm,
		zygotes: map[string]*zygote{}, fibers: map[string]*fiber{}, byPID: map[int]*fiber{},
		exits: make(chan backend.Exit, 1024)}
	if err := b.criu.Available(context.Background()); err == nil {
		b.tier = core.TierCheckpoint
	} else {
		log.Printf("%s: park/resume unavailable, offering %s: %v", b.Name(), core.TierWarm, err)
	}
	return b
}

func (b *Backend) Name() string {
	if b.opt.Launcher != nil {
		return b.opt.Launcher.Name()
	}
	return "proc"
}
func (b *Backend) Tier() core.Tier { return b.tier }

// Warm execs the zygote inside the given cgroup with the control
// socketpair as fd 3 and waits for READY.
func (b *Backend) Warm(ctx context.Context, spec backend.WarmSpec) (backend.Warm, error) {
	argv := spec.Template.Argv
	if len(argv) == 0 {
		return backend.Warm{}, errors.New("proc: empty zygote command")
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return backend.Warm{}, fmt.Errorf("proc: socketpair: %w", err)
	}
	parentF := os.NewFile(uintptr(fds[0]), "zygote-ctl")
	childF := os.NewFile(uintptr(fds[1]), "zygote-ctl-child")
	defer func() { _ = childF.Close() }()

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.ExtraFiles = []*os.File{childF} // fd 3 in the zygote
	// The zygote's stdio goes to a log file, not to our stderr: a regular
	// file is something criu can checkpoint the zygote with; a pipe to a
	// process outside the tree is not.
	if err := os.MkdirAll(spec.WorkDir, 0o755); err != nil {
		_ = parentF.Close()
		return backend.Warm{}, err
	}
	zlog, err := os.OpenFile(filepath.Join(spec.WorkDir, "zygote.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		_ = parentF.Close()
		return backend.Warm{}, err
	}
	defer func() { _ = zlog.Close() }()
	devnull, _ := os.OpenFile(os.DevNull, os.O_RDONLY, 0)
	defer func() { _ = devnull.Close() }()
	if b.opt.Launcher != nil {
		// The launcher builds the command (a container with the zygote
		// as init, fd 3 preserved); the rest is the same.
		cmd, err = b.opt.Launcher.Command(spec, argv, childF, zlog)
		if err != nil {
			_ = parentF.Close()
			return backend.Warm{}, err
		}
	} else {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, zlog, zlog
		cmd.Env = []string{"PATH=/usr/bin:/bin"} // nothing grant-specific: identical pages on every home
		// The zygote's (and so every fiber's) working directory is its own run
		// directory, never the agent's: criu's parasite creates scratch
		// entries in the dumped task's cwd.
		cmd.Dir = spec.WorkDir
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid: true, // a session leader, as criu requires to checkpoint it
		}
	}
	if spec.CgroupFD >= 0 && b.opt.Launcher == nil {
		// A launcher places the zygote in the cgroup itself (runc: the
		// container's cgroupsPath); starting runc there too would leave
		// a foreign process in a cgroup runc wants to own.
		cmd.SysProcAttr.UseCgroupFD = true
		cmd.SysProcAttr.CgroupFD = spec.CgroupFD
	}
	if err := cmd.Start(); err != nil {
		_ = parentF.Close()
		return backend.Warm{}, fmt.Errorf("%s: start zygote %v: %w", b.Name(), argv, err)
	}
	conn, err := net.FileConn(parentF)
	_ = parentF.Close()
	if err != nil {
		_ = cmd.Process.Kill()
		return backend.Warm{}, err
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		_ = cmd.Process.Kill()
		return backend.Warm{}, errors.New("proc: control socket is not unix")
	}
	z := &zygote{id: spec.GrantUID, spec: spec, cmd: cmd, pid: cmd.Process.Pid, ctl: uc, pend: map[string]chan cloneResult{}, gone: make(chan struct{})}

	ready := make(chan error, 1)
	rd := bufio.NewReaderSize(uc, 64<<10)
	go func() {
		line, err := rd.ReadString('\n')
		if err != nil {
			ready <- err
			return
		}
		if strings.TrimSpace(line) != "READY" {
			ready <- fmt.Errorf("%w: expected READY, got %q", ErrZygote, strings.TrimSpace(line))
			return
		}
		ready <- nil
	}()
	select {
	case err := <-ready:
		if err != nil {
			_ = cmd.Process.Kill()
			_ = uc.Close()
			b.release(z)
			return backend.Warm{}, fmt.Errorf("%s: zygote for %s did not become ready: %w", b.Name(), spec.GrantUID, err)
		}
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		_ = uc.Close()
		b.release(z)
		return backend.Warm{}, ctx.Err()
	}
	if b.opt.Launcher != nil {
		pid, err := b.opt.Launcher.PID(ctx, spec, cmd)
		if err != nil {
			_ = cmd.Process.Kill()
			_ = uc.Close()
			b.release(z)
			return backend.Warm{}, err
		}
		z.pid = pid
	}
	b.mu.Lock()
	b.zygotes[z.id] = z
	b.mu.Unlock()
	go b.read(z, rd)
	go func() { _ = cmd.Wait() }()
	return backend.Warm{ID: z.id, PID: z.pid}, nil
}

func (b *Backend) release(z *zygote) {
	if b.opt.Launcher != nil {
		b.opt.Launcher.Release(z.spec)
	}
}

// hostPID finds, among the processes in the fiber's leaf cgroup, the one
// the zygote reported as pid in its own pid namespace: the fiber's root
// as the host sees it. Without a launcher the two are the same.
func (b *Backend) hostPID(cgroupFD int, reported int) int {
	if b.opt.Launcher == nil || cgroupFD < 0 {
		return reported
	}
	procs, err := os.ReadFile(fmt.Sprintf("/proc/self/fd/%d/cgroup.procs", cgroupFD))
	if err != nil {
		return reported
	}
	for _, p := range strings.Fields(string(procs)) {
		status, err := os.ReadFile("/proc/" + p + "/status")
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(status), "\n") {
			if !strings.HasPrefix(line, "NSpid:") {
				continue
			}
			ids := strings.Fields(line)[1:]
			// The zygote's view is the second column (its pid namespace
			// is one below the host's); a fiber in its own namespace adds
			// a third.
			if len(ids) >= 2 && ids[1] == strconv.Itoa(reported) {
				n, _ := strconv.Atoi(p)
				return n
			}
		}
	}
	return reported
}

// CheckpointWarm implements backend.SelfCheckpointer: dump the zygote's
// pages while it keeps running, treating the control socket as external.
func (b *Backend) CheckpointWarm(ctx context.Context, warmID, dir string) error {
	b.mu.Lock()
	z, ok := b.zygotes[warmID]
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("proc: no warm instance %q", warmID)
	}
	var extra []string
	if ino, err := criu.SocketInode(z.pid, 3); err == nil {
		extra = []string{"--external", "unix[" + ino + "]"}
	}
	if b.opt.Launcher != nil {
		extra = append(extra, b.opt.Launcher.DumpExtra(z.spec)...)
	}
	return b.criu.DumpWith(ctx, z.pid, dir, true, extra)
}

func (b *Backend) Unwarm(id string) {
	b.mu.Lock()
	z, ok := b.zygotes[id]
	if ok {
		delete(b.zygotes, id)
	}
	b.mu.Unlock()
	if ok {
		_ = z.ctl.Close()
		_ = z.cmd.Process.Kill()
		b.release(z)
	}
}

// read drains the zygote's control channel: clone replies and exits.
func (b *Backend) read(z *zygote, rd *bufio.Reader) {
	defer close(z.gone)
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			b.zygoteGone(z)
			return
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "CLONED":
			if len(fields) >= 3 {
				pid, _ := strconv.Atoi(fields[2])
				z.reply(fields[1], cloneResult{pid: pid})
			}
		case "ERROR":
			if len(fields) >= 2 {
				z.reply(fields[1], cloneResult{err: fmt.Errorf("%w: %s", ErrZygote, strings.Join(fields[2:], " "))})
			}
		case "EXITED":
			if len(fields) >= 3 {
				pid, _ := strconv.Atoi(fields[1])
				b.exited(pid, fields[2])
			}
		}
	}
}

func (z *zygote) reply(fence string, res cloneResult) {
	z.pmu.Lock()
	ch, ok := z.pend[fence]
	delete(z.pend, fence)
	z.pmu.Unlock()
	if ok {
		ch <- res
	}
}

func (b *Backend) zygoteGone(z *zygote) {
	b.mu.Lock()
	if b.zygotes[z.id] == z {
		delete(b.zygotes, z.id)
	}
	b.mu.Unlock()
	z.pmu.Lock()
	for fence, ch := range z.pend {
		ch <- cloneResult{err: fmt.Errorf("%w: zygote exited", ErrZygote)}
		delete(z.pend, fence)
	}
	z.pmu.Unlock()
	b.release(z)
	b.exits <- backend.Exit{WarmID: z.id, Status: "zygote exited"}
}

// exited handles an EXITED line: the pid is the zygote's view.
func (b *Backend) exited(zpid int, status string) {
	b.mu.Lock()
	f := b.byPID[zpid]
	b.mu.Unlock()
	if f != nil {
		b.finish(f, status)
	}
}

// finish forgets a fiber and reports its end.
func (b *Backend) finish(f *fiber, status string) {
	b.mu.Lock()
	if b.fibers[f.id] != f {
		b.mu.Unlock()
		return
	}
	delete(b.fibers, f.id)
	if f.zpid != 0 {
		delete(b.byPID, f.zpid)
	}
	b.mu.Unlock()
	b.exits <- backend.Exit{FiberID: f.id, Status: status}
}

// Clone sends CLONE with the leaf cgroup fd and waits for CLONED.
func (b *Backend) Clone(ctx context.Context, warmID string, spec backend.FiberSpec) (backend.Fiber, error) {
	b.mu.Lock()
	z, ok := b.zygotes[warmID]
	b.mu.Unlock()
	if !ok {
		return backend.Fiber{}, fmt.Errorf("proc: no warm instance %q", warmID)
	}
	deadline := spec.Deadline.Milliseconds()
	if deadline <= 0 {
		deadline = 50
	}
	payload := "-"
	if len(spec.Payload) > 0 {
		payload = hex.EncodeToString(spec.Payload)
	}
	opt := "-"
	if spec.OwnPIDNS {
		opt = "pidns"
	}
	endpoint := spec.Endpoint
	if b.opt.Launcher != nil {
		endpoint = b.opt.Launcher.Endpoint(z.spec, endpoint)
	}
	msg := fmt.Sprintf("CLONE %s %s %d %s %s\n", spec.Fence, endpoint, deadline, payload, opt)
	reply := make(chan cloneResult, 1)
	z.pmu.Lock()
	z.pend[spec.Fence] = reply
	z.pmu.Unlock()
	var rights []byte
	if spec.CgroupFD >= 0 {
		rights = syscall.UnixRights(spec.CgroupFD)
	}
	if _, _, err := z.ctl.WriteMsgUnix([]byte(msg), rights, nil); err != nil {
		z.reply(spec.Fence, cloneResult{})
		return backend.Fiber{}, fmt.Errorf("proc: send CLONE: %w", err)
	}
	select {
	case res := <-reply:
		if res.err != nil {
			return backend.Fiber{}, res.err
		}
		f := &fiber{id: spec.Fence, pid: b.hostPID(spec.CgroupFD, res.pid), zpid: res.pid, warmID: warmID}
		b.mu.Lock()
		b.fibers[f.id] = f
		b.byPID[f.zpid] = f
		b.mu.Unlock()
		return backend.Fiber{ID: f.id, PID: f.pid}, nil
	case <-ctx.Done():
		// The zygote enforces the same deadline and kills the child; a
		// late reply is dropped by the pending map.
		z.reply(spec.Fence, cloneResult{})
		return backend.Fiber{}, ctx.Err()
	case <-z.gone:
		return backend.Fiber{}, fmt.Errorf("%w: zygote exited", ErrZygote)
	}
}

// Park dumps the fiber's tree with criu. With Sync the tree keeps running
// (--leave-running); the host ends it once the images are durable.
func (b *Backend) Park(ctx context.Context, fiberID string, spec backend.ParkSpec) error {
	if b.tier < core.TierCheckpoint {
		return fmt.Errorf("proc: park needs %s (criu unavailable)", core.TierCheckpoint)
	}
	b.mu.Lock()
	f, ok := b.fibers[fiberID]
	z := b.zygotes[f.warmID]
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("proc: unknown fiber %q", fiberID)
	}
	var extra []string
	if b.opt.Launcher != nil && z != nil {
		extra = b.opt.Launcher.DumpExtra(z.spec)
	}
	return b.criu.DumpWith(ctx, f.pid, spec.Dir, spec.Sync, extra)
}

// Resume restores a checkpoint into the given cgroup; criu stays as the
// tree's parent and its exit is reported as the fiber's.
func (b *Backend) Resume(ctx context.Context, spec backend.ResumeSpec) (backend.Fiber, error) {
	if b.tier < core.TierCheckpoint {
		return backend.Fiber{}, fmt.Errorf("proc: resume needs %s (criu unavailable)", core.TierCheckpoint)
	}
	rctx := ctx
	if spec.Deadline > 0 {
		var cancel context.CancelFunc
		rctx, cancel = context.WithTimeout(ctx, spec.Deadline)
		defer cancel()
	}
	var extra []string
	if b.opt.Launcher != nil {
		// The tree was dumped inside a container of this grant; it is
		// restored with that container's root and mounts.
		extra = b.opt.Launcher.RestoreExtra(backend.WarmSpec{GrantUID: spec.WarmID, WorkDir: filepath.Dir(spec.Endpoint)})
	}
	res, err := b.criu.RestoreWith(rctx, spec.Dir, spec.CgroupFD, extra)
	if err != nil {
		return backend.Fiber{}, err
	}
	f := &fiber{id: spec.Fence, pid: res.PID, restored: res, warmID: spec.WarmID}
	b.mu.Lock()
	b.fibers[f.id] = f
	b.mu.Unlock()
	go func() {
		err := res.Wait()
		status := "exit:0"
		if err != nil {
			status = "exit:" + err.Error()
		}
		b.finish(f, status)
	}()
	return backend.Fiber{ID: f.id, PID: f.pid}, nil
}

// Kill ends the fiber's root process; the exit is reported like any other.
func (b *Backend) Kill(fiberID string) error {
	b.mu.Lock()
	f, ok := b.fibers[fiberID]
	b.mu.Unlock()
	if !ok {
		return nil
	}
	return syscall.Kill(f.pid, syscall.SIGKILL)
}

func (b *Backend) Exits() <-chan backend.Exit { return b.exits }

// Close kills every zygote (and with them every fiber).
func (b *Backend) Close() {
	b.mu.Lock()
	zs := make([]*zygote, 0, len(b.zygotes))
	for _, z := range b.zygotes {
		zs = append(zs, z)
	}
	b.mu.Unlock()
	for _, z := range zs {
		_ = z.ctl.Close()
		_ = z.cmd.Process.Kill()
	}
}

// DeltaCodec over CRIU images (pkg/sys/criu).

func (b *Backend) ImageBytes(dir string) (uint64, error) { return criu.ImageBytes(dir) }
func (b *Backend) LoadParent(dir string) (backend.Parent, error) {
	p, err := criu.LoadParent(dir)
	if err != nil {
		return nil, err
	}
	return p, nil
}
func (b *Backend) Compute(dir string, parent backend.Parent) (backend.DeltaInfo, error) {
	p, ok := parent.(*criu.Parent)
	if !ok {
		return backend.DeltaInfo{}, errors.New("proc: parent is not a criu checkpoint")
	}
	info, err := criu.ComputeDelta(dir, p)
	if err != nil {
		return backend.DeltaInfo{}, err
	}
	return backend.DeltaInfo{ParentSHA256: info.ParentSHA256, Bytes: info.DeltaBytes()}, nil
}
func (b *Backend) HasDelta(dir string) bool { return criu.HasDelta(dir) }
func (b *Backend) ReadDeltaInfo(dir string) (backend.DeltaInfo, error) {
	info, err := criu.ReadDeltaInfo(dir)
	if err != nil {
		return backend.DeltaInfo{}, err
	}
	return backend.DeltaInfo{ParentSHA256: info.ParentSHA256, Bytes: info.DeltaBytes()}, nil
}
func (b *Backend) Merge(dir string, parent backend.Parent) error {
	p, ok := parent.(*criu.Parent)
	if !ok {
		return errors.New("proc: parent is not a criu checkpoint")
	}
	return criu.MergeDelta(dir, p)
}

var (
	_ backend.Backend          = (*Backend)(nil)
	_ backend.SelfCheckpointer = (*Backend)(nil)
	_ backend.DeltaCodec       = (*Backend)(nil)
)
