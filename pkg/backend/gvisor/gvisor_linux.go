//go:build linux

// Package gvisor is the gVisor backend: every fiber is its own runsc
// sandbox, restored from a checkpoint of the warm template sandbox, so a
// fiber has a sandbox kernel between it and the host and the tier is
// FIBER_SNAPSHOT. It needs no KVM (the systrap platform), which is why it
// is the first snapshot backend.
//
// How it maps onto the seam (see hack/dev/gvisor-check.sh for the probes
// these choices rest on):
//
//   - Warm: `runsc run` the template rootfs with the workload as init. The
//     workload initialises, drops a ready marker on the bind-mounted run
//     directory and blocks reading /proc/gvisor/checkpoint; the backend
//     then takes the template image with `runsc checkpoint
//     --leave-running`. That blocking read is gVisor's sync point: it is
//     where every restored sandbox resumes, and it answers "restore"
//     there (and "resume" in the original).
//   - Clone: `runsc restore` the template image into a new sandbox whose
//     spec carries the fence, endpoint and payload as environment; the
//     workload reads them from /proc/gvisor/spec_environ and serves a unix
//     socket on the bind mount, which the host connects to as readiness.
//   - Park: SIGUSR1 makes the workload close its endpoint (a listening
//     host socket cannot be checkpointed), then `runsc checkpoint`, which
//     ends the sandbox; the images are written with O_DIRECT so they are
//     not charged to the fiber's leaf.
//   - Resume: `runsc restore` the park image under a new fence and
//     endpoint; the workload's blocking read returns "restore" and it
//     re-binds.
//
// No delta codec: a park is gVisor's full state file (the memory image is
// sparse and can skip committed zero pages). Every sandbox pays for the
// template's pages itself, since nothing is shared copy-on-write between
// sandboxes; that footprint is reported as the fiber overhead so the W
// budget still means the working set the fiber dirtied.
package gvisor

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
)

// Options configure the gVisor backend.
type Options struct {
	// Runsc names the runsc binary (default "runsc").
	Runsc string
	// Rootfs is the directory every sandbox uses as its root filesystem;
	// template commands are paths inside it. Required.
	Rootfs string
	// StateDir holds runsc's container state and the template images
	// (default /var/lib/fiberd/gvisor). Not a tmpfs: images are memory
	// otherwise.
	StateDir string
	// Platform is the runsc platform (default "systrap": no KVM needed).
	Platform string
	// OverheadBytes is the fixed footprint of one restored sandbox: the
	// sentry plus the template's pages. Added to every fiber's
	// memory.max, subtracted from its measured W. 0 (the default) lets
	// the host measure it as the warm template sandbox's resident size.
	OverheadBytes uint64
	// NoDirectIO writes park images through the page cache instead of
	// O_DIRECT (for filesystems without O_DIRECT support).
	NoDirectIO bool
	// Debug writes runsc debug logs under StateDir/log.
	Debug bool
}

const (
	createDeadline = 500 * time.Millisecond
	resumeDeadline = 2 * time.Second
	readyMarker    = "warm.ready"
)

// Backend implements backend.Backend, Platformer, DeadlineAdvisor and
// Overheader.
type Backend struct {
	opt     Options
	version string
	tier    core.Tier

	mu    sync.Mutex
	warms map[string]*warm // warm id
	boxes map[string]*box  // fiber id
	exits chan backend.Exit
}

type warm struct {
	id      string
	cid     string // runsc container id
	argv    []string
	workDir string
	images  string // template checkpoint
}

type box struct {
	id       string
	cid      string
	bundle   string
	endpoint string
	done     chan struct{} // closed when the sandbox has exited
}

// New opens the backend; the tier is FIBER_SNAPSHOT when runsc answers
// and the rootfs exists, else the backend refuses to warm anything.
func New(o Options) backend.Backend {
	if o.Runsc == "" {
		o.Runsc = "runsc"
	}
	if o.StateDir == "" {
		o.StateDir = "/var/lib/fiberd/gvisor"
	}
	if o.Platform == "" {
		o.Platform = "systrap"
	}
	b := &Backend{opt: o, warms: map[string]*warm{}, boxes: map[string]*box{}, exits: make(chan backend.Exit, 1024)}
	out, err := exec.Command(o.Runsc, "--version").Output()
	if err != nil {
		log.Printf("gvisor: %s unavailable: %v", o.Runsc, err)
		return b
	}
	b.version = strings.TrimSpace(strings.TrimPrefix(strings.SplitN(string(out), "\n", 2)[0], "runsc version "))
	if st, err := os.Stat(o.Rootfs); err != nil || !st.IsDir() {
		log.Printf("gvisor: rootfs %q unusable: %v", o.Rootfs, err)
		return b
	}
	b.tier = core.TierSnapshot
	return b
}

func (b *Backend) Name() string    { return "gvisor" }
func (b *Backend) Tier() core.Tier { return b.tier }

// Platform: a gVisor image depends on the runsc release and the rootfs,
// not on the host kernel or libc.
func (b *Backend) Platform() artifact.Platform {
	return artifact.Platform{Kernel: "gvisor-" + b.version, Libc: "rootfs-" + filepath.Base(b.opt.Rootfs)}
}

func (b *Backend) DefaultDeadlines() (time.Duration, time.Duration) {
	return createDeadline, resumeDeadline
}
func (b *Backend) FiberOverheadBytes() uint64 { return b.opt.OverheadBytes }

// EndpointSchemes: unix only. A TCP listener inside a sandbox is a host
// socket (not checkpointable) unless the sandbox runs netstack in a
// network namespace of its own, which this backend does not set up.
func (b *Backend) EndpointSchemes() []string { return []string{"unix"} }

// WCounter: the guest's memory is the sentry's memfd, which the leaf
// accounts as shmem; the sentry's own Go heap (anon, tens of MiB and
// different in every sandbox) is not the fiber's working set.
func (b *Backend) WCounter() string { return "shmem" }

func (b *Backend) globalArgs() []string {
	args := []string{"--root=" + filepath.Join(b.opt.StateDir, "root"), "--platform=" + b.opt.Platform,
		"--network=none", "--ignore-cgroups", "--host-uds=all", "--overlay2=none"}
	if b.opt.Debug {
		args = append(args, "--debug", "--debug-log="+filepath.Join(b.opt.StateDir, "log")+"/", "--log-format=text")
	}
	return args
}

// runsc runs one runsc command. cgroupFD >= 0 starts it (and so the
// sandbox and gofer it leaves behind with --detach) inside that cgroup.
// A detached command's output goes to a file, never a pipe: the sandbox
// it leaves behind inherits the descriptors and a pipe would never close.
func (b *Backend) runsc(ctx context.Context, cgroupFD int, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, b.opt.Runsc, append(b.globalArgs(), args...)...)
	if cgroupFD >= 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: cgroupFD}
	}
	detached := false
	for _, a := range args {
		if a == "--detach" {
			detached = true
		}
	}
	var out []byte
	var err error
	if detached {
		var f *os.File
		f, err = os.CreateTemp(b.opt.StateDir, "runsc-*.out")
		if err != nil {
			return "", err
		}
		// The sandbox's own stdio follows: the file stays under Debug so a
		// workload's stderr can be read after the fact.
		defer func() {
			_ = f.Close()
			if !b.opt.Debug {
				_ = os.Remove(f.Name())
			}
		}()
		cmd.Stdout, cmd.Stderr = f, f
		err = cmd.Run()
		out, _ = os.ReadFile(f.Name())
	} else {
		out, err = cmd.CombinedOutput()
	}
	if err != nil {
		if ctx.Err() != nil {
			// The context ended and CommandContext killed runsc itself:
			// the deadline is the reason, and the caller must see it as
			// one ("signal: killed" is not a miss the agent can name).
			return string(out), fmt.Errorf("gvisor: runsc %s: %w", args[0], ctx.Err())
		}
		tail := strings.TrimSpace(string(out))
		if len(tail) > 400 {
			tail = "..." + tail[len(tail)-400:]
		}
		return string(out), fmt.Errorf("gvisor: runsc %s: %w: %s", args[0], err, tail)
	}
	return string(out), nil
}

// spec is the OCI config.json a sandbox is created or restored with.
type spec struct {
	OCIVersion string `json:"ociVersion"`
	Process    struct {
		Terminal bool `json:"terminal"`
		User     struct {
			UID int `json:"uid"`
			GID int `json:"gid"`
		} `json:"user"`
		Cwd  string   `json:"cwd"`
		Args []string `json:"args"`
		Env  []string `json:"env"`
	} `json:"process"`
	Root struct {
		Path     string `json:"path"`
		Readonly bool   `json:"readonly"`
	} `json:"root"`
	Hostname string `json:"hostname"`
	Mounts   []struct {
		Destination string   `json:"destination"`
		Type        string   `json:"type"`
		Source      string   `json:"source"`
		Options     []string `json:"options,omitempty"`
	} `json:"mounts"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Linux       struct {
		Namespaces []struct {
			Type string `json:"type"`
		} `json:"namespaces"`
	} `json:"linux"`
}

// writeBundle creates <dir>/config.json. workDir is bind-mounted at
// /host; images, when set, turns on the workload-triggered checkpoint.
func (b *Backend) writeBundle(dir string, argv, env []string, workDir, images string) error {
	var s spec
	s.OCIVersion = "1.0.2"
	s.Process.Cwd = "/"
	s.Process.Args = argv
	s.Process.Env = append([]string{"PATH=/bin:/usr/bin"}, env...)
	s.Root.Path = b.opt.Rootfs
	s.Hostname = "fiber"
	add := func(dst, typ, src string, opts ...string) {
		m := struct {
			Destination string   `json:"destination"`
			Type        string   `json:"type"`
			Source      string   `json:"source"`
			Options     []string `json:"options,omitempty"`
		}{dst, typ, src, opts}
		s.Mounts = append(s.Mounts, m)
	}
	add("/proc", "proc", "proc")
	add("/dev", "tmpfs", "tmpfs")
	add("/tmp", "tmpfs", "tmpfs")
	add("/host", "bind", workDir, "rbind", "rw")
	if images != "" {
		s.Annotations = map[string]string{
			"dev.gvisor.internal.checkpoint.path":   images,
			"dev.gvisor.internal.checkpoint.enable": "true",
			"dev.gvisor.internal.checkpoint.resume": "true",
		}
	}
	for _, ns := range []string{"pid", "mount", "ipc", "uts"} {
		s.Linux.Namespaces = append(s.Linux.Namespaces, struct {
			Type string `json:"type"`
		}{ns})
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "config.json"), data, 0o644)
}

func cid(s string) string {
	return strings.NewReplacer("/", "-", ":", "-", " ", "-").Replace(s)
}

// pidOf reads the sandbox process pid from `runsc state`.
func (b *Backend) pidOf(ctx context.Context, cid string) int {
	out, err := b.runsc(ctx, -1, "state", cid)
	if err != nil {
		return 0
	}
	var st struct {
		PID int `json:"pid"`
	}
	_ = json.Unmarshal([]byte(out), &st)
	return st.PID
}

// waitFile polls for path to exist (or, with gone, to be absent).
func waitFile(ctx context.Context, path string, gone bool) error {
	for {
		_, err := os.Stat(path)
		if (err == nil) != gone {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// waitEndpoint polls until the fiber's socket accepts a connection, the
// sandbox exits, or the context ends.
func waitEndpoint(ctx context.Context, ep string, done <-chan struct{}) error {
	for {
		if c, err := net.DialTimeout("unix", ep, 50*time.Millisecond); err == nil {
			_ = c.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			return errors.New("sandbox exited before serving")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// Warm runs the template sandbox and waits for its self-checkpoint.
func (b *Backend) Warm(ctx context.Context, sp backend.WarmSpec) (backend.Warm, error) {
	if b.tier < core.TierSnapshot {
		return backend.Warm{}, errors.New("gvisor: runsc or rootfs unavailable")
	}
	if len(sp.Template.Argv) == 0 {
		return backend.Warm{}, errors.New("gvisor: empty template command")
	}
	if err := os.MkdirAll(sp.WorkDir, 0o755); err != nil {
		return backend.Warm{}, err
	}
	tdir := filepath.Join(b.opt.StateDir, "templates", cid(sp.GrantUID))
	w := &warm{id: sp.GrantUID, cid: "w-" + cid(sp.GrantUID), argv: sp.Template.Argv, workDir: sp.WorkDir,
		images: filepath.Join(tdir, "images")}
	_ = os.RemoveAll(tdir)
	if err := os.MkdirAll(tdir, 0o755); err != nil {
		return backend.Warm{}, err
	}
	// Restore validates that mounts match the checkpoint's, so the warm
	// sandbox and every fiber share the grant's run directory as /host.
	marker := filepath.Join(sp.WorkDir, readyMarker)
	_ = os.Remove(marker)
	bundle := filepath.Join(tdir, "bundle")
	if err := b.writeBundle(bundle, w.argv, []string{"FIBERD_FENCE=none"}, sp.WorkDir, ""); err != nil {
		return backend.Warm{}, err
	}
	_, _ = b.runsc(ctx, -1, "delete", "-force", w.cid) // a stale one from a previous life
	if _, err := b.runsc(ctx, sp.CgroupFD, "run", "--detach", "--bundle", bundle, w.cid); err != nil {
		return backend.Warm{}, err
	}
	// The workload drops the marker once its init is done and blocks in
	// its read of /proc/gvisor/checkpoint; the template image is taken
	// there, from outside, and the original keeps running.
	if err := waitFile(ctx, marker, false); err != nil {
		_, _ = b.runsc(context.Background(), -1, "delete", "-force", w.cid)
		return backend.Warm{}, fmt.Errorf("gvisor: template did not become ready: %w", err)
	}
	time.Sleep(20 * time.Millisecond) // let it reach the read after dropping the marker
	args := []string{"checkpoint", "--leave-running", "--image-path", w.images}
	if !b.opt.NoDirectIO {
		args = append(args, "--direct")
	}
	if _, err := b.runsc(ctx, -1, append(args, w.cid)...); err != nil {
		_, _ = b.runsc(context.Background(), -1, "delete", "-force", w.cid)
		return backend.Warm{}, fmt.Errorf("gvisor: template checkpoint: %w", err)
	}
	// The footprint of a sandbox restored from this image, measured by
	// restoring one into the empty probe cgroup the host offers: a fresh
	// sandbox (its own sentry, gofer and page tables) costs more than the
	// original restored in place, and only a fiber-like restore in a
	// cgroup of its own reads true.
	bytes, total := b.probeFootprint(ctx, w, sp.ProbeCgroupFD)
	b.mu.Lock()
	b.warms[w.id] = w
	b.mu.Unlock()
	go b.waitWarm(w)
	return backend.Warm{ID: w.id, PID: b.pidOf(ctx, w.cid), Bytes: bytes, TotalBytes: total}, nil
}

// probeFootprint restores the template image once into the given empty
// cgroup exactly as a fiber would be, reads the cgroup (its shmem, the
// guest memory, and its memory.current), and ends it. 0 when it cannot
// tell.
func (b *Backend) probeFootprint(ctx context.Context, w *warm, cgroupFD int) (shmem, total uint64) {
	if cgroupFD < 0 {
		return 0, 0
	}
	cid := w.cid + "-probe"
	bundle := filepath.Join(filepath.Dir(w.images), "probe-bundle")
	ep := filepath.Join(w.workDir, "probe.sock")
	if err := b.writeBundle(bundle, w.argv, []string{"FIBERD_FENCE=probe", "FIBERD_ENDPOINT=/host/probe.sock"}, w.workDir, ""); err != nil {
		return 0, 0
	}
	_ = os.Remove(ep)
	args := []string{"restore", "--detach", "--image-path", w.images, "--bundle", bundle}
	if !b.opt.NoDirectIO {
		args = append(args, "--direct")
	}
	if _, err := b.runsc(ctx, cgroupFD, append(args, cid)...); err != nil {
		log.Printf("gvisor: footprint probe: %v", err)
	} else {
		// Serving is the state a fiber is measured in.
		wctx, cancel := context.WithTimeout(ctx, resumeDeadline)
		if err := waitEndpoint(wctx, ep, nil); err != nil {
			log.Printf("gvisor: footprint probe did not serve: %v", err)
		} else {
			// The image is read as the guest touches it, so a sandbox
			// grows for a while after it first serves; take the larger
			// of a reading at readiness and one after it has settled.
			shmem, total = cgroupStat(cgroupFD, "shmem"), cgroupCurrent(cgroupFD)
			time.Sleep(200 * time.Millisecond)
			shmem, total = max(shmem, cgroupStat(cgroupFD, "shmem")), max(total, cgroupCurrent(cgroupFD))
		}
		cancel()
	}
	_, _ = b.runsc(context.Background(), -1, "kill", cid, "KILL")
	_, _ = b.runsc(context.Background(), -1, "wait", cid)
	_, _ = b.runsc(context.Background(), -1, "delete", "-force", cid)
	_ = os.RemoveAll(bundle)
	_ = os.Remove(ep)
	return shmem, total
}

// leafDiag describes the fiber's leaf after a failed start: whether the
// kernel killed it (memory.events oom_kill), how high it got
// (memory.peak) and what the guest memory counted (shmem), so a birth
// killed on one host can be understood from another.
func leafDiag(fd int) string {
	if fd < 0 {
		return "no leaf"
	}
	oom := "?"
	if data, err := os.ReadFile(fmt.Sprintf("/proc/self/fd/%d/memory.events", fd)); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "oom_kill ") {
				oom = strings.TrimPrefix(line, "oom_kill ")
			}
		}
	}
	peak, max := "?", "?"
	if data, err := os.ReadFile(fmt.Sprintf("/proc/self/fd/%d/memory.peak", fd)); err == nil {
		peak = strings.TrimSpace(string(data))
	}
	if data, err := os.ReadFile(fmt.Sprintf("/proc/self/fd/%d/memory.max", fd)); err == nil {
		max = strings.TrimSpace(string(data))
	}
	return fmt.Sprintf("leaf: oom_kill=%s peak=%s max=%s shmem=%d current=%d", oom, peak, max, cgroupStat(fd, "shmem"), cgroupCurrent(fd))
}

// cgroupStat reads one memory.stat counter through an open cgroup
// directory fd.
func cgroupStat(fd int, key string) uint64 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/self/fd/%d/memory.stat", fd))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, key+" ") {
			var n uint64
			_, _ = fmt.Sscan(strings.TrimPrefix(line, key+" "), &n)
			return n
		}
	}
	return 0
}

// cgroupCurrent reads memory.current through an open cgroup directory fd.
func cgroupCurrent(fd int) uint64 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/self/fd/%d/memory.current", fd))
	if err != nil {
		return 0
	}
	var n uint64
	_, _ = fmt.Sscan(string(data), &n)
	return n
}

func (b *Backend) waitWarm(w *warm) {
	_, _ = b.runsc(context.Background(), -1, "wait", w.cid)
	_, _ = b.runsc(context.Background(), -1, "delete", "-force", w.cid)
	b.mu.Lock()
	gone := b.warms[w.id] == w
	if gone {
		delete(b.warms, w.id)
	}
	b.mu.Unlock()
	if gone {
		b.exits <- backend.Exit{WarmID: w.id, Status: "template sandbox exited"}
	}
}

func (b *Backend) Unwarm(id string) {
	b.mu.Lock()
	w, ok := b.warms[id]
	if ok {
		delete(b.warms, id)
	}
	b.mu.Unlock()
	if ok {
		_, _ = b.runsc(context.Background(), -1, "kill", w.cid, "KILL")
	}
}

// start restores an image as a new sandbox and waits for its endpoint,
// under the deadline when one is given.
func (b *Backend) start(ctx context.Context, images, workDir string, argv []string, fence, endpoint string, payload []byte, cgroupFD int, deadline time.Duration) (backend.Fiber, error) {
	if deadline > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, deadline)
		defer cancel()
	}
	if !strings.HasPrefix(endpoint, workDir+"/") {
		return backend.Fiber{}, fmt.Errorf("gvisor: endpoint %s is outside the grant's run directory %s", endpoint, workDir)
	}
	env := []string{"FIBERD_FENCE=" + fence, "FIBERD_ENDPOINT=/host/" + strings.TrimPrefix(endpoint, workDir+"/")}
	if len(payload) > 0 {
		env = append(env, "FIBERD_PAYLOAD="+hex.EncodeToString(payload))
	}
	x := &box{id: fence, cid: "f-" + cid(fence), bundle: filepath.Join(workDir, "bundles", cid(fence)), endpoint: endpoint, done: make(chan struct{})}
	if err := b.writeBundle(x.bundle, argv, env, workDir, ""); err != nil {
		return backend.Fiber{}, err
	}
	_ = os.Remove(endpoint)
	_, _ = b.runsc(ctx, -1, "delete", "-force", x.cid)
	args := []string{"restore", "--detach", "--image-path", images, "--bundle", x.bundle}
	if !b.opt.NoDirectIO {
		args = append(args, "--direct") // the image is read, not cached, in the fiber's leaf
	}
	if _, err := b.runsc(ctx, cgroupFD, append(args, x.cid)...); err != nil {
		return backend.Fiber{}, fmt.Errorf("%w (%s)", err, leafDiag(cgroupFD))
	}
	b.mu.Lock()
	b.boxes[x.id] = x
	b.mu.Unlock()
	go b.waitBox(x)
	if err := waitEndpoint(ctx, endpoint, x.done); err != nil {
		_, _ = b.runsc(context.Background(), -1, "kill", x.cid, "KILL")
		return backend.Fiber{}, fmt.Errorf("gvisor: %s did not serve: %w (%s)", fence, err, leafDiag(cgroupFD))
	}
	return backend.Fiber{ID: x.id, PID: b.pidOf(context.Background(), x.cid)}, nil
}

func (b *Backend) waitBox(x *box) {
	out, _ := b.runsc(context.Background(), -1, "wait", x.cid)
	_, _ = b.runsc(context.Background(), -1, "delete", "-force", x.cid)
	_ = os.RemoveAll(x.bundle)
	var st struct {
		ExitStatus int `json:"exitStatus"`
	}
	status := "exit:?"
	if json.Unmarshal([]byte(out), &st) == nil {
		status = fmt.Sprintf("exit:%d", st.ExitStatus)
		if st.ExitStatus > 128 {
			status = fmt.Sprintf("signal:%d", st.ExitStatus-128)
		}
	}
	b.mu.Lock()
	known := b.boxes[x.id] == x
	if known {
		delete(b.boxes, x.id)
	}
	b.mu.Unlock()
	close(x.done)
	if known {
		b.exits <- backend.Exit{FiberID: x.id, Status: status}
	}
}

// Clone restores the template image as a new sandbox.
func (b *Backend) Clone(ctx context.Context, warmID string, sp backend.FiberSpec) (backend.Fiber, error) {
	b.mu.Lock()
	w, ok := b.warms[warmID]
	b.mu.Unlock()
	if !ok {
		return backend.Fiber{}, fmt.Errorf("gvisor: no warm template %q", warmID)
	}
	return b.start(ctx, w.images, w.workDir, w.argv, sp.Fence, sp.Endpoint, sp.Payload, sp.CgroupFD, sp.Deadline)
}

// Park asks the workload to close its endpoint, then checkpoints.
func (b *Backend) Park(ctx context.Context, fiberID string, sp backend.ParkSpec) error {
	b.mu.Lock()
	x, ok := b.boxes[fiberID]
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("gvisor: unknown fiber %q", fiberID)
	}
	if _, err := b.runsc(ctx, -1, "kill", x.cid, "USR1"); err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := waitFile(wctx, x.endpoint, true); err != nil {
		return fmt.Errorf("gvisor: %s did not close its endpoint for the checkpoint: %w", fiberID, err)
	}
	// Sync is moot here: the endpoint is already closed, and a
	// --leave-running checkpoint restores the sandbox in place, which
	// doubles its memory inside a leaf sized for one. The checkpoint ends
	// the sandbox; the images are complete when runsc returns. Direct I/O
	// keeps the image's pages out of the leaf's page cache, where a fiber
	// near its budget would be killed for writing its own checkpoint.
	args := []string{"checkpoint", "--image-path", sp.Dir}
	if !b.opt.NoDirectIO {
		args = append(args, "--direct")
	}
	// The bundle is what a resume needs to reproduce the args; keep a copy.
	_, err := b.runsc(ctx, -1, append(args, x.cid)...)
	if err != nil {
		return err
	}
	return copyFile(filepath.Join(x.bundle, "config.json"), filepath.Join(sp.Dir, "config.json"))
}

// Resume restores a park image under a new fence and endpoint.
func (b *Backend) Resume(ctx context.Context, sp backend.ResumeSpec) (backend.Fiber, error) {
	// The args must match the checkpoint's; take them from the bundle
	// saved beside it.
	data, err := os.ReadFile(filepath.Join(sp.Dir, "config.json"))
	if err != nil {
		return backend.Fiber{}, fmt.Errorf("gvisor: park image without its bundle: %w", err)
	}
	var s spec
	if err := json.Unmarshal(data, &s); err != nil {
		return backend.Fiber{}, err
	}
	workDir := filepath.Dir(sp.Endpoint)
	return b.start(ctx, sp.Dir, workDir, s.Process.Args, sp.Fence, sp.Endpoint, nil, sp.CgroupFD, sp.Deadline)
}

func (b *Backend) Kill(fiberID string) error {
	b.mu.Lock()
	x, ok := b.boxes[fiberID]
	b.mu.Unlock()
	if !ok {
		return nil
	}
	_, err := b.runsc(context.Background(), -1, "kill", x.cid, "KILL")
	return err
}

func (b *Backend) Exits() <-chan backend.Exit { return b.exits }

func (b *Backend) Close() {
	b.mu.Lock()
	var cids []string
	for _, w := range b.warms {
		cids = append(cids, w.cid)
	}
	for _, x := range b.boxes {
		cids = append(cids, x.cid)
	}
	b.mu.Unlock()
	for _, c := range cids {
		_, _ = b.runsc(context.Background(), -1, "kill", c, "KILL")
	}
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

var (
	_ backend.Backend         = (*Backend)(nil)
	_ backend.Platformer      = (*Backend)(nil)
	_ backend.DeadlineAdvisor = (*Backend)(nil)
	_ backend.Overheader      = (*Backend)(nil)
	_ backend.WMeter          = (*Backend)(nil)
)
