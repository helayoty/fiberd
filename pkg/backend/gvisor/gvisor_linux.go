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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
)

const (
	// Every sandbox runs on the systrap platform (no KVM needed), and every
	// image is written and read with O_DIRECT so its pages are never charged
	// to the leaf that made it.
	runscPlatform = "systrap"
	directIO      = "--direct"

	createDeadline = 500 * time.Millisecond
	resumeDeadline = 2 * time.Second
	readyMarker    = "warm.ready"
	// closeWait bounds Close's wait for its reapers, hit only when runsc
	// itself is wedged.
	closeWait = 10 * time.Second
)

// runFunc runs one runsc process (args after the binary, the cgroup to
// start in or -1, where its output goes). execRunsc is the real one, a
// unit test's fake answers in-process.
type runFunc func(ctx context.Context, cgroupFD int, args []string, out io.Writer) error

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
	// MaxRestores bounds the `runsc restore` processes that run at once
	// (default, the CPUs this process may use). Restores are CPU-bound,
	// so unbounded ones all finish together at the end of a burst.
	MaxRestores int
}

// Backend implements backend.Backend, Platformer, DeadlineAdvisor,
// Overheader and Prober.
type Backend struct {
	opt     Options
	version string
	tier    core.Tier
	why     error // why tier is unspecified, nil when it is not

	// run starts every runsc process. New sets it to execRunsc.
	run runFunc

	// restores holds one token per restore that may run at once.
	restores chan struct{}

	mu    sync.Mutex
	warms map[string]*warm // warm id
	boxes map[string]*box  // fiber id
	gen   uint64           // incarnations started, the suffix of every cid
	exits chan backend.Exit
	// reapers counts the waitWarm and waitBox goroutines, each deleting
	// its container's state after `runsc wait` returns. Close waits for
	// them, so nothing of the backend runs once it returns.
	reapers sync.WaitGroup
}

type warm struct {
	id      string
	cid     string // runsc container id
	argv    []string
	workDir string
	// dir is this incarnation's own directory under <state>/templates,
	// named by its cid, so the reaper that removes it never takes a
	// successor's. It holds the bundle, the images and the staged copy.
	dir    string
	images string // template checkpoint
	// template is the host directory bound at backend.TemplateMount in
	// every sandbox of this instance: the backend's own verified copy of
	// the registry template's executable. Empty for a template that
	// lives in the rootfs.
	template string
}

type box struct {
	id       string
	cid      string
	bundle   string
	endpoint string
	done     chan struct{} // closed when the sandbox has exited
}

// New opens the backend. The tier is FIBER_SNAPSHOT when runsc answers
// and the rootfs exists. Otherwise it offers none, and ProbeErr says why.
func New(o Options) backend.Backend { return newBackend(o, nil) }

// newBackend is New with the runsc adapter chosen: nil for the process
// (execRunsc), or a unit test's in-process fake.
func newBackend(o Options, run runFunc) *Backend {
	if o.Runsc == "" {
		o.Runsc = "runsc"
	}
	if o.StateDir == "" {
		o.StateDir = "/var/lib/fiberd/gvisor"
	}
	if o.MaxRestores <= 0 {
		// GOMAXPROCS honours a cgroup CPU quota, which a home in a Pod
		// runs under; NumCPU would count the node's.
		o.MaxRestores = max(1, runtime.GOMAXPROCS(0))
	}
	b := &Backend{opt: o, run: run, warms: map[string]*warm{}, boxes: map[string]*box{}, exits: make(chan backend.Exit, 1024),
		restores: make(chan struct{}, o.MaxRestores)}
	if b.run == nil {
		b.run = b.execRunsc
	}
	out, err := b.runsc(context.Background(), -1, "--version")
	if err != nil {
		b.why = fmt.Errorf("runsc %s unavailable: %w", o.Runsc, err)
		return b
	}
	b.version = strings.TrimSpace(strings.TrimPrefix(strings.SplitN(out, "\n", 2)[0], "runsc version "))
	b.sweep()
	if st, err := os.Stat(o.Rootfs); err != nil {
		b.why = fmt.Errorf("rootfs unusable: %w", err)
		return b
	} else if !st.IsDir() {
		b.why = fmt.Errorf("rootfs %s is not a directory", o.Rootfs)
		return b
	}
	b.tier = core.TierSnapshot
	return b
}

// ProbeErr is why New found no tier: runsc does not answer, or the
// rootfs is not a directory.
func (b *Backend) ProbeErr() error { return b.why }

func (b *Backend) Name() string    { return "gvisor" }
func (b *Backend) Tier() core.Tier { return b.tier }

// IsolatesTenants is true because a fiber's syscalls are served by its
// sandbox's Sentry, not by the host kernel.
func (b *Backend) IsolatesTenants() bool { return true }

// Platform: a gVisor image depends on the runsc release and the rootfs,
// not on the host kernel or libc.
func (b *Backend) Platform() artifact.Platform {
	return artifact.Platform{Kernel: "gvisor-" + b.version, Libc: "rootfs-" + filepath.Base(b.opt.Rootfs)}
}

func (b *Backend) DefaultDeadlines() (time.Duration, time.Duration) {
	return createDeadline, resumeDeadline
}

// FiberOverheadBytes is 0, so the host measures the warm template
// sandbox's resident size. One restored sandbox costs the Sentry plus the
// template's pages.
func (b *Backend) FiberOverheadBytes() uint64 { return 0 }

// EndpointSchemes: unix only. The sandbox has no network
// (--network=none), so a tcp endpoint policy is served by the host's
// relay in front of the unix socket, and the sandbox stays network-free.
func (b *Backend) EndpointSchemes() []string { return []string{"unix"} }

// WCounter: the guest's memory is the sentry's memfd, which the leaf
// accounts as shmem; the sentry's own Go heap (anon, tens of MiB and
// different in every sandbox) is not the fiber's working set.
func (b *Backend) WCounter() string { return "shmem" }

// globalArgs are the flags every runsc command runs with. Huge pages for
// the guest's memory are off. W is the leaf's shmem above the template's
// measured footprint, and with 2 MiB pages a fresh sandbox lands several
// MiB off that in either direction. That is wider than a small budget and
// hides a real overrun.
func (b *Backend) globalArgs() []string {
	return []string{"--root=" + filepath.Join(b.opt.StateDir, "root"), "--platform=" + runscPlatform,
		"--network=none", "--ignore-cgroups", "--host-uds=all", "--overlay2=none", "--app-huge-pages=false"}
}

// runsc runs one runsc command through b.run. cgroupFD >= 0 starts it
// (and so the sandbox and gofer it leaves behind with --detach) inside
// that cgroup. A detached command's output goes to a file, never a pipe:
// the sandbox it leaves behind inherits the descriptors and a pipe would
// never close.
func (b *Backend) runsc(ctx context.Context, cgroupFD int, args ...string) (string, error) {
	full := append(b.globalArgs(), args...)
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
		// The sandbox's own stdio follows the file, which goes once runsc
		// returns.
		defer func() {
			_ = f.Close()
			_ = os.Remove(f.Name())
		}()
		err = b.run(ctx, cgroupFD, full, f)
		out, _ = os.ReadFile(f.Name())
	} else {
		var buf bytes.Buffer
		err = b.run(ctx, cgroupFD, full, &buf)
		out = buf.Bytes()
	}
	if err != nil {
		if ctx.Err() != nil {
			// The context ended and CommandContext killed runsc itself:
			// the deadline is the reason, and the caller must see it as
			// one ("signal: killed" is not a miss the agent can name).
			return string(out), fmt.Errorf("gvisor: runsc %s: %w", args[0], ctx.Err())
		}
		return string(out), fmt.Errorf("gvisor: runsc %s: %w: %s", args[0], err, clip(string(out)))
	}
	return string(out), nil
}

// clipHead and clipTail bound what a failed runsc command's error keeps.
// runsc's own error is at the end, and a crashed Sentry names its cause
// at the start, before pages of goroutines.
const clipHead, clipTail = 400, 400

// clip is out trimmed to its head and its tail.
func clip(out string) string {
	out = strings.TrimSpace(out)
	if len(out) <= clipHead+clipTail {
		return out
	}
	return out[:clipHead] + " ... " + out[len(out)-clipTail:]
}

// execRunsc is run's default: the runsc process, with its stdout and
// stderr on out. The context ending kills it.
func (b *Backend) execRunsc(ctx context.Context, cgroupFD int, args []string, out io.Writer) error {
	cmd := exec.CommandContext(ctx, b.opt.Runsc, args...)
	// A command that is not detached writes to a pipe. Should a process
	// it leaves behind hold that pipe open, Run returns this long after
	// the command itself has exited instead of waiting for the pipe.
	cmd.WaitDelay = time.Second
	if cgroupFD >= 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: cgroupFD}
	}
	cmd.Stdout, cmd.Stderr = out, out
	return cmd.Run()
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
// /host, template (when set) read-only at backend.TemplateMount, and
// images, when set, turns on the workload-triggered checkpoint.
func (b *Backend) writeBundle(dir string, argv, env []string, workDir, images, template string) error {
	var s spec
	s.OCIVersion = "1.0.2"
	s.Process.Cwd = "/"
	s.Process.Args = argv
	s.Process.Env = append([]string{"PATH=/bin:/usr/bin"}, env...)
	// The rootfs is one host directory shared by every sandbox of every
	// grant, served by the gofer with the agent's credentials, and the
	// workload is uid 0 in its sandbox. Read-only, or one fiber rewrites
	// /bin/refzygote for every later sandbox. /host and /tmp below are
	// the sandbox's writable paths.
	s.Root.Path = b.opt.Rootfs
	s.Root.Readonly = true
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
	if template != "" {
		add(backend.TemplateMount, "bind", template, backend.TemplateMountOptions...)
	}
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

// bundleDir is where a fiber sandbox's bundle is written, under the
// backend's state directory by the sandbox's cid.
func (b *Backend) bundleDir(cid string) string {
	return filepath.Join(b.opt.StateDir, "bundles", cid)
}

// cid makes a grant uid or fence usable in a container id. runsc accepts
// letters, digits, "_", "." and "-", and everything else becomes "-".
func cid(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '_' || r == '.' || r == '-' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return r
		}
		return '-'
	}, s)
}

// maxCID bounds a container id. runsc names the sandbox's control socket
// after it in the abstract namespace, which fails from 93 bytes.
const maxCID = 64

// newCID names one incarnation of a sandbox by its kind ("w" or "f"), the
// grant or fence, and a number no other sandbox of this backend has had.
// So a reaper that deletes its own cid after the sandbox exited never hits
// a successor of the same grant or fence. A long name keeps a hash of
// itself instead of its tail.
func (b *Backend) newCID(kind, name string) string {
	b.mu.Lock()
	b.gen++
	suffix := fmt.Sprintf("-%d", b.gen)
	b.mu.Unlock()
	base := cid(name)
	if room := maxCID - len(kind) - 1 - len(suffix); len(base) > room {
		sum := sha256.Sum256([]byte(base))
		base = base[:room-9] + "-" + hex.EncodeToString(sum[:4])
	}
	return kind + "-" + base + suffix
}

// sweep ends every sandbox a previous life of this backend left in its
// root, then clears the bundle and template directories they used.
// Nothing there is this life's, since no incarnation has started yet,
// and a cid is never reused across lives. When runsc cannot list, the
// sandboxes are left alone and so are their directories.
func (b *Backend) sweep() {
	out, err := b.runsc(context.Background(), -1, "list", "-quiet")
	if err != nil {
		return
	}
	for _, id := range strings.Fields(out) {
		_, _ = b.runsc(context.Background(), -1, "delete", "-force", id)
	}
	for _, sub := range []string{"bundles", "templates"} {
		ents, err := os.ReadDir(filepath.Join(b.opt.StateDir, sub))
		if err != nil {
			continue
		}
		for _, e := range ents {
			p := filepath.Join(b.opt.StateDir, sub, e.Name())
			if err := os.RemoveAll(p); err != nil {
				log.Printf("gvisor: sweep %s: %v", p, err)
			}
		}
	}
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
	w := &warm{id: sp.GrantUID, cid: b.newCID("w", sp.GrantUID), argv: sp.Template.Argv, workDir: sp.WorkDir}
	w.dir = filepath.Join(b.opt.StateDir, "templates", w.cid)
	w.images = filepath.Join(w.dir, "images")
	if err := os.MkdirAll(w.dir, 0o755); err != nil {
		return backend.Warm{}, err
	}
	// A warm that fails leaves nothing of its directory. The reaper takes
	// it for one that ran.
	warmed := false
	defer func() {
		if !warmed {
			_ = os.RemoveAll(w.dir)
		}
	}()
	if sp.Template.Dir != "" {
		// The backend's own verified copy of the executable, bound into
		// every sandbox of this instance (backend.StageTemplate).
		dir := filepath.Join(w.dir, "template")
		argv, err := backend.StageTemplate(sp.Template, dir)
		if err != nil {
			return backend.Warm{}, fmt.Errorf("gvisor: %w", err)
		}
		w.template, w.argv = dir, argv
	}
	// Restore validates that mounts match the checkpoint's, so the warm
	// sandbox and every fiber share the grant's run directory as /host.
	marker := filepath.Join(sp.WorkDir, readyMarker)
	_ = os.Remove(marker)
	bundle := filepath.Join(w.dir, "bundle")
	if err := b.writeBundle(bundle, w.argv, []string{"FIBERD_FENCE=none"}, sp.WorkDir, "", w.template); err != nil {
		return backend.Warm{}, err
	}
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
	if _, err := b.runsc(ctx, -1, "checkpoint", "--leave-running", "--image-path", w.images, directIO, w.cid); err != nil {
		_, _ = b.runsc(context.Background(), -1, "delete", "-force", w.cid)
		return backend.Warm{}, fmt.Errorf("gvisor: template checkpoint: %w", err)
	}
	warmed = true
	// The footprint of a sandbox restored from this image, measured by
	// restoring one into the empty probe cgroup the host offers: a fresh
	// sandbox (its own sentry, gofer and page tables) costs more than the
	// original restored in place, and only a fiber-like restore in a
	// cgroup of its own reads true.
	bytes, total := b.probeFootprint(ctx, w, sp.ProbeCgroupFD)
	b.mu.Lock()
	b.warms[w.id] = w
	b.mu.Unlock()
	b.reapers.Add(1)
	go b.waitWarm(w)
	return backend.Warm{ID: w.id, PID: b.pidOf(ctx, w.cid), Bytes: bytes, TotalBytes: total}, nil
}

// probeFootprint restores the template image once into the given empty
// cgroup exactly as a fiber would be, reads the cgroup (its shmem, the
// guest memory, and its memory.current), and ends it. 0 when it cannot
// tell.
func (b *Backend) probeFootprint(ctx context.Context, w *warm, cgroupFD int) (shmem, total uint64) {
	if cgroupFD < 0 {
		log.Printf("gvisor: footprint probe: no cgroup")
		return 0, 0
	}
	cid := w.cid + "-probe"
	bundle := filepath.Join(filepath.Dir(w.images), "probe-bundle")
	ep := filepath.Join(w.workDir, "probe.sock")
	if err := b.writeBundle(bundle, w.argv, []string{"FIBERD_FENCE=probe", "FIBERD_ENDPOINT=/host/probe.sock"}, w.workDir, "", w.template); err != nil {
		log.Printf("gvisor: footprint probe: %v", err)
		return 0, 0
	}
	_ = os.Remove(ep)
	if _, err := b.runsc(ctx, cgroupFD, "restore", "--detach", "--image-path", w.images, "--bundle", bundle, directIO, cid); err != nil {
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
	defer b.reapers.Done()
	_, _ = b.runsc(context.Background(), -1, "wait", w.cid)
	_, _ = b.runsc(context.Background(), -1, "delete", "-force", w.cid)
	// The image and the staged copy go with the sandbox. The directory is
	// this incarnation's own, so a successor already warmed under the
	// same grant keeps its own.
	_ = os.RemoveAll(w.dir)
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
// under the deadline when one is given. template is the warm instance's
// bound template directory, or empty.
func (b *Backend) start(ctx context.Context, images, workDir, template string, argv []string, fence, endpoint string, payload []byte, cgroupFD int, deadline time.Duration) (backend.Fiber, error) {
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
	// The bundle is the sandbox's own, named after its cid, so the reaper
	// of an earlier incarnation under the same fence never removes it. It
	// lives in the state directory, which is the agent's alone. The
	// grant's run directory is every sandbox's /host, read and write, so
	// a bundle there could be rewritten by a sibling before runsc read
	// it, or planted as a link for the agent to write through.
	x := &box{id: fence, cid: b.newCID("f", fence), endpoint: endpoint, done: make(chan struct{})}
	x.bundle = b.bundleDir(x.cid)
	if err := b.writeBundle(x.bundle, argv, env, workDir, "", template); err != nil {
		return backend.Fiber{}, err
	}
	_ = os.Remove(endpoint)
	// A restore slot, waited for under the Clone deadline.
	select {
	case b.restores <- struct{}{}:
	case <-ctx.Done():
		_ = os.RemoveAll(x.bundle)
		return backend.Fiber{}, fmt.Errorf("gvisor: %s waited for a restore slot: %w", fence, ctx.Err())
	}
	// The image is read, not cached, in the fiber's leaf.
	_, err := b.runsc(ctx, cgroupFD, "restore", "--detach", "--image-path", images, "--bundle", x.bundle, directIO, x.cid)
	<-b.restores
	if err != nil {
		// No sandbox, so no reaper to take the bundle.
		_ = os.RemoveAll(x.bundle)
		return backend.Fiber{}, fmt.Errorf("%w (%s)", err, leafDiag(cgroupFD))
	}
	b.mu.Lock()
	b.boxes[x.id] = x
	b.mu.Unlock()
	b.reapers.Add(1)
	go b.waitBox(x)
	if err := waitEndpoint(ctx, endpoint, x.done); err != nil {
		_, _ = b.runsc(context.Background(), -1, "kill", x.cid, "KILL")
		return backend.Fiber{}, fmt.Errorf("gvisor: %s did not serve: %w (%s)", fence, err, leafDiag(cgroupFD))
	}
	return backend.Fiber{ID: x.id, PID: b.pidOf(context.Background(), x.cid)}, nil
}

func (b *Backend) waitBox(x *box) {
	defer b.reapers.Done()
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
	return b.start(ctx, w.images, w.workDir, w.template, w.argv, sp.Fence, sp.Endpoint, sp.Payload, sp.CgroupFD, sp.Deadline)
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
	// The bundle is what a resume needs to reproduce the args. It is read
	// before the checkpoint, which ends the sandbox, and the reaper may
	// remove the bundle before runsc has returned.
	bundle, err := os.ReadFile(filepath.Join(x.bundle, "config.json"))
	if err != nil {
		return err
	}
	// Sync is moot here: the endpoint is already closed, and a
	// --leave-running checkpoint restores the sandbox in place, which
	// doubles its memory inside a leaf sized for one. The checkpoint ends
	// the sandbox; the images are complete when runsc returns. Direct I/O
	// keeps the image's pages out of the leaf's page cache, where a fiber
	// near its budget would be killed for writing its own checkpoint.
	if _, err := b.runsc(ctx, -1, "checkpoint", "--image-path", sp.Dir, directIO, x.cid); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(sp.Dir, "config.json"), bundle, 0o644)
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
	// The template mount, when the checkpoint has one, comes from this
	// home's own warm instance: the sandbox path is fixed and the host
	// path is wherever this home verified its copy. A checkpoint and a
	// home that disagree about having one cannot restore, since runsc
	// requires the mounts to match, so that is refused here by name.
	parked := false
	for _, m := range s.Mounts {
		if m.Destination == backend.TemplateMount {
			parked = true
		}
	}
	b.mu.Lock()
	w := b.warms[sp.WarmID]
	b.mu.Unlock()
	template := ""
	if w != nil {
		template = w.template
	}
	switch {
	case parked && template == "":
		return backend.Fiber{}, fmt.Errorf("gvisor: park image was taken with a registry template at %s, which warm instance %q does not have here", backend.TemplateMount, sp.WarmID)
	case !parked && template != "":
		return backend.Fiber{}, fmt.Errorf("gvisor: park image was taken without a template at %s, which warm instance %q binds here", backend.TemplateMount, sp.WarmID)
	}
	workDir := filepath.Dir(sp.Endpoint)
	return b.start(ctx, sp.Dir, workDir, template, s.Process.Args, sp.Fence, sp.Endpoint, nil, sp.CgroupFD, sp.Deadline)
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

// Close kills every sandbox and waits (bounded) for their reapers, so the
// state directory can go once it returns.
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
	done := make(chan struct{})
	go func() {
		b.reapers.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(closeWait):
		log.Printf("gvisor: close: a reaper is still running after %s", closeWait)
	}
}

var (
	_ backend.Backend         = (*Backend)(nil)
	_ backend.Platformer      = (*Backend)(nil)
	_ backend.DeadlineAdvisor = (*Backend)(nil)
	_ backend.Overheader      = (*Backend)(nil)
	_ backend.WMeter          = (*Backend)(nil)
)
