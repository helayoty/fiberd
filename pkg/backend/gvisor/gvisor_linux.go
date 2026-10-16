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
//     spec carries a one-shot token. The workload claims it on the pool
//     socket at /fiberd/channel and gets its fence, endpoint, payload,
//     session and a seed. It reseeds, serves its endpoint and acks. A template that
//     never dials gets its identity in the spec environment instead.
//   - Pool: the same restore, with the identity held back until Bind.
//   - Park: SIGUSR1 makes the workload close its endpoint (a listening
//     host socket cannot be checkpointed), then `runsc checkpoint`, which
//     ends the sandbox; the images are written with O_DIRECT so they are
//     not charged to the fiber's leaf.
//   - Resume: `runsc restore` the park image under a new fence and
//     endpoint, handed over on the warm instance's channel like a clone's,
//     so a resume needs the instance; the workload's blocking read
//     returns "restore" and it re-binds.
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
	"crypto/rand"
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

	"golang.org/x/sys/unix"

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

	// The deadlines a clone or resume without one of its own gets.
	// createDeadline and resumeDeadline are the floors. A warm instance
	// whose footprint probe took longer raises them to deadlineFactor
	// times what the probe took (DefaultDeadlines), so a larger template
	// on a slower host is not held to a number sized for a small one.
	// The probe restores alone, right after the checkpoint, while a
	// clone shares the CPUs with up to one sibling restore per CPU and
	// the pool fill it cut short, and a busy host (a CI runner, four
	// grants' pools filling at once) has stretched restores to two or
	// three times the probe's. Four covers that. deadlineCap bounds a
	// pathological probe (a host swapping, or at a load many times its
	// CPUs), so no clone waits without end for a default it never set.
	createDeadline = 500 * time.Millisecond
	resumeDeadline = 2 * time.Second
	deadlineFactor = 4
	deadlineCap    = 5 * time.Second
	readyMarker    = "warm.ready"
	// closeWait bounds Close's wait for its reapers, hit only when runsc
	// itself is wedged.
	closeWait = 10 * time.Second

	// channelMount is where a warm instance's own directory is bound in the
	// template sandbox and in every sandbox restored from it, read-only.
	// It holds the pool socket alone. The mount is unconditional, since
	// runsc requires a restore's mounts to match the checkpoint's.
	channelMount = "/fiberd/channel"
	poolSocket   = "pool.sock"
	// tokenBytes is the size of a restore's one-shot token.
	tokenBytes = 16
	// claimWait is how long an accepted connection has to send its
	// claim. A template claims right after it connects. unclaimedMax
	// bounds the connections a warm instance holds while they have not,
	// since any sandbox of the grant can open them, and fiberd serves
	// every grant.
	claimWait    = 3 * time.Second
	unclaimedMax = 8
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
	// await blocks until the sandbox process pid has exited and reports
	// how, or false when it cannot watch it. It is awaitExit, the pidfd
	// wait, and the fake runsc of the unit tests reports its sandboxes'
	// exits in process through it.
	await func(pid int) (string, bool)

	// restores holds one token per restore that may run at once. A clone
	// takes one as it comes. A pool restore takes one only while no clone
	// waits or runs, one pool restore at a time, and a clone that arrives
	// meanwhile cuts it short, so a pool never costs a clone its deadline.
	restores chan struct{}
	gateMu   sync.Mutex
	clones   int                // clone restores waiting for a slot or running
	fill     context.CancelFunc // cuts the running pool restore short, nil when none runs
	quiet    chan struct{}      // closed, and replaced, when a pool restore may try again

	mu     sync.Mutex
	warms  map[string]*warm // warm id
	boxes  map[string]*box  // fiber id
	pooled map[string]*box  // pooled id, sandboxes restored ahead of a fiber
	gen    uint64           // incarnations started, the suffix of every cid
	exits  chan backend.Exit
	// reapers counts the waitWarm and waitBox goroutines, each deleting
	// its container's state once the sandbox has exited, and the pool
	// socket goroutines. Close waits for them, so nothing of the backend
	// runs once it returns.
	reapers sync.WaitGroup
}

type warm struct {
	id      string
	cid     string // runsc container id
	pid     int    // the sandbox process, 0 when runsc could not say
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
	// channel is the host directory bound at channelMount in every sandbox
	// of this instance, <state>/channel/<n>, holding the pool socket ln
	// listens on.
	channel string
	ln      *net.UnixListener
	// pending maps each token minted for a restore to the sandbox it
	// was minted for. The first connection with a token takes it, under
	// the backend's mutex, and later ones are closed. unclaimed are the
	// connections accepted and not yet claimed or closed, oldest first,
	// under the same mutex.
	pending   map[string]*box
	unclaimed []net.Conn
	// noPool is set when the footprint probe found that this template
	// polls the spec environment for its identity instead of dialing
	// the pool socket. Its fibers are restored the old way and Pool
	// refuses.
	noPool bool
	// restoreTook is how long the footprint probe took to restore from
	// the image and serve, what a clone of this instance does, and 0
	// when the probe measured nothing. Written before the instance is
	// published in b.warms, and read under b.mu after.
	restoreTook time.Duration
}

type box struct {
	id       string
	cid      string
	pid      int // the sandbox process, 0 when runsc could not say
	bundle   string
	endpoint string
	workDir  string
	warmID   string // the warm instance it was restored under, for its grant's deadlines
	// pooled marks a sandbox in b.pooled (id is its pooled id) rather
	// than in b.boxes (id is its fence). probe marks the footprint probe,
	// which is in neither and reports no exit. Both are read and written
	// under b.mu.
	pooled, probe bool
	// binding marks a pooled sandbox whose hand-out is running. It keeps
	// its pooled id until the hand-out succeeds, so a failed one ends
	// under that id.
	binding bool
	// token is what the restore's spec carries, and claim is where the
	// connection that sends it is delivered. conn is that connection,
	// held from the claim until the identity is acked, under b.mu.
	token string
	claim chan net.Conn
	conn  net.Conn
	done  chan struct{} // closed when the sandbox has exited
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
	b := &Backend{opt: o, run: run, warms: map[string]*warm{}, boxes: map[string]*box{}, pooled: map[string]*box{}, exits: make(chan backend.Exit, 1024),
		restores: make(chan struct{}, o.MaxRestores), quiet: make(chan struct{}), await: awaitExit}
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

// DefaultDeadlines sizes the deadlines of a clone or resume without one
// of its own from what the footprint probe measured for the warm
// instance. They are the floors, raised to deadlineFactor times the
// probe's restore and capped at deadlineCap. An instance whose probe
// measured nothing, or one this backend does not have, gets the floors.
func (b *Backend) DefaultDeadlines(warmID string) (create, resume time.Duration) {
	var took time.Duration
	b.mu.Lock()
	if w := b.warms[warmID]; w != nil {
		took = w.restoreTook
	}
	b.mu.Unlock()
	return sizeDeadline(took, createDeadline), sizeDeadline(took, resumeDeadline)
}

// sizeDeadline is the floor or deadlineFactor times the measured restore,
// whichever is larger, and never more than deadlineCap.
func sizeDeadline(measured, floor time.Duration) time.Duration {
	return min(max(floor, deadlineFactor*measured), deadlineCap)
}

// FiberOverheadBytes is 0, so the host measures the warm template
// sandbox's resident size. One restored sandbox costs the Sentry plus the
// template's pages.
func (b *Backend) FiberOverheadBytes() uint64 { return 0 }

// EndpointSchemes: unix only. The sandbox has no network
// (--network=none), so a tcp endpoint policy is served by the host's
// relay in front of the unix socket, and the sandbox stays network-free.
func (b *Backend) EndpointSchemes() []string { return []string{"unix"} }

// wCounter is the leaf's memory.stat counter W is read from. The guest's
// memory is the sentry's memfd, which the leaf accounts as shmem, while
// the sentry's own Go heap (anon, tens of MiB and different in every
// sandbox) is not the fiber's working set.
const wCounter = "shmem"

// WCounter names the leaf counter the host reads for W.
func (b *Backend) WCounter() string { return wCounter }

// leafW reads the leaf's W counter, 0 without a cgroup. Read before the
// hand-out it is this sandbox's own footprint, since restores of one
// image settle MiB apart and the template's probe can be off.
func leafW(cgroupFD int) uint64 {
	if cgroupFD < 0 {
		return 0
	}
	return cgroupStat(cgroupFD, wCounter)
}

// globalArgs are the flags every runsc command runs with. Huge pages for
// the guest's memory are off. W is the leaf's shmem above what the leaf
// counted before the hand-out, and with 2 MiB pages a sandbox moves
// several MiB after that count in either direction. That is wider than a
// small budget and hides a real overrun.
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
			// one ("signal: killed" is not a miss fiberd can name).
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
// stderr on out, started with transparent huge pages off so the sandbox
// and gofer it leaves behind run without them. The context ending kills
// it.
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
	if err := holdTHPOff(); err != nil {
		return err
	}
	err := cmd.Start()
	releaseTHPOff()
	if err != nil {
		return err
	}
	return cmd.Wait()
}

// Sandboxes run with transparent huge pages off, which saves the Sentry's
// heap about 15 MiB and costs a clone nothing. PR_SET_THP_DISABLE is
// inherited across exec, so fiberd sets it on itself only around a start.
var (
	thpMu   sync.Mutex
	thpHeld int
)

// holdTHPOff (Transparent Huge Pages) opens the window for one start, setting the flag when it is
// the first.
func holdTHPOff() error {
	thpMu.Lock()
	defer thpMu.Unlock()
	if thpHeld == 0 {
		if err := unix.Prctl(unix.PR_SET_THP_DISABLE, 1, 0, 0, 0); err != nil {
			return fmt.Errorf("prctl(PR_SET_THP_DISABLE): %w", err)
		}
	}
	thpHeld++
	return nil
}

// releaseTHPOff ends one start's window, clearing the flag with the last.
func releaseTHPOff() {
	thpMu.Lock()
	defer thpMu.Unlock()
	thpHeld--
	if thpHeld == 0 {
		_ = unix.Prctl(unix.PR_SET_THP_DISABLE, 0, 0, 0, 0)
	}
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
// /host, channel read-only at channelMount, template (when set) read-only at
// backend.TemplateMount, and images, when set, turns on the
// workload-triggered checkpoint.
func (b *Backend) writeBundle(dir string, argv, env []string, workDir, channel, images, template string) error {
	var s spec
	s.OCIVersion = "1.0.2"
	s.Process.Cwd = "/"
	s.Process.Args = argv
	s.Process.Env = append([]string{"PATH=/bin:/usr/bin"}, env...)
	// The rootfs is one host directory shared by every sandbox of every
	// grant, served by the gofer with fiberd's credentials, and the
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
	add(channelMount, "bind", channel, backend.TemplateMountOptions...)
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
// root, then clears the bundle, template and channel directories they used.
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
	for _, sub := range []string{"bundles", "templates", "channel"} {
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

// sandboxPID reads the pid runsc wrote to pidFile, so no `runsc state`
// sits on a birth's path.
func (b *Backend) sandboxPID(ctx context.Context, cid, pidFile string) int {
	data, err := os.ReadFile(pidFile)
	if err == nil {
		var pid int
		if _, err := fmt.Sscan(string(data), &pid); err == nil && pid > 0 {
			return pid
		}
	}
	return b.pidOf(ctx, cid)
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
	w := &warm{id: sp.GrantUID, cid: b.newCID("w", sp.GrantUID), argv: sp.Template.Argv, workDir: sp.WorkDir, pending: map[string]*box{}}
	w.dir = filepath.Join(b.opt.StateDir, "templates", w.cid)
	w.images = filepath.Join(w.dir, "images")
	// Named by the incarnation's number alone. A unix socket path is at
	// most 108 bytes and a cid can be 64.
	w.channel = filepath.Join(b.opt.StateDir, "channel", w.cid[strings.LastIndex(w.cid, "-")+1:])
	if err := os.MkdirAll(w.dir, 0o755); err != nil {
		return backend.Warm{}, err
	}
	// The pool socket, in a directory of the instance's own that holds
	// nothing else. The sandbox connects with fiberd's credentials, so
	// the socket is fiberd's alone.
	if err := os.MkdirAll(w.channel, 0o700); err != nil {
		return backend.Warm{}, err
	}
	sock := filepath.Join(w.channel, poolSocket)
	ln, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: sock, Net: "unixpacket"})
	if err != nil {
		_ = os.RemoveAll(w.channel)
		return backend.Warm{}, fmt.Errorf("gvisor: pool socket: %w", err)
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		_ = ln.Close()
		_ = os.RemoveAll(w.channel)
		return backend.Warm{}, fmt.Errorf("gvisor: pool socket: %w", err)
	}
	w.ln = ln
	b.reapers.Add(1)
	go b.servePool(w)
	// A warm that fails leaves nothing of its directories. The reaper
	// takes them for one that ran.
	warmed := false
	defer func() {
		if !warmed {
			_ = ln.Close()
			_ = os.RemoveAll(w.dir)
			_ = os.RemoveAll(w.channel)
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
	if err := b.writeBundle(bundle, w.argv, []string{"FIBERD_FENCE=none"}, sp.WorkDir, w.channel, "", w.template); err != nil {
		return backend.Warm{}, err
	}
	if _, err := b.runsc(ctx, sp.CgroupFD, "run", "--detach", "--bundle", bundle, w.cid); err != nil {
		return backend.Warm{}, err
	}
	w.pid = b.pidOf(ctx, w.cid)
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
	// cgroup of its own reads true. The same restore tells whether the
	// template binds its identity late.
	bytes, total := b.probeFootprint(ctx, w, sp.ProbeCgroupFD)
	if w.noPool {
		log.Printf("gvisor: template of %s takes its identity from the spec environment and never dials the pool socket, so it has no pool", w.id)
	}
	if w.restoreTook > 0 {
		log.Printf("gvisor: template of %s restored and served in %s, default deadlines create=%s resume=%s", w.id, w.restoreTook.Round(time.Millisecond),
			sizeDeadline(w.restoreTook, createDeadline), sizeDeadline(w.restoreTook, resumeDeadline))
	}
	b.mu.Lock()
	b.warms[w.id] = w
	b.mu.Unlock()
	b.reapers.Add(1)
	go b.waitWarm(w)
	return backend.Warm{ID: w.id, PID: w.pid, Bytes: bytes, TotalBytes: total}, nil
}

// probeFootprint restores the template image once into the given empty
// cgroup exactly as a fiber would be, reads the cgroup (its shmem, the
// guest memory, and its memory.current), and ends it. 0 when it cannot
// tell, and without a cgroup it restores all the same, since the probe
// is also where late binding is detected. Its spec carries a token and
// the probe's fence and endpoint both, so whichever the template does
// first, dial or serve, says how it takes its identity, and it is
// measured serving either way. The probe is also timed, from the
// restore to serving, which is what a clone does and what sizes the
// instance's default deadlines (DefaultDeadlines). It gets deadlineCap,
// since a template that takes longer cannot be born under any default.
func (b *Backend) probeFootprint(ctx context.Context, w *warm, cgroupFD int) (shmem, total uint64) {
	if cgroupFD < 0 {
		log.Printf("gvisor: footprint probe: no cgroup")
	}
	x := &box{id: "probe", cid: w.cid + "-probe", bundle: filepath.Join(w.dir, "probe-bundle"), probe: true, workDir: w.workDir, done: make(chan struct{})}
	x.endpoint = filepath.Join(w.workDir, "probe.sock")
	env := []string{"FIBERD_FENCE=probe", "FIBERD_ENDPOINT=/host/probe.sock"}
	pctx, cancel := context.WithTimeout(ctx, deadlineCap)
	defer cancel()
	t0 := time.Now()
	if err := b.restore(pctx, w, x, w.images, w.argv, env, cgroupFD); err != nil {
		log.Printf("gvisor: footprint probe: %v", err)
		return 0, 0
	}
	defer func() {
		b.endBox(x)
		_ = os.Remove(x.endpoint)
	}()
	// Serving is the state a fiber is measured in.
	conn, err := b.claimOrServe(pctx, w, x)
	switch {
	case err != nil:
		log.Printf("gvisor: footprint probe did not serve: %v", err)
		return 0, 0
	case conn == nil:
		w.noPool = true
	default:
		if _, err := b.bind(pctx, x, conn, "clone", "probe", "/host/probe.sock", nil, "", 1); err != nil {
			log.Printf("gvisor: footprint probe did not serve: %v", err)
			return 0, 0
		}
	}
	w.restoreTook = time.Since(t0)
	if cgroupFD < 0 {
		return 0, 0
	}
	// The image is read as the guest touches it, so a sandbox grows for a
	// while after it first serves; take the larger of a reading at
	// readiness and one after it has settled.
	shmem, total = cgroupStat(cgroupFD, "shmem"), cgroupCurrent(cgroupFD)
	time.Sleep(200 * time.Millisecond)
	return max(shmem, cgroupStat(cgroupFD, "shmem")), max(total, cgroupCurrent(cgroupFD))
}

// claimOrServe returns the probe's connection when it claims its token,
// or nil when it serves the endpoint from its spec instead.
func (b *Backend) claimOrServe(ctx context.Context, w *warm, x *box) (net.Conn, error) {
	for {
		select {
		case conn := <-x.claim:
			return conn, nil
		default:
		}
		if c, err := net.DialTimeout("unix", x.endpoint, 50*time.Millisecond); err == nil {
			_ = c.Close()
			b.forgetToken(w, x)
			return nil, nil
		}
		select {
		case conn := <-x.claim:
			return conn, nil
		case <-ctx.Done():
			b.forgetToken(w, x)
			return nil, ctx.Err()
		case <-x.done:
			b.forgetToken(w, x)
			return nil, errors.New("sandbox exited before serving")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// endBox kills a sandbox and waits for its reaper, so its state is gone
// when this returns.
func (b *Backend) endBox(x *box) {
	_, _ = b.runsc(context.Background(), -1, "kill", x.cid, "KILL")
	<-x.done
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

// reap blocks until the sandbox cid has exited, deletes its state and
// reports how it ended. With the sandbox pid known, the wait is a pidfd
// parked in the Go runtime's poller, which costs no process and no
// thread per sandbox. A `runsc wait` is a process of several threads and
// some 20 MiB in fiberd's own leaf for each live fiber. Without a pid
// the sandbox is already gone or runsc could not say, and `runsc wait`
// sorts it out as before.
func (b *Backend) reap(cid string, pid int) string {
	status, ok := b.await(pid)
	if !ok {
		out, _ := b.runsc(context.Background(), -1, "wait", cid)
		status = waitStatus(out)
	}
	_, _ = b.runsc(context.Background(), -1, "delete", "-force", cid)
	return status
}

// awaitExit blocks until the process pid has exited and reports how,
// or false when it cannot watch it. The pidfd is this process's hold on
// that one incarnation of the pid, so a reused pid is never waited for.
func awaitExit(pid int) (string, bool) {
	if pid <= 0 {
		return "", false
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return "", false
	}
	// Non-blocking, so NewFile hands the fd to the poller, and RawConn's
	// Read parks this goroutine there until the fd is readable, which is
	// when the process has exited. Should the poller refuse it, poll(2)
	// blocks a thread for this one sandbox instead.
	_ = unix.SetNonblock(fd, true)
	f := os.NewFile(uintptr(fd), "pidfd")
	defer func() { _ = f.Close() }()
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	exited := func(uintptr) bool {
		n, err := unix.Poll(fds, 0)
		return n > 0 || (err != nil && err != unix.EINTR && err != unix.EAGAIN)
	}
	rc, err := f.SyscallConn()
	if err != nil || rc.Read(exited) != nil {
		for !exited(0) {
			_, _ = unix.Poll(fds, -1)
		}
	}
	return exitStatus(pid), true
}

// exitStatus is how the exited process pid ended when this process is
// its parent, which reaps it here. runsc reparents a detached sandbox
// to init, so that is fiberd when it is a container's init. Otherwise
// the status is "exited", since only a parent can read one.
func exitStatus(pid int) string {
	var ws unix.WaitStatus
	wpid, err := unix.Wait4(pid, &ws, unix.WNOHANG, nil)
	for err == unix.EINTR {
		wpid, err = unix.Wait4(pid, &ws, unix.WNOHANG, nil)
	}
	switch {
	case err != nil || wpid != pid:
		return "exited"
	case ws.Signaled():
		return fmt.Sprintf("signal:%d", ws.Signal())
	default:
		return fmt.Sprintf("exit:%d", ws.ExitStatus())
	}
}

// waitStatus reads `runsc wait` output as "exit:N", or "signal:N" for an
// exit status above 128, or "exit:?" when it was not readable.
func waitStatus(out string) string {
	var st struct {
		ExitStatus int `json:"exitStatus"`
	}
	if json.Unmarshal([]byte(out), &st) != nil {
		return "exit:?"
	}
	if st.ExitStatus > 128 {
		return fmt.Sprintf("signal:%d", st.ExitStatus-128)
	}
	return fmt.Sprintf("exit:%d", st.ExitStatus)
}

func (b *Backend) waitWarm(w *warm) {
	defer b.reapers.Done()
	b.reap(w.cid, w.pid)
	// The image, the staged copy and the pool socket go with the
	// sandbox. The directories are this incarnation's own, so a successor
	// already warmed under the same grant keeps its own.
	_ = w.ln.Close()
	_ = os.RemoveAll(w.dir)
	_ = os.RemoveAll(w.channel)
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

// The channel speaks backend's records. The sandbox claims with 't' and
// its token, the backend hands out the incarnation with 'i', and the
// sandbox acks with 'a' and the fence once its endpoint is bound.

// servePool accepts the connections of sandboxes restored under w and
// reads each claim in a goroutine of its own. At most unclaimedMax are
// held, and one more closes the oldest, so silent connections cannot
// pile up or keep a real claim out.
func (b *Backend) servePool(w *warm) {
	defer b.reapers.Done()
	for {
		conn, err := w.ln.Accept()
		if err != nil {
			return
		}
		b.mu.Lock()
		if len(w.unclaimed) >= unclaimedMax {
			_ = w.unclaimed[0].Close()
			w.unclaimed = w.unclaimed[1:]
		}
		w.unclaimed = append(w.unclaimed, conn)
		b.mu.Unlock()
		b.reapers.Add(1)
		go b.claim(w, conn)
	}
}

// claimed takes conn off w's unclaimed connections.
func (b *Backend) claimed(w *warm, conn net.Conn) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, c := range w.unclaimed {
		if c == conn {
			w.unclaimed = append(w.unclaimed[:i], w.unclaimed[i+1:]...)
			return
		}
	}
}

// claim delivers conn to the restore that minted its token, or closes
// it. The token is never logged.
func (b *Backend) claim(w *warm, conn net.Conn) {
	defer b.reapers.Done()
	defer b.claimed(w, conn)
	_ = conn.SetReadDeadline(time.Now().Add(claimWait))
	buf := make([]byte, 2+2*tokenBytes+1)
	n, err := conn.Read(buf)
	if err != nil {
		_ = conn.Close()
		return
	}
	kind, fields, ok := backend.ParseRecord(buf[:n])
	if !ok || kind != backend.RecordClaim || len(fields) != 1 {
		_ = conn.Close()
		return
	}
	// Delivered under the mutex, so forgetToken finds the connection on
	// the claim channel or the token still pending, never neither.
	b.mu.Lock()
	x := w.pending[fields[0]]
	delete(w.pending, fields[0])
	if x != nil {
		_ = conn.SetReadDeadline(time.Time{})
		x.claim <- conn
	}
	b.mu.Unlock()
	if x == nil {
		_ = conn.Close()
	}
}

// mintToken gives x a fresh one-shot token for its restore under w.
func (b *Backend) mintToken(w *warm, x *box) error {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Errorf("gvisor: token: %w", err)
	}
	x.token, x.claim = hex.EncodeToString(raw), make(chan net.Conn, 1)
	b.mu.Lock()
	w.pending[x.token] = x
	b.mu.Unlock()
	return nil
}

// forgetToken withdraws x's token, which nobody will wait for any more,
// and closes a claim that arrived meanwhile.
func (b *Backend) forgetToken(w *warm, x *box) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(w.pending, x.token)
	select {
	case conn := <-x.claim:
		_ = conn.Close()
	default:
	}
}

// enterClone takes a restore slot for a clone, a probe or a resume,
// cutting short a pool restore that holds one.
func (b *Backend) enterClone(ctx context.Context) error {
	b.gateMu.Lock()
	b.clones++
	if b.fill != nil {
		b.fill()
	}
	b.gateMu.Unlock()
	select {
	case b.restores <- struct{}{}:
		return nil
	case <-ctx.Done():
		b.leaveClone(false)
		return ctx.Err()
	}
}

// leaveClone gives the clone's slot back, when it held one, and lets a
// pool restore try again once no clone is left.
func (b *Backend) leaveClone(held bool) {
	if held {
		<-b.restores
	}
	b.gateMu.Lock()
	b.clones--
	if b.clones == 0 {
		close(b.quiet)
		b.quiet = make(chan struct{})
	}
	b.gateMu.Unlock()
}

// enterFill takes a restore slot for a pool restore only while no clone
// waits or runs, under a context a later clone cancels.
func (b *Backend) enterFill(ctx context.Context) (context.Context, error) {
	for {
		b.gateMu.Lock()
		if b.clones == 0 && b.fill == nil {
			// Every slot is free, since only clones and this hold them.
			b.restores <- struct{}{}
			fctx, cancel := context.WithCancel(ctx)
			b.fill = cancel
			b.gateMu.Unlock()
			return fctx, nil
		}
		quiet := b.quiet
		b.gateMu.Unlock()
		select {
		case <-quiet:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// leaveFill gives the pool restore's slot back.
func (b *Backend) leaveFill() {
	<-b.restores
	b.gateMu.Lock()
	b.fill()
	b.fill = nil
	close(b.quiet)
	b.quiet = make(chan struct{})
	b.gateMu.Unlock()
}

// restore brings images up as the sandbox x in cgroupFD, with a fresh
// token in its environment, and registers a reaper. A failed restore
// leaves no sandbox and no bundle. A pool restore cut short for a clone
// fails with backend.ErrYielded.
func (b *Backend) restore(ctx context.Context, w *warm, x *box, images string, argv, env []string, cgroupFD int) error {
	if err := b.mintToken(w, x); err != nil {
		return err
	}
	// The bundle is the sandbox's own, named after its cid, so the reaper
	// of an earlier incarnation under the same fence never removes it. It
	// lives in the state directory, which is fiberd's alone. The
	// grant's run directory is every sandbox's /host, read and write, so
	// a bundle there could be rewritten by a sibling before runsc read
	// it, or planted as a link for fiberd to write through.
	if err := b.writeBundle(x.bundle, argv, append([]string{"FIBERD_TOKEN=" + x.token}, env...), w.workDir, w.channel, "", w.template); err != nil {
		b.forgetToken(w, x)
		return err
	}
	// A restore slot, waited for under the deadline.
	rctx, leave := ctx, func() { b.leaveClone(true) }
	var err error
	if x.pooled {
		rctx, err = b.enterFill(ctx)
		leave = b.leaveFill
	} else {
		err = b.enterClone(ctx)
	}
	if err != nil {
		b.forgetToken(w, x)
		_ = os.RemoveAll(x.bundle)
		return fmt.Errorf("gvisor: %s waited for a restore slot: %w", x.id, err)
	}
	// The image is read, not cached, in the sandbox's leaf.
	pidFile := filepath.Join(x.bundle, "pid")
	_, err = b.runsc(rctx, cgroupFD, "restore", "--detach", "--pid-file", pidFile, "--image-path", images, "--bundle", x.bundle, directIO, x.cid)
	cut := rctx.Err() != nil
	leave()
	if err != nil {
		// No sandbox, so no reaper to take the bundle.
		b.forgetToken(w, x)
		_ = os.RemoveAll(x.bundle)
		if cut {
			// runsc was killed midway and may have left a half-restored
			// sandbox behind, which its leaf's kill ends and this forgets.
			b.reapers.Add(1)
			go func() {
				defer b.reapers.Done()
				_, _ = b.runsc(context.Background(), -1, "delete", "-force", x.cid)
			}()
			if ctx.Err() == nil {
				return fmt.Errorf("%w: %s", backend.ErrYielded, x.id)
			}
		}
		return fmt.Errorf("%w (%s)", err, leafDiag(cgroupFD))
	}
	x.pid = b.sandboxPID(ctx, x.cid, pidFile)
	b.mu.Lock()
	switch {
	case x.probe:
	case x.pooled:
		b.pooled[x.id] = x
	default:
		b.boxes[x.id] = x
	}
	b.mu.Unlock()
	b.reapers.Add(1)
	go b.waitBox(x)
	return nil
}

// awaitClaim waits for the sandbox x to claim its token. The sandbox
// exiting first, or the context ending, kills it and is an error.
func (b *Backend) awaitClaim(ctx context.Context, w *warm, x *box) (net.Conn, error) {
	var err error
	select {
	case conn := <-x.claim:
		b.mu.Lock()
		x.conn = conn
		b.mu.Unlock()
		return conn, nil
	case <-ctx.Done():
		err = fmt.Errorf("gvisor: %s sent no token: %w", x.id, ctx.Err())
	case <-x.done:
		err = fmt.Errorf("gvisor: %s exited before sending its token", x.id)
	}
	b.forgetToken(w, x)
	_, _ = b.runsc(context.Background(), -1, "kill", x.cid, "KILL")
	return nil, err
}

// bind hands x its identity and a fresh seed on conn, then waits for an
// ack naming the fence and for the endpoint to accept. Anything else
// kills the sandbox. The seed never touches a file or a log.
func (b *Backend) bind(ctx context.Context, x *box, conn net.Conn, kind, fence, endpoint string, payload []byte, session string, generation int) (backend.Fiber, error) {
	// Held in x while the hand-out runs, so the reaper closes it, and
	// ends the wait for the ack, should the sandbox die meanwhile.
	b.mu.Lock()
	x.conn = conn
	b.mu.Unlock()
	fiber, err := b.handOut(ctx, x, conn, kind, fence, endpoint, payload, session, generation)
	b.mu.Lock()
	x.conn = nil
	b.mu.Unlock()
	_ = conn.Close()
	if err != nil {
		_, _ = b.runsc(context.Background(), -1, "kill", x.cid, "KILL")
		return backend.Fiber{}, err
	}
	return fiber, nil
}

func (b *Backend) handOut(ctx context.Context, x *box, conn net.Conn, kind, fence, endpoint string, payload []byte, session string, generation int) (backend.Fiber, error) {
	seed := make([]byte, backend.SeedBytes)
	if _, err := rand.Read(seed); err != nil {
		return backend.Fiber{}, fmt.Errorf("gvisor: seed: %w", err)
	}
	// The generation is the host's count of the fiber's lineage: 1 for a
	// sandbox restored from the template image, the parked one's plus one
	// for a resume. The backend passes it on as given, and a record the
	// template would refuse (a generation under 1) is refused here by
	// name rather than shown as a missing ack. No sandbox serves handoff,
	// so the identity fields stay empty.
	rec, err := backend.Incarnation{Generation: generation, Kind: kind, Fence: fence, Endpoint: endpoint, Payload: payload, Session: session, Seed: seed}.Record()
	clear(seed)
	if err != nil {
		return backend.Fiber{}, fmt.Errorf("gvisor: %w", err)
	}
	// The context ending cuts the write and the read short.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if _, err := conn.Write(rec); err != nil {
		clear(rec)
		return backend.Fiber{}, fmt.Errorf("gvisor: %s: identity: %w", fence, err)
	}
	clear(rec)
	buf := make([]byte, 2+len(fence)+1)
	n, err := conn.Read(buf)
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return backend.Fiber{}, fmt.Errorf("gvisor: %s: no ack: %w", fence, err)
	}
	k, fields, ok := backend.ParseRecord(buf[:n])
	if !ok || k != backend.RecordAck || len(fields) != 1 || fields[0] != fence {
		return backend.Fiber{}, fmt.Errorf("gvisor: %s: ack names %q", fence, buf[:n])
	}
	if err := waitEndpoint(ctx, x.endpoint, x.done); err != nil {
		return backend.Fiber{}, fmt.Errorf("gvisor: %s did not serve: %w", fence, err)
	}
	return backend.Fiber{ID: x.id, PID: x.pid}, nil
}

// sandboxEndpoint is endpoint as the sandbox names it, under /host, or
// an error when it is not under the grant's run directory.
func sandboxEndpoint(workDir, endpoint string) (string, error) {
	if !strings.HasPrefix(endpoint, workDir+"/") {
		return "", fmt.Errorf("gvisor: endpoint %s is outside the grant's run directory %s", endpoint, workDir)
	}
	return "/host/" + strings.TrimPrefix(endpoint, workDir+"/"), nil
}

// start restores an image as a new sandbox serving endpoint, under the
// deadline when one is given. The identity goes over the channel, or in
// the spec environment for a template that never dials.
func (b *Backend) start(ctx context.Context, w *warm, images string, argv []string, kind, fence, endpoint string, payload []byte, session string, generation int, cgroupFD int, deadline time.Duration) (backend.Fiber, error) {
	if deadline > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, deadline)
		defer cancel()
	}
	inside, err := sandboxEndpoint(w.workDir, endpoint)
	if err != nil {
		return backend.Fiber{}, err
	}
	x := &box{id: fence, cid: b.newCID("f", fence), endpoint: endpoint, workDir: w.workDir, warmID: w.id, done: make(chan struct{})}
	x.bundle = b.bundleDir(x.cid)
	_ = os.Remove(endpoint)
	if w.noPool {
		env := []string{"FIBERD_FENCE=" + fence, "FIBERD_ENDPOINT=" + inside}
		if len(payload) > 0 {
			env = append(env, "FIBERD_PAYLOAD="+hex.EncodeToString(payload))
		}
		if session != "" {
			env = append(env, "FIBERD_SESSION="+session)
		}
		if err := b.restore(ctx, w, x, images, argv, env, cgroupFD); err != nil {
			return backend.Fiber{}, err
		}
		// The identity sat in the spec, so the restore is the last
		// moment the sandbox has surely not touched its payload.
		base := leafW(cgroupFD)
		b.forgetToken(w, x)
		if err := waitEndpoint(ctx, endpoint, x.done); err != nil {
			_, _ = b.runsc(context.Background(), -1, "kill", x.cid, "KILL")
			return backend.Fiber{}, fmt.Errorf("gvisor: %s did not serve: %w (%s)", fence, err, leafDiag(cgroupFD))
		}
		return backend.Fiber{ID: x.id, PID: x.pid, Footprint: base}, nil
	}
	if err := b.restore(ctx, w, x, images, argv, nil, cgroupFD); err != nil {
		return backend.Fiber{}, err
	}
	conn, err := b.awaitClaim(ctx, w, x)
	if err != nil {
		return backend.Fiber{}, fmt.Errorf("%w (%s)", err, leafDiag(cgroupFD))
	}
	// Restored, with every page of the image read, and waiting on the
	// channel for an identity it has not been given.
	base := leafW(cgroupFD)
	fiber, err := b.bind(ctx, x, conn, kind, fence, inside, payload, session, generation)
	if err != nil {
		return backend.Fiber{}, fmt.Errorf("%w (%s)", err, leafDiag(cgroupFD))
	}
	fiber.Footprint = base
	return fiber, nil
}

func (b *Backend) waitBox(x *box) {
	defer b.reapers.Done()
	status := b.reap(x.cid, x.pid)
	_ = os.RemoveAll(x.bundle)
	b.mu.Lock()
	known := false
	switch {
	case x.probe:
	case x.pooled:
		known = b.pooled[x.id] == x
		if known {
			delete(b.pooled, x.id)
		}
	default:
		known = b.boxes[x.id] == x
		if known {
			delete(b.boxes, x.id)
		}
	}
	pooled, id, conn := x.pooled, x.id, x.conn
	x.conn = nil
	b.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	close(x.done)
	switch {
	case !known:
	case pooled:
		b.exits <- backend.Exit{PooledID: id, Status: status}
	default:
		b.exits <- backend.Exit{FiberID: id, Status: status}
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
	return b.start(ctx, w, w.images, w.argv, "clone", sp.Fence, sp.Endpoint, sp.Payload, sp.Session, sp.Generation, sp.CgroupFD, sp.Deadline)
}

// Pool restores a sandbox with no identity, which waits for Bind. A
// failed Pool leaves no sandbox, and one it restored reports its end
// under the pooled id.
func (b *Backend) Pool(ctx context.Context, warmID string, sp backend.PoolSpec) (backend.Pooled, error) {
	b.mu.Lock()
	w, ok := b.warms[warmID]
	b.mu.Unlock()
	if !ok {
		return backend.Pooled{}, fmt.Errorf("gvisor: no warm template %q", warmID)
	}
	if w.noPool {
		return backend.Pooled{}, backend.ErrNoPool
	}
	if sp.Deadline > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, sp.Deadline)
		defer cancel()
	}
	x := &box{cid: b.newCID("p", warmID), pooled: true, workDir: w.workDir, warmID: warmID, done: make(chan struct{})}
	x.id = x.cid
	x.bundle = b.bundleDir(x.cid)
	if err := b.restore(ctx, w, x, w.images, w.argv, nil, sp.CgroupFD); err != nil {
		return backend.Pooled{}, err
	}
	if _, err := b.awaitClaim(ctx, w, x); err != nil {
		return backend.Pooled{}, fmt.Errorf("%w (%s)", err, leafDiag(sp.CgroupFD))
	}
	return backend.Pooled{ID: x.id, PID: x.pid}, nil
}

// Bind hands a pooled sandbox the fiber's identity and waits for it to
// serve. The sandbox keeps its pooled id until then, so a failed
// hand-out never reports an end under a fence.
func (b *Backend) Bind(ctx context.Context, pooledID string, sp backend.FiberSpec) (backend.Fiber, error) {
	if sp.Deadline > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, sp.Deadline)
		defer cancel()
	}
	b.mu.Lock()
	x := b.pooled[pooledID]
	var conn net.Conn
	if x != nil && !x.binding {
		x.binding = true
		x.endpoint, conn = sp.Endpoint, x.conn
	} else {
		x = nil
	}
	b.mu.Unlock()
	if x == nil {
		return backend.Fiber{}, fmt.Errorf("gvisor: no pooled sandbox %q", pooledID)
	}
	inside, err := sandboxEndpoint(x.workDir, sp.Endpoint)
	if err != nil {
		_, _ = b.runsc(context.Background(), -1, "kill", x.cid, "KILL")
		return backend.Fiber{}, err
	}
	_ = os.Remove(sp.Endpoint)
	// Idle in the pool since its restore, so this is its settled footprint.
	base := leafW(sp.CgroupFD)
	if _, err := b.bind(ctx, x, conn, "clone", sp.Fence, inside, sp.Payload, sp.Session, sp.Generation); err != nil {
		return backend.Fiber{}, fmt.Errorf("%w (%s)", err, leafDiag(sp.CgroupFD))
	}
	// The sandbox is the fiber from here on, unless the reaper took it
	// first, in which case its end went out under the pooled id.
	b.mu.Lock()
	alive := b.pooled[pooledID] == x
	if alive {
		delete(b.pooled, pooledID)
		x.pooled, x.id = false, sp.Fence
		b.boxes[sp.Fence] = x
	}
	b.mu.Unlock()
	if !alive {
		return backend.Fiber{}, fmt.Errorf("gvisor: %s died during its hand-out", pooledID)
	}
	return backend.Fiber{ID: sp.Fence, PID: x.pid, Footprint: base}, nil
}

// Discard kills a pooled sandbox. Its end is reported as Exit{PooledID}.
func (b *Backend) Discard(pooledID string) {
	b.mu.Lock()
	x := b.pooled[pooledID]
	b.mu.Unlock()
	if x != nil {
		_, _ = b.runsc(context.Background(), -1, "kill", x.cid, "KILL")
	}
}

// Park asks the workload to close its endpoint, then checkpoints. The
// wait for the endpoint to go is the spec's deadline, the grant's
// resume deadline, or without one what this backend advises for the
// grant's warm instance (DefaultDeadlines).
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
	deadline := sp.Deadline
	if deadline <= 0 {
		_, deadline = b.DefaultDeadlines(x.warmID)
	}
	wctx, cancel := context.WithTimeout(ctx, deadline)
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
	// The resumed sandbox takes its identity from the warm instance's
	// pool socket, so a resume needs the instance.
	b.mu.Lock()
	w := b.warms[sp.WarmID]
	b.mu.Unlock()
	if w == nil {
		return backend.Fiber{}, fmt.Errorf("gvisor: no warm template %q to resume under", sp.WarmID)
	}
	switch {
	case parked && w.template == "":
		return backend.Fiber{}, fmt.Errorf("gvisor: park image was taken with a registry template at %s, which warm instance %q does not have here", backend.TemplateMount, sp.WarmID)
	case !parked && w.template != "":
		return backend.Fiber{}, fmt.Errorf("gvisor: park image was taken without a template at %s, which warm instance %q binds here", backend.TemplateMount, sp.WarmID)
	}
	return b.start(ctx, w, sp.Dir, s.Process.Args, "resume", sp.Fence, sp.Endpoint, nil, sp.Session, sp.Generation, sp.CgroupFD, sp.Deadline)
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

// Close kills every sandbox, pooled ones included, and waits (bounded)
// for their reapers, so the state directory can go once it returns.
func (b *Backend) Close() {
	b.mu.Lock()
	var cids []string
	for _, w := range b.warms {
		cids = append(cids, w.cid)
	}
	for _, x := range b.boxes {
		cids = append(cids, x.cid)
	}
	for _, x := range b.pooled {
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
	_ backend.Pooler          = (*Backend)(nil)
)
