//go:build linux

// Package proc is the fork backend. It runs one zygote per grant, linked
// with zygote/libfiberzygote, which forks fibers on request over a
// socketpair inherited as fd 3. CRIU checkpoints them. It is the reference
// backend that the conformance suite runs against.
//
// The control socket carries lines. The zygote side is libfiberzygote.c.
// The host speaks first.
//
//	host   -> zygote HIDE <dir> | DROP <path> | RUNDIR <parent> <own>   (any number)
//	host   -> zygote PREPARE mntns|none                                 (ends the setup)
//	zygote -> host   READY
//	host   -> zygote CLONE <fence> <endpoint> <deadline_ms> <payload-hex|-> [opt,opt...]   + SCM_RIGHTS cgroup fd [, handoff channel]
//	zygote -> host   CLONED <fence> <pid>  |  ERROR <fence> <text>
//	zygote -> host   EXITED <pid> exit:<n>|signal:<name>
//
// RUNDIR names the directory all grants' run directories sit under, and this
// grant's own. A fiber with a mount namespace sees the parent covered and
// only its own directory bound back. PREPARE mntns has the zygote build
// that view once, in a mount namespace of its own, before it says READY,
// and every fiber's namespace is a copy of it. The namespace itself is
// taken at fz_init, before any thread, when FIBERD_OWN_MNTNS is in the
// zygote's environment. A launcher's fibers get no mount namespace, so
// its zygote is started without the variable and sent PREPARE none and
// nothing else.
// CLONE options are any of pidns, mntns, nocaps and handoff,
// comma-separated. With none the field is empty and the line ends in a
// space. The host queues the grant's TLS identity as the handoff channel's
// first message. A child that cannot get every confinement it asked for
// ends before it runs, and the zygote sends ERROR. A zygote that could not
// prepare its namespace says READY, then ERROR ? with the reason, and
// answers every mount-namespace CLONE with an ERROR.
package proc

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
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
	// RootBind is where the host's / is bind-mounted as the root of a
	// restored fiber's mount namespace, on the first resume that needs it
	// (default fiberd-root-<pid> under the temp directory). Every later
	// fiber unmounts it from its own namespace, because the bind would show
	// what HIDE covers. The backend makes the leaf directory and removes it
	// at Close, so its parent must be a place only the agent writes. It
	// refuses a symlink or another user's directory there, and unmounts a
	// stale bind at the same path when it opens.
	RootBind string
}

// Launcher starts the zygote for a Backend in an environment of its own.
type Launcher interface {
	// Name is the backend name this launcher gives the fork backend.
	Name() string
	// Command builds the command that starts argv as the warm instance
	// for spec with ctl as its fd 3, logging to logf. It is exec'd by the
	// backend inside spec's cgroup.
	Command(spec backend.WarmSpec, argv []string, ctl, logf *os.File) (*exec.Cmd, error)
	// Channel is the control channel to speak to the started instance
	// on, given boot, the host's end of the pair Command was handed.
	// A launcher whose instance lives in a network namespace of its own
	// makes a pair there and hands the instance its end over boot, so the
	// instance can be checkpointed holding it. Returning boot keeps it.
	Channel(ctx context.Context, spec backend.WarmSpec, cmd *exec.Cmd, boot *net.UnixConn) (*net.UnixConn, error)
	// Socketpair makes a unix pair the instance's fibers can be
	// checkpointed with (backend.ChannelMaker). pid is the instance as
	// the host sees it.
	Socketpair(spec backend.WarmSpec, pid int, typ int) ([2]int, error)
	// PID is the zygote process itself (the container's init) once
	// Command has started, as the host sees it.
	PID(ctx context.Context, spec backend.WarmSpec, cmd *exec.Cmd) (int, error)
	// Restored is told of every tree of spec's grant criu brought back,
	// rooted at pid as the host sees it, for what the restored
	// namespaces still need.
	Restored(spec backend.WarmSpec, pid int) error
	// RestoredGone is told once for every RestoreExtra, when the restore
	// failed or when the restored tree has exited, so what RestoreExtra
	// made for it on this home can go.
	RestoredGone(spec backend.WarmSpec)
	// Release ends whatever Command created besides the process.
	Release(spec backend.WarmSpec)
	// Endpoint maps a host path in spec.WorkDir to where the zygote sees
	// it (the run directory is bind-mounted into its namespace).
	Endpoint(spec backend.WarmSpec, hostPath string) string
	// DumpExtra and RestoreExtra are criu arguments for a tree that
	// lives inside the launcher's namespaces. Both are given the image
	// directory. DumpExtra may record there what its restore will need
	// to know. RestoreExtra may have to make what the restore needs on
	// this home first (a root filesystem for a grant it never warmed,
	// images the restored tree's own identity may read).
	DumpExtra(spec backend.WarmSpec, dir string) ([]string, error)
	RestoreExtra(spec backend.WarmSpec, dir string) ([]string, error)
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
	// byPID finds a fiber by the pid its zygote reports. A pid is only
	// meaningful with the zygote that reported it. With a launcher every
	// zygote is the init of a pid namespace of its own, so two zygotes
	// may both report pid 7.
	byPID map[pidKey]*fiber
	exits chan backend.Exit

	// defaultRoot means RootBind is the default fiberd-root-<pid>, so this
	// backend cleans stale siblings left by dead pids. rootHeld means this
	// backend holds a reference to the bind at RootBind. Both are under
	// rootMu.
	defaultRoot bool
	rootHeld    bool
}

// pidKey names a fiber by its zygote and the pid the zygote reported.
type pidKey struct {
	warm string
	pid  int
}

// rootBinds are the restore roots this process has mounted, shared by
// every backend that names the same one and unmounted when the last of
// them closes.
var (
	rootMu    sync.Mutex
	rootBinds = map[string]*rootBind{}
)

type rootBind struct {
	refs int // backends holding it
}

// rootName prefixes the default restore root's directory name.
const rootName = "fiberd-root-"

// bindRoot mounts the restore root at b.opt.RootBind on first use and
// takes this backend's reference to it.
func (b *Backend) bindRoot() error {
	dir := b.opt.RootBind
	rootMu.Lock()
	defer rootMu.Unlock()
	rb := rootBinds[dir]
	if rb == nil {
		if err := mountRoot(dir); err != nil {
			return fmt.Errorf("proc: restore root %s: %w", dir, err)
		}
		rb = &rootBind{}
		rootBinds[dir] = rb
	}
	if !b.rootHeld {
		b.rootHeld = true
		rb.refs++
	}
	return nil
}

// unbindRoot drops this backend's reference. The last one unmounts the
// bind and removes the directory.
func (b *Backend) unbindRoot() {
	dir := b.opt.RootBind
	rootMu.Lock()
	defer rootMu.Unlock()
	if !b.rootHeld {
		return
	}
	b.rootHeld = false
	rb := rootBinds[dir]
	if rb == nil {
		return
	}
	if rb.refs--; rb.refs > 0 {
		return
	}
	delete(rootBinds, dir)
	if err := syscall.Unmount(dir, syscall.MNT_DETACH); err != nil {
		log.Printf("proc: unmount restore root %s: %v", dir, err)
		return
	}
	_ = os.Remove(dir)
	_ = os.Remove(holderFile(dir))
}

// holderFile is where the process holding the restore root at dir
// records its pid. Another agent configured with the same RootBind reads
// it before reaping, so a live agent's bind is never pulled from under
// its fibers.
func holderFile(dir string) string { return dir + ".pid" }

// heldByLiveProcess reports whether the holder file names a process
// that is alive and is not this one. A missing, unreadable or malformed
// file, or a dead holder, means the bind is nobody's.
func heldByLiveProcess(pidfile string, self int) bool {
	b, err := os.ReadFile(pidfile)
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 || pid == self {
		return false
	}
	return !errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
}

// mountRoot binds / at dir, a leaf directory this process creates, or
// finds after an unclean shutdown. It checks dir before mounting over it,
// because mount(2) follows a planted symlink and a directory someone else
// owns is theirs to replace. The bind is private so nothing mounted under
// it propagates. Callers hold rootMu.
func mountRoot(dir string) error {
	if !filepath.IsAbs(dir) {
		return errors.New("want an absolute path")
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	created := false
	switch err := os.Mkdir(dir, 0o700); {
	case err == nil:
		created = true
	case !errors.Is(err, fs.ErrExist):
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	switch st, _ := fi.Sys().(*syscall.Stat_t); {
	case fi.Mode()&fs.ModeSymlink != 0:
		err = errors.New("is a symlink")
	case !fi.IsDir():
		err = errors.New("is not a directory")
	case st != nil && os.Geteuid() == 0 && st.Uid != 0:
		err = fmt.Errorf("is owned by uid %d", st.Uid)
	default:
		if ents, rerr := readMountinfo(); rerr == nil {
			for _, e := range ents {
				if e.point == dir {
					err = errors.New("is already a mount point (another instance's restore root?)")
					break
				}
			}
		}
	}
	if err == nil {
		err = syscall.Mount("/", dir, "", syscall.MS_BIND, "")
		if err == nil {
			// MS_BIND ignores propagation flags, so a second call sets them.
			if err = syscall.Mount("", dir, "", syscall.MS_PRIVATE, ""); err != nil {
				_ = syscall.Unmount(dir, syscall.MNT_DETACH)
			}
		}
	}
	if err != nil && created {
		_ = os.Remove(dir)
	}
	if err == nil {
		if werr := os.WriteFile(holderFile(dir), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); werr != nil {
			log.Printf("proc: record holder of restore root %s: %v", dir, werr)
		}
	}
	return err
}

// reapStaleRoots unmounts restore roots that earlier runs left behind. It
// takes a bind of / at dir, unless the holder file names a live process.
// With siblings it also takes fiberd-root-<pid> beside dir for a dead pid.
// Any other bind stays. Binds stacked at one path come off one per pass.
func reapStaleRoots(dir string, siblings bool) {
	rootMu.Lock()
	defer rootMu.Unlock()
	for pass := 0; pass < 16; pass++ {
		ents, err := readMountinfo()
		if err != nil {
			return
		}
		var slash *mountEntry
		for i := range ents {
			if ents[i].point == "/" {
				slash = &ents[i] // the last line is the mount on top
			}
		}
		if slash == nil {
			return
		}
		var stale []string
		for _, e := range ents {
			if e.point == "/" || e.dev != slash.dev || e.root != slash.root {
				continue // not a bind of /
			}
			if _, held := rootBinds[e.point]; held {
				continue
			}
			if e.point == dir && heldByLiveProcess(holderFile(dir), os.Getpid()) {
				continue
			}
			if e.point == dir || (siblings && deadSibling(dir, e.point)) {
				stale = append(stale, e.point)
			}
		}
		if len(stale) == 0 {
			return
		}
		for _, p := range stale {
			if err := syscall.Unmount(p, syscall.MNT_DETACH); err != nil {
				log.Printf("proc: unmount stale restore root %s: %v", p, err)
				continue
			}
			log.Printf("proc: unmounted stale restore root %s", p)
			_ = os.Remove(p) // fails while a bind is stacked underneath, and the next pass gets it
			_ = os.Remove(holderFile(p))
		}
	}
}

// deadSibling reports whether point is fiberd-root-<pid> in dir's
// directory for a pid without a process.
func deadSibling(dir, point string) bool {
	if filepath.Dir(point) != filepath.Dir(dir) {
		return false
	}
	rest, ok := strings.CutPrefix(filepath.Base(point), rootName)
	if !ok {
		return false
	}
	pid, err := strconv.Atoi(rest)
	if err != nil || pid <= 0 || strconv.Itoa(pid) != rest {
		return false
	}
	return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
}

// mountEntry is one line of /proc/self/mountinfo, the fields read here.
type mountEntry struct {
	dev   string // major:minor
	root  string // the mount's root within its filesystem
	point string // the mount point in this namespace
	opts  []string
}

func readMountinfo() ([]mountEntry, error) { return readMountinfoOf("/proc/self/mountinfo") }

// mountedAt reports whether pid's mount namespace has a mount at point,
// as pid sees the path.
func mountedAt(pid int, point string) bool {
	ents, err := readMountinfoOf(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		return false
	}
	for _, e := range ents {
		if e.point == point {
			return true
		}
	}
	return false
}

func readMountinfoOf(path string) ([]mountEntry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ents []mountEntry
	for _, line := range strings.Split(string(b), "\n") {
		// 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw
		f := strings.Fields(line)
		if len(f) < 7 {
			continue
		}
		e := mountEntry{dev: f[2], root: unescapeMount(f[3]), point: unescapeMount(f[4])}
		for _, o := range f[6:] {
			if o == "-" {
				break
			}
			e.opts = append(e.opts, o)
		}
		ents = append(ents, e)
	}
	return ents, nil
}

// unescapeMount undoes mountinfo's octal escapes (\040 for a space).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && isOctal(s[i+1]) && isOctal(s[i+2]) && isOctal(s[i+3]) {
			sb.WriteByte((s[i+1]-'0')<<6 | (s[i+2]-'0')<<3 | (s[i+3] - '0'))
			i += 3
			continue
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

func isOctal(c byte) bool { return c >= '0' && c <= '7' }

type zygote struct {
	id   string
	spec backend.WarmSpec
	cmd  *exec.Cmd
	pid  int // the zygote process as the host sees it (cmd's, or the container init's)
	ctl  *net.UnixConn
	pmu  sync.Mutex
	pend map[string]*pending // fence -> the Clone waiting for CLONED
	gone chan struct{}

	// The engine's device reports (DEVICE lines), when it sends any.
	dmu    sync.Mutex
	dev    map[string]uint64 // fence -> slice bytes
	devUse uint64
	devCap uint64
	devOK  bool
}

// pending is a Clone waiting on the zygote's answer. The reader builds
// the fiber from it when CLONED arrives (see cloned), so what the fiber
// needs beyond the zygote's line is here.
type pending struct {
	ch      chan cloneResult // buffered 1, written once by whoever takes the entry
	handoff bool
}

type cloneResult struct {
	pid int
	f   *fiber // registered under pid before the reply was sent
	err error
}

// parseCloned reads <fence> <pid> after the CLONED keyword and ignores the
// rest. ok is false when the line is too short or the pid is not positive.
func parseCloned(fields []string) (fence string, pid int, ok bool) {
	if len(fields) < 2 {
		return "", 0, false
	}
	pid, err := strconv.Atoi(fields[1])
	if err != nil || pid <= 0 {
		return "", 0, false
	}
	return fields[0], pid, true
}

type fiber struct {
	id       string
	pid      int // as the host sees it, under Backend.mu. 0 when unknown, and then never signalled
	zpid     int // as the zygote reported it (its own pid namespace); 0 for restored trees
	warmID   string
	restored *criu.Restored
	handoff  bool // holds a handoff channel at handoffFD
	// runDir is where the fiber's mount namespace binds its grant's run
	// directory (RUNDIR). The path is fixed at birth and survives every
	// park and resume, while the host directory behind it is the resuming
	// grant's. It is "" for a launcher's fiber or a restore without the
	// record.
	runDir string
}

// handoffFD is where libfiberzygote keeps a handoff fiber's channel
// (FZ_HANDOFF_FD).
const handoffFD = 4

// runDirFile, in a checkpoint of a fiber whose run directory was
// narrowed, records the mount point of its grant's directory in the
// fiber's namespace. The dump names that mount runDirKey, an external
// mount, and the restore binds the resuming grant's run directory there.
const (
	runDirFile = "fiberd-rundir.json"
	runDirKey  = "rundir"
)

type runDirRecord struct {
	MountPoint string `json:"mountpoint"`
}

// handoffFile, in a checkpoint of a handoff fiber, records the inode
// its channel had, the key criu restores a replacement under.
const handoffFile = "handoff.json"

type handoffRecord struct {
	Inode string `json:"inode"`
}

// New opens the backend. It offers FIBER_CHECKPOINT when `criu check`
// passes and FIBER_WARM otherwise.
func New(o Options) backend.Backend { return NewBackend(o) }

// NewBackend is New with the concrete type, for launchers that wrap it.
func NewBackend(o Options) *Backend {
	// The default names the process, so two agents on one host never
	// share it and a bind a dead one left is recognisable as such.
	defaultRoot := o.RootBind == ""
	if defaultRoot {
		o.RootBind = filepath.Join(os.TempDir(), rootName+strconv.Itoa(os.Getpid()))
	}
	o.RootBind = filepath.Clean(o.RootBind)
	b := &Backend{opt: o, criu: criu.Options{Bin: o.CRIU}, tier: core.TierWarm, defaultRoot: defaultRoot,
		zygotes: map[string]*zygote{}, fibers: map[string]*fiber{}, byPID: map[pidKey]*fiber{},
		exits: make(chan backend.Exit, 1024)}
	if o.Launcher == nil {
		// A launcher's fibers restore in its container, never on the
		// restore root. Only the plain fork backend owns one.
		reapStaleRoots(o.RootBind, defaultRoot)
	}
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

// EndpointSchemes: a forked fiber binds whatever it is told, a unix
// socket or a tcp port in the home's network namespace; criu restores
// a listening tcp socket on its port like any other.
func (b *Backend) EndpointSchemes() []string { return []string{"unix", "tcp"} }

// Handoff implements backend.Handoffer. libfiberzygote keeps the channel
// at a fixed descriptor, and criu treats it as external.
func (b *Backend) Handoff() bool { return true }

// Socketpair implements backend.ChannelMaker. Without a launcher the
// fibers share the host's network namespace and any pair will do. With
// one, the launcher makes the pair where the fiber's checkpoint can
// carry it, which needs the instance to be up.
func (b *Backend) Socketpair(warmID string, typ int) ([2]int, error) {
	if b.opt.Launcher == nil {
		return syscall.Socketpair(syscall.AF_UNIX, typ|syscall.SOCK_CLOEXEC, 0)
	}
	b.mu.Lock()
	z, ok := b.zygotes[warmID]
	b.mu.Unlock()
	if !ok {
		return [2]int{-1, -1}, fmt.Errorf("%s: no warm instance %q to make a channel for", b.Name(), warmID)
	}
	return b.opt.Launcher.Socketpair(z.spec, z.pid, typ)
}

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
	if b.opt.Launcher == nil && spec.Template.ZygoteSHA256 != "" {
		// A registry template is exec'd from a descriptor whose bytes
		// were hashed against what the host verified, so a swap of the
		// cache entry between the host's check and this exec runs
		// nothing. A rewrite in place is kept off by the hide list, which
		// covers the cache for every fiber. The descriptor is the
		// zygote's fd 4, open across the exec so a script template's
		// interpreter can read it too; a fiber closes everything above
		// its own descriptors. The zygote's /proc/self/exe still names
		// the path, which is what CRIU records.
		exe, err := openVerified(argv[0], spec.Template.ZygoteSHA256)
		if err != nil {
			_ = parentF.Close()
			return backend.Warm{}, fmt.Errorf("proc: template %s: %w", spec.Template.Digest, err)
		}
		defer func() { _ = exe.Close() }()
		cmd.ExtraFiles = append(cmd.ExtraFiles, exe)
		cmd.Path = exeFDPath
	}
	// The zygote's stdio goes to a log file, not to our stderr: a regular
	// file is something criu can checkpoint the zygote with; a pipe to a
	// process outside the tree is not.
	if err := os.MkdirAll(spec.WorkDir, 0o755); err != nil {
		_ = parentF.Close()
		return backend.Warm{}, err
	}
	// The grant's fibers write this directory as uid 0, so a name in
	// it may be a link one planted. The log is opened by name and never
	// through a link, and a warm over a planted one is refused.
	zlog, err := os.OpenFile(filepath.Join(spec.WorkDir, "zygote.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		_ = parentF.Close()
		if errors.Is(err, syscall.ELOOP) {
			err = fmt.Errorf("proc: %s/zygote.log is a link, not a file; refusing to write through it", spec.WorkDir)
		}
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
		// Nothing grant-specific, so the pages are identical on every
		// home. FIBERD_OWN_MNTNS has the zygote take a mount namespace
		// of its own in fz_init, before any thread, which it prepares
		// for its fibers before READY (see sendSetup).
		cmd.Env = []string{"PATH=/usr/bin:/bin", ownMntnsEnv}
		if len(spec.Devices) > 0 {
			// The fabric channel: the one grant-specific thing an engine
			// needs at warm-up (a CUDA engine reads it as its visible set).
			cmd.Env = append(cmd.Env, "FIBERD_DEVICES="+strings.Join(spec.Devices, ","))
		}
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
	// The zygote holds its own copy. Ours must close before READY is
	// awaited, or a zygote that dies first leaves the socket open on this
	// side and Warm waits for the whole deadline instead of seeing EOF.
	_ = childF.Close()
	conn, err := net.FileConn(parentF)
	_ = parentF.Close()
	if err != nil {
		endZygote(cmd)
		return backend.Warm{}, err
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		endZygote(cmd)
		return backend.Warm{}, errors.New("proc: control socket is not unix")
	}
	if b.opt.Launcher != nil {
		// The launcher may move the conversation onto a pair of its own
		// making. The zygote does the same on its side before READY.
		ch, err := b.opt.Launcher.Channel(ctx, spec, cmd, uc)
		if err != nil {
			endZygote(cmd)
			_ = uc.Close()
			b.release(&zygote{spec: spec})
			return backend.Warm{}, fmt.Errorf("%s: control channel for %s: %w", b.Name(), spec.GrantUID, err)
		}
		if ch != uc {
			_ = uc.Close()
			uc = ch
		}
	}
	// The setup lines go first. The zygote prepares the mount namespace
	// every fiber copies from them and says READY from inside it, so
	// READY means the view is built. A launcher's fibers get no mount
	// namespace (see Clone), and its zygote is told only that.
	if err := sendSetup(uc, spec.Hide, b.opt.RootBind, spec.WorkDir, b.opt.Launcher == nil); err != nil {
		endZygote(cmd)
		_ = uc.Close()
		b.release(&zygote{spec: spec})
		return backend.Warm{}, err
	}
	z := &zygote{id: spec.GrantUID, spec: spec, cmd: cmd, pid: cmd.Process.Pid, ctl: uc, pend: map[string]*pending{}, gone: make(chan struct{})}

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
			endZygote(cmd)
			_ = uc.Close()
			b.release(z)
			return backend.Warm{}, fmt.Errorf("%s: zygote for %s did not become ready: %w", b.Name(), spec.GrantUID, err)
		}
	case <-ctx.Done():
		endZygote(cmd)
		_ = uc.Close()
		b.release(z)
		return backend.Warm{}, ctx.Err()
	}
	if b.opt.Launcher != nil {
		pid, err := b.opt.Launcher.PID(ctx, spec, cmd)
		if err != nil {
			endZygote(cmd)
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

// openVerified opens the executable at path read-only and hashes its
// bytes through that descriptor. It returns the descriptor only when they
// hash to sha, the hash the host verified the cache entry at, so an exec
// through the descriptor (exeFDPath) runs the bytes that were checked and
// not whatever the path leads to by then.
func openVerified(path, sha string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		_ = f.Close()
		return nil, err
	}
	if sum := hex.EncodeToString(h.Sum(nil)); sum != sha {
		_ = f.Close()
		return nil, fmt.Errorf("executable %s hashes to %s, the host verified %s; the cache changed under it", path, sum[:12], sha[:12])
	}
	return f, nil
}

// exeFDPath is the path Warm execs a registry template through: the
// verified descriptor, which it passes as the zygote's fd 4, right after
// the control socket at fd 3.
const exeFDPath = "/proc/self/fd/4"

// ownMntnsEnv tells libfiberzygote to take a private mount namespace of
// its own at fz_init, so PREPARE mntns has one to fill. A launcher's
// zygote is started without it and keeps the container's namespace.
const ownMntnsEnv = "FIBERD_OWN_MNTNS=1"

// sendSetup tells the zygote, before READY, what a fiber with its own
// mount namespace covers (hide), unmounts (drop) and keeps of the run
// directory, then PREPARE mntns, on which the zygote builds that view in
// a mount namespace of its own. workDir is the grant's directory as the
// host sees it, which is also the zygote's view without a launcher. Its
// parent is the run directory all grants share, and fibers see it
// covered. With mntns false, a launcher's zygote, the paths are left out
// and PREPARE none is all that is sent. A zygote that exited already
// fails the write, which is reported as it not becoming ready.
func sendSetup(c *net.UnixConn, hide []string, drop, workDir string, mntns bool) error {
	var msg strings.Builder
	if mntns {
		for _, p := range hide {
			if !filepath.IsAbs(p) || strings.ContainsAny(p, " \t\r\n") {
				return fmt.Errorf("proc: cannot hide %q: want an absolute path without whitespace", p)
			}
			msg.WriteString("HIDE " + filepath.Clean(p) + "\n")
		}
		msg.WriteString("DROP " + drop + "\n")
		parent, own, err := runDirPair(workDir)
		if err != nil {
			return err
		}
		msg.WriteString("RUNDIR " + parent + " " + own + "\n")
		msg.WriteString("PREPARE mntns\n")
	} else {
		msg.WriteString("PREPARE none\n")
	}
	if _, err := c.Write([]byte(msg.String())); err != nil {
		return fmt.Errorf("proc: zygote did not become ready: sending its setup lines: %w", err)
	}
	return nil
}

// runDirPair returns the RUNDIR line's two paths, the parent that fibers
// see covered and the grant's own directory. A path that is relative,
// holds whitespace or sits right under / is an error, because the backend
// never warms a grant whose fibers would see other grants' endpoints.
func runDirPair(workDir string) (parent, own string, err error) {
	if !filepath.IsAbs(workDir) || strings.ContainsAny(workDir, " \t\r\n") {
		return "", "", fmt.Errorf("proc: run directory %q: want an absolute path without whitespace", workDir)
	}
	own = filepath.Clean(workDir)
	parent = filepath.Dir(own)
	if parent == "/" || own == "/" {
		return "", "", fmt.Errorf("proc: run directory %q sits right under /: its parent is what fibers see covered", workDir)
	}
	return parent, own, nil
}

// endZygote kills a zygote Warm gave up on and reaps it. Without the
// wait every failed warm would leave a zombie of this process behind.
func endZygote(cmd *exec.Cmd) {
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}

func (b *Backend) release(z *zygote) {
	if b.opt.Launcher != nil {
		b.opt.Launcher.Release(z.spec)
	}
}

// hostPID finds, among the processes in the fiber's leaf cgroup, the one
// the zygote reported as pid in its own pid namespace: the fiber's root
// as the host sees it. Without a launcher the two are the same. With
// one, a pid that cannot be translated is 0, never the container's
// number, because that number may be another process's on the host.
func (b *Backend) hostPID(cgroupFD int, reported int) int {
	if b.opt.Launcher == nil {
		return reported
	}
	if cgroupFD < 0 {
		return 0
	}
	procs, err := os.ReadFile(fmt.Sprintf("/proc/self/fd/%d/cgroup.procs", cgroupFD))
	if err != nil {
		return 0
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
	return 0
}

// CheckpointWarm implements backend.SelfCheckpointer: dump the zygote's
// pages while it keeps running, treating the control socket as external.
// A plain zygote lives in the mount namespace it prepared for its fibers,
// so its mounts are named the way a fiber's are at Park (the single-file
// mounts, and the run directory bind by name).
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
		more, err := b.opt.Launcher.DumpExtra(z.spec, dir)
		if err != nil {
			return err
		}
		extra = append(extra, more...)
	} else {
		mounts, err := mountExtra(z.pid, filepath.Clean(z.spec.WorkDir), dir)
		if err != nil {
			return fmt.Errorf("proc: mounts of the zygote for %s: %w", warmID, err)
		}
		extra = append(extra, mounts...)
	}
	return b.criu.DumpWith(ctx, z.pid, dir, true, extra)
}

// mountExtra is the criu dump arguments for the mount namespace of pid,
// a plain zygote or one of its fibers, written beside the images in dir.
// nil when pid shares the host's namespace. The run directory bind at
// runDir is dumped by name, like the single-file mounts. Autodetection
// would record the host path it came from, and a resume binds the
// resuming grant's directory instead.
func mountExtra(pid int, runDir, dir string) ([]string, error) {
	extra, err := criu.DumpMounts(pid, dir)
	if err != nil {
		return nil, err
	}
	if extra != nil && runDir != "" && mountedAt(pid, runDir) {
		rec, err := json.Marshal(runDirRecord{MountPoint: runDir})
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(dir, runDirFile), rec, 0o600); err != nil {
			return nil, err
		}
		extra = append(extra, "--external", "mnt["+runDir+"]:"+runDirKey)
	}
	return extra, nil
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
			fence, pid, ok := parseCloned(fields[1:])
			switch {
			case ok:
				b.cloned(z, fence, cloneResult{pid: pid})
			case len(fields) >= 2:
				// A fiber the backend cannot name a pid for is not one it
				// can hand out. The zygote ends it at the deadline.
				z.reply(fields[1], cloneResult{err: fmt.Errorf("%w: malformed %q", ErrZygote, strings.TrimSpace(line))})
			}
		case "ERROR":
			switch {
			case len(fields) >= 2 && fields[1] == "?":
				// The zygote refused a setup line or could not prepare
				// its mount namespace, not a clone. It refuses all of
				// the grant's mount-namespace clones after that.
				log.Printf("%s: zygote for %s: %s", b.Name(), z.id, strings.Join(fields[2:], " "))
			case len(fields) >= 2:
				z.reply(fields[1], cloneResult{err: fmt.Errorf("%w: %s", ErrZygote, strings.Join(fields[2:], " "))})
			}
		case "EXITED":
			if len(fields) >= 3 {
				pid, _ := strconv.Atoi(fields[1])
				b.exited(z, pid, fields[2])
			}
		case "DEVICE":
			// DEVICE <fence|-> <bytes> <capacity|0>: the engine's own
			// accounting, per fiber or for the whole device.
			if len(fields) >= 4 {
				used, _ := strconv.ParseUint(fields[2], 10, 64)
				capacity, _ := strconv.ParseUint(fields[3], 10, 64)
				z.dmu.Lock()
				if z.dev == nil {
					z.dev = map[string]uint64{}
				}
				switch {
				case fields[1] == "-":
					z.devUse, z.devCap, z.devOK = used, capacity, true
				case used == 0:
					delete(z.dev, fields[1])
				default:
					z.dev[fields[1]] = used
				}
				z.dmu.Unlock()
			}
		}
	}
}

// FiberDevice implements backend.DeviceReporter from the engine's lines.
func (b *Backend) FiberDevice(fiberID string) (uint64, bool) {
	b.mu.Lock()
	f, ok := b.fibers[fiberID]
	var z *zygote
	if ok {
		z = b.zygotes[f.warmID]
	}
	b.mu.Unlock()
	if z == nil {
		return 0, false
	}
	z.dmu.Lock()
	defer z.dmu.Unlock()
	if !z.devOK {
		return 0, false
	}
	return z.dev[fiberID], true
}

// WarmDevice implements backend.DeviceReporter.
func (b *Backend) WarmDevice(warmID string) (used, capacity uint64, ok bool) {
	b.mu.Lock()
	z := b.zygotes[warmID]
	b.mu.Unlock()
	if z == nil {
		return 0, 0, false
	}
	z.dmu.Lock()
	defer z.dmu.Unlock()
	return z.devUse, z.devCap, z.devOK
}

// EvictDevice implements backend.DeviceReporter: EVICT <fence> to the
// engine, which drops the slice and reports it gone.
func (b *Backend) EvictDevice(fiberID string) error {
	b.mu.Lock()
	f, ok := b.fibers[fiberID]
	var z *zygote
	if ok {
		z = b.zygotes[f.warmID]
	}
	b.mu.Unlock()
	if z == nil {
		return fmt.Errorf("proc: no engine for %q", fiberID)
	}
	if _, err := z.ctl.Write([]byte("EVICT " + fiberID + "\n")); err != nil {
		return fmt.Errorf("proc: send EVICT: %w", err)
	}
	return nil
}

// take removes and returns the Clone waiting on fence, if any. Whoever
// takes it owns the one send on its channel.
func (z *zygote) take(fence string) (*pending, bool) {
	z.pmu.Lock()
	p, ok := z.pend[fence]
	delete(z.pend, fence)
	z.pmu.Unlock()
	return p, ok
}

func (z *zygote) reply(fence string, res cloneResult) {
	if p, ok := z.take(fence); ok {
		p.ch <- res
	}
}

// cloned handles a CLONED line. The reader registers the fiber under the
// reported pid before Clone is answered, because the zygote may send
// EXITED for it right after and that exit must find it in byPID. With a
// launcher the reported pid is the container's number, so the fiber has
// no host pid until Clone translates it with the caller's cgroup fd.
func (b *Backend) cloned(z *zygote, fence string, res cloneResult) {
	p, ok := z.take(fence)
	if !ok {
		return // Clone gave up, and the zygote kills the child at its deadline
	}
	f := &fiber{id: fence, pid: res.pid, zpid: res.pid, warmID: z.id, handoff: p.handoff}
	if b.opt.Launcher != nil {
		f.pid = 0
	}
	if b.opt.Launcher == nil {
		// Its own mount namespace, with the run directory narrowed.
		f.runDir = filepath.Clean(z.spec.WorkDir)
	}
	b.mu.Lock()
	b.fibers[f.id] = f
	b.byPID[pidKey{z.id, f.zpid}] = f
	b.mu.Unlock()
	res.f = f
	p.ch <- res
}

// forget drops a fiber Clone could not hand to its caller, without
// reporting an exit. A later EXITED under its pid finds nothing.
func (b *Backend) forget(f *fiber) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fibers[f.id] != f {
		return
	}
	delete(b.fibers, f.id)
	if k := (pidKey{f.warmID, f.zpid}); f.zpid != 0 && b.byPID[k] == f {
		delete(b.byPID, k)
	}
}

func (b *Backend) zygoteGone(z *zygote) {
	b.mu.Lock()
	if b.zygotes[z.id] == z {
		delete(b.zygotes, z.id)
	}
	b.mu.Unlock()
	z.pmu.Lock()
	for fence, p := range z.pend {
		p.ch <- cloneResult{err: fmt.Errorf("%w: zygote exited", ErrZygote)}
		delete(z.pend, fence)
	}
	z.pmu.Unlock()
	b.release(z)
	b.exits <- backend.Exit{WarmID: z.id, Status: "zygote exited"}
}

// exited handles an EXITED line from z. The pid is z's view.
func (b *Backend) exited(z *zygote, zpid int, status string) {
	b.mu.Lock()
	f := b.byPID[pidKey{z.id, zpid}]
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
		delete(b.byPID, pidKey{f.warmID, f.zpid})
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
	// A launcher's fibers already live in its container's mount
	// namespace, which holds none of the agent's paths. They keep the
	// container's capabilities, because CRIU will not dump a fiber without
	// capabilities whose /proc is not its own pid namespace's.
	var opts []string
	if spec.OwnPIDNS {
		opts = append(opts, "pidns")
	}
	if b.opt.Launcher == nil {
		opts = append(opts, "mntns", "nocaps")
	}
	if spec.Handoff != nil {
		opts = append(opts, "handoff")
	}
	opt := strings.Join(opts, ",")
	endpoint := spec.Endpoint
	if b.opt.Launcher != nil && !strings.Contains(endpoint, "://") {
		// A unix path under the run directory is seen at the launcher's
		// mount; a tcp endpoint is the same address inside and out.
		endpoint = b.opt.Launcher.Endpoint(z.spec, endpoint)
	}
	msg := fmt.Sprintf("CLONE %s %s %d %s %s\n", spec.Fence, endpoint, deadline, payload, opt)
	reply := make(chan cloneResult, 1)
	z.pmu.Lock()
	z.pend[spec.Fence] = &pending{ch: reply, handoff: spec.Handoff != nil}
	z.pmu.Unlock()
	abandon := func() { b.abandon(z, spec.Fence, reply) }
	var fds []int
	if spec.CgroupFD >= 0 {
		fds = append(fds, spec.CgroupFD)
	}
	if spec.Handoff != nil {
		fds = append(fds, int(spec.Handoff.Fd()))
	}
	var rights []byte
	if len(fds) > 0 {
		rights = syscall.UnixRights(fds...)
	}
	if _, _, err := z.ctl.WriteMsgUnix([]byte(msg), rights, nil); err != nil {
		abandon()
		return backend.Fiber{}, fmt.Errorf("proc: send CLONE: %w", err)
	}
	select {
	case res := <-reply:
		if res.err != nil {
			return backend.Fiber{}, res.err
		}
		// The reader registered f under the zygote's pid. The host's pid
		// is found here, while the caller's cgroup fd is still open. A
		// fiber that already exited is out of b.fibers, so nothing
		// signals it.
		f := res.f
		pid := b.hostPID(spec.CgroupFD, res.pid)
		b.mu.Lock()
		if b.fibers[f.id] == f {
			f.pid = pid
		}
		b.mu.Unlock()
		return backend.Fiber{ID: f.id, PID: pid}, nil
	case <-ctx.Done():
		// The zygote enforces the same deadline and kills the child.
		abandon()
		return backend.Fiber{}, ctx.Err()
	case <-z.gone:
		abandon()
		return backend.Fiber{}, fmt.Errorf("%w: zygote exited", ErrZygote)
	}
}

// abandon is Clone returning without a fiber. It drops the pending entry
// and forgets any fiber the reader already registered, since the caller
// never learns of it. The zygote kills the unwaited child at its deadline.
// Whoever takes the entry sends on reply exactly once, so a failed take
// here means the reader or zygoteGone is already answering.
func (b *Backend) abandon(z *zygote, fence string, reply chan cloneResult) {
	if _, ok := z.take(fence); ok {
		return
	}
	if res := <-reply; res.f != nil {
		b.forget(res.f)
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
	var z *zygote
	var pid int
	if ok {
		z = b.zygotes[f.warmID]
		pid = f.pid
	}
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("proc: unknown fiber %q", fiberID)
	}
	if pid <= 0 {
		return fmt.Errorf("proc: fiber %q has no host pid to dump", fiberID)
	}
	var extra []string
	switch {
	case b.opt.Launcher != nil && z == nil:
		// The tree lives in a container whose mounts only the launcher
		// can name for criu. A dump without them would not restore.
		return fmt.Errorf("proc: fiber %q: its zygote is gone, cannot name its container's mounts", fiberID)
	case b.opt.Launcher != nil:
		var err error
		if extra, err = b.opt.Launcher.DumpExtra(z.spec, spec.Dir); err != nil {
			return err
		}
	case b.opt.Launcher == nil:
		var err error
		if extra, err = mountExtra(pid, f.runDir, spec.Dir); err != nil {
			return fmt.Errorf("proc: mounts of %s: %w", fiberID, err)
		}
	}
	if f.handoff {
		// The channel's peer is the host's end, outside the dumped tree.
		ino, err := criu.SocketInode(pid, handoffFD)
		if err != nil {
			return fmt.Errorf("proc: handoff channel of %s: %w", fiberID, err)
		}
		if err := os.MkdirAll(spec.Dir, 0o700); err != nil {
			return err
		}
		rec, err := json.Marshal(handoffRecord{Inode: ino})
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(spec.Dir, handoffFile), rec, 0o600); err != nil {
			return err
		}
		extra = append(extra, "--external", "unix["+ino+"]")
	}
	return b.criu.DumpWith(ctx, pid, spec.Dir, spec.Sync, extra)
}

// handoffInherit returns the criu arguments and files that restore a
// handoff checkpoint in dir with ch as its new channel. Every other
// checkpoint takes neither, and ch must then be nil.
func handoffInherit(dir string, ch *os.File) ([]string, []*os.File, error) {
	b, err := os.ReadFile(filepath.Join(dir, handoffFile))
	switch {
	case errors.Is(err, os.ErrNotExist) && ch == nil:
		return nil, nil, nil
	case errors.Is(err, os.ErrNotExist):
		return nil, nil, fmt.Errorf("proc: checkpoint %s has no handoff channel to replace", dir)
	case err != nil:
		return nil, nil, err
	case ch == nil:
		return nil, nil, fmt.Errorf("proc: checkpoint %s serves handoff and needs a channel", dir)
	}
	var rec handoffRecord
	if err := json.Unmarshal(b, &rec); err != nil || rec.Inode == "" {
		return nil, nil, fmt.Errorf("proc: %s in %s: malformed", handoffFile, dir)
	}
	return []string{"--inherit-fd", "fd[3]:socket:[" + rec.Inode + "]"}, []*os.File{ch}, nil
}

// runDirInherit returns the criu arguments that bind the run directory
// mount dir records to workDir, the resuming grant's run directory, plus
// the mount point to remember for the next park. A checkpoint without
// the record takes nothing.
func runDirInherit(dir, workDir string) ([]string, string, error) {
	b, err := os.ReadFile(filepath.Join(dir, runDirFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	var rec runDirRecord
	if err := json.Unmarshal(b, &rec); err != nil || !filepath.IsAbs(rec.MountPoint) {
		return nil, "", fmt.Errorf("proc: %s in %s: malformed", runDirFile, dir)
	}
	if !filepath.IsAbs(workDir) {
		return nil, "", fmt.Errorf("proc: checkpoint %s has a run directory to bind and needs the grant's (WorkDir)", dir)
	}
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return nil, "", err
	}
	return []string{"--external", "mnt[" + runDirKey + "]:" + filepath.Clean(workDir)}, rec.MountPoint, nil
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
	runDir := ""
	// gone tells the launcher the tree it prepared for never came up, or
	// has exited.
	gone := func() {}
	if b.opt.Launcher != nil {
		// The tree was dumped inside a container of this grant; it is
		// restored with that container's root and mounts.
		workDir := spec.WorkDir
		if workDir == "" {
			workDir = filepath.Dir(spec.Endpoint)
		}
		var err error
		wspec := backend.WarmSpec{GrantUID: spec.WarmID, WorkDir: workDir}
		if extra, err = b.opt.Launcher.RestoreExtra(wspec, spec.Dir); err != nil {
			return backend.Fiber{}, err
		}
		gone = func() { b.opt.Launcher.RestoredGone(wspec) }
	} else {
		var err error
		if extra, err = criu.RestoreMounts(spec.Dir, b.opt.RootBind); err != nil {
			return backend.Fiber{}, err
		}
		if extra != nil {
			if err := b.bindRoot(); err != nil {
				return backend.Fiber{}, err
			}
			// The fiber's run directory, if the checkpoint has one, is
			// bound to the resuming grant's, where the host dials and
			// writes the fence file. Its path inside the fiber stays the
			// one it was born with.
			var more []string
			if more, runDir, err = runDirInherit(spec.Dir, spec.WorkDir); err != nil {
				return backend.Fiber{}, err
			}
			extra = append(extra, more...)
		}
	}
	inherit, files, err := handoffInherit(spec.Dir, spec.Handoff)
	if err != nil {
		gone()
		return backend.Fiber{}, err
	}
	res, err := b.criu.RestoreWith(rctx, spec.Dir, spec.CgroupFD, append(extra, inherit...), files)
	if err != nil {
		gone()
		return backend.Fiber{}, err
	}
	if b.opt.Launcher != nil {
		if err := b.opt.Launcher.Restored(backend.WarmSpec{GrantUID: spec.WarmID, WorkDir: spec.WorkDir}, res.PID); err != nil {
			log.Printf("%s: restored %s: %v", b.Name(), spec.Fence, err)
		}
	}
	f := &fiber{id: spec.Fence, pid: res.PID, restored: res, warmID: spec.WarmID, handoff: spec.Handoff != nil, runDir: runDir}
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
		gone()
	}()
	return backend.Fiber{ID: f.id, PID: f.pid}, nil
}

// Kill ends the fiber's root process; the exit is reported like any other.
// A fiber already reported gone is a no-op. One whose host pid is unknown
// is an error, never a signal, because kill(2) of 0 is this process group
// and a negative or guessed number is some other process.
func (b *Backend) Kill(fiberID string) error {
	b.mu.Lock()
	f, ok := b.fibers[fiberID]
	pid := 0
	if ok {
		pid = f.pid
	}
	b.mu.Unlock()
	if !ok {
		return nil
	}
	if pid <= 0 {
		return fmt.Errorf("proc: fiber %q has no host pid to signal", fiberID)
	}
	return syscall.Kill(pid, syscall.SIGKILL)
}

func (b *Backend) Exits() <-chan backend.Exit { return b.exits }

// Close kills every zygote (and with them every fiber) and gives up the
// restore root.
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
	b.unbindRoot()
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
	_ backend.ChannelMaker     = (*Backend)(nil)
	_ backend.SelfCheckpointer = (*Backend)(nil)
	_ backend.DeltaCodec       = (*Backend)(nil)
	_ backend.DeviceReporter   = (*Backend)(nil)
)
