//go:build linux

// Package runc is the proc backend with a launcher that runs the zygote as
// the init of an OCI container. The container gets a per-grant copy of the
// root filesystem, the grant's run directory at /host, and user, pid,
// mount, network, ipc and uts namespaces. The user namespace maps to a host
// id range derived from the grant uid (see IDPool), so the kernel refuses
// fibers the host's sysctls, sysfs knobs and cgroup limits by ownership.
// The network namespace holds only the loopback, so fibers serve unix
// sockets or handed-off connections.
package runc

import (
	"context"
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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/backend/proc"
	"github.com/helayoty/fiberd/pkg/sys/netns"
)

// Options configure the runc backend.
type Options struct {
	// Runc names the runc binary (default "runc").
	Runc string
	// Rootfs is the directory every grant's root filesystem is copied
	// from. Template commands are paths inside it. Required.
	Rootfs string
	// StateDir holds runc's container state, the bundles and the
	// per-grant root filesystem copies (default /var/lib/fiberd/runc).
	StateDir string
	// CRIU names the criu binary (default "criu").
	CRIU string
	// Pool is the host id space grants' user namespaces map into
	// (default DefaultPool).
	Pool IDPool
	// SubIDFiles are the host's subordinate id files the pool must not
	// overlap (default DefaultSubIDFiles). For tests.
	SubIDFiles []string
}

// Backend is the proc backend with the runc launcher.
type Backend struct {
	*proc.Backend
	l *launcher
}

type launcher struct {
	opt    Options
	claims *claims

	// fsMu serialises taking and giving back one grant's hold on its id
	// range together with making and removing its root filesystem copy.
	// The copy lives exactly as long as the grant holds the range here.
	fsMu    sync.Mutex
	fsLocks map[string]*sync.Mutex

	// staged maps a container id to the directory holding the launcher's
	// verified copy of the grant's registry template, bound at
	// backend.TemplateMount in its container, from Command until Release.
	// A grant on a template from the rootfs has no entry.
	smu    sync.Mutex
	staged map[string]string
}

// fsLock is the grant's lock for its hold and root filesystem copy.
func (l *launcher) fsLock(spec backend.WarmSpec) *sync.Mutex {
	l.fsMu.Lock()
	defer l.fsMu.Unlock()
	if l.fsLocks == nil {
		l.fsLocks = map[string]*sync.Mutex{}
	}
	m, ok := l.fsLocks[l.cid(spec)]
	if !ok {
		m = &sync.Mutex{}
		l.fsLocks[l.cid(spec)] = m
	}
	return m
}

// New opens the backend. Without runc or the rootfs it opens as a
// backend that cannot warm anything. It refuses a pool that is not a
// usable id space or that overlaps a range the host has handed out in
// /etc/subuid or /etc/subgid.
//
// No previous agent holds a range when the backend opens. The agent kills
// every fiber of a prior epoch at reconcile, and a stale container is
// ended here and again when its grant is warmed. So the claims start
// empty, and every root filesystem copy and bundle under the state
// directory is a leftover to sweep.
func New(o Options) (backend.Backend, error) {
	if o.Runc == "" {
		o.Runc = "runc"
	}
	if o.StateDir == "" {
		o.StateDir = "/var/lib/fiberd/runc"
	}
	if o.Pool == (IDPool{}) {
		o.Pool, _ = ParsePool(DefaultPool)
	}
	if err := o.Pool.Validate(); err != nil {
		return nil, fmt.Errorf("runc: userns pool: %w", err)
	}
	if err := o.Pool.CheckSubIDs(o.SubIDFiles...); err != nil {
		return nil, fmt.Errorf("runc: %w", err)
	}
	// The mapped root walks through the state directory to its root
	// filesystem copy, so the directory is made here, searchable, before
	// runc gets to make it as its own private 0700 state root.
	if err := os.MkdirAll(o.StateDir, 0o755); err != nil {
		return nil, fmt.Errorf("runc: state directory: %w", err)
	}
	l := &launcher{opt: o, claims: newClaims(o.Pool)}
	l.sweep()
	return &Backend{Backend: proc.NewBackend(proc.Options{CRIU: o.CRIU, CRIUWrap: l.sysWrap(), Launcher: l}), l: l}, nil
}

// sweep ends the containers a previous life left in runc's state and
// removes every bundle and root filesystem copy. A copy whose grant is
// warmed or resumed again is made afresh.
func (l *launcher) sweep() {
	ctx := context.Background()
	if _, err := os.Stat(l.root()); err == nil {
		// Only with a state root from before. Asking runc about one that
		// does not exist would have it make the directory.
		if out, err := l.runc(ctx, "list", "-q"); err == nil {
			for _, id := range strings.Fields(out) {
				_, _ = l.runc(ctx, "kill", id, "KILL")
				_, _ = l.runc(ctx, "delete", "-f", id)
			}
		}
	}
	for _, sub := range []string{"rootfs", "bundles", "templates"} {
		ents, err := os.ReadDir(filepath.Join(l.opt.StateDir, sub))
		if err != nil {
			continue
		}
		for _, e := range ents {
			p := filepath.Join(l.opt.StateDir, sub, e.Name())
			if err := os.RemoveAll(p); err != nil {
				log.Printf("runc: sweep %s: %v", p, err)
			} else {
				log.Printf("runc: swept leftover %s", p)
			}
		}
	}
}

// Platform: the checkpoints depend on the host kernel like proc's, and
// on the rootfs the zygote was built against rather than the host libc.
func (b *Backend) Platform() artifact.Platform {
	return artifact.Platform{Libc: "rootfs-" + filepath.Base(b.l.opt.Rootfs)}
}

// EndpointSchemes is unix only. The container's network namespace has no
// route out, so a tcp endpoint bound inside it could never be dialled.
// Fibers serve unix sockets under /host, which the host relays a tcp
// port to under a tcp policy, or handed-off connections (see
// proc.Backend.Handoff).
func (b *Backend) EndpointSchemes() []string { return []string{"unix"} }

// MappedRoot implements backend.IDMapper.
func (b *Backend) MappedRoot(grantUID string) (uint32, error) {
	if err := b.l.claims.check(grantUID); err != nil {
		return 0, err
	}
	return b.l.opt.Pool.Range(grantUID).Start, nil
}

func (l *launcher) Name() string { return "runc" }

func (l *launcher) root() string { return filepath.Join(l.opt.StateDir, "root") }

func (l *launcher) cid(spec backend.WarmSpec) string {
	return "w-" + strings.NewReplacer("/", "-", ":", "-").Replace(spec.GrantUID)
}

func (l *launcher) bundle(spec backend.WarmSpec) string {
	return filepath.Join(l.opt.StateDir, "bundles", l.cid(spec))
}

// runcLog is runc's own log for the grant's `runc run`, at debug level,
// beside the bundle rather than in it, so it outlives Release and a
// failure dump can read it. It is in the state directory, which the
// container never sees, so nothing inside can plant a link there. The
// sweep at the next start removes it with the bundles.
func (l *launcher) runcLog(spec backend.WarmSpec) string {
	return filepath.Join(l.opt.StateDir, "bundles", l.cid(spec)+".runc.log")
}

// logTails is what runc and the zygote last wrote, for an error about a
// container that never came up. runc's log holds its error and the
// stages before it. The zygote log holds runc's stdio and the template's
// (the zygote reopens its stdio to it inside). Both are bounded, and
// neither holds a secret, since the zygote's log is the template's own
// stdio and runc's is runc's.
func (l *launcher) logTails(spec backend.WarmSpec) string {
	var b strings.Builder
	for _, f := range []struct{ name, path string }{
		{"runc log", l.runcLog(spec)},
		{"zygote log", filepath.Join(spec.WorkDir, "zygote.log")},
	} {
		tail := tailFile(f.path, tailLimit)
		if tail == "" {
			fmt.Fprintf(&b, "\n%s %s: empty or missing", f.name, f.path)
			continue
		}
		fmt.Fprintf(&b, "\n%s %s (last %d bytes):\n%s", f.name, f.path, len(tail), strings.TrimRight(tail, "\n"))
	}
	return b.String()
}

// rootfs is where the grant's copy of the root filesystem lives.
func (l *launcher) rootfs(spec backend.WarmSpec) string {
	return filepath.Join(l.opt.StateDir, "rootfs", l.cid(spec))
}

// sysDir is where runc and criu find the bind of the host's /sys mount
// that sysWrap makes them, the source of every container's /sys.
func (l *launcher) sysDir() string { return filepath.Join(l.opt.StateDir, "sys") }

// sysWrap is the command `runc run` and `criu restore` run through (its
// argv follows): a private mount namespace of their own with the host's
// top /sys mount alone bound at sysDir, read-only, nosuid, nodev and
// noexec. A container gets its /sys as a bind of that directory rather
// than a sysfs mount of its own, because the kernel lets a user
// namespace mount sysfs only while an existing sysfs mount is fully
// visible to it, and a Pod's /sys can have a locked mount covering part
// of it (the mount then fails with EPERM). The bind is of the top mount
// alone, so no cgroup or other mount under the host's /sys comes with
// it, and a restore needs it for the same reason: a bind of the host's
// /sys from inside the restored tree's namespace trips over the same
// locks. It lives in the wrapper's namespace alone, so the agent's own
// mounts, which a proc fiber's namespace copies, stay as they were. The
// container's copy of the bind carries the flags locked, so the mapped
// root cannot lift them.
func (l *launcher) sysWrap() []string {
	return []string{"unshare", "--mount", "--propagation", "private", "sh", "-c",
		`mount --bind /sys "$0" && mount -o remount,bind,ro,nosuid,nodev,noexec "$0" && exec "$@"`, l.sysDir()}
}

// sysMountPoint makes sure sysDir is there for sysWrap to bind at.
func (l *launcher) sysMountPoint() error {
	if err := os.MkdirAll(l.sysDir(), 0o755); err != nil {
		return fmt.Errorf("runc: /sys bind: %w", err)
	}
	return nil
}

// templateDir is where the grant's verified copy of its registry
// template lives, the directory its container binds at
// backend.TemplateMount.
func (l *launcher) templateDir(spec backend.WarmSpec) string {
	return filepath.Join(l.opt.StateDir, "templates", l.cid(spec))
}

// stagedFor is the staged template directory of the grant's warm
// instance on this home, or "" when it has none.
func (l *launcher) stagedFor(spec backend.WarmSpec) string {
	l.smu.Lock()
	defer l.smu.Unlock()
	return l.staged[l.cid(spec)]
}

// setStaged records, or with "" forgets, the grant's staged directory.
func (l *launcher) setStaged(spec backend.WarmSpec, dir string) {
	l.smu.Lock()
	defer l.smu.Unlock()
	if dir == "" {
		delete(l.staged, l.cid(spec))
		return
	}
	if l.staged == nil {
		l.staged = map[string]string{}
	}
	l.staged[l.cid(spec)] = dir
}

// templateFile, beside a checkpoint of a fiber whose container binds a
// registry template, records that the tree holds the mount at
// backend.TemplateMount. The dump names that mount templateKey, an
// external mount, and the restore binds this home's verified copy there.
const (
	templateFile = "fiberd-template.json"
	templateKey  = "template"
)

type templateRecord struct {
	MountPoint string `json:"mountpoint"`
}

func (l *launcher) runc(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, l.opt.Runc, append([]string{"--root", l.root()}, args...)...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("runc %s: %w: %s", args[0], err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// cgroupPath resolves an open cgroup directory fd to the path runc's
// cgroupsPath wants, relative to the cgroup v2 mount.
func cgroupPath(fd int) (string, error) {
	p, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return "", err
	}
	const root = "/sys/fs/cgroup"
	if !strings.HasPrefix(p, root) {
		return "", fmt.Errorf("runc: cgroup %s is not under %s", p, root)
	}
	rel := strings.TrimPrefix(p, root)
	if rel == "" {
		rel = "/"
	}
	return rel, nil
}

// deviceBinds are the device nodes runc bind-mounts into a container
// with a user namespace, where mknod is not allowed. Each is a mount from
// outside the container, named for criu on both sides of a checkpoint.
var deviceBinds = []string{"null", "zero", "full", "random", "urandom", "tty"}

// containerCaps is what the zygote holds inside its user namespace. They
// are capabilities over the namespace's own resources only. SYS_ADMIN
// for clone3 into a pid namespace and the mounts, SYS_RESOURCE for the
// zygote to cap nested user namespaces at init (it drops it before
// serving, see zygote/libfiberzygote.c), and the rest as runc's defaults
// for an init that forks and signals children.
var containerCaps = []string{"CAP_SYS_ADMIN", "CAP_KILL", "CAP_SETPCAP", "CAP_SETUID", "CAP_SETGID", "CAP_SYS_PTRACE",
	"CAP_DAC_OVERRIDE", "CAP_CHOWN", "CAP_FOWNER", "CAP_SYS_RESOURCE"}

// nestedUsernsEnv tells libfiberzygote to set user.max_user_namespaces
// to 0 inside its user namespace before it serves, so a fiber cannot
// make a namespace of its own and be capable again. rebindEnv tells it
// to take its control socket from a REBIND message on the bootstrap one
// first (see Channel).
const (
	nestedUsernsEnv = "FIBERD_USERNS_NESTED=deny"
	rebindEnv       = "FIBERD_CTL_REBIND=1"
)

// hold takes the grant's id range for one user, its warm zygote (warm)
// or one fiber about to be restored here, and makes sure the grant's
// root filesystem copy is there. The hold is given back by drop, and
// the copy goes with the last hold. Taking the hold and making the copy
// happen under one lock, so a drop that finds the grant free never
// removes a copy a new hold has just found in place.
func (l *launcher) hold(spec backend.WarmSpec, warm bool) (string, error) {
	mu := l.fsLock(spec)
	mu.Lock()
	defer mu.Unlock()
	if err := l.claims.acquire(spec.GrantUID, warm); err != nil {
		return "", err
	}
	rootfs, err := l.ensureRootfs(spec, l.opt.Pool.Range(spec.GrantUID))
	if err != nil {
		if l.claims.release(spec.GrantUID, warm) {
			_ = os.RemoveAll(l.rootfs(spec))
		}
		return "", err
	}
	return rootfs, nil
}

// drop gives one user's hold on the grant's id range back and removes
// the root filesystem copy with the last one.
func (l *launcher) drop(spec backend.WarmSpec, warm bool) {
	mu := l.fsLock(spec)
	mu.Lock()
	defer mu.Unlock()
	if l.claims.release(spec.GrantUID, warm) {
		_ = os.RemoveAll(l.rootfs(spec))
	}
}

// Command writes the bundle and builds `runc run` with fd 3 preserved.
// It holds the grant's id range as the zygote until Release.
func (l *launcher) Command(spec backend.WarmSpec, argv []string, ctl, logf *os.File) (cmd *exec.Cmd, err error) {
	if st, err := os.Stat(l.opt.Rootfs); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("runc: rootfs %q unusable", l.opt.Rootfs)
	}
	rootfs, err := l.hold(spec, true)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			l.drop(spec, true)
		}
	}()
	rng := l.opt.Pool.Range(spec.GrantUID)
	if err := prepareWorkDir(spec.WorkDir, rng); err != nil {
		return nil, err
	}
	if err := l.sysMountPoint(); err != nil {
		return nil, err
	}
	// A registry template lives in the host's cache, outside the rootfs.
	// The launcher's own verified copy of its executable is bound
	// read-only at backend.TemplateMount, and the command runs from
	// there (backend.StageTemplate). The copy is the mapped root's to
	// read and run (mode 0555) and nobody's to write.
	mounts := []map[string]any{
		{"destination": "/proc", "type": "proc", "source": "proc"},
		{"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": []string{"nosuid", "strictatime", "mode=755", "size=65536k"}},
		// /sys is a read-only bind of the host's sysfs that sysWrap
		// makes runc, not a sysfs mount of the container's own, which
		// the kernel refuses a user namespace in some Pods. The kernel
		// refuses the mapped root every knob by ownership before the
		// mount flag is looked at. No cgroup mount. The zygote is
		// handed each leaf as a descriptor and never needs the
		// hierarchy by path.
		{"destination": "/sys", "type": "bind", "source": l.sysDir(), "options": []string{"rbind", "nosuid", "noexec", "nodev", "ro"}},
		{"destination": "/host", "type": "bind", "source": spec.WorkDir, "options": []string{"rbind", "rw"}},
	}
	tdir := l.templateDir(spec)
	_ = os.RemoveAll(tdir)
	l.setStaged(spec, "")
	if spec.Template.Dir != "" {
		staged := filepath.Join(tdir, "template")
		defer func() {
			if err != nil {
				_ = os.RemoveAll(tdir)
			}
		}()
		if argv, err = backend.StageTemplate(spec.Template, staged); err != nil {
			return nil, fmt.Errorf("runc: %w", err)
		}
		mounts = append(mounts, map[string]any{"destination": backend.TemplateMount, "type": "bind", "source": staged, "options": backend.TemplateMountOptions})
		l.setStaged(spec, staged)
	}
	// The host opened the log as root. The zygote reopens it from inside
	// as the mapped root, which needs group write.
	if err := logf.Chmod(0o664); err != nil {
		return nil, fmt.Errorf("runc: chmod zygote log: %w", err)
	}
	if err := logf.Chown(-1, int(rng.Start)); err != nil {
		return nil, fmt.Errorf("runc: chown zygote log: %w", err)
	}
	cgPath := ""
	if spec.CgroupFD >= 0 {
		p, err := cgroupPath(spec.CgroupFD)
		if err != nil {
			return nil, err
		}
		cgPath = p
	}
	b := l.bundle(spec)
	if err := os.MkdirAll(b, 0o755); err != nil {
		return nil, err
	}
	idMap := []map[string]uint32{{"containerID": 0, "hostID": rng.Start, "size": rng.Count}}
	cfg := map[string]any{
		"ociVersion": "1.0.2",
		"process": map[string]any{
			"terminal": false,
			"user":     map[string]int{"uid": 0, "gid": 0},
			"cwd":      "/host", // criu's parasite scratch lands on the bind mount, not the rootfs
			"args":     append(append([]string{}, argv...), "--log", "/host/zygote.log"),
			"env":      []string{"PATH=/usr/bin:/bin", nestedUsernsEnv, rebindEnv},
			"capabilities": map[string][]string{
				"bounding":    containerCaps,
				"effective":   containerCaps,
				"permitted":   containerCaps,
				"inheritable": {},
			},
			"noNewPrivileges": false,
		},
		"root":     map[string]any{"path": rootfs, "readonly": false},
		"hostname": "fiber",
		"mounts":   mounts,
		"linux": map[string]any{
			// No cgroup namespace, since the zygote's clone3 into a leaf
			// needs to see the host's hierarchy. The network namespace is
			// new and empty but for the loopback runc brings up.
			"namespaces":  []map[string]string{{"type": "user"}, {"type": "pid"}, {"type": "mount"}, {"type": "network"}, {"type": "ipc"}, {"type": "uts"}},
			"uidMappings": idMap,
			"gidMappings": idMap,
			"cgroupsPath": cgPath,
			// The runc/Docker defaults, kept as the second line behind the
			// user namespace. runc skips a path the rootfs or this kernel
			// lacks.
			"readonlyPaths": []string{"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"},
			"maskedPaths": []string{"/proc/kcore", "/proc/keys", "/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats",
				"/proc/sched_debug", "/proc/scsi", "/sys/firmware", "/sys/devices/virtual/powercap"},
		},
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(b, "config.json"), data, 0o644); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(l.root(), 0o700); err != nil {
		return nil, err
	}
	_, _ = l.runc(context.Background(), "delete", "-f", l.cid(spec)) // a stale one from a previous life
	// runc's own log, fresh for this run and at debug level, so a
	// container that never comes up says which stage it died in.
	if err := os.Remove(l.runcLog(spec)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("runc: remove old runc log: %w", err)
	}
	wrap := l.sysWrap()
	cmd = exec.Command(wrap[0], append(wrap[1:], l.opt.Runc, "--root", l.root(), "--log", l.runcLog(spec), "--debug",
		"run", "--preserve-fds", "1", "--bundle", b, l.cid(spec))...)
	cmd.ExtraFiles = []*os.File{ctl} // fd 3 in the container's init
	devnull, err := os.OpenFile(os.DevNull, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	// runc's own stdio. The zygote reopens its stdio inside (--log), so
	// no descriptor of a host file survives into the container.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	log.Printf("runc: grant %s runs as host ids %d-%d", spec.GrantUID, rng.Start, uint64(rng.Start)+uint64(rng.Count)-1)
	return cmd, nil
}

// prepareWorkDir lets the mapped root create its sockets in the grant's
// run directory. The directory stays root's with the grant's mapped gid
// and group write, so the zygote can bind in it but cannot change the
// directory's mode or owner (it does not own it, and its DAC_OVERRIDE
// does not reach an inode owned by an id outside its namespace). The
// agent connects to the sockets the mapped root creates through its own
// DAC_OVERRIDE.
func prepareWorkDir(dir string, rng IDRange) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.Chown(dir, 0, int(rng.Start)); err != nil {
		return fmt.Errorf("runc: chown run directory %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o775); err != nil {
		return fmt.Errorf("runc: chmod run directory %s: %w", dir, err)
	}
	return nil
}

// rootfsMarker, inside a copy, says what it is a copy of and for which
// ids. A copy with a different marker is remade.
const rootfsMarker = ".fiberd-rootfs.json"

type rootfsRecord struct {
	Source string `json:"source"`
	Start  uint32 `json:"start"`
	Count  uint32 `json:"count"`
}

// mountpoints are the directories the container's mounts need in the
// root filesystem. runc makes them in the copy when it starts the
// container, and a restore with --root needs them there before any
// container has run on this home. backend.TemplateMount is among them
// whether or not the grant binds a template, so a copy made for a
// restore has it; it stays an empty directory for a template from the
// rootfs.
var mountpoints = []string{"proc", "dev", "sys", "host", "tmp", strings.TrimPrefix(backend.TemplateMount, "/")}

// ensureRootfs makes the grant's copy of the root filesystem, chowned
// to its range, or keeps the one an earlier hold left when it matches.
// The caller holds the grant's fsLock. Idmapped mounts would avoid the
// copy and are not available on the runc 1.1 line fiberd targets.
func (l *launcher) ensureRootfs(spec backend.WarmSpec, rng IDRange) (string, error) {
	dst := l.rootfs(spec)
	want := rootfsRecord{Source: l.opt.Rootfs, Start: rng.Start, Count: rng.Count}
	if have, err := readRootfsMarker(dst); err == nil && have == want {
		return dst, nil
	}
	_ = os.RemoveAll(dst)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", err
	}
	if err := copyTree(l.opt.Rootfs, dst, rng); err != nil {
		_ = os.RemoveAll(dst)
		return "", fmt.Errorf("runc: copy rootfs for %s: %w", spec.GrantUID, err)
	}
	for _, d := range mountpoints {
		if err := makeMountpoint(dst, d, rng); err != nil {
			_ = os.RemoveAll(dst)
			return "", err
		}
	}
	data, err := json.Marshal(want)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dst, rootfsMarker), data, 0o644); err != nil {
		_ = os.RemoveAll(dst)
		return "", err
	}
	return dst, nil
}

// makeMountpoint makes rel under root, every level of it, owned by the
// mapped root so it can be walked from inside the container. A level
// that is already there is left as it is.
func makeMountpoint(root, rel string, rng IDRange) error {
	p := root
	for _, part := range strings.Split(rel, "/") {
		p = filepath.Join(p, part)
		err := os.Mkdir(p, 0o755)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return err
		}
		if err := os.Lchown(p, int(rng.Start), int(rng.Start)); err != nil {
			return err
		}
	}
	return nil
}

func readRootfsMarker(dir string) (rootfsRecord, error) {
	var rec rootfsRecord
	b, err := os.ReadFile(filepath.Join(dir, rootfsMarker))
	if err != nil {
		return rec, err
	}
	err = json.Unmarshal(b, &rec)
	return rec, err
}

// copyTree copies src to dst, shifting every owner into rng. Directories,
// regular files and symlinks are copied. Device nodes, fifos and sockets
// are skipped, since runc binds the devices a container needs and the
// rest have no place in a template root. An id past the range is left
// as it is and reads as nobody inside the namespace. Every mode is set
// before the owner, since changing the mode of a file another uid owns
// would need CAP_FOWNER.
func copyTree(src, dst string, rng IDRange) error {
	shift := func(id uint32) int {
		if id < rng.Count {
			return int(rng.Start + id)
		}
		return int(id)
	}
	type owned struct {
		rel      string
		uid, gid int
	}
	var dirs []owned
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		st, _ := info.Sys().(*syscall.Stat_t)
		uid, gid := 0, 0
		if st != nil {
			uid, gid = shift(st.Uid), shift(st.Gid)
		}
		switch {
		case d.IsDir():
			// Writable while the tree is filled in. Mode and owner are set
			// after the walk, deepest first.
			if err := os.Mkdir(target, 0o700); err != nil && (rel != "." || !errors.Is(err, fs.ErrExist)) {
				return err
			}
			dirs = append(dirs, owned{rel, uid, gid})
			return nil
		case info.Mode()&fs.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			if err := os.Symlink(link, target); err != nil {
				return err
			}
			return os.Lchown(target, uid, gid)
		case info.Mode().IsRegular():
			if err := copyFile(path, target, info.Mode().Perm()); err != nil {
				return err
			}
			return os.Lchown(target, uid, gid)
		default:
			return nil
		}
	})
	if err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		info, err := os.Lstat(filepath.Join(src, dirs[i].rel))
		if err != nil {
			return err
		}
		target := filepath.Join(dst, dirs[i].rel)
		if err := os.Chmod(target, info.Mode().Perm()); err != nil {
			return err
		}
		if err := os.Lchown(target, dirs[i].uid, dirs[i].gid); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string, perm fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Chmod(perm); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// Channel moves the control conversation onto a pair made in the
// container's network namespace. The bootstrap pair was made in the
// agent's, and criu, when it checkpoints the zygote, only finds the
// sockets of the namespaces it dumps. The zygote's end goes to it over
// the bootstrap socket as a REBIND message, which libfiberzygote reads
// before READY (FIBERD_CTL_REBIND), and the agent's end is returned.
func (l *launcher) Channel(ctx context.Context, spec backend.WarmSpec, cmd *exec.Cmd, boot *net.UnixConn) (*net.UnixConn, error) {
	pid, err := l.waitPID(ctx, spec, cmd)
	if err != nil {
		return nil, err
	}
	fds, err := netns.Socketpair(pid, syscall.SOCK_STREAM)
	if err != nil {
		return nil, err
	}
	theirs := os.NewFile(uintptr(fds[1]), "zygote-ctl-rebind")
	defer func() { _ = theirs.Close() }()
	if _, _, err := boot.WriteMsgUnix([]byte("REBIND\n"), syscall.UnixRights(int(theirs.Fd())), nil); err != nil {
		_ = syscall.Close(fds[0])
		return nil, fmt.Errorf("runc: send REBIND: %w", err)
	}
	ours := os.NewFile(uintptr(fds[0]), "zygote-ctl")
	defer func() { _ = ours.Close() }()
	conn, err := net.FileConn(ours)
	if err != nil {
		return nil, err
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("runc: rebound control socket is not unix")
	}
	return uc, nil
}

// waitPID polls runc for the container's init until it is known, the
// context ends or runc exits. Nobody waits on `runc run` until the
// channel is up, so its exit is read from /proc, where it is a zombie.
// An error about a container that never came up carries the tails of
// runc's log and the zygote's, since `runc run` tears its state down on
// the way out and `runc state` only says the container does not exist.
func (l *launcher) waitPID(ctx context.Context, spec backend.WarmSpec, cmd *exec.Cmd) (int, error) {
	for {
		pid, err := l.PID(ctx, spec, cmd)
		if err == nil {
			return pid, nil
		}
		if cmd.ProcessState != nil {
			return 0, fmt.Errorf("runc: exited before the container was up (%s): %w%s", cmd.ProcessState, err, l.logTails(spec))
		}
		if exited(cmd.Process.Pid) {
			return 0, fmt.Errorf("runc: exited before the container was up: %w%s", err, l.logTails(spec))
		}
		select {
		case <-ctx.Done():
			return 0, fmt.Errorf("runc: waiting for the container of %s: %w (%w)%s", spec.GrantUID, ctx.Err(), err, l.logTails(spec))
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// exited reports whether pid is gone or a zombie nobody has reaped yet.
// The state is the field after the parenthesised command name in
// /proc/<pid>/stat.
func exited(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return true
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 >= len(s) {
		return true
	}
	return s[i+2] == 'Z' || s[i+2] == 'X'
}

// Socketpair makes a pair in the container's network namespace, so a
// fiber holding one end can be checkpointed with it.
func (l *launcher) Socketpair(_ backend.WarmSpec, pid int, typ int) ([2]int, error) {
	return netns.Socketpair(pid, typ)
}

// Restored brings the loopback up in the restored tree's network
// namespace. The namespace is a fresh one criu made empty (see
// emptyNet), and the fiber had a loopback when it was parked.
func (l *launcher) Restored(_ backend.WarmSpec, pid int) error {
	return netns.LoopbackUp(pid)
}

// PID is the container's init as the host sees it.
func (l *launcher) PID(ctx context.Context, spec backend.WarmSpec, _ *exec.Cmd) (int, error) {
	out, err := l.runc(ctx, "state", l.cid(spec))
	if err != nil {
		return 0, err
	}
	var st struct {
		PID int `json:"pid"`
	}
	if err := json.Unmarshal([]byte(out), &st); err != nil || st.PID == 0 {
		return 0, errors.New("runc: no init pid in state")
	}
	return st.PID, nil
}

// Release ends the container, removes its bundle and its staged
// template, and gives the zygote's hold on the grant's id range back.
// The root filesystem copy goes with it unless a fiber restored on this
// home still runs in the range.
func (l *launcher) Release(spec backend.WarmSpec) {
	ctx := context.Background()
	_, _ = l.runc(ctx, "kill", l.cid(spec), "KILL")
	_, _ = l.runc(ctx, "delete", "-f", l.cid(spec))
	_ = os.RemoveAll(l.bundle(spec))
	l.setStaged(spec, "")
	_ = os.RemoveAll(l.templateDir(spec))
	l.drop(spec, true)
}

// RestoredGone gives a restored fiber's hold on the grant's id range
// back, once for every RestoreExtra.
func (l *launcher) RestoredGone(spec backend.WarmSpec) { l.drop(spec, false) }

func (l *launcher) Endpoint(spec backend.WarmSpec, hostPath string) string {
	return "/host/" + strings.TrimPrefix(hostPath, spec.WorkDir+"/")
}

// emptyNet and netExtra are criu's network flags. criu cannot dump the
// tunnel devices the kernel puts in every new network namespace, so the
// restored tree gets a fresh, empty one of its own, never the host's, and
// Restored brings its loopback up. Its user namespace is new too, a
// sibling of the container's, so the fiber's own seccomp filter is what
// keeps nested user namespaces denied after a resume (see
// zygote/libfiberzygote.c). The dump skips the network lock, which needs
// iptables and only guards TCP peers. A fiber's endpoints are unix sockets.
var (
	emptyNet = []string{"--empty-ns", "net"}
	netExtra = append(append([]string{}, emptyNet...), "--network-lock", "skip")
)

// shareImages lets the restored tree read its own images. criu opens
// the image directory as root, but the tasks it brings back open some
// images themselves with the identity they are restored with, the
// grant's mapped root. The directory and its files get the grant's
// mapped gid with group read and nothing for others.
func shareImages(dir string, rng IDRange) error {
	gid := int(rng.Start)
	if err := os.Chown(dir, -1, gid); err != nil {
		return fmt.Errorf("runc: share images %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		return err
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if !e.Type().IsRegular() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if err := os.Chown(p, -1, gid); err != nil {
			return fmt.Errorf("runc: share image %s: %w", p, err)
		}
		if err := os.Chmod(p, 0o640); err != nil {
			return err
		}
	}
	return nil
}

// DumpExtra names the mounts that come from outside the container's
// mount namespace, the run directory, the /sys bind, runc's device
// binds and, for a grant on a registry template, the template bind,
// which it also records beside the images in dir so the restore knows
// to bind one.
func (l *launcher) DumpExtra(spec backend.WarmSpec, dir string) ([]string, error) {
	extra := append([]string{"--external", "mnt[/host]:host", "--external", "mnt[/sys]:sys"}, netExtra...)
	for _, d := range deviceBinds {
		extra = append(extra, "--external", "mnt[/dev/"+d+"]:dev-"+d)
	}
	if spec.Template.Dir != "" {
		rec, err := json.Marshal(templateRecord{MountPoint: backend.TemplateMount})
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(dir, templateFile), rec, 0o600); err != nil {
			return nil, err
		}
		extra = append(extra, "--external", "mnt["+backend.TemplateMount+"]:"+templateKey)
	}
	return extra, nil
}

// templateBind returns the restore argument that binds this home's
// verified template copy where the checkpoint in dir had one, or nothing
// for a checkpoint taken without a template mount. A checkpoint with one
// needs the grant's warm instance on this home, which is what staged and
// verified the copy, so without it the restore is refused by name.
func (l *launcher) templateBind(spec backend.WarmSpec, dir string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(dir, templateFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rec templateRecord
	if err := json.Unmarshal(b, &rec); err != nil || rec.MountPoint != backend.TemplateMount {
		return nil, fmt.Errorf("runc: %s in %s: malformed", templateFile, dir)
	}
	staged := l.stagedFor(spec)
	if staged == "" {
		return nil, fmt.Errorf("runc: checkpoint was taken with a registry template at %s, which warm instance %q does not have here", backend.TemplateMount, spec.GrantUID)
	}
	return []string{"--external", "mnt[" + templateKey + "]:" + staged}, nil
}

// RestoreExtra gives the restored tree the grant's root filesystem copy
// on this home, its run directory at /host, this home's /sys bind and
// the host's device nodes.
// The tree maps the grant's id range, so it takes a hold on it, which
// refuses a restore while another grant holds the slot and keeps the
// range and the copy for as long as the tree runs (until RestoredGone).
// The copy is made when this home has not warmed the grant.
func (l *launcher) RestoreExtra(spec backend.WarmSpec, dir string) (extra []string, err error) {
	rootfs, err := l.hold(spec, false)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			l.drop(spec, false)
		}
	}()
	rng := l.opt.Pool.Range(spec.GrantUID)
	if err := prepareWorkDir(spec.WorkDir, rng); err != nil {
		return nil, err
	}
	if err := shareImages(dir, rng); err != nil {
		return nil, err
	}
	if err := l.sysMountPoint(); err != nil {
		return nil, err
	}
	extra = append([]string{"--root", rootfs, "--external", "mnt[host]:" + spec.WorkDir, "--external", "mnt[sys]:" + l.sysDir()}, emptyNet...)
	for _, d := range deviceBinds {
		extra = append(extra, "--external", "mnt[dev-"+d+"]:/dev/"+d)
	}
	bind, err := l.templateBind(spec, dir)
	if err != nil {
		return nil, err
	}
	return append(extra, bind...), nil
}

var (
	_ backend.Backend         = (*Backend)(nil)
	_ backend.Platformer      = (*Backend)(nil)
	_ backend.EndpointSchemer = (*Backend)(nil)
	_ backend.IDMapper        = (*Backend)(nil)
	_ proc.Launcher           = (*launcher)(nil)
)
