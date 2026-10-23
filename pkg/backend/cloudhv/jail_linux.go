//go:build linux

package cloudhv

// The jail each VMM runs in. fiberd starts a VMM by re-executing itself
// as a jail stage in fresh namespaces. The stage builds the VMM's view
// of the host on a tmpfs, pivots into it, drops to the grant's uid and
// execs the VMM. Go runs nothing between fork and exec, so the stage is
// a process of its own, which init below recognises by its argv[0].

import (
	"bufio"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	runcbackend "github.com/helayoty/fiberd/pkg/backend/runc"
)

// jailSpec is one VMM to start.
type jailSpec struct {
	GrantUID string   // picks the VMM's unprivileged uid and gid
	VMM      string   // host path of the VMM executable
	Args     []string // the VMM's arguments, which name namespace paths only
	Kernel   string   // host file, shown read-only at vmKernel
	Rootfs   string   // host file, or a directory for the fake VMM, shown read-only at vmRootfs
	RunDir   string   // host directory from prepareRunDir, shown read-write at vmRun
	From     string   // host snapshot directory shown read-only at vmFrom, "" for a fresh boot
	Engine   string   // host path of the grant's engine socket, whose directory is shown read-only at vmEngine, "" for none
	CgroupFD int      // the leaf the VMM is born in, -1 for none
	Log      *os.File // the VMM's stdout and stderr, where the guest's console goes too
	API      *os.File // the bound API socket, which the VMM gets as descriptor apiFD
}

// The VMM uids. A grant's VMM runs as jailIDBase plus a hash of the
// grant uid, with the same number as its gid. The range starts above
// every id a host hands out by convention (useradd's /etc/subuid ranges
// end at SUB_UID_MAX, 600100000) and ends below the runc backend's user
// namespace pool at 2^30, so a VMM never shares an id with a host user
// or a runc container. Two grants that hash to one id share nothing
// even so, since each VMM sees only its own namespaces, but the range
// is wide so it rarely happens.
const (
	jailIDBase  = 3 << 28 // 805306368
	jailIDSlots = 1 << 24 // the range ends at 822083584
)

// jailIDs are the uid and gid a grant's VMMs run as.
func jailIDs(grantUID string) (uid, gid uint32) {
	h := fnv.New64a()
	_, _ = h.Write([]byte(grantUID))
	id := uint32(jailIDBase + h.Sum64()%jailIDSlots)
	return id, id
}

// checkIDs refuses a host whose other ids reach into the VMM range: the
// -userns-pool the runc backend carves user namespaces from, and the
// uid the engine runs as. A VMM sharing an id with either could signal
// or ptrace it, or open what is its own. pool is "" for the default
// pool, and engineUID 0 names no engine.
func checkIDs(pool string, engineUID uint32) error {
	if pool == "" {
		pool = runcbackend.DefaultPool
	}
	p, err := runcbackend.ParsePool(pool)
	if err != nil {
		return err
	}
	const lo, hi = uint64(jailIDBase), uint64(jailIDBase + jailIDSlots)
	pstart, pend := uint64(p.Start), uint64(p.Start)+uint64(p.Slots)*runcbackend.SlotIDs
	if pstart < hi && lo < pend {
		return fmt.Errorf("-userns-pool ids [%d, %d) overlap the VMM uids [%d, %d)", pstart, pend, lo, hi)
	}
	if e := uint64(engineUID); e != 0 && lo <= e && e < hi {
		return fmt.Errorf("-engine-uid %d is inside the VMM uids [%d, %d)", e, lo, hi)
	}
	return nil
}

// The stage. A re-executed fiberd whose argv[0] is stageArg0 reads a
// stageSpec from specFD and reports why it failed, if it did, on
// statusFD, which its exec closes on success. The VMM's API socket, bound
// by fiberd, rides on apiFD and stays open across the exec. maxSpec
// bounds the spec, which must fit the pipe it waits in unread.
const (
	stageArg0 = "fiberd-cloudhv-jail"
	specFD    = 3
	statusFD  = 4
	apiFD     = 5
	maxSpec   = 32 << 10
)

// stageSpec is what the stage reads from its spec pipe.
type stageSpec struct {
	Probe  bool // only check that a jail can be made here
	UID    uint32
	GID    uint32
	VMM    string
	Args   []string
	Kernel string
	Rootfs string
	RunDir string
	From   string
	Engine string // the engine's host directory
}

// Mount flags of the VMM's view.
const (
	baseFlags = unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC // the root tmpfs, proc and the run directory
	devFlags  = unix.MS_NOSUID | unix.MS_NOEXEC                 // /dev takes device nodes
	roBind    = unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NODEV // the VMM and the rootfs, which may exec
)

// jailProbe is why no VMM can be jailed here, nil when one can. It
// re-executes fiberd as a probing stage, which needs the namespaces,
// mounts, device nodes and pivot_root a jail needs and makes nothing on
// the host.
func jailProbe() error {
	if uid := os.Geteuid(); uid != 0 {
		return fmt.Errorf("fiberd runs as uid %d, and only root can mount a VMM's namespaces", uid)
	}
	cmd, err := startStage(stageSpec{Probe: true}, os.Stderr, -1, nil)
	if err != nil {
		return err
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("jail probe: %w", err)
	}
	return nil
}

// prepareRunDir makes dir for one VMM of the grant, with dir/snap for
// its snapshots. Both are root's, in the VMM's group, so the VMM can
// make its sockets and snapshot files there and fiberd, as root, can
// connect to them. dir is sticky, so a name root makes there is one the
// VMM can use but not unlink or rename, nor rename anything over. The
// rest of the host sees none of it, since dir's parent is root's alone.
//
// Every name root wants to own in dir, it must make before the VMM
// starts, since a name the VMM makes first is the VMM's to replace. The
// API socket is bound here before launch starts the VMM for that reason.
// So is the engine's name, when engine names the grant's engine socket.
// A guest that connects to host port enginePort has the VMM connect to
// vsock.sock_5000, which is made here as root's symlink to the socket
// as the jail shows it, beneath vmEngine. It dangles on the host, and
// only the VMM, inside its jail, follows it. A symlink rather than a
// bind of the socket, since an engine that restarts binds a new socket
// in the same directory, which the jail's bind of the directory shows.
func prepareRunDir(dir, grantUID, engine string) error {
	_, gid := jailIDs(grantUID)
	if err := ownDir(dir, gid, os.ModeSticky|0o770); err != nil {
		return err
	}
	if engine != "" {
		link := filepath.Join(dir, vsockSock+"_"+strconv.Itoa(enginePort))
		if err := os.Symlink(vmEngine+"/"+filepath.Base(engine), link); err != nil {
			return err
		}
	}
	return ownDir(filepath.Join(dir, snapDir), gid, 0o770)
}

// ownDir makes a directory that is root's in the group, with the exact
// mode whatever the umask.
func ownDir(dir string, gid uint32, mode os.FileMode) error {
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chown(dir, 0, int(gid)); err != nil {
		return err
	}
	return os.Chmod(dir, mode)
}

// startJailed starts the VMM in a jail of its own. It checks first what
// the stage could only report as a bare ENOENT or EACCES from inside:
// the VMM must be a static executable, since the jail holds no
// libraries, and the VMM's uid must be able to read what it is shown.
func startJailed(sp jailSpec) (process, error) {
	uid, gid := jailIDs(sp.GrantUID)
	if err := checkStatic(sp.VMM); err != nil {
		return nil, err
	}
	shown := []struct {
		what, path string
		run        bool
	}{{"VMM", sp.VMM, true}, {"kernel", sp.Kernel, false}, {"rootfs", sp.Rootfs, false}}
	for _, s := range shown {
		if err := checkReadable(s.what, s.path, uid, gid, s.run); err != nil {
			return nil, err
		}
	}
	engineDir := ""
	if sp.Engine != "" {
		engineDir = filepath.Dir(sp.Engine)
		if err := checkReadable("engine directory", engineDir, uid, gid, false); err != nil {
			return nil, err
		}
	}
	spec := stageSpec{UID: uid, GID: gid, VMM: sp.VMM, Args: sp.Args, Kernel: sp.Kernel, Rootfs: sp.Rootfs, RunDir: sp.RunDir, From: sp.From, Engine: engineDir}
	cmd, err := startStage(spec, sp.Log, sp.CgroupFD, sp.API)
	if err != nil {
		return nil, err
	}
	return cmdProcess{cmd}, nil
}

// checkStatic refuses a VMM that asks for a dynamic loader. Cloud
// Hypervisor ships a static build, and a Go fake is one when built with
// CGO_ENABLED=0.
func checkStatic(path string) error {
	f, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("VMM %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return fmt.Errorf("VMM %s is dynamically linked, and the jail holds no libraries; use a static build", path)
		}
	}
	return nil
}

// checkReadable is an error by name when uid, in group gid, could not
// read path, or run it when run is set. A directory needs search and
// read. The owner's bits alone count for the owner and the group's for
// the group, as the kernel has it.
func checkReadable(what, path string, uid, gid uint32, run bool) error {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return fmt.Errorf("%s %s: %w", what, path, err)
	}
	want := uint32(unix.S_IROTH)
	if run || st.Mode&unix.S_IFMT == unix.S_IFDIR {
		want |= unix.S_IXOTH
	}
	have := st.Mode
	switch {
	case st.Uid == uid:
		have >>= 6
	case st.Gid == gid:
		have >>= 3
	}
	if have&want != want {
		return fmt.Errorf("%s %s has mode %04o, which keeps the VMM's uid %d out", what, path, st.Mode&0o7777, uid)
	}
	return nil
}

// startStage re-executes fiberd as a jail stage with the spec on an
// inherited pipe, in fresh mount, pid, ipc, uts and net namespaces, as
// a session leader, and in the leaf when cgroupFD is not -1. The VMM
// then has no network, and its unix sockets, which are paths, need
// none. The stage gets no environment, so the VMM inherits none of
// fiberd's. api, when not nil, is the bound API socket the VMM gets as
// apiFD. startStage returns once the stage has exec'd the VMM, or with
// the stage's own reason when it could not.
func startStage(spec stageSpec, log *os.File, cgroupFD int, api *os.File) (*exec.Cmd, error) {
	data, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	if len(data) > maxSpec {
		return nil, fmt.Errorf("jail stage: a spec of %d bytes is over %d", len(data), maxSpec)
	}
	specR, specW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer func() { _ = specR.Close() }()
	// The pipe holds the spec until the stage reads it.
	_, err = specW.Write(data)
	_ = specW.Close()
	if err != nil {
		return nil, err
	}
	statusR, statusW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer func() { _ = statusR.Close() }()
	cmd := exec.Command("/proc/self/exe")
	cmd.Args = []string{stageArg0}
	cmd.Env = []string{}
	cmd.Stdout, cmd.Stderr = log, log
	cmd.ExtraFiles = []*os.File{specR, statusW}
	if api != nil {
		cmd.ExtraFiles = append(cmd.ExtraFiles, api)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:     true,
		Cloneflags: syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS | syscall.CLONE_NEWNET,
	}
	if cgroupFD >= 0 {
		cmd.SysProcAttr.UseCgroupFD = true
		cmd.SysProcAttr.CgroupFD = cgroupFD
	}
	err = cmd.Start()
	_ = statusW.Close()
	if err != nil {
		return nil, fmt.Errorf("jail stage: %w", err)
	}
	msg, _ := io.ReadAll(io.LimitReader(statusR, 4096))
	if len(msg) > 0 {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("jail stage: %s", msg)
	}
	return cmd, nil
}

// init turns a re-executed fiberd into the jail stage. Every other
// process, fiberd and the test binaries of this package among them,
// makes the one comparison and goes on.
func init() {
	if len(os.Args) > 0 && os.Args[0] == stageArg0 {
		stage()
	}
}

// stage runs as root and pid 1 of the VMM's namespaces. It never
// returns: it execs the VMM, or writes why it could not on the status
// pipe and exits. The thread is locked from the first step, since
// no_new_privs and the credentials are per thread and the exec must
// come from the thread that set them. Of the descriptors fiberd handed
// it, the spec pipe is closed once read, the status pipe closes on exec,
// the API socket at apiFD stays open for the VMM to listen on, and
// everything else is close-on-exec, as the Go runtime and os/exec make
// every descriptor they open.
func stage() {
	runtime.LockOSThread()
	status := os.NewFile(statusFD, "status")
	fail := func(err error) {
		_, _ = status.WriteString(err.Error())
		os.Exit(1)
	}
	unix.CloseOnExec(statusFD)
	specf := os.NewFile(specFD, "spec")
	data, err := io.ReadAll(io.LimitReader(specf, maxSpec))
	_ = specf.Close()
	if err != nil {
		fail(fmt.Errorf("read the spec: %w", err))
	}
	var sp stageSpec
	if err := json.Unmarshal(data, &sp); err != nil {
		fail(fmt.Errorf("decode the spec: %w", err))
	}
	if sp.Probe {
		if err := probeIn(); err != nil {
			fail(err)
		}
		os.Exit(0)
	}
	if err := enter(sp); err != nil {
		fail(err)
	}
	if err := drop(sp.UID, sp.GID); err != nil {
		fail(err)
	}
	err = unix.Exec(vmBin, append([]string{vmBin}, sp.Args...), []string{})
	fail(fmt.Errorf("exec %s: %w", vmBin, err))
}

// probeIn checks, inside fresh namespaces, what enter needs: a private
// mount tree, a proc of the new pid namespace, a tmpfs that takes
// device nodes, and a pivot_root into it. Nothing it mounts outlives
// the stage.
func probeIn() error {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make the mount tree private: %w", err)
	}
	if err := unix.Mount("proc", "/proc", "proc", baseFlags, ""); err != nil {
		return fmt.Errorf("mount proc: %w", err)
	}
	if err := unix.Mount("tmpfs", "/dev", "tmpfs", devFlags, "mode=0755"); err != nil {
		return fmt.Errorf("mount a tmpfs for /dev: %w", err)
	}
	if err := node("/dev/null", 0o666, 1, 3, 0, 0); err != nil {
		return err
	}
	return pivotInto("/dev")
}

// enter builds the VMM's root on a tmpfs and pivots into it. The VMM
// then sees its executable at vmBin, the kernel at vmKernel, the rootfs
// at vmRootfs, its run directory at vmRun, the snapshot it restores at
// vmFrom, the grant's engine directory at vmEngine when it has one, a
// /dev with null, urandom and kvm, and a /proc of its own pid namespace,
// which holds it alone. Nothing else of the host is there, and nothing
// but vmRun takes a write.
//
// The tmpfs sits on the run directory, the one host path the stage is
// sure of. The directory is opened first, so the bind of it can name
// the original as "." through the descriptor once the tmpfs hides it.
func enter(sp stageSpec) error {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make the mount tree private: %w", err)
	}
	runFD, err := unix.Open(sp.RunDir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open the run directory: %w", err)
	}
	root := sp.RunDir
	if err := unix.Mount("tmpfs", root, "tmpfs", baseFlags, "mode=0755"); err != nil {
		return fmt.Errorf("mount the root tmpfs: %w", err)
	}
	for _, d := range []string{filepath.Dir(vmBin), "/dev", "/proc"} {
		if err := os.MkdirAll(root+d, 0o755); err != nil {
			return err
		}
	}
	if err := bind(sp.VMM, root+vmBin, roBind); err != nil {
		return err
	}
	if err := bind(sp.Kernel, root+vmKernel, roBind|unix.MS_NOEXEC); err != nil {
		return err
	}
	if err := bind(sp.Rootfs, root+vmRootfs, roBind); err != nil {
		return err
	}
	if err := unix.Fchdir(runFD); err != nil {
		return fmt.Errorf("enter the run directory: %w", err)
	}
	_ = unix.Close(runFD)
	if err := bind(".", root+vmRun, baseFlags); err != nil {
		return err
	}
	if sp.From != "" {
		if err := bind(sp.From, root+vmFrom, roBind|unix.MS_NOEXEC); err != nil {
			return err
		}
	}
	// Read-only, so neither the VMM nor its guest can replace the socket
	// the run directory's engine link names. connect needs no write on
	// the mount, only on the socket, which the engine makes 0666.
	if sp.Engine != "" {
		if err := bind(sp.Engine, root+vmEngine, roBind|unix.MS_NOEXEC); err != nil {
			return err
		}
	}
	if err := makeDev(root+"/dev", sp.UID, sp.GID); err != nil {
		return err
	}
	if err := unix.Mount("proc", root+"/proc", "proc", baseFlags, ""); err != nil {
		return fmt.Errorf("mount proc: %w", err)
	}
	if err := pivotInto(root); err != nil {
		return err
	}
	if err := unix.Mount("", "/", "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY|baseFlags, ""); err != nil {
		return fmt.Errorf("make the root read-only: %w", err)
	}
	return nil
}

// bind shows the host path src at target with flags, a file on a file
// and a directory on a directory. The flags take a second mount, since
// a bind ignores them.
func bind(src, target string, flags uintptr) error {
	st, err := os.Stat(src)
	if err != nil {
		return err
	}
	if st.IsDir() {
		err = os.MkdirAll(target, 0o755)
	} else {
		err = os.WriteFile(target, nil, 0o644)
	}
	if err != nil {
		return err
	}
	if err := unix.Mount(src, target, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind %s at %s: %w", src, target, err)
	}
	if err := unix.Mount("", target, "", unix.MS_REMOUNT|unix.MS_BIND|flags, ""); err != nil {
		return fmt.Errorf("remount %s: %w", target, err)
	}
	return nil
}

// makeDev fills the VMM's /dev, a tmpfs of its own, with null, urandom
// and kvm, and leaves it read-only. The nodes are made, not bound, so
// kvm can be the VMM's own, 0600 under its uid, whatever mode and group
// the host's /dev/kvm has. The major and minor come from the host's
// node. A host without one, as CI is, gets no kvm, which the fake VMM
// does without. A host whose device rules refuse the node gets none
// either, with a line in the log, and a real VMM then fails to open it
// by name.
func makeDev(dev string, uid, gid uint32) error {
	if err := unix.Mount("tmpfs", dev, "tmpfs", devFlags, "mode=0755"); err != nil {
		return fmt.Errorf("mount /dev: %w", err)
	}
	if err := node(dev+"/null", 0o666, 1, 3, 0, 0); err != nil {
		return err
	}
	if err := node(dev+"/urandom", 0o666, 1, 9, 0, 0); err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Stat("/dev/kvm", &st); err == nil && st.Mode&unix.S_IFMT == unix.S_IFCHR {
		if err := node(dev+"/kvm", 0o600, unix.Major(st.Rdev), unix.Minor(st.Rdev), uid, gid); err != nil {
			fmt.Fprintf(os.Stderr, "cloudhv jail: the VMM gets no /dev/kvm: %v\n", err)
		}
	}
	if err := unix.Mount("", dev, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY|devFlags, ""); err != nil {
		return fmt.Errorf("make /dev read-only: %w", err)
	}
	return nil
}

// node makes a character device node with the exact mode, whatever the
// umask, owned by uid and gid.
func node(path string, mode, major, minor, uid, gid uint32) error {
	if err := unix.Mknod(path, unix.S_IFCHR|mode, int(unix.Mkdev(major, minor))); err != nil {
		return fmt.Errorf("mknod %s: %w", path, err)
	}
	if err := os.Chown(path, int(uid), int(gid)); err != nil {
		return err
	}
	return os.Chmod(path, os.FileMode(mode))
}

// pivotInto makes root, a mount point, the stage's root and detaches
// the old one, as runc does: with the new root and put_old the same
// directory, the old root sits on top of the new one until it is
// unmounted from there.
func pivotInto(root string) error {
	oldroot, err := unix.Open("/", unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open the old root: %w", err)
	}
	defer func() { _ = unix.Close(oldroot) }()
	if err := unix.Chdir(root); err != nil {
		return err
	}
	if err := unix.PivotRoot(".", "."); err != nil {
		return fmt.Errorf("pivot_root into %s: %w", root, err)
	}
	if err := unix.Fchdir(oldroot); err != nil {
		return err
	}
	if err := unix.Unmount(".", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("detach the old root: %w", err)
	}
	return unix.Chdir("/")
}

// drop leaves root behind on the locked thread. The bounding and
// ambient sets go first, then no_new_privs is set, the supplementary
// groups are cleared, the gid and uid become the grant's, which empties
// the permitted and effective sets, and the inheritable set is cleared
// last. The exec inherits all of it, and no_new_privs keeps setuid bits
// and file capabilities from giving anything back. The umask makes the
// VMM's sockets and snapshot files its own alone, which root reaches
// anyway.
func drop(uid, gid uint32) error {
	for c := 0; ; c++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil {
			if errors.Is(err, unix.EINVAL) {
				break
			}
			return fmt.Errorf("drop capability %d from the bounding set: %w", c, err)
		}
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("clear the ambient set: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	unix.Umask(0o077)
	if err := unix.Setgroups([]int{}); err != nil {
		return fmt.Errorf("clear the supplementary groups: %w", err)
	}
	if err := unix.Setresgid(int(gid), int(gid), int(gid)); err != nil {
		return fmt.Errorf("become gid %d: %w", gid, err)
	}
	if err := unix.Setresuid(int(uid), int(uid), int(uid)); err != nil {
		return fmt.Errorf("become uid %d: %w", uid, err)
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var none [2]unix.CapUserData
	if err := unix.Capset(&hdr, &none[0]); err != nil {
		return fmt.Errorf("clear the inheritable set: %w", err)
	}
	return nil
}

// takeSnapshot moves the snapshot a VMM wrote into src out of its reach
// into dst, which it makes when absent. Files already in dst keep their
// place, and only a same-named one is replaced. Only regular files move,
// and one that turns out to be something else once moved, as a VMM that
// swaps a symlink in under the move would make it, is removed and named.
//
// Each file is renamed, not copied, since memory-ranges can be hundreds
// of MiB and a park is on the fiber's clock. A rename keeps the inode,
// so afterwards every file is made fiberd's, 0640 in the VMM's group,
// and dst 0750 in that group, since a restore reads the snapshot as that
// group through the vmFrom bind, and then every process of the VMM's uid
// is checked for a descriptor or a writable shared mapping of a moved
// file, which would let it write on after the park. One found fails the
// park by name. A dst on another filesystem gets a copy into a fresh
// inode, which needs no such check.
func takeSnapshot(src, dst string) error {
	ents, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	if len(ents) == 0 {
		return fmt.Errorf("%s holds no snapshot", src)
	}
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	// fiberd is root. A test that is not keeps what it owns.
	owner := os.Geteuid()
	moved := map[inode]string{}
	var uid, gid uint32
	for _, e := range ents {
		name := e.Name()
		from, to := filepath.Join(src, name), filepath.Join(dst, name)
		var st unix.Stat_t
		if err := unix.Lstat(from, &st); err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			return fmt.Errorf("%s is not a regular file", from)
		}
		uid, gid = st.Uid, st.Gid
		switch rerr := os.Rename(from, to); {
		case rerr == nil:
			var after unix.Stat_t
			if err := unix.Lstat(to, &after); err != nil {
				return err
			}
			if after.Mode&unix.S_IFMT != unix.S_IFREG || after.Dev != st.Dev || after.Ino != st.Ino {
				_ = os.Remove(to)
				return fmt.Errorf("%s changed under the move", from)
			}
			moved[inodeOf(&after)] = name
		case errors.Is(rerr, unix.EXDEV):
			if err := copyFile(from, to); err != nil {
				return err
			}
			_ = os.Remove(from)
		default:
			return rerr
		}
		if err := os.Chown(to, owner, int(gid)); err != nil {
			return err
		}
		if err := os.Chmod(to, 0o640); err != nil {
			return err
		}
	}
	if err := os.Chown(dst, owner, int(gid)); err != nil {
		return err
	}
	if err := os.Chmod(dst, 0o750); err != nil {
		return err
	}
	if uid == 0 {
		return nil
	}
	name, err := keptOpen(uid, moved)
	if err != nil {
		return err
	}
	if name != "" {
		return fmt.Errorf("the VMM holds %s open after the snapshot", name)
	}
	return nil
}

// copyFile copies the regular file at src into a fresh inode at dst,
// 0600 and fiberd's, replacing a same-named file only once the copy is
// whole. src is opened without following a symlink and checked again
// once open, since the VMM may still change its directory.
func copyFile(src, dst string) error {
	fd, err := unix.Open(src, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	in := os.NewFile(uintptr(fd), src)
	defer func() { _ = in.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("%s is not a regular file", src)
	}
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, dst)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("copy %s: %w", src, err)
	}
	return nil
}

// inode names a file as stat and /proc/<pid>/maps show it.
type inode struct {
	major, minor uint32
	ino          uint64
}

func inodeOf(st *unix.Stat_t) inode {
	return inode{unix.Major(st.Dev), unix.Minor(st.Dev), st.Ino}
}

// keptOpen is the moved file some process of uid holds a descriptor or
// a writable shared mapping of, "" when none does. It reads the host's
// /proc, where the VMM's processes show whatever pid namespace they sit
// in. A process that is gone meanwhile holds nothing.
func keptOpen(uid uint32, moved map[inode]string) (string, error) {
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return "", err
	}
	for _, p := range procs {
		if _, err := strconv.Atoi(p.Name()); err != nil {
			continue
		}
		dir := "/proc/" + p.Name()
		if !runsAs(dir, uid) {
			continue
		}
		if name := holds(dir, moved); name != "" {
			return name, nil
		}
	}
	return "", nil
}

// runsAs is whether any of the process's uids is uid.
func runsAs(dir string, uid uint32) bool {
	f, err := os.Open(dir + "/status")
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		rest, ok := strings.CutPrefix(sc.Text(), "Uid:")
		if !ok {
			continue
		}
		for _, w := range strings.Fields(rest) {
			if n, err := strconv.ParseUint(w, 10, 32); err == nil && uint32(n) == uid {
				return true
			}
		}
		return false
	}
	return false
}

// holds is the moved file the process has a descriptor or a writable
// shared mapping of, "" when none.
func holds(dir string, moved map[inode]string) string {
	fds, _ := os.ReadDir(dir + "/fd")
	for _, fd := range fds {
		var st unix.Stat_t
		if unix.Stat(dir+"/fd/"+fd.Name(), &st) != nil {
			continue
		}
		if name, ok := moved[inodeOf(&st)]; ok {
			return name
		}
	}
	f, err := os.Open(dir + "/maps")
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// address perms offset major:minor inode path
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 || len(fields[1]) < 4 || fields[1][1] != 'w' || fields[1][3] != 's' {
			continue
		}
		mj, mn, ok := strings.Cut(fields[3], ":")
		if !ok {
			continue
		}
		major, err1 := strconv.ParseUint(mj, 16, 32)
		minor, err2 := strconv.ParseUint(mn, 16, 32)
		ino, err3 := strconv.ParseUint(fields[4], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		if name, ok := moved[inode{uint32(major), uint32(minor), ino}]; ok {
			return name
		}
	}
	return ""
}
