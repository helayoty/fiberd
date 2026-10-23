//go:build linux

package cloudhv

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Every VMM runs in a mount namespace of its own (jail_linux.go), where
// it sees the same few paths whatever fiber it holds. A snapshot records
// the paths its VM was created with, so a restore in another fiber's
// namespace finds its kernel, rootfs and sockets at the same names, and
// two restores of one snapshot never collide.
const (
	vmKernel = "/fiberd/vm/kernel" // the guest kernel, read-only
	vmRootfs = "/fiberd/vm/rootfs" // the guest's root image, read-only
	vmRun    = "/fiberd/vm/run"    // the VMM's own directory, read-write
	vmFrom   = "/fiberd/vm/from"   // the snapshot a restore reads, read-only
	vmBin    = "/fiberd/vm/bin/vmm"

	// Inside vmRun, and so inside the host run directory too.
	apiSock   = "api.sock"
	vsockSock = "vsock.sock"
	snapDir   = "snap"
	serialLog = "serial.log"
)

// The guest's vsock ports. The guest init serves the fiber's endpoint on
// endpointPort and its control lines on controlPort. Port 5000 on the
// host (CID 2) is the engine, which M10b links.
const (
	guestCID     = 3
	endpointPort = 1024
	controlPort  = 1025
)

// guestInit is where the rootfs keeps the guest init, which the kernel
// runs as PID 1 with the template's command after "--".
const guestInit = "/fiberd/init"

// ErrVMM is a refusal or failure of the VMM's API, and ErrGuest one of
// the guest init's control lines.
var (
	ErrVMM   = errors.New("cloudhv: VMM error")
	ErrGuest = errors.New("cloudhv: guest error")
)

// api is plain HTTP over one VMM's API socket, as the Firecracker
// comparator drives its VMM. Cloud Hypervisor answers one request per
// connection, so nothing is kept alive. The socket is dialed by name,
// which is safe because fiberd bound it as root before the VMM started
// (bindAPI), so the VMM cannot put another socket under that name.
type api struct{ c *http.Client }

func newAPI(sock string) *api {
	tr := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}
	return &api{c: &http.Client{Transport: tr}}
}

// do sends one request to /api/v1/<endpoint>, with body as JSON when it
// is not nil, and decodes the answer into out when out is not nil.
func (a *api) do(ctx context.Context, method, endpoint string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost/api/v1/"+endpoint, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.c.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %s %s: %w", ErrVMM, method, endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%w: %s %s: %s: %s", ErrVMM, method, endpoint, resp.Status, clip(data))
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("%w: %s %s: %w", ErrVMM, method, endpoint, err)
		}
	}
	return nil
}

func (a *api) put(ctx context.Context, endpoint string, body any) error {
	return a.do(ctx, http.MethodPut, endpoint, body, nil)
}

// clip is a VMM's answer short enough for an error.
func clip(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 512 {
		s = s[:512] + "..."
	}
	return s
}

// vmConfig is the body of vm.create, Cloud Hypervisor's VmConfig with
// only the fields the backend sets. Every path is a namespace path.
type vmConfig struct {
	Cpus    cpusConfig    `json:"cpus"`
	Memory  memoryConfig  `json:"memory"`
	Payload payloadConfig `json:"payload"`
	Disks   []diskConfig  `json:"disks"`
	Vsock   vsockConfig   `json:"vsock"`
	Rng     rngConfig     `json:"rng"`
	Serial  consoleConfig `json:"serial"`
	Console consoleConfig `json:"console"`
}

type cpusConfig struct {
	BootVcpus int `json:"boot_vcpus"`
	MaxVcpus  int `json:"max_vcpus"`
}

type memoryConfig struct {
	Size uint64 `json:"size"`
}

type payloadConfig struct {
	Kernel  string `json:"kernel"`
	Cmdline string `json:"cmdline"`
}

type diskConfig struct {
	Path      string `json:"path"`
	Readonly  bool   `json:"readonly"`
	ImageType string `json:"image_type"`
}

type vsockConfig struct {
	Cid    int    `json:"cid"`
	Socket string `json:"socket"`
}

type rngConfig struct {
	Src string `json:"src"`
}

type consoleConfig struct {
	Mode string `json:"mode"`
	File string `json:"file,omitempty"`
}

// vmConfig is the warm VM's configuration. The serial port writes a file
// in the VMM's run directory, the same path in every restore, which is
// copied into the grant's log when the VMM ends. The console device is
// off.
func (b *Backend) vmConfig(cmdline string) vmConfig {
	return vmConfig{
		Cpus:    cpusConfig{BootVcpus: b.opt.VCPUs, MaxVcpus: b.opt.VCPUs},
		Memory:  memoryConfig{Size: b.opt.MemoryMiB << 20},
		Payload: payloadConfig{Kernel: vmKernel, Cmdline: cmdline},
		Disks:   []diskConfig{{Path: vmRootfs, Readonly: true, ImageType: "Raw"}},
		Vsock:   vsockConfig{Cid: guestCID, Socket: vmRun + "/" + vsockSock},
		Rng:     rngConfig{Src: "/dev/urandom"},
		Serial:  consoleConfig{Mode: "File", File: vmRun + "/" + serialLog},
		Console: consoleConfig{Mode: "Off"},
	}
}

// baseCmdline boots the read-only rootfs on the virtio-blk disk with the
// guest init as PID 1. The guest powers off on a panic, which ends the
// VMM.
const baseCmdline = "console=ttyS0 root=/dev/vda ro rootfstype=ext4 panic=-1 quiet init=" + guestInit

// maxCmdline is x86's COMMAND_LINE_SIZE less its NUL.
const maxCmdline = 2047

// kernelCmdline hands the template's command to the guest init after
// "--", where the kernel passes words on to init's argv. The kernel
// splits on spaces and knows no quoting, so a word with a space, a quote
// or a control byte is refused rather than split.
func kernelCmdline(argv []string) (string, error) {
	if len(argv) == 0 {
		return "", errors.New("cloudhv: empty template command")
	}
	var sb strings.Builder
	sb.WriteString(baseCmdline)
	sb.WriteString(" --")
	for _, w := range argv {
		if w == "" || strings.ContainsFunc(w, func(r rune) bool { return r <= ' ' || r > '~' || r == '"' || r == '\'' }) {
			return "", fmt.Errorf("cloudhv: template word %q cannot ride on a kernel command line", w)
		}
		sb.WriteByte(' ')
		sb.WriteString(w)
	}
	if sb.Len() > maxCmdline {
		return "", fmt.Errorf("cloudhv: kernel command line is %d bytes, over %d", sb.Len(), maxCmdline)
	}
	return sb.String(), nil
}

// starter starts VMM processes. It is the one point where a process
// enters the backend, so the fake VMM replaces cloud-hypervisor through
// Options.VMM alone, and a test can put a goroutine here.
type starter interface {
	// Version is what `vmm --version` prints.
	Version(ctx context.Context) (string, error)
	// Probe is why no VMM can be started on this host, nil when one can.
	Probe() error
	// Start runs the VMM as jailSpec says.
	Start(sp jailSpec) (process, error)
}

// process is a started VMM.
type process interface {
	Pid() int
	Kill() error
	Wait() error
}

// execStarter starts the VMM executable in a jail of its own
// (jail_linux.go).
type execStarter struct{ vmm string }

func (s execStarter) Version(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, s.vmm, "--version").CombinedOutput()
	return string(out), err
}

func (s execStarter) Probe() error {
	return jailProbe()
}

func (s execStarter) Start(sp jailSpec) (process, error) {
	return startJailed(sp)
}

// cmdProcess is a process started through os/exec.
type cmdProcess struct{ cmd *exec.Cmd }

func (p cmdProcess) Pid() int    { return p.cmd.Process.Pid }
func (p cmdProcess) Kill() error { return p.cmd.Process.Kill() }
func (p cmdProcess) Wait() error { return p.cmd.Wait() }

// vm is one running VMM and the host directory it owns.
type vm struct {
	id   string
	run  string // the host side of vmRun
	log  string // the grant's log, which takes the guest's console at the end
	uid  uint32 // the uid the VMM runs as (jailIDs)
	proc process
	api  *api
	done chan struct{} // closed once the process is reaped
	gone sync.Once

	mu     sync.Mutex
	status string // how it ended, once done is closed
}

// cleanup copies the end of the guest's console into the grant's log and
// removes the run directory, once, after the VMM has ended. A console
// that cannot be trusted is skipped with one line saying why.
func (v *vm) cleanup() {
	v.gone.Do(func() {
		if out, err := os.OpenFile(v.log, os.O_WRONLY|os.O_APPEND, 0); err == nil {
			if f, err := v.openConsole(); err == nil {
				_, _ = fmt.Fprintf(out, "cloudhv: console of VMM %s (%s)\n", v.id, v.exited())
				_, _ = io.Copy(out, f)
				_ = f.Close()
			} else {
				_, _ = fmt.Fprintf(out, "cloudhv: console of VMM %s (%s) skipped: %v\n", v.id, v.exited(), err)
			}
			_ = out.Close()
		}
		_ = os.RemoveAll(v.run)
	})
}

// openConsole opens the guest's console in the run directory, seeked to
// its last maxConsole bytes. The VMM owned the directory's names, so the
// file is opened beneath a descriptor of the directory with no symlink
// or magic link followed, without blocking should it be a FIFO, and is
// taken only once it proves a regular file of the VMM's uid. Anything
// else the VMM put under the name is an error.
func (v *vm) openConsole() (*os.File, error) {
	dir, err := unix.Open(v.run, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open the run directory: %w", err)
	}
	defer func() { _ = unix.Close(dir) }()
	fd, err := unix.Openat2(dir, serialLog, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NONBLOCK | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", serialLog, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("stat %s: %w", serialLog, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != v.uid {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%s is not a regular file of uid %d", serialLog, v.uid)
	}
	// O_NONBLOCK only kept a FIFO from blocking the open. A regular file
	// reads the same either way, and blocking keeps it off the poller.
	_ = unix.SetNonblock(fd, false)
	f := os.NewFile(uintptr(fd), serialLog)
	if st.Size > maxConsole {
		_, _ = f.Seek(-maxConsole, io.SeekEnd)
	}
	return f, nil
}

// maxConsole is how much of a guest's console reaches the grant's log.
const maxConsole = 64 << 10

func (v *vm) vsock() guestSock {
	return guestSock{path: v.run + "/" + vsockSock, pid: v.proc.Pid(), uid: v.uid}
}

func (v *vm) snapshot() string { return v.run + "/" + snapDir }

func (v *vm) exited() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.status
}

// launch starts a VMM for the grant in the cgroup, restoring from the
// snapshot directory from when it is not empty, with extra after the
// API socket flag. It returns once the API answers.
func (b *Backend) launch(ctx context.Context, grantUID, from, logp string, cgroupFD int, extra []string) (*vm, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}
	run := b.runDir(id)
	if err := prepareRunDir(run, grantUID); err != nil {
		return nil, fmt.Errorf("cloudhv: run directory of %s: %w", id, err)
	}
	apif, err := bindAPI(run + "/" + apiSock)
	if err != nil {
		_ = os.RemoveAll(run)
		return nil, fmt.Errorf("cloudhv: API socket of %s: %w", id, err)
	}
	defer func() { _ = apif.Close() }()
	logf, err := os.OpenFile(logp, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		_ = os.RemoveAll(run)
		return nil, err
	}
	defer func() { _ = logf.Close() }()
	args := append([]string{"--api-socket", "fd=" + strconv.Itoa(apiFD)}, extra...)
	proc, err := b.starter.Start(jailSpec{GrantUID: grantUID, VMM: b.opt.VMM, Args: args, Kernel: b.opt.Kernel,
		Rootfs: b.opt.Rootfs, RunDir: run, From: from, CgroupFD: cgroupFD, Log: logf, API: apif})
	if err != nil {
		_ = os.RemoveAll(run)
		return nil, fmt.Errorf("cloudhv: start VMM: %w", err)
	}
	uid, _ := jailIDs(grantUID)
	v := &vm{id: id, run: run, log: logp, uid: uid, proc: proc, api: newAPI(run + "/" + apiSock), done: make(chan struct{})}
	go func() {
		st := waitStatus(proc.Wait())
		v.mu.Lock()
		v.status = st
		v.mu.Unlock()
		close(v.done)
	}()
	if err := v.waitAPI(ctx); err != nil {
		v.end()
		return nil, err
	}
	return v, nil
}

// bindAPI makes the VMM's API socket at path. fiberd binds and listens
// on it as root before the VMM starts and hands the VMM the descriptor
// (--api-socket fd=), so the name in the run directory is root's own.
// The directory is sticky, so the VMM can neither unlink the name nor
// rename anything over it, and what fiberd later dials there is the
// socket it bound and nothing the VMM planted. The socket is root's
// alone to connect to. fiberd's own listener is closed, with the name
// kept, once the VMM holds its copy, so a VMM that has ended refuses
// connections instead of queueing them.
func bindAPI(path string) (*os.File, error) {
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	ln.SetUnlinkOnClose(false)
	f, err := ln.File()
	_ = ln.Close()
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// waitStatus names how a process ended, as backend.Exit wants it.
func waitStatus(err error) string {
	if err == nil {
		return "exit:0"
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok {
			if ws.Signaled() {
				return "signal:" + strings.ToUpper(strings.TrimPrefix(ws.Signal().String(), "signal "))
			}
			return "exit:" + strconv.Itoa(ws.ExitStatus())
		}
	}
	return err.Error()
}

// poll runs try until it says done, the VMM exits or ctx ends, backing
// off from 2ms to 50ms. It returns try's last error with the reason it
// stopped.
func (v *vm) poll(ctx context.Context, what string, try func() (bool, error)) error {
	wait := 2 * time.Millisecond
	last := "nothing"
	for {
		ok, err := try()
		if ok {
			return nil
		}
		if err != nil {
			last = err.Error()
		}
		select {
		case <-v.done:
			return fmt.Errorf("%w: VMM %s exited (%s) waiting for %s (last: %s)", ErrVMM, v.id, v.exited(), what, last)
		case <-ctx.Done():
			return fmt.Errorf("%w: %s on VMM %s: %w (last: %s)", ErrVMM, what, v.id, ctx.Err(), last)
		case <-time.After(wait):
		}
		wait = min(2*wait, 50*time.Millisecond)
	}
}

// waitAPI waits for vmm.ping to answer.
func (v *vm) waitAPI(ctx context.Context) error {
	return v.poll(ctx, "the API socket", func() (bool, error) {
		pctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		err := v.api.do(pctx, http.MethodGet, "vmm.ping", nil, nil)
		return err == nil, err
	})
}

// waitState waits for vm.info to report the VM in state, as a restore
// reaches Paused once its memory is in place.
func (v *vm) waitState(ctx context.Context, state string) error {
	return v.poll(ctx, "state "+state, func() (bool, error) {
		var info struct {
			State string `json:"state"`
		}
		pctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		if err := v.api.do(pctx, http.MethodGet, "vm.info", nil, &info); err != nil {
			return false, err
		}
		if info.State == state {
			return true, nil
		}
		return false, fmt.Errorf("state %s", info.State)
	})
}

// end shuts the VMM down through its API, kills it when that does not
// end it within shutdownGrace, reaps it and removes its run directory.
func (v *vm) end() {
	select {
	case <-v.done:
	default:
		ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		_ = v.api.put(ctx, "vmm.shutdown", nil)
		cancel()
		select {
		case <-v.done:
		case <-time.After(shutdownGrace):
			_ = v.proc.Kill()
			<-v.done
		}
	}
	v.cleanup()
}

// shutdownGrace is how long vmm.shutdown gets before a kill.
const shutdownGrace = 2 * time.Second

// guestSock is a VMM's hybrid vsock socket and the VMM that must answer
// it. The VMM makes the socket and owns its name, so a compromised one
// could put a symlink to any host socket under it and have fiberd, as
// root, send it the guest's lines. Every dial is checked against the
// peer's credentials before a byte is written.
type guestSock struct {
	path string
	pid  int    // the VMM's host pid
	uid  uint32 // the VMM's uid
}

// check is an error unless c's peer is the VMM itself, by the
// credentials the kernel keeps of the process that listens behind a
// unix socket, seen from fiberd's pid namespace.
func (gs guestSock) check(c net.Conn) error {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("vsock: %T is not a unix connection", c)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		cred, gerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if gerr != nil {
		return fmt.Errorf("vsock: peer credentials: %w", gerr)
	}
	if int(cred.Pid) != gs.pid || cred.Uid != gs.uid {
		return fmt.Errorf("vsock: peer is pid %d uid %d, not the VMM (pid %d uid %d)", cred.Pid, cred.Uid, gs.pid, gs.uid)
	}
	return nil
}

// dialGuest connects to a guest port through the VMM's hybrid vsock
// socket. fiberd writes "CONNECT <port>", and the VMM answers
// "OK <host port>" once the guest has accepted. A guest that is not
// listening gets the connection dropped instead. A connection the VMM
// is not behind is closed unused.
func dialGuest(ctx context.Context, vsock guestSock, port int) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", vsock.path)
	if err != nil {
		return nil, err
	}
	if err := vsock.check(c); err != nil {
		_ = c.Close()
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if _, err := fmt.Fprintf(c, "CONNECT %d\n", port); err != nil {
		_ = c.Close()
		return nil, err
	}
	ack, err := readLine(c, 64)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("vsock port %d: %w", port, err)
	}
	if !strings.HasPrefix(ack, "OK ") {
		_ = c.Close()
		return nil, fmt.Errorf("vsock port %d: handshake answered %q", port, ack)
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

// readLine reads one line a byte at a time, so nothing after its newline
// is taken from a connection that is spliced afterwards.
func readLine(r io.Reader, limit int) (string, error) {
	var buf []byte
	b := make([]byte, 1)
	for len(buf) < limit {
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		if b[0] == '\n' {
			return string(buf), nil
		}
		buf = append(buf, b[0])
	}
	return "", fmt.Errorf("line longer than %d bytes", limit)
}

// The guest init's states, the line it opens every control connection
// with (hack/cloudhv/PROTOCOL.md).
const (
	stateReady   = "ready"   // warm, no incarnation yet
	stateServing = "serving" // an incarnation serves the endpoint
	stateParked  = "parked"  // an incarnation stopped serving for a park
)

// control opens the guest init's control port and reads its state. A
// guest that is still booting or restoring drops the connection, so it
// is tried again until ctx ends.
func (v *vm) control(ctx context.Context) (net.Conn, *bufio.Reader, string, error) {
	var c net.Conn
	var rd *bufio.Reader
	var state string
	err := v.poll(ctx, "the guest init", func() (bool, error) {
		dctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		conn, err := dialGuest(dctx, v.vsock(), controlPort)
		if err != nil {
			return false, err
		}
		if dl, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(dl)
		}
		r := bufio.NewReaderSize(conn, 512)
		line, err := r.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			return false, err
		}
		c, rd, state = conn, r, strings.TrimSpace(line)
		return true, nil
	})
	return c, rd, state, err
}

// guest sends one control line, which it zeroes once written since an
// INCARNATE carries the seed, to a guest init in one of the states from,
// and waits for want. A line the guest refuses comes back as ErrGuest
// with its reason.
func (v *vm) guest(ctx context.Context, line []byte, want string, from ...string) error {
	defer clear(line)
	c, rd, state, err := v.control(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	ok := false
	for _, s := range from {
		ok = ok || s == state
	}
	if !ok {
		return fmt.Errorf("%w: guest init is %q, want %s", ErrGuest, state, strings.Join(from, " or "))
	}
	msg := make([]byte, 0, len(line)+1)
	msg = append(msg, line...)
	msg = append(msg, '\n')
	_, err = c.Write(msg)
	clear(msg)
	if err != nil {
		return fmt.Errorf("%w: send: %w", ErrGuest, err)
	}
	reply, err := rd.ReadString('\n')
	if err != nil {
		return fmt.Errorf("%w: no answer: %w", ErrGuest, err)
	}
	reply = strings.TrimSpace(reply)
	if reply != want {
		return fmt.Errorf("%w: %s", ErrGuest, reply)
	}
	return nil
}

// endpoint serves a fiber's unix endpoint on the host. Each connection
// is spliced to a fresh connection to the guest's endpointPort, so no
// tap device, network namespace or address per fiber is needed.
type endpoint struct {
	path  string
	vsock guestSock
	ln    net.Listener

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

// serveEndpoint binds path, replacing a stale socket, and splices what
// it accepts to the guest behind vsock.
func serveEndpoint(path string, vsock guestSock) (*endpoint, error) {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("cloudhv: endpoint %s: %w", path, err)
	}
	e := &endpoint{path: path, vsock: vsock, ln: ln, conns: map[net.Conn]struct{}{}}
	e.wg.Add(1)
	go e.accept()
	return e, nil
}

func (e *endpoint) accept() {
	defer e.wg.Done()
	for {
		c, err := e.ln.Accept()
		if err != nil {
			return
		}
		if !e.track(c) {
			_ = c.Close()
			return
		}
		e.wg.Add(1)
		go e.splice(c)
	}
}

// track adds a connection to the ones close ends, and reports false once
// the endpoint is closed.
func (e *endpoint) track(c net.Conn) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return false
	}
	e.conns[c] = struct{}{}
	return true
}

func (e *endpoint) untrack(c net.Conn) {
	e.mu.Lock()
	delete(e.conns, c)
	e.mu.Unlock()
	_ = c.Close()
}

// splice copies both ways between a host client and the guest until
// either side ends.
func (e *endpoint) splice(c net.Conn) {
	defer e.wg.Done()
	defer e.untrack(c)
	ctx, cancel := context.WithTimeout(context.Background(), guestDialTimeout)
	g, err := dialGuest(ctx, e.vsock, endpointPort)
	cancel()
	if err != nil {
		return
	}
	if !e.track(g) {
		_ = g.Close()
		return
	}
	defer e.untrack(g)
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go pipe(g, c)
	go pipe(c, g)
	<-done
	<-done
}

// guestDialTimeout bounds one connection's handshake to the guest.
const guestDialTimeout = 5 * time.Second

// close stops accepting, ends every spliced connection, removes the
// socket and waits for the splices to return.
func (e *endpoint) close() {
	e.mu.Lock()
	e.closed = true
	conns := make([]net.Conn, 0, len(e.conns))
	for c := range e.conns {
		conns = append(conns, c)
	}
	e.mu.Unlock()
	_ = e.ln.Close()
	for _, c := range conns {
		_ = c.Close()
	}
	e.wg.Wait()
	_ = os.Remove(e.path)
}
