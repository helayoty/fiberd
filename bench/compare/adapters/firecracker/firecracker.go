// Package firecracker is the microVM comparator: one Firecracker
// process per instance, restored from a snapshot of a booted guest with
// `PUT /snapshot/load` and resumed in the same call. It is plain
// Firecracker v1.17.0 over its API socket, the mechanism every
// Firecracker product sits above (docs/design/compare.md says why not
// firecracker-containerd or E2B's stack).
//
// Every restored guest has the snapshot's IP and MAC, so each instance
// runs in a network namespace of its own with a tap0 of its own, and the
// host reaches it through a veth pair and a DNAT rule (netns.sh). The
// guest memory comes from the snapshot file (the default) or through a
// UFFD page-fault handler (the labelled variant).
package firecracker

import (
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
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/helayoty/fiberd/bench/compare"
)

// Options configure the adapter.
type Options struct {
	Binary string
	Kernel string
	Rootfs string
	// SnapshotDir holds vmstate and mem of the warm guest. Setup makes
	// them when missing and keeps them, so the page cache is the one
	// allowed cache.
	SnapshotDir string
	// WorkDir holds API sockets and per-instance park directories.
	WorkDir string
	// Netns is netns.sh, which makes and removes a slot's namespace.
	Netns string
	// UFFDHandler is Firecracker's example page-fault handler. Empty
	// restores from the file.
	UFFDHandler string
	VCPU        int
	MemMiB      int
	// GuestIP is what the guest configures on eth0, and Port where the
	// counter listens.
	GuestIP  string
	Port     int
	BootArgs string
	// MaxSlots caps concurrent instances, one namespace each.
	MaxSlots int
	Poll     time.Duration
	// Launch overrides how a Firecracker process is started, for tests.
	Launch Launcher
}

// VM is one running Firecracker process.
type VM interface {
	// Addr is the address the host dials to reach the guest's port.
	Addr() string
	Pid() int
	Kill() error
}

// Launcher starts a Firecracker process in a slot's network namespace,
// serving its API on sock, and returns once the socket answers.
type Launcher interface {
	Start(ctx context.Context, slot int, sock string) (VM, error)
}

// Adapter implements compare.Adapter.
type Adapter struct {
	o      Options
	launch Launcher

	mu    sync.Mutex
	slots map[int]bool
	vms   map[string]*instance
}

type instance struct {
	slot    int
	vm      VM
	handler *exec.Cmd
}

// New checks the options.
func New(o Options) (*Adapter, error) {
	if o.Kernel == "" || o.Rootfs == "" || o.SnapshotDir == "" || o.WorkDir == "" {
		return nil, errors.New("firecracker: need Kernel, Rootfs, SnapshotDir and WorkDir")
	}
	if o.Binary == "" {
		o.Binary = "firecracker"
	}
	if o.VCPU <= 0 {
		o.VCPU = 1
	}
	if o.MemMiB <= 0 {
		o.MemMiB = 64
	}
	if o.GuestIP == "" {
		o.GuestIP = "172.16.0.2"
	}
	if o.Port == 0 {
		o.Port = 8080
	}
	if o.MaxSlots <= 0 {
		o.MaxSlots = 256
	}
	if o.BootArgs == "" {
		// The counter is init. It brings eth0 up itself (--ifup) and
		// serves HTTP, so the rootfs holds nothing else.
		o.BootArgs = "console=ttyS0 reboot=k panic=1 pci=off quiet init=/counter -- --plain --port " + strconv.Itoa(o.Port) + " --ifup eth0=" + o.GuestIP + "/30"
	}
	a := &Adapter{o: o, launch: o.Launch, slots: map[int]bool{}, vms: map[string]*instance{}}
	if a.launch == nil {
		a.launch = &execLauncher{o: o}
	}
	return a, nil
}

// api is the HTTP client over one API socket.
type api struct{ c *http.Client }

func dialAPI(sock string) api {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}
	return api{c: &http.Client{Transport: tr}}
}

func (a api) do(ctx context.Context, method, path string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://firecracker"+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.c.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("firecracker: %s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(out)))
	}
	return nil
}

func (a *Adapter) vmstate(dir string) string { return filepath.Join(dir, "vmstate") }
func (a *Adapter) mem(dir string) string     { return filepath.Join(dir, "mem") }

// LoadParams is the body of PUT /snapshot/load for a snapshot in dir.
// uffdSock selects the UFFD backend when set.
func (a *Adapter) LoadParams(dir, uffdSock string) map[string]any {
	backend := map[string]any{"backend_type": "File", "backend_path": a.mem(dir)}
	if uffdSock != "" {
		backend = map[string]any{"backend_type": "Uffd", "backend_path": uffdSock}
	}
	return map[string]any{"snapshot_path": a.vmstate(dir), "mem_backend": backend, "resume_vm": true}
}

// BootSequence is the API calls that boot the warm guest, in order.
func (a *Adapter) BootSequence() []struct {
	Path string
	Body map[string]any
} {
	return []struct {
		Path string
		Body map[string]any
	}{
		{"/machine-config", map[string]any{"vcpu_count": a.o.VCPU, "mem_size_mib": a.o.MemMiB, "smt": false}},
		{"/boot-source", map[string]any{"kernel_image_path": a.o.Kernel, "boot_args": a.o.BootArgs}},
		{"/drives/rootfs", map[string]any{"drive_id": "rootfs", "path_on_host": a.o.Rootfs, "is_root_device": true, "is_read_only": true}},
		{"/network-interfaces/eth0", map[string]any{"iface_id": "eth0", "guest_mac": "06:00:AC:10:00:02", "host_dev_name": "tap0"}},
		{"/actions", map[string]any{"action_type": "InstanceStart"}},
	}
}

// Setup boots the guest once, waits for its first 200, pauses it and
// writes the snapshot. Nothing is done when the snapshot exists.
func (a *Adapter) Setup(ctx context.Context) error {
	if err := os.MkdirAll(a.o.WorkDir, 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(a.vmstate(a.o.SnapshotDir)); err == nil {
		return nil
	}
	if err := os.MkdirAll(a.o.SnapshotDir, 0o755); err != nil {
		return err
	}
	slot, err := a.take()
	if err != nil {
		return err
	}
	defer a.free(slot)
	sock := filepath.Join(a.o.WorkDir, "boot.sock")
	vm, err := a.launch.Start(ctx, slot, sock)
	if err != nil {
		return err
	}
	defer func() { _ = vm.Kill() }()
	c := dialAPI(sock)
	for _, step := range a.BootSequence() {
		if err := c.do(ctx, http.MethodPut, step.Path, step.Body); err != nil {
			return err
		}
	}
	addr := net.JoinHostPort(vm.Addr(), strconv.Itoa(a.o.Port))
	if _, err := (compare.Probe{Dial: compare.TCP(addr), Framing: compare.HTTP, Poll: a.o.Poll}).Run(ctx); err != nil {
		return fmt.Errorf("boot: %w", err)
	}
	return a.snapshot(ctx, c, a.o.SnapshotDir)
}

// snapshot pauses the guest and writes a full snapshot into dir.
func (a *Adapter) snapshot(ctx context.Context, c api, dir string) error {
	if err := c.do(ctx, http.MethodPatch, "/vm", map[string]any{"state": "Paused"}); err != nil {
		return err
	}
	return c.do(ctx, http.MethodPut, "/snapshot/create", map[string]any{
		"snapshot_type": "Full", "snapshot_path": a.vmstate(dir), "mem_file_path": a.mem(dir),
	})
}

func (a *Adapter) take() (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for s := range a.o.MaxSlots {
		if !a.slots[s] {
			a.slots[s] = true
			return s, nil
		}
	}
	return 0, fmt.Errorf("firecracker: all %d slots busy", a.o.MaxSlots)
}

func (a *Adapter) free(slot int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.slots, slot)
}

// Activate restores the warm snapshot into a fresh process.
func (a *Adapter) Activate(ctx context.Context, id string) (compare.Handle, error) {
	slot, err := a.take()
	if err != nil {
		return compare.Handle{}, err
	}
	h, err := a.restore(ctx, id, slot, a.o.SnapshotDir)
	if err != nil {
		a.free(slot)
	}
	return h, err
}

// restore starts a process in slot and loads the snapshot in dir.
func (a *Adapter) restore(ctx context.Context, id string, slot int, dir string) (compare.Handle, error) {
	sock := filepath.Join(a.o.WorkDir, fmt.Sprintf("fc-%d.sock", slot))
	_ = os.Remove(sock)
	vm, err := a.launch.Start(ctx, slot, sock)
	if err != nil {
		return compare.Handle{}, err
	}
	inst := &instance{slot: slot, vm: vm}
	uffd := ""
	if a.o.UFFDHandler != "" {
		uffd = filepath.Join(a.o.WorkDir, fmt.Sprintf("uffd-%d.sock", slot))
		_ = os.Remove(uffd)
		inst.handler = exec.CommandContext(ctx, a.o.UFFDHandler, uffd, a.mem(dir))
		if err := inst.handler.Start(); err != nil {
			_ = vm.Kill()
			return compare.Handle{}, fmt.Errorf("uffd handler: %w", err)
		}
		if err := waitSocket(ctx, uffd); err != nil {
			inst.kill()
			return compare.Handle{}, fmt.Errorf("uffd handler: %w", err)
		}
	}
	if err := dialAPI(sock).do(ctx, http.MethodPut, "/snapshot/load", a.LoadParams(dir, uffd)); err != nil {
		inst.kill()
		return compare.Handle{}, err
	}
	a.mu.Lock()
	a.vms[id] = inst
	a.mu.Unlock()
	return compare.Handle{ID: id, Addr: net.JoinHostPort(vm.Addr(), strconv.Itoa(a.o.Port)),
		Meta: map[string]string{"slot": strconv.Itoa(slot), "pid": strconv.Itoa(vm.Pid()), "sock": sock}}, nil
}

func (i *instance) kill() {
	_ = i.vm.Kill()
	if i.handler != nil && i.handler.Process != nil {
		_ = i.handler.Process.Kill()
		_ = i.handler.Wait()
	}
}

// Ready polls the guest's port. The address is routable before the
// resumed guest answers, so attempts are expected.
func (a *Adapter) Ready(ctx context.Context, h compare.Handle) (compare.Handle, time.Time, error) {
	r, err := compare.Probe{Dial: compare.TCP(h.Addr), Framing: compare.HTTP, Poll: a.o.Poll}.Run(ctx)
	if err != nil {
		return h, time.Time{}, err
	}
	h.Meta["attempts"] = strconv.Itoa(r.Attempts)
	return h, r.FirstByte, nil
}

// Release kills the process and frees the slot.
func (a *Adapter) Release(_ context.Context, h compare.Handle) error {
	a.mu.Lock()
	inst := a.vms[h.ID]
	delete(a.vms, h.ID)
	a.mu.Unlock()
	if inst == nil {
		return nil
	}
	inst.kill()
	a.free(inst.slot)
	return nil
}

// Resume pauses the guest, snapshots it into its own directory, ends the
// process and restores that snapshot into a new one in the same slot.
func (a *Adapter) Resume(ctx context.Context, h compare.Handle) (compare.Handle, error) {
	a.mu.Lock()
	inst := a.vms[h.ID]
	a.mu.Unlock()
	if inst == nil {
		return compare.Handle{}, fmt.Errorf("firecracker: unknown instance %s", h.ID)
	}
	dir := filepath.Join(a.o.WorkDir, "park-"+h.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return compare.Handle{}, err
	}
	if err := a.snapshot(ctx, dialAPI(h.Meta["sock"]), dir); err != nil {
		return compare.Handle{}, err
	}
	a.mu.Lock()
	delete(a.vms, h.ID)
	a.mu.Unlock()
	inst.kill()
	nh, err := a.restore(ctx, h.ID, inst.slot, dir)
	if err != nil {
		a.free(inst.slot)
	}
	return nh, err
}

// Density is the resident set of the instances' processes, the handler
// included. Nothing stands between activations but the snapshot files.
func (a *Adapter) Density(_ context.Context, hs []compare.Handle) (int64, error) {
	var total int64
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, h := range hs {
		inst := a.vms[h.ID]
		if inst == nil {
			continue
		}
		pids := []int{inst.vm.Pid()}
		if inst.handler != nil && inst.handler.Process != nil {
			pids = append(pids, inst.handler.Process.Pid)
		}
		for _, pid := range pids {
			n, err := RSS(pid)
			if err != nil {
				return 0, err
			}
			total += n
		}
	}
	return total, nil
}

// RSS reads VmRSS of a process, in bytes.
func RSS(pid int) (int64, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "VmRSS:" {
			kb, err := strconv.ParseInt(f[1], 10, 64)
			return kb << 10, err
		}
	}
	return 0, fmt.Errorf("no VmRSS for pid %d", pid)
}

// waitSocket waits for a unix socket to accept.
func waitSocket(ctx context.Context, path string) error {
	for {
		c, err := net.Dial("unix", path)
		if err == nil {
			_ = c.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s: %w", path, ctx.Err())
		case <-time.After(2 * time.Millisecond):
		}
	}
}

// execLauncher runs netns.sh and Firecracker.
type execLauncher struct{ o Options }

type process struct {
	cmd  *exec.Cmd
	addr string
	down func()
}

func (p *process) Addr() string { return p.addr }
func (p *process) Pid() int     { return p.cmd.Process.Pid }
func (p *process) Kill() error {
	err := p.cmd.Process.Kill()
	_ = p.cmd.Wait()
	p.down()
	return err
}

// Start brings the slot's namespace up (netns.sh prints the address the
// host dials), runs Firecracker inside it and waits for the API socket.
func (l *execLauncher) Start(ctx context.Context, slot int, sock string) (VM, error) {
	if l.o.Netns == "" {
		return nil, errors.New("firecracker: need Netns (netns.sh)")
	}
	out, err := exec.CommandContext(ctx, l.o.Netns, "up", strconv.Itoa(slot)).Output()
	if err != nil {
		return nil, fmt.Errorf("netns up %d: %w", slot, err)
	}
	addr := strings.TrimSpace(string(out))
	down := func() { _ = exec.Command(l.o.Netns, "down", strconv.Itoa(slot)).Run() }
	cmd := exec.Command("ip", "netns", "exec", Namespace(slot), l.o.Binary, "--api-sock", sock, "--id", fmt.Sprintf("slot%d", slot))
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		down()
		return nil, err
	}
	p := &process{cmd: cmd, addr: addr, down: down}
	if err := waitSocket(ctx, sock); err != nil {
		_ = p.Kill()
		return nil, err
	}
	return p, nil
}

// Namespace is the network namespace name netns.sh gives a slot.
func Namespace(slot int) string { return "fc-" + strconv.Itoa(slot) }
