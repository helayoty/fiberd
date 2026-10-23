// Command fakevmm stands in for cloud-hypervisor where there is no KVM,
// so fiberd's cloudhv backend, the host runtime and the conformance
// suite run in CI as hack/hyperlight/fakehelper lets the hyperlight
// backend run. It serves the subset of Cloud Hypervisor's REST API the
// backend calls (hack/cloudhv/PROTOCOL.md) on --api-socket, takes the
// same flags the backend passes, and plays the guest too.
//
// Booting runs the template from the kernel command line, after "--", as
// a child process, from inside the rootfs, which must be a directory
// here. The fake then does what the guest init does in a VM, over the
// unix sockets a real VMM would make: the vsock socket with its
// "CONNECT <port>" handshake, the control port and the endpoint port.
// The template reaches host port 5000, the engine, through a guest-side
// socket the fake forwards to <vsock socket>_5000, as a real VMM
// forwards a guest's connection, so the host sees the VMM as its peer. A
// snapshot is a config.json, a state.json and an empty memory-ranges,
// and a restore starts the template afresh in the phase the snapshot
// recorded, so park and resume round-trip. The template's memory is not
// carried, so a counter starts again at a resume here.
//
//	fakevmm --api-socket path=<sock> [--restore source_url=file://<dir>[,...]] [--log-file <f>] [-v]
//	fakevmm --version
//
// Build it static (CGO_ENABLED=0), since the backend's jail holds no
// libraries.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
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
	"syscall"
	"time"
)

// version is what --version and vmm.ping report. The release is the one
// the backend's spikes pin, marked as the fake's, so parity never mixes
// a fake snapshot with a real one.
const version = "v53.0-fakevmm"

// The guest's ports, as the guest init has them, and the host port of
// the engine, the one host port the fake forwards.
const (
	endpointPort = 1024
	controlPort  = 1025
	enginePort   = 5000
)

// guestVsock is the name, beside the vsock socket, under which the fake
// plays the guest's side of a host port, guest.vsock_<port>. The template
// finds it in FIBERD_FAKE_VSOCK, where in a VM it would use AF_VSOCK.
const guestVsock = "guest.vsock"

// readyTimeout bounds the template's own init.
const readyTimeout = 2 * time.Minute

func main() {
	apiSocket := flag.String("api-socket", "", "path=<socket> (or the bare path) of the API socket")
	restore := flag.String("restore", "", "source_url=file://<dir>[,memory_restore_mode=copy|ondemand][,resume=false]")
	logFile := flag.String("log-file", "", "where the fake logs, besides stderr")
	_ = flag.Bool("v", false, "verbose (accepted, ignored)")
	_ = flag.String("seccomp", "true", "accepted, ignored: the fake has no guest to filter for")
	showVersion := flag.Bool("version", false, "print the release and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("cloud-hypervisor " + version)
		return
	}
	logw := io.Writer(os.Stderr)
	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			fatal(err)
		}
		logw = io.MultiWriter(os.Stderr, f)
	}
	if *apiSocket == "" {
		fatal(errors.New("--api-socket path=<socket> or fd=<fd> is required"))
	}
	m := &vmm{log: logw}
	if *restore != "" {
		if err := m.restoreFrom(*restore); err != nil {
			fatal(fmt.Errorf("--restore: %w", err))
		}
	}
	// fiberd binds the socket itself and passes it as fd=N, as the real
	// VMM takes it. path= is for a run by hand.
	var ln net.Listener
	if fd, ok := strings.CutPrefix(*apiSocket, "fd="); ok {
		n, err := strconv.Atoi(fd)
		if err != nil || n < 3 {
			fatal(fmt.Errorf("--api-socket fd=%s: want a descriptor above 2", fd))
		}
		ln, err = net.FileListener(os.NewFile(uintptr(n), "api"))
		if err != nil {
			fatal(fmt.Errorf("--api-socket fd=%d: %w", n, err))
		}
	} else {
		sock := strings.TrimPrefix(*apiSocket, "path=")
		_ = os.Remove(sock)
		var err error
		ln, err = net.Listen("unix", sock)
		if err != nil {
			fatal(err)
		}
	}
	m.logf("API on %s", *apiSocket)
	if err := http.Serve(ln, m.routes()); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "fakevmm: %v\n", err)
	os.Exit(1)
}

// vmConfig is the part of Cloud Hypervisor's VmConfig the fake reads.
// The whole body is kept as it came, for vm.info and config.json.
type vmConfig struct {
	Payload struct {
		Cmdline string `json:"cmdline"`
	} `json:"payload"`
	Disks []struct {
		Path string `json:"path"`
	} `json:"disks"`
	Vsock struct {
		Socket string `json:"socket"`
	} `json:"vsock"`
	Serial struct {
		Mode string `json:"mode"`
		File string `json:"file"`
	} `json:"serial"`
}

// vmm is the fake's one VM: its API state, Cloud Hypervisor's names
// (Created, Running, Paused), and the guest it plays.
type vmm struct {
	log io.Writer

	mu    sync.Mutex
	state string
	raw   json.RawMessage
	cfg   vmConfig
	g     *guest
}

func (m *vmm) logf(format string, args ...any) {
	_, _ = fmt.Fprintf(m.log, "fakevmm: "+format+"\n", args...)
}

// apiError is an answer other than success, with Cloud Hypervisor's
// status for it.
type apiError struct {
	code int
	msg  string
}

func (e *apiError) Error() string { return e.msg }

func conflict(format string, args ...any) error {
	return &apiError{http.StatusConflict, fmt.Sprintf(format, args...)}
}

// routes serves /api/v1/<action> for the actions the backend calls.
func (m *vmm) routes() http.Handler {
	mux := http.NewServeMux()
	act := func(method, name string, fn func(body []byte) (any, error)) {
		mux.HandleFunc("/api/v1/"+name, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != method {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			out, err := fn(body)
			if err != nil {
				code := http.StatusInternalServerError
				var ae *apiError
				if errors.As(err, &ae) {
					code = ae.code
				}
				m.logf("%s %s: %v", method, name, err)
				http.Error(w, err.Error(), code)
				return
			}
			if out == nil {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(out)
		})
	}
	act(http.MethodGet, "vmm.ping", func([]byte) (any, error) {
		return map[string]any{"version": version, "pid": os.Getpid()}, nil
	})
	act(http.MethodGet, "vm.info", m.info)
	act(http.MethodPut, "vm.create", m.create)
	act(http.MethodPut, "vm.boot", m.boot)
	act(http.MethodPut, "vm.pause", m.pause)
	act(http.MethodPut, "vm.resume", m.resume)
	act(http.MethodPut, "vm.snapshot", m.snapshot)
	act(http.MethodPut, "vm.restore", func(body []byte) (any, error) {
		var rc struct {
			SourceURL string `json:"source_url"`
		}
		if err := json.Unmarshal(body, &rc); err != nil {
			return nil, &apiError{http.StatusBadRequest, err.Error()}
		}
		return nil, m.restoreFrom("source_url=" + rc.SourceURL)
	})
	act(http.MethodPut, "vmm.shutdown", func([]byte) (any, error) {
		// Answer first, then end, as the real VMM's shutdown does.
		go func() {
			time.Sleep(20 * time.Millisecond)
			m.mu.Lock()
			if m.g != nil {
				m.g.kill()
			}
			m.mu.Unlock()
			os.Exit(0)
		}()
		return nil, nil
	})
	return mux
}

func (m *vmm) info([]byte) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == "" {
		return nil, &apiError{http.StatusNotFound, "VM is not created"}
	}
	return map[string]any{"state": m.state, "config": m.raw}, nil
}

func (m *vmm) create(body []byte) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != "" {
		return nil, conflict("VM is already created")
	}
	var cfg vmConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, &apiError{http.StatusBadRequest, err.Error()}
	}
	m.raw, m.cfg, m.state = append(json.RawMessage(nil), body...), cfg, "Created"
	return nil, nil
}

func (m *vmm) boot([]byte) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != "Created" {
		return nil, conflict("VM is %s, not created", m.state)
	}
	g, err := m.startGuest(phaseReady)
	if err != nil {
		return nil, err
	}
	m.g, m.state = g, "Running"
	return nil, nil
}

func (m *vmm) pause([]byte) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != "Running" {
		return nil, &apiError{http.StatusMethodNotAllowed, "VM is " + m.state + ", not running"}
	}
	m.g.signal(syscall.SIGSTOP)
	m.state = "Paused"
	return nil, nil
}

func (m *vmm) resume([]byte) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != "Paused" {
		return nil, &apiError{http.StatusMethodNotAllowed, "VM is " + m.state + ", not paused"}
	}
	m.g.signal(syscall.SIGCONT)
	m.state = "Running"
	return nil, nil
}

// snapshotState is the fake's state.json: the guest's phase, which a
// restore starts the template again in.
type snapshotState struct {
	Fake  string `json:"fake"`
	Phase string `json:"phase"`
}

func (m *vmm) snapshot(body []byte) (any, error) {
	var sc struct {
		DestinationURL string `json:"destination_url"`
	}
	if err := json.Unmarshal(body, &sc); err != nil {
		return nil, &apiError{http.StatusBadRequest, err.Error()}
	}
	dir, ok := strings.CutPrefix(sc.DestinationURL, "file://")
	if !ok {
		return nil, &apiError{http.StatusBadRequest, "destination_url is not file://"}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != "Paused" {
		return nil, &apiError{http.StatusMethodNotAllowed, "VM is " + m.state + ", not paused"}
	}
	st, err := json.Marshal(snapshotState{Fake: version, Phase: m.g.phaseNow()})
	if err != nil {
		return nil, err
	}
	for name, data := range map[string][]byte{"config.json": m.raw, "state.json": st, "memory-ranges": nil} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return nil, err
		}
	}
	m.logf("snapshot in %s, guest %s", dir, m.g.phaseNow())
	return nil, nil
}

// restoreFrom takes --restore's option string and leaves the VM paused
// with the template ready again in the snapshot's phase. A guest that
// was serving when snapshotted comes back parked, since the fake carries
// no connection or memory over. It refuses the options v53.0 refuses, so
// a run over the fake catches a mode the pinned VMM would not take.
func (m *vmm) restoreFrom(opts string) error {
	var dir string
	onDemand, prefault := false, false
	for _, kv := range strings.Split(opts, ",") {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case "source_url":
			d, ok := strings.CutPrefix(v, "file://")
			if !ok {
				return &apiError{http.StatusBadRequest, "source_url is not file://"}
			}
			dir = d
		case "memory_restore_mode":
			// v53.0 takes copy and ondemand only. copyonwrite is v54.0's.
			if v != "copy" && v != "ondemand" {
				return &apiError{http.StatusBadRequest, "invalid memory_restore_mode " + strconv.Quote(v)}
			}
			onDemand = v == "ondemand"
		case "prefault":
			prefault = v == "on" || v == "true"
		case "resume":
		default:
			return &apiError{http.StatusBadRequest, "unknown restore option " + strconv.Quote(k)}
		}
	}
	if onDemand && prefault {
		return &apiError{http.StatusBadRequest, "'prefault' cannot be combined with 'memory_restore_mode=ondemand'"}
	}
	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return err
	}
	var cfg vmConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	stRaw, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		return err
	}
	var st snapshotState
	if err := json.Unmarshal(stRaw, &st); err != nil {
		return err
	}
	if st.Fake != version {
		return fmt.Errorf("snapshot in %s was not taken by fakevmm %s", dir, version)
	}
	phase := st.Phase
	if phase != phaseReady {
		phase = phaseParked
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != "" {
		return conflict("VM is already created")
	}
	m.raw, m.cfg = raw, cfg
	g, err := m.startGuest(phase)
	if err != nil {
		return err
	}
	g.signal(syscall.SIGSTOP)
	m.g, m.state = g, "Paused"
	m.logf("restored from %s, guest %s", dir, phase)
	return nil
}

// The guest init's phases, the line every control connection opens with.
const (
	phaseReady   = "ready"
	phaseServing = "serving"
	phaseParked  = "parked"
)

// guest is the template child and the guest init's part, played here.
type guest struct {
	m        *vmm
	cmd      *exec.Cmd
	ch       *os.File
	rd       *bufio.Reader
	vsock    string
	endpoint string
	ln       net.Listener
	host     net.Listener // the guest side of host port enginePort

	ctl sync.Mutex // one control exchange at a time, as the guest init has

	pmu    sync.Mutex
	phase  string
	splice map[net.Conn]struct{}
}

func (g *guest) phaseNow() string {
	g.pmu.Lock()
	defer g.pmu.Unlock()
	return g.phase
}

func (g *guest) setPhase(p string) {
	g.pmu.Lock()
	g.phase = p
	g.pmu.Unlock()
}

// startGuest boots the guest the configuration names: the template
// after "--" on the kernel command line, run from the directory rootfs
// with the template side of the protocol on fd 3, and the vsock socket
// listening. It returns once the template has said READY. Called with
// m.mu held.
func (m *vmm) startGuest(phase string) (*guest, error) {
	cfg := m.cfg
	_, args, ok := strings.Cut(cfg.Payload.Cmdline, " -- ")
	argv := strings.Fields(args)
	if !ok || len(argv) == 0 {
		return nil, conflict("kernel command line names no template after --")
	}
	if len(cfg.Disks) == 0 || cfg.Vsock.Socket == "" {
		return nil, conflict("VM has no rootfs disk or no vsock")
	}
	rootfs := cfg.Disks[0].Path
	if st, err := os.Stat(rootfs); err != nil || !st.IsDir() {
		return nil, conflict("the fake VMM needs a directory as its rootfs, not %s", rootfs)
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	parent, child := os.NewFile(uintptr(fds[0]), "channel"), os.NewFile(uintptr(fds[1]), "channel-child")
	defer func() { _ = child.Close() }()
	dir := filepath.Dir(cfg.Vsock.Socket)
	g := &guest{m: m, ch: parent, rd: bufio.NewReader(parent), vsock: cfg.Vsock.Socket,
		endpoint: filepath.Join(dir, "fiber.sock"), phase: phase, splice: map[net.Conn]struct{}{}}
	// The guest side of the engine's port listens before the template
	// starts, so its first request finds it.
	guestSide := filepath.Join(dir, guestVsock)
	guestPort := guestSide + "_" + strconv.Itoa(enginePort)
	_ = os.Remove(guestPort)
	if g.host, err = net.Listen("unix", guestPort); err != nil {
		_ = parent.Close()
		return nil, err
	}
	cmd := exec.Command(filepath.Join(rootfs, argv[0]), argv[1:]...)
	cmd.Env = []string{"FIBERD_ENDPOINT=" + g.endpoint, "FIBERD_ENGINE=vsock://2:" + strconv.Itoa(enginePort), "FIBERD_FAKE_VSOCK=" + guestSide}
	cmd.ExtraFiles = []*os.File{child}
	cmd.Stdout, cmd.Stderr = m.console(), m.console()
	if err := cmd.Start(); err != nil {
		_ = parent.Close()
		_ = g.host.Close()
		return nil, fmt.Errorf("start template %s: %w", argv[0], err)
	}
	g.cmd = cmd
	ready := make(chan error, 1)
	go func() {
		line, err := g.rd.ReadString('\n')
		switch {
		case err != nil:
			ready <- fmt.Errorf("template ended before READY: %w", err)
		case strings.TrimSpace(line) != "READY":
			ready <- fmt.Errorf("template said %q, want READY", strings.TrimSpace(line))
		default:
			ready <- nil
		}
	}()
	select {
	case err = <-ready:
	case <-time.After(readyTimeout):
		err = errors.New("template not READY in time")
	}
	if err != nil {
		g.kill()
		_ = g.host.Close()
		return nil, err
	}
	// A template that ends is a guest that powered off, which ends the
	// VMM, as it ends a real one.
	go func() {
		err := cmd.Wait()
		m.logf("template ended (%v), powering off", err)
		os.Exit(0)
	}()
	_ = os.Remove(g.vsock)
	if g.ln, err = net.Listen("unix", g.vsock); err != nil {
		g.kill()
		_ = g.host.Close()
		return nil, err
	}
	go g.acceptVsock()
	go g.acceptHost(enginePort)
	return g, nil
}

// console is where the guest's output goes: the serial file the
// configuration names, else the fake's own log.
func (m *vmm) console() io.Writer {
	if m.cfg.Serial.Mode == "File" && m.cfg.Serial.File != "" {
		if f, err := os.OpenFile(m.cfg.Serial.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
			return f
		}
	}
	return m.log
}

func (g *guest) signal(sig syscall.Signal) {
	if g.cmd != nil && g.cmd.Process != nil {
		_ = g.cmd.Process.Signal(sig)
	}
}

func (g *guest) kill() {
	if g.cmd != nil && g.cmd.Process != nil {
		_ = g.cmd.Process.Kill()
	}
}

// running reports whether the VM runs, since a paused guest answers no
// connection.
func (g *guest) running() bool {
	g.m.mu.Lock()
	defer g.m.mu.Unlock()
	return g.m.state == "Running"
}

// control is one control connection, as the guest init serves it: the
// phase, one command, one answer. The fake cannot add entropy to a
// kernel pool, so the seed reaches the template alone.
func (g *guest) control(c net.Conn) {
	g.ctl.Lock()
	defer g.ctl.Unlock()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	phase := g.phaseNow()
	if _, err := fmt.Fprintln(c, phase); err != nil {
		return
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return
	}
	words := strings.Fields(line)
	answer := "error empty line"
	if len(words) > 0 {
		answer = g.command(phase, words[0], strings.TrimSpace(line))
	}
	_, _ = fmt.Fprintln(c, answer)
}

// command runs one control command in phase and is the answer to it.
func (g *guest) command(phase, verb, line string) string {
	want := map[string]string{"INCARNATE": "ready|parked", "PARK": "serving", "UNPARK": "parked"}[verb]
	if want == "" {
		return "error unknown command " + strconv.Quote(verb)
	}
	if !strings.Contains("|"+want+"|", "|"+phase+"|") {
		return "error " + verb + " in phase " + phase
	}
	if verb == "PARK" {
		g.dropSplices()
	}
	reply, err := g.tell(line)
	if err != nil {
		return "error template " + err.Error()
	}
	switch {
	case verb == "PARK" && reply == "PARKED":
		g.setPhase(phaseParked)
		return "parked"
	case verb != "PARK" && reply == "SERVED":
		g.setPhase(phaseServing)
		return "served"
	}
	return "error template " + reply
}

// tell sends the template one line on its channel and reads its answer.
func (g *guest) tell(line string) (string, error) {
	if _, err := g.ch.WriteString(line + "\n"); err != nil {
		return "", err
	}
	reply, err := g.rd.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(reply), nil
}

// acceptVsock serves the vsock socket as a real VMM does for the host's
// connections into the guest: "CONNECT <port>\n", then "OK <port>\n" once
// the guest has accepted, or the connection dropped when nothing listens.
func (g *guest) acceptVsock() {
	for {
		c, err := g.ln.Accept()
		if err != nil {
			return
		}
		go g.connect(c)
	}
}

func (g *guest) connect(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	port, err := readConnect(c)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil || !g.running() {
		_ = c.Close()
		return
	}
	switch port {
	case controlPort:
		if _, err := fmt.Fprintf(c, "OK %d\n", 50000+port); err == nil {
			g.control(c)
		}
		_ = c.Close()
	case endpointPort:
		g.serveEndpoint(c)
	default:
		_ = c.Close()
	}
}

// readConnect reads the handshake a byte at a time, so nothing after it
// is taken from what is spliced. The VMM takes "connect" in either case.
func readConnect(c net.Conn) (int, error) {
	var line []byte
	b := make([]byte, 1)
	for len(line) < 32 {
		if _, err := io.ReadFull(c, b); err != nil {
			return 0, err
		}
		if b[0] == '\n' {
			rest, ok := strings.CutPrefix(strings.ToLower(string(line)), "connect ")
			if !ok {
				return 0, fmt.Errorf("handshake %q", line)
			}
			return strconv.Atoi(strings.TrimSpace(rest))
		}
		line = append(line, b[0])
	}
	return 0, errors.New("handshake too long")
}

// serveEndpoint splices a host connection to the template's endpoint,
// while the guest serves.
func (g *guest) serveEndpoint(c net.Conn) {
	if g.phaseNow() != phaseServing {
		_ = c.Close()
		return
	}
	t, err := net.Dial("unix", g.endpoint)
	if err != nil {
		_ = c.Close()
		return
	}
	if !g.track(c, t) {
		_ = c.Close()
		_ = t.Close()
		return
	}
	if _, err := fmt.Fprintf(c, "OK %d\n", 50000+endpointPort); err != nil {
		g.untrack(c, t)
		return
	}
	splice(c, t)
	g.untrack(c, t)
}

// splice copies both ways between a and b until both directions end,
// half-closing the other side when one reaches its end.
func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go pipe(b, a)
	go pipe(a, b)
	<-done
	<-done
}

// acceptHost serves the guest side of host port port. Each connection
// the template makes there is one its guest made to the host, which the
// fake connects on to <vsock socket>_<port> and splices, as Cloud
// Hypervisor's vsock muxer does. The name there is fiberd's, made before
// the VMM started, and the host's end sees this process as its peer.
func (g *guest) acceptHost(port int) {
	for {
		c, err := g.host.Accept()
		if err != nil {
			return
		}
		go g.forward(c, port)
	}
}

// forward is one guest connection to host port port, dropped when the VM
// is paused or nothing listens on the host's side.
func (g *guest) forward(c net.Conn, port int) {
	defer func() { _ = c.Close() }()
	if !g.running() {
		return
	}
	h, err := net.Dial("unix", g.vsock+"_"+strconv.Itoa(port))
	if err != nil {
		return
	}
	defer func() { _ = h.Close() }()
	splice(c, h)
}

// track records a splice's two ends, so a park can drop them, and
// reports false when the guest stopped serving meanwhile.
func (g *guest) track(cs ...net.Conn) bool {
	g.pmu.Lock()
	defer g.pmu.Unlock()
	if g.phase != phaseServing {
		return false
	}
	for _, c := range cs {
		g.splice[c] = struct{}{}
	}
	return true
}

func (g *guest) untrack(cs ...net.Conn) {
	g.pmu.Lock()
	for _, c := range cs {
		delete(g.splice, c)
	}
	g.pmu.Unlock()
	for _, c := range cs {
		_ = c.Close()
	}
}

// dropSplices ends every spliced connection, as the guest init does
// before it asks the template to park.
func (g *guest) dropSplices() {
	g.pmu.Lock()
	cs := make([]net.Conn, 0, len(g.splice))
	for c := range g.splice {
		cs = append(cs, c)
		delete(g.splice, c)
	}
	g.pmu.Unlock()
	for _, c := range cs {
		_ = c.Close()
	}
}
