//go:build linux

package gvisor

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The test binary doubles as a runsc and as the sandbox a runsc leaves
// behind, so the backend's commands can be exercised without gVisor.
// Options.Runsc is a one-line shell wrapper that execs the binary with
// fakeRunscArg and the configuration directory.
const (
	fakeRunscArg   = "fake-runsc"
	fakeSandboxArg = "fake-sandbox"
	fakeVersion    = "release-20260817.0"
	imageFile      = "checkpoint.img"
)

// knobs script the fake runsc. They are read from <cfg>/knobs on every
// invocation.
type knobs struct {
	Fail        map[string]bool // commands that fail: run, restore, checkpoint, state, kill, wait
	LongOutput  bool            // a failing command prints more than the error tail keeps
	NoMarker    bool            // the template sandbox never drops its ready marker
	NoServe     bool            // a fiber sandbox never serves its endpoint
	IgnoreUSR1  bool            // a sandbox keeps its endpoint through a park request
	SlowRestore time.Duration   // restore sleeps this long before starting the sandbox
	SlowCheckpt time.Duration   // a checkpoint that ends the sandbox returns this long after it is gone
	ExitStatus  int             // what `wait` reports
	BadWaitJSON bool            // `wait` prints something that is not JSON
	// GateDelete holds the first `delete` that runs after the knob is set
	// until <cfg>/gate.open exists, and marks <cfg>/gate.passed once that
	// delete has done its work: a reaper's late delete, placed at will.
	GateDelete bool
}

// gateFiles are what GateDelete uses: the claim the one gated delete
// takes, the file the test creates to let it go, and its mark.
const (
	gateClaimed = "gate.claimed"
	gateOpen    = "gate.open"
	gatePassed  = "gate.passed"
)

func TestMain(m *testing.M) {
	switch {
	case len(os.Args) >= 3 && os.Args[1] == fakeRunscArg:
		os.Exit(fakeRunsc(os.Args[2], os.Args[3:]))
	case len(os.Args) >= 5 && os.Args[1] == fakeSandboxArg:
		fakeSandbox(os.Args[2], os.Args[3], os.Args[4])
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// fakeRunscBin writes the wrapper and the knobs into a fresh
// configuration directory and returns the wrapper's path and that
// directory.
func fakeRunscBin(t *testing.T, k knobs) (bin, cfg string) {
	t.Helper()
	cfg = t.TempDir()
	setKnobs(t, cfg, k)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin = filepath.Join(cfg, "runsc")
	// Under -race the test binary sleeps a second at exit (GORACE
	// atexit_sleep_ms defaults to 1000), which every fake runsc command
	// and every fake sandbox would pay. The backend's deadlines are sized
	// for runsc, so the sleep is turned off for both.
	script := fmt.Sprintf("#!/bin/sh\nexport GORACE=\"${GORACE:+$GORACE }atexit_sleep_ms=0\"\nexec %q %s %q \"$@\"\n", exe, fakeRunscArg, cfg)
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, cfg
}

func setKnobs(t *testing.T, cfg string, k knobs) {
	t.Helper()
	b, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg, "knobs"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// runscCalls is every recorded invocation, arguments joined by spaces.
func runscCalls(t *testing.T, cfg string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(cfg, "calls.log"))
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

// sandboxState is what the fake sandbox records about itself while it
// runs, at <cfg>/state/<cid>.json. Its absence means the sandbox is gone.
type sandboxState struct {
	PID      int    `json:"pid"`
	Endpoint string `json:"endpoint"`
}

func stateFile(cfg, cid string) string { return filepath.Join(cfg, "state", cid+".json") }

func readState(cfg, cid string) (sandboxState, error) {
	var st sandboxState
	b, err := os.ReadFile(stateFile(cfg, cid))
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(b, &st)
}

// fakeRunsc is one runsc invocation. The global --flags come first.
func fakeRunsc(cfg string, args []string) int {
	logf, err := os.OpenFile(filepath.Join(cfg, "calls.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err == nil {
		_, _ = logf.WriteString(strings.Join(args, " ") + "\n")
		_ = logf.Close()
	}
	var k knobs
	if b, err := os.ReadFile(filepath.Join(cfg, "knobs")); err == nil {
		_ = json.Unmarshal(b, &k)
	}
	for _, a := range args {
		if a == "--version" {
			fmt.Printf("runsc version %s\nspec: 1.1.0-rc.1\n", fakeVersion)
			return 0
		}
	}
	for len(args) > 0 && strings.HasPrefix(args[0], "--") {
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Println("no command")
		return 1
	}
	cmd, rest := args[0], args[1:]
	flag := func(name string) string {
		for i := range rest {
			if rest[i] == name && i+1 < len(rest) {
				return rest[i+1]
			}
		}
		return ""
	}
	has := func(name string) bool {
		for _, a := range rest {
			if a == name {
				return true
			}
		}
		return false
	}
	cid := ""
	if len(rest) > 0 {
		cid = rest[len(rest)-1]
		if cmd == "kill" && len(rest) >= 2 {
			cid = rest[len(rest)-2]
		}
	}
	fail := func(what string) int {
		if k.LongOutput {
			fmt.Print(strings.Repeat("x", 600))
		}
		fmt.Printf("fake runsc: %s failed\n", what)
		return 1
	}
	if k.Fail[cmd] {
		return fail(cmd)
	}
	switch cmd {
	case "list":
		// -quiet: one container id per line, from the state directory.
		ents, _ := os.ReadDir(filepath.Join(cfg, "state"))
		for _, e := range ents {
			fmt.Println(strings.TrimSuffix(e.Name(), ".json"))
		}
		return 0
	case "delete":
		gated := false
		if k.GateDelete {
			if f, err := os.OpenFile(filepath.Join(cfg, gateClaimed), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644); err == nil {
				_ = f.Close()
				gated = true
				for {
					if _, err := os.Stat(filepath.Join(cfg, gateOpen)); err == nil {
						break
					}
					time.Sleep(5 * time.Millisecond)
				}
			}
		}
		// -force on a running container ends it first.
		code := endSandbox(cfg, cid)
		if gated {
			_ = os.WriteFile(filepath.Join(cfg, gatePassed), nil, 0o644)
		}
		return code
	case "run", "restore":
		if cmd == "restore" {
			if _, err := os.Stat(filepath.Join(flag("--image-path"), imageFile)); err != nil {
				fmt.Printf("fake runsc: no image at %s\n", flag("--image-path"))
				return 1
			}
			time.Sleep(k.SlowRestore)
		}
		return startSandbox(cfg, cid, flag("--bundle"))
	case "checkpoint":
		img := flag("--image-path")
		if err := os.MkdirAll(img, 0o755); err != nil {
			return fail("mkdir")
		}
		if err := os.WriteFile(filepath.Join(img, imageFile), []byte(cid), 0o644); err != nil {
			return fail("write image")
		}
		if !has("--leave-running") {
			code := endSandbox(cfg, cid)
			time.Sleep(k.SlowCheckpt) // image flush and cleanup after the sandbox is gone
			return code
		}
		return 0
	case "state":
		st, err := readState(cfg, cid)
		if err != nil {
			fmt.Printf("fake runsc: container %q does not exist\n", cid)
			return 1
		}
		fmt.Printf(`{"id": %q, "pid": %d, "status": "running"}`+"\n", cid, st.PID)
		return 0
	case "wait":
		for {
			if _, err := os.Stat(stateFile(cfg, cid)); err != nil {
				break
			}
			if os.Getppid() == 1 {
				return 1 // the backend that asked is gone
			}
			time.Sleep(5 * time.Millisecond)
		}
		if k.BadWaitJSON {
			fmt.Println("not json")
		} else {
			fmt.Printf(`{"id": %q, "exitStatus": %d}`+"\n", cid, k.ExitStatus)
		}
		return 0
	case "kill":
		st, err := readState(cfg, cid)
		if err != nil {
			fmt.Printf("fake runsc: container %q does not exist\n", cid)
			return 1
		}
		switch rest[len(rest)-1] {
		case "USR1":
			_ = syscall.Kill(st.PID, syscall.SIGUSR1)
		default:
			// The sandbox cleans up on SIGTERM, which stands in for
			// the kill a real runsc would make it vanish with.
			_ = syscall.Kill(st.PID, syscall.SIGTERM)
		}
		return 0
	}
	fmt.Printf("fake runsc: unknown command %q\n", cmd)
	return 1
}

// startSandbox detaches a sandbox for the bundle and returns once it has
// recorded itself, as `runsc run --detach` returns with the sandbox up.
func startSandbox(cfg, cid, bundle string) int {
	exe, err := os.Executable()
	if err != nil {
		return 1
	}
	if err := os.MkdirAll(filepath.Join(cfg, "state"), 0o755); err != nil {
		return 1
	}
	_ = os.Remove(stateFile(cfg, cid))
	sb := exec.Command(exe, fakeSandboxArg, cfg, cid, bundle)
	sb.Stdout, sb.Stderr = os.Stdout, os.Stderr // the detached output file
	sb.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := sb.Start(); err != nil {
		fmt.Printf("fake runsc: start sandbox: %v\n", err)
		return 1
	}
	_ = sb.Process.Release()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := readState(cfg, cid); err == nil {
			return 0
		}
		if time.Now().After(deadline) {
			fmt.Println("fake runsc: sandbox did not come up")
			return 1
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// endSandbox ends a sandbox and waits for it to be gone.
func endSandbox(cfg, cid string) int {
	st, err := readState(cfg, cid)
	if err != nil {
		return 0
	}
	_ = syscall.Kill(st.PID, syscall.SIGTERM)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(stateFile(cfg, cid)); err != nil {
			return 0
		}
		if time.Now().After(deadline) {
			fmt.Println("fake runsc: sandbox did not end")
			return 1
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// fakeSandbox is the workload a sandbox runs, as the reference zygote
// behaves under --gvisor: a template (FIBERD_FENCE=none) drops the ready
// marker on /host and waits; a fiber serves its endpoint on /host and
// closes it on SIGUSR1. Both record themselves while they run and go
// away on SIGTERM.
func fakeSandbox(cfg, cid, bundle string) {
	var k knobs
	if b, err := os.ReadFile(filepath.Join(cfg, "knobs")); err == nil {
		_ = json.Unmarshal(b, &k)
	}
	data, err := os.ReadFile(filepath.Join(bundle, "config.json"))
	if err != nil {
		return
	}
	var s spec
	if err := json.Unmarshal(data, &s); err != nil {
		return
	}
	host := ""
	for _, m := range s.Mounts {
		if m.Destination == "/host" {
			host = m.Source
		}
	}
	env := map[string]string{}
	for _, e := range s.Process.Env {
		if key, val, ok := strings.Cut(e, "="); ok {
			env[key] = val
		}
	}
	st := sandboxState{PID: os.Getpid()}
	var ln net.Listener
	if env["FIBERD_FENCE"] == "none" {
		if !k.NoMarker {
			_ = os.WriteFile(filepath.Join(host, readyMarker), nil, 0o644)
		}
	} else if ep := env["FIBERD_ENDPOINT"]; ep != "" && !k.NoServe {
		st.Endpoint = filepath.Join(host, strings.TrimPrefix(ep, "/host/"))
		ln, err = net.Listen("unix", st.Endpoint)
		if err != nil {
			return
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
	}
	b, _ := json.Marshal(st)
	if err := os.WriteFile(stateFile(cfg, cid), b, 0o644); err != nil {
		return
	}
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGUSR1)
	for sig := range sigs {
		switch sig {
		case syscall.SIGUSR1:
			if ln != nil && !k.IgnoreUSR1 {
				_ = ln.Close()
				_ = os.Remove(st.Endpoint)
				ln = nil
			}
		default:
			if ln != nil {
				_ = ln.Close()
			}
			_ = os.Remove(stateFile(cfg, cid))
			return
		}
	}
}

// sandboxAlive reports whether the fake sandbox for cid still runs.
func sandboxAlive(cfg, cid string) bool {
	st, err := readState(cfg, cid)
	if err != nil {
		return false
	}
	return !errors.Is(syscall.Kill(st.PID, 0), syscall.ESRCH)
}

// endAllSandboxes ends every fake sandbox the configuration knows of, so
// a test never leaves a process behind.
func endAllSandboxes(t *testing.T, cfg string) {
	t.Helper()
	ents, _ := os.ReadDir(filepath.Join(cfg, "state"))
	for _, e := range ents {
		cid := strings.TrimSuffix(e.Name(), ".json")
		if st, err := readState(cfg, cid); err == nil {
			_ = syscall.Kill(st.PID, syscall.SIGTERM)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		ents, _ := os.ReadDir(filepath.Join(cfg, "state"))
		if len(ents) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("%d fake sandboxes still recorded", len(ents))
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}
