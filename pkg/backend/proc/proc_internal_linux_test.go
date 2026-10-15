//go:build linux

package proc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/sys/criu"
)

// TestBackendFacts checks what the backend says about itself, with and without
// criu and with a launcher naming it.
func TestBackendFacts(t *testing.T) {
	cases := []struct {
		name     string
		version  string
		checkErr error
		launcher Launcher
		wantName string
		wantTier core.Tier
		wantLast string // the last thing criu was asked
	}{
		{name: "criu passes", wantName: "proc", wantTier: core.TierCheckpoint, wantLast: "check --no-default-config"},
		{name: "criu check fails", checkErr: errors.New("exit status 1"), wantName: "proc", wantTier: core.TierWarm, wantLast: "check --no-default-config"},
		{name: "a criu older than 4.2 parks nothing", version: "Version: 4.1.1\n", wantName: "proc", wantTier: core.TierWarm, wantLast: "--version"},
		{name: "a launcher names the backend", launcher: &fakeLauncher{}, wantName: "fake", wantTier: core.TierCheckpoint, wantLast: "check --no-default-config"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakes(t)
			f.criu.version, f.criu.checkErr = tc.version, tc.checkErr
			b := f.open(t, Options{Launcher: tc.launcher})
			if b.Name() != tc.wantName || b.Tier() != tc.wantTier {
				t.Fatalf("Name=%s Tier=%s, want %s %s", b.Name(), b.Tier(), tc.wantName, tc.wantTier)
			}
			if !b.Handoff() {
				t.Fatal("Handoff() = false, want true")
			}
			if got := strings.Join(b.EndpointSchemes(), ","); got != "unix,tcp" {
				t.Fatalf("EndpointSchemes = %s, want unix,tcp", got)
			}
			if got := f.criu.last(t); got != tc.wantLast {
				t.Fatalf("criu was asked %q last, want %q", got, tc.wantLast)
			}
		})
	}
}

// TestWarmRefusals checks every way Warm fails before the zygote serves.
// Nothing is left registered, the launcher is released, and a zygote that
// was started is killed and reaped.
func TestWarmRefusals(t *testing.T) {
	cases := []struct {
		name     string
		script   string
		argv     []string // overrides the scripted zygote
		startErr error
		workDir  func(t *testing.T) string
		hide     []string
		timeout  time.Duration
		launcher *fakeLauncher
		wantErr  error
		wantText string
	}{
		{name: "empty command", argv: []string{}, wantText: "empty zygote command"},
		{name: "run directory under a file", script: "never", workDir: func(t *testing.T) string {
			f := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(f, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(f, "g")
		}, wantText: "not a directory"},
		{name: "zygote log is a directory", script: "never", workDir: func(t *testing.T) string {
			d := t.TempDir()
			if err := os.Mkdir(filepath.Join(d, "zygote.log"), 0o755); err != nil {
				t.Fatal(err)
			}
			return d
		}, wantText: "is a directory"},
		{name: "command does not start", script: "never", startErr: os.ErrNotExist, wantErr: os.ErrNotExist, wantText: "start zygote"},
		{name: "greets with something other than READY", script: "notready", wantErr: ErrZygote, wantText: `expected READY, got "HELLO"`},
		// The zygote could not build the mount namespace its fibers copy
		// and said so instead of READY. The old backend only knew READY
		// first and the reason after it, so the warm went through and
		// the home reported a template ready that refused every clone.
		{name: "could not prepare its mount namespace", script: "unprepared", wantErr: ErrZygote,
			wantText: "could not prepare the mount namespace its fibers need: the zygote could not cover a HIDE path (/var/lib/fiberd/templates: Permission denied)"},
		{name: "exits before READY", script: "quit", wantText: "did not become ready"},
		{name: "never says READY", script: "silent", timeout: 50 * time.Millisecond, wantErr: context.DeadlineExceeded},
		{name: "a relative hide path", script: "never", hide: []string{"relative/dir"}, wantText: "cannot hide"},
		{name: "a run directory with whitespace", script: "never", workDir: func(t *testing.T) string {
			return filepath.Join(t.TempDir(), "with space", "g")
		}, wantText: "want an absolute path without whitespace"},
		{name: "a hide path with whitespace", script: "never", hide: []string{"/with space"}, wantText: "cannot hide"},
		{name: "launcher cannot build the command", script: "never", launcher: &fakeLauncher{commandErr: errors.New("no rootfs")}, wantText: "no rootfs"},
		{name: "launcher has no channel", script: "never", launcher: &fakeLauncher{channelErr: errors.New("no pair")}, wantText: "control channel for g: no pair"},
		{name: "launcher cannot find the pid", script: "never", launcher: &fakeLauncher{pidErr: errors.New("no init")}, wantText: "no init"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakes(t)
			f.spawn.startErr = tc.startErr
			var launcher Launcher
			if tc.launcher != nil {
				launcher = tc.launcher
			}
			b := f.open(t, Options{Launcher: launcher})
			argv := tc.argv
			if argv == nil {
				argv = fakeArgv(tc.script, impossiblePID(t))
			}
			workDir := t.TempDir()
			if tc.workDir != nil {
				workDir = tc.workDir(t)
			}
			timeout := 5 * time.Second
			if tc.timeout > 0 {
				timeout = tc.timeout
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			_, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "g", Template: backend.Template{Argv: argv}, CgroupFD: -1, ProbeCgroupFD: -1, WorkDir: workDir, Hide: tc.hide})
			if err == nil {
				t.Fatal("Warm succeeded, want an error")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("Warm = %v, want errors.Is %v", err, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("Warm = %v, want it to mention %q", err, tc.wantText)
			}
			b.mu.Lock()
			n := len(b.zygotes)
			b.mu.Unlock()
			if n != 0 {
				t.Fatalf("%d zygotes registered after a failed warm, want none", n)
			}
			if tc.launcher != nil {
				calls := tc.launcher.recorded()
				if tc.launcher.commandErr == nil && calls[len(calls)-1] != "release" {
					t.Fatalf("launcher calls = %v, want release last", calls)
				}
			}
			// The zygote it killed is reaped too, not left a zombie of
			// this process for every warm that failed.
			for _, z := range f.spawn.started() {
				if !z.killed.Load() || !z.waited.Load() {
					t.Fatalf("zygote %d: killed %v waited %v, want both", z.pid, z.killed.Load(), z.waited.Load())
				}
			}
		})
	}
}

// TestWarmTellsTheZygoteItsPaths checks that a zygote the backend starts is
// told what to hide and drop and its run directory, in that order, then
// PREPARE mntns, all before it is expected to say READY. A launcher's
// zygote is told only PREPARE none, since its fibers get no mount
// namespace, and the launcher names its pid and may move the
// conversation onto its own channel.
func TestWarmTellsTheZygoteItsPaths(t *testing.T) {
	cases := []struct {
		name     string
		hide     []string
		devices  []string
		launcher *fakeLauncher
	}{
		{name: "hide two paths", hide: []string{"/var/lib/secret", "/etc/keys/"}},
		{name: "nothing to hide"},
		{name: "devices reach the engine's environment", devices: []string{"/dev/nvidia0", "/dev/nvidia1"}},
		{name: "launcher on the boot channel", launcher: &fakeLauncher{}},
		{name: "launcher on its own channel", launcher: &fakeLauncher{ownPair: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakes(t)
			rootBind := filepath.Join(t.TempDir(), "root")
			var launcher Launcher
			if tc.launcher != nil {
				tc.launcher.pid = impossiblePID(t) + 7
				launcher = tc.launcher
			}
			b := f.open(t, Options{Launcher: launcher, RootBind: rootBind})
			workDir := filepath.Join(t.TempDir(), "g")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			w, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "g", Template: backend.Template{Argv: fakeArgv("never", impossiblePID(t))}, CgroupFD: -1, ProbeCgroupFD: -1, WorkDir: workDir, Hide: tc.hide, Devices: tc.devices})
			if err != nil {
				t.Fatalf("Warm: %v", err)
			}
			zy := f.spawn.started()[0]
			b.mu.Lock()
			z := b.zygotes[w.ID]
			b.mu.Unlock()
			wantPID := zy.pid
			if tc.launcher != nil {
				wantPID = tc.launcher.pid
			}
			if z == nil || w.ID != "g" || w.PID != wantPID || z.pid != w.PID {
				t.Fatalf("Warm = %+v, zygote %+v, want id g and pid %d", w, z, wantPID)
			}
			if tc.launcher != nil {
				// No paths, since its fibers share the container's
				// namespace, and no CLONE has been sent.
				if got := zy.waitRecv(t, "PREPARE"); strings.Join(got, "\n") != "PREPARE none" {
					t.Fatalf("a launcher's zygote read %q, want PREPARE none alone", got)
				}
				if calls := tc.launcher.recorded(); strings.Join(calls, ",") != "command,channel,pid" {
					t.Fatalf("launcher calls = %v, want command,channel,pid", calls)
				}
				return
			}
			var want []string
			if len(tc.devices) > 0 {
				want = append(want, "ENV FIBERD_DEVICES="+strings.Join(tc.devices, ","))
			}
			for _, h := range tc.hide {
				want = append(want, "HIDE "+filepath.Clean(h))
			}
			want = append(want, "DROP "+rootBind, "RUNDIR "+filepath.Dir(workDir)+" "+workDir, "PREPARE mntns")
			got := zy.waitRecv(t, "PREPARE")
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Fatalf("the zygote read\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
		})
	}
}

// TestWarmCommand checks the command the zygote is started with: its run
// directory as cwd, a fixed environment with the mount namespace switch,
// a session of its own, stdio on the zygote log and never this process's,
// and the cgroup the host hands over.
func TestWarmCommand(t *testing.T) {
	cases := []struct {
		name    string
		cgroup  bool
		devices []string
	}{
		{name: "no cgroup"},
		{name: "born in the host's cgroup", cgroup: true},
		{name: "the device channel in the environment", devices: []string{"/dev/nvidia0"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakes(t)
			b := f.open(t, Options{})
			workDir := filepath.Join(t.TempDir(), "g")
			cgroupFD := -1
			if tc.cgroup {
				cgroupFD = fakeCgroup(t)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "g", Template: backend.Template{Argv: fakeArgv("never", impossiblePID(t))}, CgroupFD: cgroupFD, ProbeCgroupFD: -1, WorkDir: workDir, Devices: tc.devices}); err != nil {
				t.Fatalf("Warm: %v", err)
			}
			cmd := f.spawn.started()[0].cmd
			if cmd.Dir != workDir {
				t.Errorf("cwd = %q, want the run directory %q", cmd.Dir, workDir)
			}
			wantEnv := []string{"PATH=/usr/bin:/bin", ownMntnsEnv}
			if len(tc.devices) > 0 {
				wantEnv = append(wantEnv, "FIBERD_DEVICES="+strings.Join(tc.devices, ","))
			}
			if strings.Join(cmd.Env, " ") != strings.Join(wantEnv, " ") {
				t.Errorf("env = %v, want %v", cmd.Env, wantEnv)
			}
			if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setsid {
				t.Error("the zygote is not a session leader")
			}
			if got := cmd.SysProcAttr.UseCgroupFD; got != tc.cgroup || (tc.cgroup && cmd.SysProcAttr.CgroupFD != cgroupFD) {
				t.Errorf("cgroup fd %d used %v, want %d used %v", cmd.SysProcAttr.CgroupFD, got, cgroupFD, tc.cgroup)
			}
			out, ok := cmd.Stdout.(*os.File)
			if !ok || out.Name() != filepath.Join(workDir, "zygote.log") || cmd.Stderr != cmd.Stdout {
				t.Errorf("stdio = %v %v, want the zygote log", cmd.Stdout, cmd.Stderr)
			}
			if in, ok := cmd.Stdin.(*os.File); !ok || in.Name() != os.DevNull {
				t.Errorf("stdin = %v, want %s", cmd.Stdin, os.DevNull)
			}
			if len(cmd.ExtraFiles) != 1 {
				t.Errorf("extra files = %v, want the control socket alone", cmd.ExtraFiles)
			}
		})
	}
}

// TestCloneLine checks that the CLONE line carries the fence, the endpoint as
// the zygote sees it, the deadline in ms, the payload in hex, the session
// in hex and the confinement options, and that the fiber's channel rides
// with it as the last descriptor, after the cgroup's when there is one,
// with the fiber's record queued on it. A handoff fiber's host end is
// handed back, and any other fiber's is closed once the clone is
// answered. A record the library would refuse is refused before any
// line is sent.
func TestCloneLine(t *testing.T) {
	identity := &backend.Identity{KeyPEM: "k", CertPEM: "c", Caller: "x5t", CallerPEM: "p"}
	cases := []struct {
		name     string
		spec     backend.FiberSpec
		cgroup   bool // pass a cgroup fd
		launcher *fakeLauncher
		wantLine string // after "CLONE g/1-1 ", with EP for the endpoint path
		wantFDs  int
		wantErr  string
	}{
		{name: "a handoff fiber keeps its channel", spec: backend.FiberSpec{Generation: 1, Deadline: time.Second, Endpoint: "handoff", Identity: identity},
			wantLine: "handoff 1000 - - mntns,nocaps", wantFDs: 1},
		{name: "defaults", spec: backend.FiberSpec{Generation: 1}, wantLine: "EP 50 - - mntns,nocaps", wantFDs: 1},
		{name: "deadline, payload and own pid namespace", spec: backend.FiberSpec{Generation: 1, Deadline: 1500 * time.Millisecond, Payload: []byte{0xde, 0xad}, OwnPIDNS: true},
			wantLine: "EP 1500 dead - pidns,mntns,nocaps", wantFDs: 1},
		// A session name is hex, so one with a space stays one field.
		{name: "session", spec: backend.FiberSpec{Generation: 1, Deadline: time.Second, Session: "conv 42"},
			wantLine: "EP 1000 - " + hex.EncodeToString([]byte("conv 42")) + " mntns,nocaps", wantFDs: 1},
		{name: "cgroup descriptor before the channel", spec: backend.FiberSpec{Generation: 1, Deadline: time.Second}, cgroup: true,
			wantLine: "EP 1000 - - mntns,nocaps", wantFDs: 2},
		{name: "a generation the record cannot carry is refused", spec: backend.FiberSpec{Deadline: time.Second}, wantErr: "not an incarnation"},
		{name: "launcher maps a unix endpoint and keeps capabilities", spec: backend.FiberSpec{Generation: 1, Deadline: time.Second, OwnPIDNS: true}, launcher: &fakeLauncher{endpointRoot: "/run/inside"},
			wantLine: "/run/inside/ep.sock 1000 - - pidns", wantFDs: 1},
		{name: "launcher leaves a tcp endpoint alone", spec: backend.FiberSpec{Generation: 1, Deadline: time.Second, Endpoint: "tcp://0.0.0.0:9000"}, launcher: &fakeLauncher{endpointRoot: "/run/inside"},
			wantLine: "tcp://0.0.0.0:9000 1000 - -", wantFDs: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakes(t)
			var launcher Launcher
			if tc.launcher != nil {
				launcher = tc.launcher
			}
			b := f.open(t, Options{Launcher: launcher})
			w, zy, workDir := f.warm(t, b, "never", impossiblePID(t))
			spec := tc.spec
			spec.Fence = "g/1-1"
			if spec.Endpoint == "" {
				spec.Endpoint = filepath.Join(workDir, "ep.sock")
			}
			spec.CgroupFD = -1
			if tc.cgroup {
				d, err := os.Open(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = d.Close() }()
				spec.CgroupFD = int(d.Fd())
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			fb, err := b.Clone(ctx, w.ID, spec)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Clone = %v, want %q", err, tc.wantErr)
				}
				for _, l := range zy.lines() {
					if strings.HasPrefix(l, "CLONE ") {
						t.Fatalf("a refused clone sent %q", l)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("Clone: %v", err)
			}
			wantPID := impossiblePID(t)
			if tc.launcher != nil {
				wantPID = 0 // never a host pid without a cgroup to translate it in
			}
			if fb.ID != "g/1-1" || fb.PID != wantPID || channelOf(t, fb) != (spec.Identity != nil) {
				t.Fatalf("Clone = %+v, want g/1-1 pid %d with the host's end of the channel only for a handoff fiber", fb, wantPID)
			}
			// The record waits on the channel for the fiber, with the
			// endpoint as the fiber sees it and the host's generation.
			rec := recordOn(t, zy)
			if rec.Generation != 1 || rec.Kind != "fork" || rec.Fence != "g/1-1" || string(rec.Payload) != string(spec.Payload) || rec.Session != spec.Session {
				t.Fatalf("record = %+v", rec)
			}
			if (rec.Identity == nil) != (spec.Identity == nil) || (rec.Identity != nil && *rec.Identity != *identity) {
				t.Fatalf("record identity = %+v, want %+v", rec.Identity, spec.Identity)
			}
			if wantEP := strings.Replace(strings.Fields(tc.wantLine)[0], "EP", filepath.Join(workDir, "ep.sock"), 1); rec.Endpoint != wantEP {
				t.Fatalf("record endpoint = %q, want %q", rec.Endpoint, wantEP)
			}
			if len(rec.Seed) != backend.SeedBytes {
				t.Fatalf("record seed = %x", rec.Seed)
			}
			lines := zy.waitRecv(t, "CLONE ")
			var cloneLine string
			fdsLine := ""
			for i, l := range lines {
				if strings.HasPrefix(l, "CLONE ") {
					cloneLine = strings.TrimRight(l, " ") // no options is an empty last field
					if i+1 < len(lines) && strings.HasPrefix(lines[i+1], "FDS ") {
						fdsLine = lines[i+1]
					}
				}
			}
			want := "CLONE g/1-1 " + strings.Replace(tc.wantLine, "EP", filepath.Join(workDir, "ep.sock"), 1)
			if cloneLine != want {
				t.Fatalf("zygote read %q, want %q", cloneLine, want)
			}
			wantFDs := ""
			if tc.wantFDs > 0 {
				wantFDs = "FDS " + strconv.Itoa(tc.wantFDs)
			}
			if fdsLine != wantFDs {
				t.Fatalf("descriptors with CLONE: %q, want %q", fdsLine, wantFDs)
			}
		})
	}
}

// TestCloneReplies checks that every answer a zygote can give to CLONE, and
// the zygote dying instead, are errors the caller can name. The grant's warm
// instance is reported gone when the zygote is, and nothing else is.
func TestCloneReplies(t *testing.T) {
	cases := []struct {
		name     string
		script   string
		wantErr  error
		wantText string
		wantGone bool // an Exit for the warm instance
		wantLog  string
	}{
		{name: "ERROR names the reason", script: "error", wantErr: ErrZygote, wantText: "deadline exceeded before ready"},
		{name: "a refused path is logged, the clone refused", script: "refuse", wantErr: ErrZygote, wantText: "refused: the mount namespace", wantLog: "zygote for g: DROP refused: by the script"},
		{name: "a pid the backend cannot name", script: "malformed", wantErr: ErrZygote, wantText: `malformed "CLONED g/1-1 abc"`},
		{name: "a CLONED without a pid", script: "short", wantErr: ErrZygote, wantText: "malformed"},
		{name: "noise before the answer is tolerated", script: "noise"},
		{name: "the zygote dies", script: "die", wantErr: ErrZygote, wantText: "zygote exited", wantGone: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(os.Stderr) })
			f := newFakes(t)
			b := f.open(t, Options{})
			pid := impossiblePID(t)
			w, _, workDir := f.warm(t, b, tc.script, pid)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			fb, err := b.Clone(ctx, w.ID, backend.FiberSpec{Generation: 1, Fence: "g/1-1", Endpoint: filepath.Join(workDir, "ep.sock"), CgroupFD: -1, Deadline: time.Second})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Clone = %v, want errors.Is %v", err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("Clone = %v, want it to mention %q", err, tc.wantText)
			}
			if err == nil && (fb.ID != "g/1-1" || fb.PID != pid) {
				t.Fatalf("Clone = %+v, want g/1-1 pid %d", fb, pid)
			}
			if tc.wantGone {
				if e := waitExit(t, b); e != (backend.Exit{WarmID: "g", Status: "zygote exited"}) {
					t.Fatalf("exit = %+v, want the warm instance gone", e)
				}
			} else if n := len(b.exits); n != 0 {
				// The reader answered the clone after the lines before
				// it, none of which ends a fiber.
				t.Fatalf("%d exits reported, want none", n)
			}
			// The refusal was logged before the reply that ended Clone.
			if tc.wantLog != "" && !strings.Contains(logs.String(), tc.wantLog) {
				t.Fatalf("log = %q, want %q", logs.String(), tc.wantLog)
			}
			b.mu.Lock()
			nf, z := len(b.fibers), b.zygotes[w.ID]
			b.mu.Unlock()
			npend := 0
			if z != nil {
				z.pmu.Lock()
				npend = len(z.pend)
				z.pmu.Unlock()
			}
			wantFibers := 0
			if err == nil {
				wantFibers = 1
			}
			if nf != wantFibers || npend != 0 {
				t.Fatalf("fibers=%d pending=%d, want %d and 0", nf, npend, wantFibers)
			}
		})
	}
}

// TestCloneWithoutAZygoteToAnswer checks that no warm instance, a control
// channel that cannot be written, and a zygote already gone when the reply is
// awaited are each errors with nothing left pending.
func TestCloneWithoutAZygoteToAnswer(t *testing.T) {
	cases := []struct {
		name     string
		inject   func(t *testing.T, b *Backend) string // registers a zygote, returns its id
		wantErr  error
		wantText string
	}{
		{name: "unknown warm instance", inject: func(*testing.T, *Backend) string { return "nobody" }, wantText: `no warm instance "nobody"`},
		{name: "control channel closed", inject: func(t *testing.T, b *Backend) string {
			c := pairConn(t)
			_ = c.Close()
			b.zygotes["g"] = &zygote{id: "g", ctl: c, pend: map[string]*pending{}, gone: make(chan struct{})}
			return "g"
		}, wantText: "send CLONE"},
		{name: "zygote gone before it answers", inject: func(t *testing.T, b *Backend) string {
			gone := make(chan struct{})
			close(gone)
			b.zygotes["g"] = &zygote{id: "g", ctl: pairConn(t), pend: map[string]*pending{}, gone: gone}
			return "g"
		}, wantErr: ErrZygote, wantText: "zygote exited"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &Backend{zygotes: map[string]*zygote{}, fibers: map[string]*fiber{}, byPID: map[pidKey]*fiber{}}
			id := tc.inject(t, b)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := b.Clone(ctx, id, backend.FiberSpec{Generation: 1, Fence: "g/1-1", Endpoint: "/run/g/ep.sock", CgroupFD: -1})
			if err == nil || !strings.Contains(err.Error(), tc.wantText) || (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) {
				t.Fatalf("Clone = %v, want %q (errors.Is %v)", err, tc.wantText, tc.wantErr)
			}
			if z := b.zygotes[id]; z != nil && len(z.pend) != 0 {
				t.Fatalf("%d clones left pending", len(z.pend))
			}
		})
	}
}

// TestDeviceReports checks that an engine's DEVICE lines are the warm
// instance's usage and capacity and each fiber's slice, which EVICT asks it
// to drop. Without an engine there is nothing to report or evict.
func TestDeviceReports(t *testing.T) {
	cases := []struct {
		name   string
		script string
		engine bool
	}{
		{name: "engine reports and evicts", script: "device", engine: true},
		{name: "no engine", script: "never"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakes(t)
			b := f.open(t, Options{})
			w, zy, workDir := f.warm(t, b, tc.script, impossiblePID(t))
			if _, _, ok := b.WarmDevice("nobody"); ok {
				t.Fatal("WarmDevice of an unknown instance reported something")
			}
			if _, ok := b.FiberDevice("g/9-9"); ok {
				t.Fatal("FiberDevice of an unknown fiber reported something")
			}
			if err := b.EvictDevice("g/9-9"); err == nil || !strings.Contains(err.Error(), "no engine") {
				t.Fatalf("EvictDevice of an unknown fiber = %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := b.Clone(ctx, w.ID, backend.FiberSpec{Generation: 1, Fence: "g/1-1", Endpoint: filepath.Join(workDir, "ep.sock"), CgroupFD: -1, Deadline: time.Second}); err != nil {
				t.Fatalf("Clone: %v", err)
			}
			if !tc.engine {
				if _, _, ok := b.WarmDevice(w.ID); ok {
					t.Fatal("WarmDevice reported without an engine")
				}
				if _, ok := b.FiberDevice("g/1-1"); ok {
					t.Fatal("FiberDevice reported without an engine")
				}
				return
			}
			waitFor(t, "the warm instance's report", func() bool {
				used, capacity, ok := b.WarmDevice(w.ID)
				return ok && used == 100 && capacity == 1000
			})
			waitFor(t, "the fiber's slice", func() bool {
				n, ok := b.FiberDevice("g/1-1")
				return ok && n == 42
			})
			if err := b.EvictDevice("g/1-1"); err != nil {
				t.Fatalf("EvictDevice: %v", err)
			}
			zy.waitRecv(t, "EVICT g/1-1")
			waitFor(t, "the slice to go", func() bool {
				n, ok := b.FiberDevice("g/1-1")
				return ok && n == 0
			})
		})
	}
}

// TestEvictWithoutAChannel checks that an EVICT that cannot reach the
// engine is an error naming the send, not a lost request.
func TestEvictWithoutAChannel(t *testing.T) {
	cases := []struct {
		name string
	}{{name: "control channel closed"}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := pairConn(t)
			_ = c.Close()
			b := &Backend{zygotes: map[string]*zygote{"g": {id: "g", ctl: c}}, fibers: map[string]*fiber{"f": {id: "f", warmID: "g"}}}
			if err := b.EvictDevice("f"); err == nil || !strings.Contains(err.Error(), "send EVICT") {
				t.Fatalf("EvictDevice = %v, want a send error", err)
			}
		})
	}
}

// TestUnwarm checks that ending a warm instance kills its zygote and reports
// the instance gone once. An unknown id is nothing to do.
func TestUnwarm(t *testing.T) {
	cases := []struct {
		name  string
		known bool
	}{
		{name: "known instance", known: true},
		{name: "unknown instance"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakes(t)
			b := f.open(t, Options{})
			w, zy, _ := f.warm(t, b, "never", impossiblePID(t))
			id := w.ID
			if !tc.known {
				id = "nobody"
			}
			b.Unwarm(id)
			if !tc.known {
				if zy.killed.Load() || len(b.exits) != 0 {
					t.Fatal("an unknown id killed the zygote or reported an exit")
				}
				return
			}
			if e := waitExit(t, b); e != (backend.Exit{WarmID: "g", Status: "zygote exited"}) {
				t.Fatalf("exit = %+v, want the warm instance gone", e)
			}
			if !zy.killed.Load() {
				t.Fatal("the zygote was not killed")
			}
			b.mu.Lock()
			n := len(b.zygotes)
			b.mu.Unlock()
			if n != 0 {
				t.Fatalf("%d zygotes left, want none", n)
			}
		})
	}
}

// TestClonePair checks that a fiber's channel is made by the launcher,
// for the instance it is forked from, and by plain socketpair without
// one, so the zygote always gets a pair its fiber can be checkpointed
// with.
func TestClonePair(t *testing.T) {
	cases := []struct {
		name     string
		launcher *fakeLauncher
	}{
		{name: "no launcher"},
		{name: "launcher makes the pair for the instance", launcher: &fakeLauncher{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakes(t)
			var launcher Launcher
			if tc.launcher != nil {
				tc.launcher.pid = impossiblePID(t) + 9
				launcher = tc.launcher
			}
			b := f.open(t, Options{Launcher: launcher})
			w, _, _ := f.warm(t, b, "never", impossiblePID(t))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			fb, err := b.Clone(ctx, w.ID, backend.FiberSpec{Generation: 1, Fence: "g/1-1", Endpoint: "handoff", CgroupFD: -1, Deadline: time.Second,
				Identity: &backend.Identity{KeyPEM: "k", CertPEM: "c", Caller: "x5t", CallerPEM: "p"}})
			if err != nil || !channelOf(t, fb) {
				t.Fatalf("Clone = %+v, %v", fb, err)
			}
			if tc.launcher == nil {
				return
			}
			want := "socketpair:" + strconv.Itoa(w.PID)
			if calls := tc.launcher.recorded(); !slices.Contains(calls, want) {
				t.Fatalf("launcher calls = %v, want %s", calls, want)
			}
		})
	}
}

// TestCheckpointWarm checks that the zygote is dumped running, with its
// control socket external when its inode can be read, plus whatever the
// launcher's container needs. The mounts of a zygote in a mount namespace
// of its own are named at tests/integration/proc TestCheckpointWarmExternalSocket.
func TestCheckpointWarm(t *testing.T) {
	cases := []struct {
		name     string
		launcher *fakeLauncher
		warmID   string
		noSocket bool // fd 3 cannot be read under /proc
		wantErr  string
	}{
		{name: "plain zygote", warmID: "g"},
		{name: "launcher adds its arguments", launcher: &fakeLauncher{}, warmID: "g"},
		{name: "control socket unreadable", warmID: "g", noSocket: true},
		{name: "unknown instance", warmID: "nobody", wantErr: `no warm instance "nobody"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakes(t)
			var launcher Launcher
			if tc.launcher != nil {
				tc.launcher.pid = impossiblePID(t) + 9
				launcher = tc.launcher
			}
			b := f.open(t, Options{Launcher: launcher})
			w, _, _ := f.warm(t, b, "never", impossiblePID(t))
			if !tc.noSocket {
				f.socket(t, w.PID, 3, "60373")
			}
			dir := t.TempDir()
			err := b.CheckpointWarm(context.Background(), tc.warmID, dir)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("CheckpointWarm = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("CheckpointWarm: %v", err)
			}
			dump := f.criu.last(t)
			for _, want := range []string{"dump ", " -t " + strconv.Itoa(w.PID) + " ", " -D " + dir + " ", "--leave-running"} {
				if !strings.Contains(dump, want) {
					t.Fatalf("criu dump %q lacks %q", dump, want)
				}
			}
			if strings.Contains(dump, "--external unix[60373]") == tc.noSocket {
				t.Fatalf("criu dump %q: control socket external = %v", dump, !tc.noSocket)
			}
			if strings.Contains(dump, "--dump-extra") != (tc.launcher != nil) {
				t.Fatalf("criu dump %q: launcher arguments present = %v", dump, tc.launcher != nil)
			}
		})
	}
}

// TestHostPIDFromProcfs checks pid translation with a launcher. The
// zygote's pid is a number in its own namespace. The host's pid is the
// process in the fiber's leaf whose NSpid shows that number one level
// down. Processes gone from the leaf or without that level are skipped,
// and without a cgroup to look in there is no host pid, never the
// container's number.
func TestHostPIDFromProcfs(t *testing.T) {
	cases := []struct {
		name     string
		launcher Launcher
		leaf     func(t *testing.T, f *fakes, host, zpid int) int // the cgroup fd
		reported func(zpid int) int
		want     func(host int) int
	}{
		{name: "no launcher keeps the reported pid", leaf: func(*testing.T, *fakes, int, int) int { return -1 },
			reported: func(zpid int) int { return zpid }, want: func(int) int { return 0 }},
		{name: "launcher without a cgroup", launcher: nopLauncher{}, leaf: func(*testing.T, *fakes, int, int) int { return -1 },
			reported: func(zpid int) int { return zpid }, want: func(int) int { return 0 }},
		{name: "launcher with a closed fd", launcher: nopLauncher{}, leaf: func(*testing.T, *fakes, int, int) int { return 1 << 20 },
			reported: func(zpid int) int { return zpid }, want: func(int) int { return 0 }},
		{name: "the init of its namespace", launcher: nopLauncher{}, leaf: func(t *testing.T, f *fakes, host, zpid int) int {
			f.status(t, host-1) // a process in the leaf with no namespace below the host's
			f.status(t, host, zpid)
			return fakeCgroup(t, host+5, host-1, host) // the first is gone from /proc
		}, reported: func(zpid int) int { return zpid }, want: func(host int) int { return host }},
		{name: "a number nobody has", launcher: nopLauncher{}, leaf: func(t *testing.T, f *fakes, host, zpid int) int {
			f.status(t, host, zpid)
			return fakeCgroup(t, host)
		}, reported: func(zpid int) int { return zpid + 1 }, want: func(int) int { return 0 }},
		{name: "an empty leaf", launcher: nopLauncher{}, leaf: func(t *testing.T, _ *fakes, _, _ int) int { return fakeCgroup(t) },
			reported: func(zpid int) int { return zpid }, want: func(int) int { return 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakes(t)
			host, zpid := impossiblePID(t)+10, impossiblePID(t)+20
			b := &Backend{opt: Options{Launcher: tc.launcher, procRoot: f.proc}}
			fd := tc.leaf(t, f, host, zpid)
			reported := tc.reported(zpid)
			want := tc.want(host)
			if tc.launcher == nil {
				want = reported
			}
			if got := b.hostPID(fd, reported); got != want {
				t.Fatalf("hostPID(%d, %d) = %d, want %d", fd, reported, got, want)
			}
		})
	}
}

// TestCloneTranslatesTheHostPID checks that a launcher's fiber is known
// under the host pid Clone found for it in the caller's leaf, never the
// number the zygote reported, and that Kill signals that pid. The pids
// here are ones no process has, so the signal reaches nobody.
func TestCloneTranslatesTheHostPID(t *testing.T) {
	cases := []struct {
		name string
	}{{name: "kill goes to the translated pid"}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakes(t)
			host, zpid := impossiblePID(t)+10, impossiblePID(t)+20
			f.status(t, host, zpid)
			l := &fakeLauncher{endpointRoot: "/inside", pid: impossiblePID(t) + 9}
			b := f.open(t, Options{Launcher: l})
			w, _, workDir := f.warm(t, b, "never", zpid)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			fb, err := b.Clone(ctx, w.ID, backend.FiberSpec{Generation: 1, Fence: "g/1-1", Endpoint: filepath.Join(workDir, "ep.sock"), CgroupFD: fakeCgroup(t, host), Deadline: time.Second})
			if err != nil {
				t.Fatalf("Clone: %v", err)
			}
			if fb.PID != host {
				t.Fatalf("Clone pid = %d, want the host's %d for the namespace's %d", fb.PID, host, zpid)
			}
			b.mu.Lock()
			fib := b.fibers["g/1-1"]
			b.mu.Unlock()
			if fib == nil || fib.pid != host || fib.zpid != zpid {
				t.Fatalf("fiber = %+v, want pid %d zpid %d", fib, host, zpid)
			}
			if err := b.Kill("g/1-1"); !errors.Is(err, syscall.ESRCH) {
				t.Fatalf("Kill = %v, want ESRCH for the translated pid nobody has", err)
			}
		})
	}
}

// TestPark checks that a fiber is dumped with its handoff channel
// external, running on with Sync, through the launcher's arguments when
// it has one, and that a dump failing on a client from outside the
// container is retried. What cannot be dumped is refused before criu
// runs. A fiber with a mount namespace of its own has its mounts named at
// tests/integration/proc TestParkNamesOwnMounts.
func TestPark(t *testing.T) {
	cases := []struct {
		name      string
		criu      criuKnobs
		launcher  bool
		zygote    bool // the launcher's zygote is registered
		handoff   bool // the fiber serves handoff
		channel   bool // and holds its channel at fd 4
		sync      bool
		fiber     bool   // register the fiber at all
		dirIs     string // a directory already at this name in the image directory, or "file" for the image directory's parent
		wantErr   string
		wantArgs  []string
		wantFiles []string
		noFiles   []string
		wantDumps int
	}{
		{name: "shares the host's mount namespace", fiber: true, wantArgs: []string{"dump", "--ext-unix-sk"}, noFiles: []string{runDirFile, criu.MountsFile, handoffFile}, wantDumps: 1},
		{name: "handoff channel is external", fiber: true, handoff: true, channel: true, wantArgs: []string{"--external unix[4711]"}, wantFiles: []string{handoffFile}, wantDumps: 1},
		{name: "handoff fiber without a channel", fiber: true, handoff: true, wantErr: "handoff channel of f"},
		{name: "sync keeps it running", fiber: true, sync: true, wantArgs: []string{"--leave-running"}, wantDumps: 1},
		{name: "criu fails", fiber: true, criu: criuKnobs{dumpErr: errors.New("exit status 1")}, wantErr: "criu dump"},
		{name: "launcher names the container's mounts", fiber: true, launcher: true, zygote: true, wantArgs: []string{"--dump-extra"}, wantDumps: 1},
		{name: "a client from outside the container is retried", fiber: true, launcher: true, zygote: true, wantDumps: 2,
			criu: criuKnobs{dumpErr: errors.New("Error (criu/sk-unix.c:351): unix: Unix socket 60373 not found"), dumpErrOnce: true}},
		{name: "unknown fiber", wantErr: `unknown fiber "f"`},
		{name: "criu unavailable", fiber: true, criu: criuKnobs{checkErr: errors.New("exit status 1")}, wantErr: "park needs FIBER_CHECKPOINT"},
		{name: "handoff record cannot be written", fiber: true, handoff: true, channel: true, dirIs: handoffFile, wantErr: "is a directory"},
		{name: "image directory under a file", fiber: true, handoff: true, channel: true, dirIs: "file", wantErr: "not a directory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakes(t)
			f.criu.criuKnobs = tc.criu
			var launcher Launcher
			if tc.launcher {
				launcher = &fakeLauncher{}
			}
			b := f.open(t, Options{Launcher: launcher})
			pid := impossiblePID(t) + 30
			if tc.channel {
				f.socket(t, pid, channelFD, "4711")
			}
			if tc.fiber {
				b.fibers["f"] = &fiber{id: "f", pid: pid, warmID: "g", handoff: tc.handoff}
			}
			if tc.zygote {
				// A zygote by record only, for the launcher's arguments.
				// Close must not find it.
				b.zygotes["g"] = &zygote{id: "g", spec: backend.WarmSpec{GrantUID: "g"}}
				t.Cleanup(func() { delete(b.zygotes, "g") })
			}
			dir := filepath.Join(t.TempDir(), "parent", "img")
			if tc.dirIs != "file" {
				if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			switch tc.dirIs {
			case "":
			case "file":
				if err := os.WriteFile(filepath.Dir(dir), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.MkdirAll(filepath.Join(dir, tc.dirIs), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			err := b.Park(context.Background(), "f", backend.ParkSpec{Dir: dir, Sync: tc.sync})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Park = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Park: %v", err)
			}
			dumps := 0
			for _, c := range f.criu.recorded() {
				if strings.HasPrefix(c, "dump ") {
					dumps++
				}
			}
			if dumps != tc.wantDumps {
				t.Fatalf("%d dumps, want %d", dumps, tc.wantDumps)
			}
			dump := f.criu.last(t)
			if !strings.Contains(dump, " -t "+strconv.Itoa(pid)+" ") || !strings.Contains(dump, " -D "+dir+" ") {
				t.Fatalf("criu dump %q names neither pid %d nor %s", dump, pid, dir)
			}
			for _, want := range tc.wantArgs {
				if !strings.Contains(dump, want) {
					t.Fatalf("criu dump %q lacks %q", dump, want)
				}
			}
			if !tc.sync && strings.Contains(dump, "--leave-running") {
				t.Fatalf("criu dump %q leaves the tree running without Sync", dump)
			}
			for _, name := range tc.wantFiles {
				data, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					t.Fatalf("%s not written: %v", name, err)
				}
				var rec handoffRecord
				if json.Unmarshal(data, &rec) != nil || rec.Inode != "4711" {
					t.Fatalf("%s = %s, want inode 4711", name, data)
				}
			}
			for _, name := range tc.noFiles {
				if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
					t.Fatalf("%s written, want none", name)
				}
			}
		})
	}
}

// TestHandoffInherit checks that a checkpoint of a handoff fiber names the
// inode its channel had, and a resume must bring a replacement. Any other
// checkpoint takes none.
func TestHandoffInherit(t *testing.T) {
	cases := []struct {
		name    string
		record  string // "" for no file
		channel bool
		want    string
		wantErr string
	}{
		{name: "no record, no channel"},
		{name: "record and channel", record: `{"inode":"12345"}`, channel: true, want: "--inherit-fd fd[3]:socket:[12345]"},
		{name: "channel for a checkpoint without one", channel: true, wantErr: "no handoff channel to replace"},
		{name: "record without a channel", record: `{"inode":"12345"}`, wantErr: "needs a channel"},
		{name: "malformed record", record: `{"inode":""}`, channel: true, wantErr: "malformed"},
		{name: "unreadable record", record: "dir", channel: true, wantErr: "is a directory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			switch tc.record {
			case "":
			case "dir":
				if err := os.Mkdir(filepath.Join(dir, handoffFile), 0o755); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(filepath.Join(dir, handoffFile), []byte(tc.record), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var ch *os.File
			if tc.channel {
				var err error
				if ch, err = os.Open(os.DevNull); err != nil {
					t.Fatal(err)
				}
				defer func() { _ = ch.Close() }()
			}
			args, files, err := handoffInherit(dir, ch)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("handoffInherit = %v %v %v, want %q", args, files, err, tc.wantErr)
				}
				return
			}
			if err != nil || strings.Join(args, " ") != tc.want {
				t.Fatalf("handoffInherit = %v %v, want %q", args, err, tc.want)
			}
			wantFiles := 0
			if tc.channel {
				wantFiles = 1
			}
			if len(files) != wantFiles || (wantFiles == 1 && files[0] != ch) {
				t.Fatalf("files = %v, want the channel only when given", files)
			}
		})
	}
}

// writeMounts records a dump with a mount namespace and no file mounts.
func writeMounts(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, criu.MountsFile), []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestResume checks that a checkpoint is restored under the resuming grant's
// directory, with a handoff channel replaced, and its end reported as
// the fiber's exit. A launcher is told of the tree it prepared for, and
// when it is gone. A checkpoint with a mount namespace binds the restore
// root, which is tests/integration/proc TestResumeBindsRunDir, and what refuses the
// bind before any mount is refused here.
func TestResume(t *testing.T) {
	cases := []struct {
		name      string
		criu      criuKnobs
		launcher  *fakeLauncher
		setup     func(t *testing.T, dir, rootBind string)
		spec      backend.ResumeSpec
		record    bool // the checkpoint names a handoff channel
		kill      bool
		wantErr   error
		wantText  string
		wantArgs  []string
		wantExit  string
		wantCalls string
	}{
		{name: "plain checkpoint", wantArgs: []string{"restore ", "--pidfile", "files=0 cgroup=-1"}, wantExit: "exit:0"},
		{name: "restore root is a symlink", setup: func(t *testing.T, dir, rootBind string) {
			writeMounts(t, dir)
			if err := os.MkdirAll(filepath.Dir(rootBind), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/", rootBind); err != nil {
				t.Fatal(err)
			}
		}, wantText: "restore root"},
		{name: "restore root under a file", setup: func(t *testing.T, dir, rootBind string) {
			writeMounts(t, dir)
			if err := os.WriteFile(filepath.Dir(rootBind), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, wantText: "not a directory"},
		{name: "malformed mounts record", setup: func(t *testing.T, dir, _ string) {
			if err := os.WriteFile(filepath.Join(dir, criu.MountsFile), []byte(`nonsense`), 0o600); err != nil {
				t.Fatal(err)
			}
		}, wantText: criu.MountsFile},
		{name: "handoff channel replaced", record: true, spec: backend.ResumeSpec{Handoff: true}, wantArgs: []string{"--inherit-fd fd[3]:socket:[777]", "files=1"}, wantExit: "exit:0"},
		{name: "handoff checkpoint without a channel", record: true, wantText: "needs a channel"},
		{name: "handoff resume of a plain checkpoint", spec: backend.ResumeSpec{Handoff: true}, wantText: "no handoff channel to replace"},
		{name: "launcher handoff resume needs the warm instance for the channel", launcher: &fakeLauncher{}, spec: backend.ResumeSpec{Handoff: true, WarmID: "nobody"}, record: true,
			wantText: `no warm instance "nobody"`, wantCalls: "restoreExtra:DIR,restoredGone"},
		{name: "restore fails", criu: criuKnobs{restore: "no"}, wantText: "criu restore failed"},
		{name: "restore misses the deadline", criu: criuKnobs{restore: "hang"}, spec: backend.ResumeSpec{Deadline: 50 * time.Millisecond}, wantErr: context.DeadlineExceeded},
		{name: "the tree exits with an error", criu: criuKnobs{restoreErr: errors.New("exit status 3")}, wantExit: "exit:exit status 3"},
		{name: "the tree is killed", kill: true, wantExit: "exit:signal: killed"},
		{name: "criu unavailable", criu: criuKnobs{checkErr: errors.New("exit status 1")}, wantText: "resume needs FIBER_CHECKPOINT"},
		{name: "launcher restores in its container", launcher: &fakeLauncher{}, wantArgs: []string{"--restore-extra"}, wantExit: "exit:0",
			wantCalls: "restoreExtra:DIR,restored:PID,restoredGone"},
		{name: "launcher restore without a run directory takes the endpoint's", launcher: &fakeLauncher{restoredErr: errors.New("mounts")}, spec: backend.ResumeSpec{WorkDir: "-"},
			wantArgs: []string{"--restore-extra"}, wantExit: "exit:0", wantCalls: "restoreExtra:DIR,restored:PID,restoredGone"},
		{name: "launcher cannot prepare the restore", launcher: &fakeLauncher{restoreExtraErr: errors.New("no rootfs")}, wantText: "no rootfs", wantCalls: "restoreExtra:DIR"},
		{name: "launcher prepared, restore fails", launcher: &fakeLauncher{}, criu: criuKnobs{restore: "no"}, wantText: "criu restore failed", wantCalls: "restoreExtra:DIR,restoredGone"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakes(t)
			f.criu.criuKnobs = tc.criu
			var launcher Launcher
			if tc.launcher != nil {
				launcher = tc.launcher
			}
			rootBind := filepath.Join(t.TempDir(), "parent", "root")
			b := f.open(t, Options{Launcher: launcher, RootBind: rootBind})
			dir := t.TempDir()
			if tc.record {
				if err := os.WriteFile(filepath.Join(dir, handoffFile), []byte(`{"inode":"777"}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.setup != nil {
				tc.setup(t, dir, rootBind)
			}
			workDir := filepath.Join(t.TempDir(), "g2")
			spec := tc.spec
			spec.Dir, spec.Fence, spec.CgroupFD = dir, "g/2-1", -1
			if spec.WarmID == "" {
				spec.WarmID = "g"
			}
			spec.Endpoint = filepath.Join(workDir, "ep.sock")
			switch spec.WorkDir {
			case "":
				spec.WorkDir = workDir
			case "-":
				spec.WorkDir = ""
			}
			fb, err := b.Resume(context.Background(), spec)
			if tc.wantErr != nil || tc.wantText != "" {
				if err == nil || (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) || !strings.Contains(err.Error(), tc.wantText) {
					t.Fatalf("Resume = %v, want %q (errors.Is %v)", err, tc.wantText, tc.wantErr)
				}
				if b.rootHeld {
					t.Fatal("a refused resume holds the restore root")
				}
			} else if err != nil {
				t.Fatalf("Resume: %v", err)
			}
			if err == nil {
				if fb.ID != "g/2-1" || fb.PID != f.criu.restorePID || channelOf(t, fb) != spec.Handoff {
					t.Fatalf("Resume = %+v, want g/2-1 with the restored pid %d and the host's end of a handoff channel", fb, f.criu.restorePID)
				}
				restore := f.criu.last(t)
				for _, want := range tc.wantArgs {
					want = strings.NewReplacer("ROOT", rootBind, "WORK", workDir).Replace(want)
					if !strings.Contains(restore, want) {
						t.Fatalf("criu restore %q lacks %q", restore, want)
					}
				}
				p := f.criu.restored()[0]
				if tc.kill {
					// Kill signals the restored root, a pid nobody has
					// here, so the kernel ending the tree is played by
					// the fake.
					if err := b.Kill("g/2-1"); !errors.Is(err, syscall.ESRCH) {
						t.Fatalf("Kill = %v, want ESRCH for the restored pid", err)
					}
					_ = p.Kill()
				} else {
					p.release(tc.criu.restoreErr)
				}
				if e := waitExit(t, b); e != (backend.Exit{FiberID: "g/2-1", Status: tc.wantExit}) {
					t.Fatalf("exit = %+v, want %s", e, tc.wantExit)
				}
				b.mu.Lock()
				n := len(b.fibers)
				b.mu.Unlock()
				if n != 0 {
					t.Fatalf("%d fibers left after the exit, want none", n)
				}
			}
			if tc.launcher != nil {
				want := strings.NewReplacer("DIR", dir, "PID", strconv.Itoa(fb.PID)).Replace(tc.wantCalls)
				waitFor(t, "launcher calls "+want, func() bool { return strings.Join(tc.launcher.recorded(), ",") == want })
			}
		})
	}
}

// TestFinishAndForgetOnce checks that a fiber's exit is reported once, and a
// fiber forgotten or replaced under its fence is not touched again.
func TestFinishAndForgetOnce(t *testing.T) {
	cases := []struct {
		name     string
		second   func(b *Backend, f *fiber)
		wantExit int
	}{
		{name: "finish twice reports once", second: func(b *Backend, f *fiber) { b.finish(f, "exit:1") }, wantExit: 1},
		{name: "forget after finish is nothing", second: func(b *Backend, f *fiber) { b.forget(f) }, wantExit: 1},
		{name: "finish of a replaced fiber leaves the new one", second: func(b *Backend, f *fiber) {
			b.fibers[f.id] = &fiber{id: f.id, zpid: 9, warmID: "g"}
			b.byPID[pidKey{"g", 9}] = b.fibers[f.id]
			b.finish(f, "exit:2")
		}, wantExit: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &Backend{fibers: map[string]*fiber{}, byPID: map[pidKey]*fiber{}, exits: make(chan backend.Exit, 8)}
			f := &fiber{id: "f", zpid: 7, warmID: "g"}
			b.fibers[f.id] = f
			b.byPID[pidKey{"g", 7}] = f
			b.finish(f, "exit:0")
			tc.second(b, f)
			if len(b.exits) != tc.wantExit {
				t.Fatalf("%d exits reported, want %d", len(b.exits), tc.wantExit)
			}
			if e := <-b.exits; e != (backend.Exit{FiberID: "f", Status: "exit:0"}) {
				t.Fatalf("exit = %+v", e)
			}
			if _, ok := b.byPID[pidKey{"g", 7}]; ok {
				t.Fatal("the finished fiber is still in byPID")
			}
		})
	}
}

// pagemapHeader is the 8 magic bytes a pagemap image starts with.
var pagemapHeader = []byte{0x19, 0x43, 0x56, 0x54, 0x01, 0x00, 0x00, 0x00}

// writeCheckpoint writes a one-task checkpoint with one present page of
// fill at the second page address.
func writeCheckpoint(t *testing.T, dir string, fill byte) {
	t.Helper()
	msg := func(fields ...[2]uint64) []byte {
		var m []byte
		for _, f := range fields {
			m = binary.AppendUvarint(m, f[0]<<3)
			m = binary.AppendUvarint(m, f[1])
		}
		return append(binary.LittleEndian.AppendUint32(nil, uint32(len(m))), m...)
	}
	img := append([]byte{}, pagemapHeader...)
	img = append(img, msg([2]uint64{1, 1})...)
	img = append(img, msg([2]uint64{1, criu.PageSize}, [2]uint64{2, 1}, [2]uint64{4, criu.PEPresent})...)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pagemap-1.img"), img, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pages-1.img"), bytes.Repeat([]byte{fill}, int(criu.PageSize)), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestDeltaCodec checks that the backend's delta codec is criu's. A
// checkpoint is computed as a delta over the parent, recognised as one, read
// back and merged whole again. Anything but a criu parent is refused.
func TestDeltaCodec(t *testing.T) {
	cases := []struct {
		name      string
		childFill byte
		wantBytes uint64 // the delta's
	}{
		{name: "same page as the parent is dropped", childFill: 'a', wantBytes: 0},
		{name: "a changed page is kept", childFill: 'b', wantBytes: criu.PageSize},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &Backend{}
			parentDir, dir := filepath.Join(t.TempDir(), "p"), filepath.Join(t.TempDir(), "c")
			writeCheckpoint(t, parentDir, 'a')
			writeCheckpoint(t, dir, tc.childFill)
			if n, err := b.ImageBytes(dir); err != nil || n != criu.PageSize {
				t.Fatalf("ImageBytes = %d %v, want one page", n, err)
			}
			if _, err := b.ImageBytes(filepath.Join(dir, "missing")); err == nil {
				t.Fatal("ImageBytes of a missing directory succeeded")
			}
			if _, err := b.LoadParent(t.TempDir()); err == nil {
				t.Fatal("LoadParent of an empty directory succeeded")
			}
			parent, err := b.LoadParent(parentDir)
			if err != nil {
				t.Fatalf("LoadParent: %v", err)
			}
			t.Cleanup(parent.(*criu.Parent).Close)
			if _, err := b.Compute(dir, notAParent{}); err == nil || !strings.Contains(err.Error(), "not a criu checkpoint") {
				t.Fatalf("Compute over a foreign parent = %v", err)
			}
			if err := b.Merge(dir, notAParent{}); err == nil || !strings.Contains(err.Error(), "not a criu checkpoint") {
				t.Fatalf("Merge over a foreign parent = %v", err)
			}
			if _, err := b.Compute(t.TempDir(), parent); err == nil {
				t.Fatal("Compute of an empty directory succeeded")
			}
			if b.HasDelta(dir) {
				t.Fatal("HasDelta before Compute")
			}
			if _, err := b.ReadDeltaInfo(dir); err == nil {
				t.Fatal("ReadDeltaInfo before Compute succeeded")
			}
			info, err := b.Compute(dir, parent)
			if err != nil {
				t.Fatalf("Compute: %v", err)
			}
			if info.ParentSHA256 != parent.(*criu.Parent).SHA256() || info.Bytes != tc.wantBytes {
				t.Fatalf("Compute = %+v, want parent %s and %d bytes", info, parent.(*criu.Parent).SHA256(), tc.wantBytes)
			}
			if !b.HasDelta(dir) {
				t.Fatal("HasDelta after Compute = false")
			}
			if read, err := b.ReadDeltaInfo(dir); err != nil || read != info {
				t.Fatalf("ReadDeltaInfo = %+v %v, want %+v", read, err, info)
			}
			if err := b.Merge(dir, parent); err != nil {
				t.Fatalf("Merge: %v", err)
			}
			if b.HasDelta(dir) {
				t.Fatal("HasDelta after Merge")
			}
			pages, err := os.ReadFile(filepath.Join(dir, "pages-1.img"))
			if err != nil || !bytes.Equal(pages, bytes.Repeat([]byte{tc.childFill}, int(criu.PageSize))) {
				t.Fatalf("merged pages are not the child's own (%d bytes, %v)", len(pages), err)
			}
		})
	}
}

type notAParent struct{}

func (notAParent) SHA256() string { return "" }
func (notAParent) Close()         {}

// TestMountinfo checks the mount table reader, its escape decoding, and the
// questions asked of it (is this a mount point, is this a dead sibling's
// restore root).
func TestMountinfo(t *testing.T) {
	t.Run("unescape", func(t *testing.T) {
		cases := []struct{ in, want string }{
			{"/plain", "/plain"},
			{`/with\040space`, "/with space"},
			{`/tab\011and\134backslash`, "/tab\tand\\backslash"},
			{`/short\04`, `/short\04`},
			{`/not\0z0octal`, `/not\0z0octal`},
			{`/trailing\`, `/trailing\`},
		}
		for _, tc := range cases {
			t.Run(tc.in, func(t *testing.T) {
				if got := unescapeMount(tc.in); got != tc.want {
					t.Fatalf("unescapeMount(%q) = %q, want %q", tc.in, got, tc.want)
				}
			})
		}
	})
	t.Run("read", func(t *testing.T) {
		cases := []struct {
			name    string
			content string // "" for a missing file
			want    []mountEntry
			wantErr bool
		}{
			{name: "missing file", wantErr: true},
			{name: "entries with options before the separator", content: "36 35 98:0 /mnt1 /mnt\\0402 rw,noatime master:1 - ext3 /dev/root rw\nshort line\n37 35 0:5 / /proc rw - proc proc rw\n",
				want: []mountEntry{{dev: "98:0", root: "/mnt1", point: "/mnt 2", opts: []string{"master:1"}}, {dev: "0:5", root: "/", point: "/proc"}}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "mountinfo")
				if tc.content != "" {
					if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				got, err := readMountinfoOf(path)
				if (err != nil) != tc.wantErr {
					t.Fatalf("readMountinfoOf = %v %v", got, err)
				}
				if fmt.Sprint(got) != fmt.Sprint(tc.want) {
					t.Fatalf("readMountinfoOf = %+v, want %+v", got, tc.want)
				}
			})
		}
	})
	t.Run("mountedAt", func(t *testing.T) {
		cases := []struct {
			name  string
			pid   int
			point string
			want  bool
		}{
			{name: "/proc in our namespace", pid: os.Getpid(), point: "/proc", want: true},
			{name: "a path that is no mount", pid: os.Getpid(), point: filepath.Join(os.TempDir(), "nowhere"), want: false},
			{name: "no such process", pid: impossiblePID(t), point: "/proc", want: false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if got := mountedAt(tc.pid, tc.point); got != tc.want {
					t.Fatalf("mountedAt(%d, %s) = %v, want %v", tc.pid, tc.point, got, tc.want)
				}
			})
		}
	})
	t.Run("deadSibling", func(t *testing.T) {
		dir := "/tmp/" + rootName + "100"
		cases := []struct {
			name  string
			point string
			want  bool
		}{
			{name: "a dead pid's root beside ours", point: "/tmp/" + rootName + strconv.Itoa(impossiblePID(t)), want: true},
			{name: "a live pid's root", point: "/tmp/" + rootName + strconv.Itoa(os.Getpid()), want: false},
			{name: "another directory", point: "/var/" + rootName + strconv.Itoa(impossiblePID(t)), want: false},
			{name: "another name", point: "/tmp/other-" + strconv.Itoa(impossiblePID(t)), want: false},
			{name: "not a number", point: "/tmp/" + rootName + "abc", want: false},
			{name: "a leading zero is not a pid", point: "/tmp/" + rootName + "0" + strconv.Itoa(impossiblePID(t)), want: false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if got := deadSibling(dir, tc.point); got != tc.want {
					t.Fatalf("deadSibling(%s, %s) = %v, want %v", dir, tc.point, got, tc.want)
				}
			})
		}
	})
}

// TestMountRootRefusals checks what the restore root refuses before it
// mounts anything, and that a directory it made for a refused mount goes
// again. A trusted path is mounted at tests/integration/proc TestRootBindShared.
func TestMountRootRefusals(t *testing.T) {
	cases := []struct {
		name    string
		dir     func(t *testing.T, base string) string
		wantErr string
	}{
		{name: "relative path", dir: func(*testing.T, string) string { return "relative/root" }, wantErr: "absolute"},
		{name: "name too long", dir: func(_ *testing.T, base string) string { return filepath.Join(base, strings.Repeat("r", 300)) }, wantErr: "file name too long"},
		{name: "parent is a file", dir: func(t *testing.T, base string) string {
			f := filepath.Join(base, "file")
			if err := os.WriteFile(f, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(f, "root")
		}, wantErr: "not a directory"},
		{name: "a symlink", dir: func(t *testing.T, base string) string {
			d := filepath.Join(base, "root")
			if err := os.Symlink("/", d); err != nil {
				t.Fatal(err)
			}
			return d
		}, wantErr: "is a symlink"},
		{name: "a regular file", dir: func(t *testing.T, base string) string {
			d := filepath.Join(base, "root")
			if err := os.WriteFile(d, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return d
		}, wantErr: "not a directory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			dir := tc.dir(t, base)
			existed := false
			if _, err := os.Lstat(dir); err == nil {
				existed = true
			}
			rootMu.Lock()
			err := mountRoot(dir)
			rootMu.Unlock()
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("mountRoot = %v, want %q", err, tc.wantErr)
			}
			if _, serr := os.Lstat(dir); !existed && serr == nil {
				t.Fatal("a directory made for the refused mount was left behind")
			}
			if filepath.IsAbs(dir) && mountedAt(os.Getpid(), dir) {
				t.Fatalf("%s was mounted", dir)
			}
		})
	}
}

// TestRootBindRefs checks the bookkeeping of the restore root's
// reference: a backend that never bound has nothing to give up, one whose
// bind is in the table but not mounted logs the failed unmount, and a
// refused mount is not held. Two backends sharing one real bind are
// tests/integration/proc TestRootBindShared.
func TestRootBindRefs(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, dir string, a *Backend)
	}{
		{name: "never bound", setup: func(_ *testing.T, _ string, a *Backend) { a.unbindRoot() }},
		{name: "in the table but not mounted", setup: func(t *testing.T, dir string, a *Backend) {
			var logs bytes.Buffer
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(os.Stderr) })
			a.rootHeld = true
			rootMu.Lock()
			rootBinds[dir] = &rootBind{refs: 1}
			rootMu.Unlock()
			a.unbindRoot()
			if !strings.Contains(logs.String(), "unmount restore root "+dir) {
				t.Fatalf("log = %q, want the failed unmount", logs.String())
			}
		}},
		{name: "held but not in the table", setup: func(_ *testing.T, _ string, a *Backend) {
			a.rootHeld = true
			a.unbindRoot()
			if a.rootHeld {
				t.Fatal("still held")
			}
		}},
		{name: "mount refused", setup: func(t *testing.T, dir string, a *Backend) {
			if err := os.Symlink("/", dir); err != nil {
				t.Fatal(err)
			}
			if err := a.bindRoot(); err == nil || !strings.Contains(err.Error(), "restore root "+dir) {
				t.Fatalf("bindRoot over a symlink = %v", err)
			}
			if a.rootHeld {
				t.Fatal("a refused bind is held")
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "root")
			a := &Backend{opt: Options{RootBind: dir}}
			tc.setup(t, dir, a)
			if mountedAt(os.Getpid(), dir) {
				t.Fatalf("%s is mounted", dir)
			}
			rootMu.Lock()
			_, held := rootBinds[dir]
			rootMu.Unlock()
			if held {
				t.Fatal("the bind is still in the table")
			}
		})
	}
}

// sha256Hex is the hex SHA-256 of a file's bytes.
func sha256Hex(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// TestOpenVerified checks that a registry template's executable is
// verified through the descriptor it is exec'd from: the bytes are hashed
// against what the host verified and a mismatch is refused. That an exec
// through the descriptor runs those bytes after the path was swapped is
// tests/integration/proc TestExecThroughVerifiedFD.
func TestOpenVerified(t *testing.T) {
	cases := []struct {
		name    string
		sha     func(path string) string
		missing bool
		wantErr string
	}{
		{name: "the verified bytes", sha: func(p string) string { return sha256Hex(t, p) }},
		{name: "a hash the bytes do not match", sha: func(string) string { return strings.Repeat("0", 64) }, wantErr: "hashes to"},
		{name: "no file", sha: func(string) string { return strings.Repeat("0", 64) }, missing: true, wantErr: "no such file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "zygote")
			if !tc.missing {
				if err := os.WriteFile(path, []byte("#!/bin/sh\necho verified\n"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			f, err := openVerified(path, tc.sha(path))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("openVerified = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("openVerified: %v", err)
			}
			defer func() { _ = f.Close() }()
			// The descriptor is open on the verified bytes, whatever the
			// path leads to by now.
			if err := os.Rename(path, path+".moved"); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(fmt.Sprintf("/proc/self/fd/%d", f.Fd()))
			if err != nil || string(data) != "#!/bin/sh\necho verified\n" {
				t.Fatalf("the descriptor reads %q (%v), want the verified bytes", data, err)
			}
		})
	}
}

// TestWarmVerifiesRegistryTemplate checks that Warm refuses a registry
// template (one with a verified hash) whose executable no longer hashes
// to it, before anything starts, and execs one that does through the
// verified descriptor as the zygote's fd 4. A launcher's template is the
// launcher's to verify (runc stages its own copy).
func TestWarmVerifiesRegistryTemplate(t *testing.T) {
	cases := []struct {
		name     string
		sha      func(exe string) string
		launcher *fakeLauncher
		wantErr  string
	}{
		{name: "the executable the host verified", sha: func(exe string) string { return sha256Hex(t, exe) }},
		{name: "an executable that changed since", sha: func(string) string { return strings.Repeat("0", 64) }, wantErr: "hashes to"},
		{name: "a launcher verifies its own copy", sha: func(string) string { return strings.Repeat("0", 64) }, launcher: &fakeLauncher{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakes(t)
			var launcher Launcher
			if tc.launcher != nil {
				tc.launcher.pid = impossiblePID(t) + 9
				launcher = tc.launcher
			}
			b := f.open(t, Options{Launcher: launcher})
			exe := filepath.Join(t.TempDir(), "zygote")
			if err := os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			argv := append([]string{exe}, fakeArgv("never", impossiblePID(t))[1:]...)
			tpl := backend.Template{Argv: argv, Dir: filepath.Dir(exe), Digest: "sha256:test", ZygoteSHA256: tc.sha(exe)}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "g", Template: tpl, CgroupFD: -1, ProbeCgroupFD: -1, WorkDir: t.TempDir()})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Warm = %v, want %q", err, tc.wantErr)
				}
				b.mu.Lock()
				n := len(b.zygotes)
				b.mu.Unlock()
				if n != 0 || len(f.spawn.started()) != 0 {
					t.Fatalf("%d zygotes registered and %d started after a refused template, want none", n, len(f.spawn.started()))
				}
				return
			}
			if err != nil {
				t.Fatalf("Warm: %v", err)
			}
			zy := f.spawn.started()[0]
			cmd := zy.cmd
			if tc.launcher != nil {
				if cmd.Path == exeFDPath || len(cmd.ExtraFiles) != 1 {
					t.Fatalf("a launcher's command was given the verified descriptor: %s %v", cmd.Path, cmd.ExtraFiles)
				}
				return
			}
			// The exec goes through the descriptor at fd 4, which holds
			// the bytes that were hashed, while argv still names the path.
			if cmd.Path != exeFDPath || cmd.Args[0] != exe || len(cmd.ExtraFiles) != 2 {
				t.Fatalf("command = %s %v with %d extra files, want %s through fd 4", cmd.Path, cmd.Args, len(cmd.ExtraFiles), exeFDPath)
			}
			if zy.exeSHA != tpl.ZygoteSHA256 {
				t.Fatalf("fd 4 held bytes hashing to %s, want the verified %s", zy.exeSHA, tpl.ZygoteSHA256)
			}
		})
	}
}

func TestHostSocket(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "criu cannot find a host socket", err: errors.New("criu dump pid 7: exit status 1: Error (criu/sk-unix.c:351): unix: Unix socket 60373 not found"), want: true},
		{name: "another dump failure", err: errors.New("criu dump pid 7: exit status 1: Error (criu/cr-dump.c:2011): Dumping FAILED")},
		{name: "no error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hostSocket(tc.err); got != tc.want {
				t.Fatalf("hostSocket = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSocketInode checks the read of a socket's inode under /proc.
func TestSocketInode(t *testing.T) {
	cases := []struct {
		name    string
		link    string // "" for no entry
		want    string
		wantErr string
	}{
		{name: "a socket", link: "socket:[60373]", want: "60373"},
		{name: "a file", link: "/dev/null", wantErr: "not a socket"},
		{name: "no such descriptor", wantErr: "no such file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakes(t)
			if tc.link != "" {
				dir := filepath.Join(f.proc, "7", "fd")
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(tc.link, filepath.Join(dir, "3")); err != nil {
					t.Fatal(err)
				}
			}
			got, err := socketInode(f.proc, 7, 3)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("socketInode = %q %v, want %q", got, err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("socketInode = %q %v, want %q", got, err, tc.want)
			}
		})
	}
}
