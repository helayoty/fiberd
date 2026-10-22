//go:build linux

package runc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"

	"go.uber.org/goleak"

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/backend/proc"
)

// TestMain fails the package when a test leaves a goroutine behind.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// testPool is a small pool whose ranges sit past any host id.
var testPool = IDPool{Start: 1 << 20, Slots: 4}

// identityPool maps every id onto itself, so a copy made for its one
// range chowns every file to the owner it already has, which needs no
// privilege. The shift onto a mapped range is tests/integration/runc TestRootfsCopy.
var identityPool = IDPool{Start: 0, Slots: 1}

// fakeRunc stands in for the runc binary behind launcher.run. It records
// every call without its --root prefix and answers as the body says.
type fakeRunc struct {
	// body answers one call, given the subcommand and its arguments.
	// Nil answers everything with nothing.
	body func(sub string, args []string) ([]byte, error)

	mu    sync.Mutex
	calls []string
}

func (f *fakeRunc) run(_ context.Context, args []string) ([]byte, error) {
	if len(args) >= 2 && args[0] == "--root" {
		args = args[2:]
	}
	f.mu.Lock()
	f.calls = append(f.calls, strings.Join(args, " "))
	f.mu.Unlock()
	if f.body == nil || len(args) == 0 {
		return nil, nil
	}
	return f.body(args[0], args[1:])
}

// recorded is every call so far.
func (f *fakeRunc) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// state is a body that reports pid as the container's init.
func state(pid int) func(string, []string) ([]byte, error) {
	return func(sub string, _ []string) ([]byte, error) {
		if sub == "state" {
			return []byte(fmt.Sprintf(`{"pid": %d}`, pid)), nil
		}
		return nil, nil
	}
}

// templateRootfs makes a small root filesystem: a directory with a file,
// a symlink, a fifo the copy skips, and every mount point a container
// needs, so a copy has nothing to make for the mapped root.
func templateRootfs(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "rootfs")
	steps := []func() error{
		func() error { return os.MkdirAll(filepath.Join(dir, "bin"), 0o755) },
		func() error { return os.WriteFile(filepath.Join(dir, "bin", "zygote"), []byte("#!/bin/sh\n"), 0o755) },
		func() error { return os.Symlink("bin/zygote", filepath.Join(dir, "z")) },
		func() error { return syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o600) },
	}
	for _, mp := range mountpoints {
		steps = append(steps, func() error { return os.MkdirAll(filepath.Join(dir, mp), 0o755) })
	}
	for _, step := range steps {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// identityLauncher is newLauncher over the identity pool.
func identityLauncher(t *testing.T) *launcher {
	t.Helper()
	l, _ := newLauncher(t, nil)
	l.opt.Pool, l.claims = identityPool, newClaims(identityPool)
	return l
}

// owner is the uid and gid of path.
func owner(t *testing.T, path string) (uid, gid int) {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	return int(st.Uid), int(st.Gid)
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}

// newLauncher is a launcher over the fake runc and a template rootfs.
func newLauncher(t *testing.T, body func(string, []string) ([]byte, error)) (*launcher, *fakeRunc) {
	t.Helper()
	f := &fakeRunc{body: body}
	l := &launcher{opt: Options{Runc: "runc", Rootfs: templateRootfs(t), StateDir: filepath.Join(t.TempDir(), "state"), Pool: testPool}, claims: newClaims(testPool), run: f.run}
	if err := os.MkdirAll(l.opt.StateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return l, f
}

// warmSpec is a grant's spec with its run directory under a temp dir.
func warmSpec(t *testing.T, grant string) backend.WarmSpec {
	t.Helper()
	return backend.WarmSpec{GrantUID: grant, WorkDir: filepath.Join(t.TempDir(), "run", grant), CgroupFD: -1, ProbeCgroupFD: -1}
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// stateFile makes path a regular file where a directory is wanted.
func stateFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

// ociConfig is the part of the bundle's config.json the tests check.
type ociConfig struct {
	OCIVersion string `json:"ociVersion"`
	Process    struct {
		Terminal        bool                `json:"terminal"`
		User            map[string]int      `json:"user"`
		Cwd             string              `json:"cwd"`
		Args            []string            `json:"args"`
		Env             []string            `json:"env"`
		Capabilities    map[string][]string `json:"capabilities"`
		NoNewPrivileges bool                `json:"noNewPrivileges"`
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
		Options     []string `json:"options"`
	} `json:"mounts"`
	Linux struct {
		Namespaces  []map[string]string `json:"namespaces"`
		UIDMappings []map[string]uint32 `json:"uidMappings"`
		GIDMappings []map[string]uint32 `json:"gidMappings"`
		CgroupsPath string              `json:"cgroupsPath"`
		Propagation string              `json:"rootfsPropagation"`
		Readonly    []string            `json:"readonlyPaths"`
		Masked      []string            `json:"maskedPaths"`
	} `json:"linux"`
}

// configOf reads a bundle config back the way runc would.
func configOf(t *testing.T, cfg map[string]any) ociConfig {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var out ociConfig
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// templateMountOf returns the source of the template mount in a bundle's
// config, or "" when it has none, checking the mount's options.
func templateMountOf(t *testing.T, cfg ociConfig) string {
	t.Helper()
	for _, m := range cfg.Mounts {
		if m.Destination == backend.TemplateMount {
			if m.Type != "bind" || !reflect.DeepEqual(m.Options, backend.TemplateMountOptions) {
				t.Fatalf("template mount = %+v, want a bind with %v", m, backend.TemplateMountOptions)
			}
			return m.Source
		}
	}
	return ""
}

// TestBundleConfig checks the spec runc runs the zygote from: its
// namespaces, mappings, mounts, read-only and masked paths, the process
// as root in its namespace logging under /host, and the template bind
// when the grant has a staged copy. What Command makes around it (the
// rootfs copy, the run directory, the log's owner) is tests/integration/runc
// TestCommandPreparesTheBundle.
func TestBundleConfig(t *testing.T) {
	cases := []struct {
		name   string
		cgPath string
		staged string
		check  func(t *testing.T, l *launcher, spec backend.WarmSpec, cfg ociConfig)
	}{
		{name: "namespaces, mappings, mounts, read-only and masked paths",
			check: func(t *testing.T, l *launcher, spec backend.WarmSpec, cfg ociConfig) {
				rng := testPool.Range("g1")
				var ns []string
				for _, n := range cfg.Linux.Namespaces {
					ns = append(ns, n["type"])
				}
				if want := []string{"user", "pid", "mount", "network", "ipc", "uts"}; !reflect.DeepEqual(ns, want) {
					t.Errorf("namespaces = %v, want %v", ns, want)
				}
				wantMap := []map[string]uint32{{"containerID": 0, "hostID": rng.Start, "size": rng.Count}}
				if !reflect.DeepEqual(cfg.Linux.UIDMappings, wantMap) || !reflect.DeepEqual(cfg.Linux.GIDMappings, wantMap) {
					t.Errorf("mappings = %v / %v, want %v", cfg.Linux.UIDMappings, cfg.Linux.GIDMappings, wantMap)
				}
				var dests []string
				for _, m := range cfg.Mounts {
					dests = append(dests, m.Destination+"="+m.Type)
				}
				if want := []string{"/proc=proc", "/dev=tmpfs", "/sys=bind", "/host=bind"}; !reflect.DeepEqual(dests, want) {
					t.Errorf("mounts = %v, want %v", dests, want)
				}
				if m := cfg.Mounts[3]; m.Source != spec.WorkDir || !reflect.DeepEqual(m.Options, []string{"rbind", "rw"}) {
					t.Errorf("/host mount = %+v, want a rw rbind of %s", m, spec.WorkDir)
				}
				// Not a sysfs mount of the container's own: the kernel refuses
				// one to a user namespace when a locked mount covers part of
				// the host's /sys, as in some Pods. A bind of fiberd's bind.
				if m := cfg.Mounts[2]; m.Source != l.sysDir() || !reflect.DeepEqual(m.Options, []string{"rbind", "nosuid", "noexec", "nodev", "ro"}) {
					t.Errorf("/sys mount = %+v, want a read-only rbind of fiberd's /sys bind %s", m, l.sysDir())
				}
				if want := []string{"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"}; !reflect.DeepEqual(cfg.Linux.Readonly, want) {
					t.Errorf("readonlyPaths = %v, want %v", cfg.Linux.Readonly, want)
				}
				if len(cfg.Linux.Masked) != 9 || cfg.Linux.Masked[0] != "/proc/kcore" || cfg.Linux.Masked[8] != "/sys/devices/virtual/powercap" {
					t.Errorf("maskedPaths = %v", cfg.Linux.Masked)
				}
				if cfg.Linux.CgroupsPath != "" {
					t.Errorf("cgroupsPath = %q, want none", cfg.Linux.CgroupsPath)
				}
				// A workspace moved in one fiber's copy of the namespace
				// must reach no sibling, whatever the host's default.
				if cfg.Linux.Propagation != "rslave" {
					t.Errorf("rootfsPropagation = %q, want rslave", cfg.Linux.Propagation)
				}
				if cfg.Root.Path != l.rootfs(spec) || cfg.Root.Readonly {
					t.Errorf("root = %+v, want the writable copy at %s", cfg.Root, l.rootfs(spec))
				}
				if cfg.Hostname != "fiber" || cfg.OCIVersion != "1.0.2" {
					t.Errorf("hostname %q version %q", cfg.Hostname, cfg.OCIVersion)
				}
				if src := templateMountOf(t, cfg); src != "" {
					t.Errorf("a template from the rootfs got a template mount of %s", src)
				}
			}},
		{name: "the process: the zygote as root in its namespace, logging under /host",
			check: func(t *testing.T, _ *launcher, _ backend.WarmSpec, cfg ociConfig) {
				p := cfg.Process
				if want := []string{"/bin/zygote", "-x", "--log", "/host/zygote.log"}; !reflect.DeepEqual(p.Args, want) {
					t.Errorf("args = %v, want %v", p.Args, want)
				}
				if want := []string{"PATH=/usr/bin:/bin", nestedUsernsEnv, rebindEnv}; !reflect.DeepEqual(p.Env, want) {
					t.Errorf("env = %v, want %v", p.Env, want)
				}
				if p.Cwd != "/host" || p.Terminal || p.NoNewPrivileges || p.User["uid"] != 0 || p.User["gid"] != 0 {
					t.Errorf("process = %+v", p)
				}
				for _, set := range []string{"bounding", "effective", "permitted"} {
					if !reflect.DeepEqual(p.Capabilities[set], containerCaps) {
						t.Errorf("%s caps = %v, want %v", set, p.Capabilities[set], containerCaps)
					}
				}
				if len(p.Capabilities["inheritable"]) != 0 {
					t.Errorf("inheritable caps = %v, want none", p.Capabilities["inheritable"])
				}
			}},
		{name: "a cgroup leaf is the container's cgroupsPath", cgPath: "/fiberd/g1/zygote",
			check: func(t *testing.T, _ *launcher, _ backend.WarmSpec, cfg ociConfig) {
				if cfg.Linux.CgroupsPath != "/fiberd/g1/zygote" {
					t.Errorf("cgroupsPath = %q, want the leaf", cfg.Linux.CgroupsPath)
				}
			}},
		{name: "a staged registry template is bound read-only at its mount", staged: "/state/templates/w-g1/template",
			check: func(t *testing.T, _ *launcher, _ backend.WarmSpec, cfg ociConfig) {
				if src := templateMountOf(t, cfg); src != "/state/templates/w-g1/template" || len(cfg.Mounts) != 5 {
					t.Errorf("mounts = %v, want the staged copy bound as the fifth", cfg.Mounts)
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, _ := newLauncher(t, nil)
			spec := warmSpec(t, "g1")
			cfg := l.bundleConfig(spec, []string{"/bin/zygote", "-x"}, l.rootfs(spec), tc.cgPath, tc.staged, testPool.Range("g1"))
			tc.check(t, l, spec, configOf(t, cfg))
		})
	}
}

// TestCommandRefusals checks what Command refuses before it copies
// anything, and that every refusal gives the grant's hold back. What it
// prepares when nothing refuses is tests/integration/runc TestCommandPreparesTheBundle.
func TestCommandRefusals(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T, l *launcher, spec *backend.WarmSpec)
		wantErr string
		wantIs  error
	}{
		{name: "a missing rootfs", wantErr: "unusable",
			setup: func(_ *testing.T, l *launcher, _ *backend.WarmSpec) { l.opt.Rootfs += "-missing" }},
		{name: "a rootfs that is a file", wantErr: "unusable",
			setup: func(t *testing.T, l *launcher, _ *backend.WarmSpec) {
				l.opt.Rootfs = filepath.Join(l.opt.Rootfs, "bin", "zygote")
			}},
		{name: "another grant holds the slot", wantIs: ErrRangeCollision,
			setup: func(t *testing.T, l *launcher, _ *backend.WarmSpec) {
				if err := l.claims.acquire(colliding(testPool, "g1"), false); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "the rootfs copies directory is a file", wantErr: "not a directory",
			setup: func(t *testing.T, l *launcher, _ *backend.WarmSpec) {
				stateFile(t, filepath.Join(l.opt.StateDir, "rootfs"))
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, f := newLauncher(t, nil)
			spec := warmSpec(t, "g1")
			logf, err := os.Create(filepath.Join(t.TempDir(), "zygote.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = logf.Close() }()
			ctl, err := os.Open(os.DevNull)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = ctl.Close() }()
			tc.setup(t, l, &spec)
			_, err = l.Command(spec, []string{"/bin/zygote", "-x"}, ctl, logf)
			if err == nil {
				t.Fatalf("Command succeeded, want an error (%s %v)", tc.wantErr, tc.wantIs)
			}
			if tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Command = %v, want an error containing %q", err, tc.wantErr)
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("Command = %v, want %v", err, tc.wantIs)
			}
			if l.claims.release(spec.GrantUID, true) {
				t.Fatal("the failed Command kept the zygote's hold on the slot")
			}
			if exists(l.rootfs(spec)) {
				t.Fatal("the failed Command left the rootfs copy")
			}
			if exists(l.templateDir(spec)) || l.stagedFor(spec) != "" {
				t.Fatal("the failed Command left a staged template")
			}
			if n := len(f.recorded()); n != 0 {
				t.Fatalf("runc was run %d times before the refusal", n)
			}
		})
	}
}

// TestSweep checks that a new backend ends the containers a previous life
// left in runc's state and removes every bundle and rootfs copy.
func TestSweep(t *testing.T) {
	cases := []struct {
		name      string
		body      func(string, []string) ([]byte, error)
		stateRoot bool // runc's state root exists from before
		busy      bool // a leftover that cannot be removed
		wantCalls []string
	}{
		{name: "no state root: runc is not asked, leftovers go"},
		{name: "every container listed is killed and deleted", stateRoot: true,
			body: func(sub string, _ []string) ([]byte, error) {
				if sub == "list" {
					return []byte("c1\nc2\n"), nil
				}
				return nil, nil
			},
			wantCalls: []string{"list -q", "kill c1 KILL", "delete -f c1", "kill c2 KILL", "delete -f c2"}},
		{name: "runc cannot list: nothing is killed", stateRoot: true,
			body: func(sub string, _ []string) ([]byte, error) {
				if sub == "list" {
					return nil, errors.New("exit status 1")
				}
				return nil, nil
			},
			wantCalls: []string{"list -q"}},
		{name: "a leftover that will not go is reported and kept", busy: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.busy && os.Geteuid() == 0 {
				t.Skip("root removes a directory it cannot write")
			}
			l, f := newLauncher(t, tc.body)
			if tc.stateRoot {
				if err := os.Mkdir(l.root(), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			leftovers := []string{filepath.Join(l.opt.StateDir, "rootfs", "w-old"), filepath.Join(l.opt.StateDir, "bundles", "w-old"), filepath.Join(l.opt.StateDir, "templates", "w-old")}
			for _, p := range leftovers {
				if err := os.MkdirAll(p, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(p, "f"), []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			busy := filepath.Join(l.opt.StateDir, "rootfs", "w-busy")
			if tc.busy {
				// A directory nobody may write keeps its entries.
				if err := os.Mkdir(busy, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(busy, "f"), []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(busy, 0o555); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(busy, 0o755) })
			}
			var logged bytes.Buffer
			prev := log.Writer()
			log.SetOutput(&logged)
			t.Cleanup(func() { log.SetOutput(prev) })

			l.sweep()

			for _, p := range leftovers {
				if exists(p) {
					t.Errorf("leftover %s survived the sweep", p)
				}
				if !strings.Contains(logged.String(), "swept leftover "+p) {
					t.Errorf("the sweep did not report %s", p)
				}
			}
			if tc.busy {
				if !exists(busy) {
					t.Error("the busy leftover is gone")
				}
				if !strings.Contains(logged.String(), "sweep "+busy) {
					t.Errorf("the sweep did not report the busy leftover: %s", logged.String())
				}
			}
			if got := f.recorded(); !reflect.DeepEqual(got, tc.wantCalls) {
				t.Errorf("runc calls = %v, want %v", got, tc.wantCalls)
			}
		})
	}
}

// TestReadRootfsMarker checks that the marker is read, or why it cannot be.
func TestReadRootfsMarker(t *testing.T) {
	cases := []struct {
		name    string
		body    string // "" for no marker
		want    rootfsRecord
		wantErr bool
	}{
		{name: "no marker", wantErr: true},
		{name: "broken marker", body: "{", wantErr: true},
		{name: "a marker", body: `{"source":"/tpl","start":65536,"count":65536}`, want: rootfsRecord{Source: "/tpl", Start: 65536, Count: 65536}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.body != "" {
				if err := os.WriteFile(filepath.Join(dir, rootfsMarker), []byte(tc.body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			got, err := readRootfsMarker(dir)
			if (err != nil) != tc.wantErr {
				t.Fatalf("readRootfsMarker = %+v, %v, want error %v", got, err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("readRootfsMarker = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestCgroupPath checks that an open cgroup directory resolves to the path
// runc wants, relative to the hierarchy's mount. A temp directory stands
// in for the mount, since the path is all that is read.
func TestCgroupPath(t *testing.T) {
	cases := []struct {
		name    string
		open    func(t *testing.T, mount string) int
		want    string
		wantErr string
	}{
		{name: "the cgroup root", want: "/", open: openDir},
		{name: "a leaf", want: "/fiberd/g1/zygote", open: func(t *testing.T, mount string) int {
			leaf := filepath.Join(mount, "fiberd", "g1", "zygote")
			if err := os.MkdirAll(leaf, 0o755); err != nil {
				t.Fatal(err)
			}
			return openDir(t, leaf)
		}},
		{name: "a directory elsewhere", wantErr: "is not under", open: func(t *testing.T, _ string) int { return openDir(t, t.TempDir()) }},
		{name: "a descriptor that is not open", wantErr: "no such file", open: func(*testing.T, string) int { return 1 << 20 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mount := t.TempDir()
			got, err := cgroupPath(tc.open(t, mount), mount)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("cgroupPath = %q, %v, want an error containing %q", got, err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("cgroupPath = %q, %v, want %q", got, err, tc.want)
			}
		})
	}
}

// openDir opens a directory for the test and returns its descriptor.
func openDir(t *testing.T, path string) int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return int(f.Fd())
}

// TestPID checks that the container's init is read from `runc state`.
func TestPID(t *testing.T) {
	cases := []struct {
		name    string
		body    func(string, []string) ([]byte, error)
		want    int
		wantErr string
	}{
		{name: "the init pid", body: state(4242), want: 4242},
		{name: "runc fails", wantErr: "container does not exist", body: func(string, []string) ([]byte, error) {
			return []byte("container does not exist"), errors.New("exit status 1")
		}},
		{name: "no pid in the state", wantErr: "no init pid", body: func(string, []string) ([]byte, error) {
			return []byte(`{"status":"stopped"}`), nil
		}},
		{name: "a state that is not json", wantErr: "no init pid", body: func(string, []string) ([]byte, error) {
			return []byte("nonsense"), nil
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, f := newLauncher(t, tc.body)
			got, err := l.PID(context.Background(), warmSpec(t, "g1"), nil)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("PID = %d, %v, want an error containing %q", got, err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("PID = %d, %v, want %d", got, err, tc.want)
			}
			if calls := f.recorded(); len(calls) != 1 || calls[0] != "state w-g1" {
				t.Fatalf("runc calls = %v, want state w-g1", calls)
			}
		})
	}
}

// TestRelease checks that the container is ended, its bundle and staged
// template go, and the zygote's hold is given back. The rootfs copy that
// goes with the last hold is tests/integration/runc TestReleaseKeepsRestoredCopy.
func TestRelease(t *testing.T) {
	cases := []struct {
		name string
	}{{name: "kill, delete, bundle and staged copy gone, slot free"}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, f := newLauncher(t, nil)
			spec := warmSpec(t, "g1")
			if err := l.claims.acquire(spec.GrantUID, true); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(l.bundle(spec), 0o755); err != nil {
				t.Fatal(err)
			}
			staged := filepath.Join(l.templateDir(spec), "template")
			if err := os.MkdirAll(staged, 0o755); err != nil {
				t.Fatal(err)
			}
			l.setStaged(spec, staged)
			l.Release(spec)
			if got, want := f.recorded(), []string{"kill w-g1 KILL", "delete -f w-g1"}; !reflect.DeepEqual(got, want) {
				t.Errorf("runc calls = %v, want %v", got, want)
			}
			if exists(l.bundle(spec)) {
				t.Error("the bundle survived Release")
			}
			if exists(l.templateDir(spec)) || l.stagedFor(spec) != "" {
				t.Error("the staged template survived Release")
			}
			if l.claims.release("g1", true) || l.claims.release("g1", false) {
				t.Error("the slot is still held")
			}
		})
	}
}

// TestEndpoint checks that a host path in the run directory maps to where
// the zygote sees it.
func TestEndpoint(t *testing.T) {
	cases := []struct {
		name string
		work string
		host string
		want string
	}{
		{name: "a socket in the run directory", work: "/run/fiberd/g1", host: "/run/fiberd/g1/f-1.sock", want: "/host/f-1.sock"},
		{name: "nested", work: "/run/fiberd/g1", host: "/run/fiberd/g1/a/b.sock", want: "/host/a/b.sock"},
		{name: "the run directory itself is not stripped", work: "/run/fiberd/g1", host: "/run/fiberd/g1", want: "/host//run/fiberd/g1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := &launcher{}
			if got := l.Endpoint(backend.WarmSpec{WorkDir: tc.work}, tc.host); got != tc.want {
				t.Fatalf("Endpoint = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestDumpExtra checks that criu is told which mounts come from outside and to
// leave the network namespace alone, and that a grant on a registry
// template has its template bind named too and recorded beside the
// images for the restore.
func TestDumpExtra(t *testing.T) {
	base := []string{"--external", "mnt[/host]:host", "--external", "mnt[/sys]:sys", "--empty-ns", "net", "--network-lock", "skip"}
	for _, d := range []string{"null", "zero", "full", "random", "urandom", "tty"} {
		base = append(base, "--external", "mnt[/dev/"+d+"]:dev-"+d)
	}
	cases := []struct {
		name      string
		template  backend.Template
		want      []string
		record    bool
		workspace bool // the dumped tree is a fiber with a workspace
		wantErr   string
	}{
		{name: "a template from the rootfs", want: base},
		{name: "a registry template names its bind", template: backend.Template{Dir: "/cache/x", Argv: []string{"/cache/x/zygote"}},
			want: append(append([]string{}, base...), "--external", "mnt["+backend.TemplateMount+"]:template"), record: true},
		{name: "a record that cannot be written", template: backend.Template{Dir: "/cache/x", Argv: []string{"/cache/x/zygote"}}, wantErr: "not a directory"},
		// A fiber with a workspace lives in a copy of the container's
		// namespace, so the files it holds through the container's mounts
		// are named too, the zygote's text here (mount 200, inode 19).
		{name: "a fiber with a workspace names its foreign files", workspace: true,
			want: append(append([]string{}, base...), "--external", "file[c8:13]")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "images")
			if tc.wantErr != "" {
				dir = filepath.Join(t.TempDir(), "file", "images")
				stateFile(t, filepath.Dir(dir))
			}
			l, d := &launcher{}, proc.Dumped{PID: 7, Zygote: 3}
			if tc.workspace {
				f := newFakeProc(t)
				f.mapping(fiberPID, 0x400000, 0x47e000, "r-xp", "/zyg", reg(mntRootfs, 19))
				l, d = f.launcher(), proc.Dumped{PID: fiberPID, Zygote: zygotePID, Workspace: true}
			}
			got, err := l.DumpExtra(backend.WarmSpec{GrantUID: "g1", Template: tc.template}, dir, d)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("DumpExtra = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("DumpExtra = %v %v, want %v", got, err, tc.want)
			}
			b, err := os.ReadFile(filepath.Join(dir, templateFile))
			if (err == nil) != tc.record {
				t.Fatalf("record %s: %q %v, want one %v", templateFile, b, err, tc.record)
			}
			if tc.record && !strings.Contains(string(b), backend.TemplateMount) {
				t.Fatalf("record = %s, want the mount point", b)
			}
			if fb, err := os.ReadFile(filepath.Join(dir, foreignFile)); (err == nil) != tc.workspace || (tc.workspace && !strings.Contains(string(fb), `"/zyg"`)) {
				t.Fatalf("record %s: %q %v, want one naming /zyg only for a fiber with a workspace", foreignFile, fb, err)
			}
		})
	}
}

// TestTemplateBind checks that a checkpoint taken with a template bind is
// restored with this home's own verified copy, the one its warm instance
// staged, and is refused by name without one. The rest of RestoreExtra,
// the hold and what the mapped root may read, is tests/integration/runc
// TestReleaseKeepsRestoredCopy and TestResumedFiberHoldsRange.
func TestTemplateBind(t *testing.T) {
	cases := []struct {
		name    string
		record  string // the record's mount point, "" for no record, "dir" for an unreadable one
		staged  string // this home's staged template copy, "" for none
		want    []string
		wantErr string
	}{
		{name: "a checkpoint without a template bind binds none, warm or not", staged: "/state/templates/w-g1/template"},
		{name: "a checkpoint with a template bind, the grant warm here", record: backend.TemplateMount, staged: "/state/templates/w-g1/template",
			want: []string{"--external", "mnt[template]:/state/templates/w-g1/template"}},
		{name: "a checkpoint with a template bind, the grant not warm here", record: backend.TemplateMount, wantErr: "does not have here"},
		{name: "a record naming another mount point is malformed", record: "/elsewhere", staged: "/state/templates/w-g1/template", wantErr: "malformed"},
		{name: "a record that cannot be read", record: "dir", staged: "/state/templates/w-g1/template", wantErr: "is a directory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, _ := newLauncher(t, nil)
			spec := warmSpec(t, "g1")
			if tc.staged != "" {
				l.setStaged(spec, tc.staged)
			}
			images := t.TempDir()
			switch tc.record {
			case "":
			case "dir":
				if err := os.Mkdir(filepath.Join(images, templateFile), 0o755); err != nil {
					t.Fatal(err)
				}
			default:
				b, err := json.Marshal(templateRecord{MountPoint: tc.record})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(images, templateFile), b, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := l.templateBind(spec, images)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("templateBind = %v %v, want an error containing %q", got, err, tc.wantErr)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("templateBind = %v %v, want %v", got, err, tc.want)
			}
		})
	}
}

// TestMappedRoot checks that the grant's mapped root is the start of its range,
// unless another grant holds the slot here.
func TestMappedRoot(t *testing.T) {
	cases := []struct {
		name   string
		held   string // a grant holding g1's slot first
		want   uint32
		wantIs error
	}{
		{name: "a free slot", want: testPool.Range("g1").Start},
		{name: "the grant's own hold", held: "g1", want: testPool.Range("g1").Start},
		{name: "another grant's hold", held: colliding(testPool, "g1"), wantIs: ErrRangeCollision},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, _ := newLauncher(t, nil)
			b := &Backend{l: l}
			if tc.held != "" {
				if err := l.claims.acquire(tc.held, true); err != nil {
					t.Fatal(err)
				}
			}
			got, err := b.MappedRoot("g1")
			if tc.wantIs != nil {
				if !errors.Is(err, tc.wantIs) {
					t.Fatalf("MappedRoot = %d, %v, want %v", got, err, tc.wantIs)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("MappedRoot = %d, %v, want %d", got, err, tc.want)
			}
		})
	}
}

// TestStaged checks the record of a grant's staged template copy.
func TestStaged(t *testing.T) {
	cases := []struct {
		name string
		set  []string // successive setStaged values
		want string
	}{
		{name: "nothing staged"},
		{name: "staged", set: []string{"/a"}, want: "/a"},
		{name: "staged then forgotten", set: []string{"/a", ""}},
		{name: "restaged", set: []string{"/a", "/b"}, want: "/b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := &launcher{}
			spec := backend.WarmSpec{GrantUID: "g1"}
			for _, s := range tc.set {
				l.setStaged(spec, s)
			}
			if got := l.stagedFor(spec); got != tc.want {
				t.Fatalf("stagedFor = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestHoldDrop checks that the rootfs copy lives exactly as long as some user
// of the grant holds its range, and is remade when it is not the copy the
// grant needs. The identity pool keeps every file its owner's, so no
// privilege is needed for the copy.
func TestHoldDrop(t *testing.T) {
	const warm, fiber = true, false
	cases := []struct {
		name string
		run  func(t *testing.T, l *launcher, spec backend.WarmSpec)
	}{
		{name: "the copy goes with the last hold", run: func(t *testing.T, l *launcher, spec backend.WarmSpec) {
			dir, err := l.hold(spec, warm)
			if err != nil {
				t.Fatal(err)
			}
			sentinel := filepath.Join(dir, "sentinel")
			if err := os.WriteFile(sentinel, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			if dir2, err := l.hold(spec, fiber); err != nil || dir2 != dir {
				t.Fatalf("second hold = %s, %v, want %s", dir2, err, dir)
			}
			if !exists(sentinel) {
				t.Fatal("the second hold remade a copy that matched")
			}
			l.drop(spec, warm)
			if !exists(sentinel) {
				t.Fatal("the zygote's drop removed a copy a fiber still uses")
			}
			l.RestoredGone(spec)
			if exists(dir) {
				t.Fatal("the last drop left the copy")
			}
		}},
		{name: "a copy for other ids is remade", run: func(t *testing.T, l *launcher, spec backend.WarmSpec) {
			dir, err := l.hold(spec, warm)
			if err != nil {
				t.Fatal(err)
			}
			l.drop(spec, warm)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			stale, _ := json.Marshal(rootfsRecord{Source: l.opt.Rootfs, Start: 1, Count: 1})
			if err := os.WriteFile(filepath.Join(dir, rootfsMarker), stale, 0o644); err != nil {
				t.Fatal(err)
			}
			sentinel := filepath.Join(dir, "sentinel")
			if err := os.WriteFile(sentinel, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := l.hold(spec, warm); err != nil {
				t.Fatal(err)
			}
			if exists(sentinel) {
				t.Fatal("a copy with another marker was kept")
			}
			if have, err := readRootfsMarker(dir); err != nil || have != (rootfsRecord{Source: l.opt.Rootfs, Start: 0, Count: SlotIDs}) {
				t.Fatalf("marker after remake = %+v, %v", have, err)
			}
		}},
		{name: "a copy with an unreadable marker is remade", run: func(t *testing.T, l *launcher, spec backend.WarmSpec) {
			dir := l.rootfs(spec)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, rootfsMarker), []byte("{"), 0o644); err != nil {
				t.Fatal(err)
			}
			sentinel := filepath.Join(dir, "sentinel")
			if err := os.WriteFile(sentinel, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := l.hold(spec, fiber); err != nil {
				t.Fatal(err)
			}
			if exists(sentinel) {
				t.Fatal("a copy with a broken marker was kept")
			}
		}},
		{name: "a source that cannot be copied frees the hold", run: func(t *testing.T, l *launcher, spec backend.WarmSpec) {
			l.opt.Rootfs += "-missing"
			_, err := l.hold(spec, fiber)
			if err == nil || !strings.Contains(err.Error(), "copy rootfs for "+spec.GrantUID) {
				t.Fatalf("hold = %v, want a copy error", err)
			}
			if exists(l.rootfs(spec)) {
				t.Fatal("a failed copy was left")
			}
			if l.claims.release(spec.GrantUID, fiber) {
				t.Fatal("the failed hold kept the slot")
			}
		}},
		{name: "a source whose marker name is a directory", run: func(t *testing.T, l *launcher, spec backend.WarmSpec) {
			if err := os.Mkdir(filepath.Join(l.opt.Rootfs, rootfsMarker), 0o755); err != nil {
				t.Fatal(err)
			}
			if _, err := l.hold(spec, warm); err == nil || !strings.Contains(err.Error(), "is a directory") {
				t.Fatalf("hold = %v, want the marker write to fail", err)
			}
			if exists(l.rootfs(spec)) {
				t.Fatal("a copy without a marker was left")
			}
		}},
		{name: "a collision makes no copy", run: func(t *testing.T, l *launcher, spec backend.WarmSpec) {
			if err := l.claims.acquire(colliding(identityPool, spec.GrantUID), warm); err != nil {
				t.Fatal(err)
			}
			if _, err := l.hold(spec, warm); !errors.Is(err, ErrRangeCollision) {
				t.Fatalf("hold = %v, want ErrRangeCollision", err)
			}
			if exists(l.rootfs(spec)) {
				t.Fatal("a copy was made for a grant that cannot run here")
			}
		}},
		{name: "a drop by a grant without a hold changes nothing", run: func(t *testing.T, l *launcher, spec backend.WarmSpec) {
			dir, err := l.hold(spec, warm)
			if err != nil {
				t.Fatal(err)
			}
			other := warmSpec(t, colliding(identityPool, spec.GrantUID))
			l.drop(other, warm)
			l.drop(spec, fiber)
			if !exists(dir) {
				t.Fatal("a stranger's drop removed the copy")
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.run(t, identityLauncher(t), warmSpec(t, "g1"))
		})
	}
}

// TestCopyTree checks what the copy keeps, skips and refuses. Owners are
// kept as they are under the identity range, and what the shift onto a
// mapped range does to them is tests/integration/runc TestRootfsCopy.
func TestCopyTree(t *testing.T) {
	rng := identityPool.Range("g1")
	cases := []struct {
		name    string
		src     func(t *testing.T, src string)
		dst     func(t *testing.T, dst string) // what is at dst before
		wantErr string
		check   func(t *testing.T, dst string)
	}{
		{name: "files, modes, symlinks, a fifo skipped",
			src: func(t *testing.T, src string) {
				if err := os.MkdirAll(filepath.Join(src, "ro", "deep"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(src, "ro", "deep", "f"), []byte("data"), 0o640); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("deep/f", filepath.Join(src, "ro", "link")); err != nil {
					t.Fatal(err)
				}
				if err := syscall.Mkfifo(filepath.Join(src, "fifo"), 0o600); err != nil {
					t.Fatal(err)
				}
				// Read-only after its contents are in place.
				if err := os.Chmod(filepath.Join(src, "ro"), 0o555); err != nil {
					t.Fatal(err)
				}
			},
			check: func(t *testing.T, dst string) {
				f := filepath.Join(dst, "ro", "deep", "f")
				if b, err := os.ReadFile(f); err != nil || string(b) != "data" {
					t.Errorf("f = %q, %v", b, err)
				}
				if uid, gid := owner(t, f); uid != os.Getuid() || gid != os.Getgid() || mode(t, f) != 0o640 {
					t.Errorf("f = %d:%d %o, want the caller's ids and mode 640", uid, gid, mode(t, f))
				}
				ro := filepath.Join(dst, "ro")
				if mode(t, ro) != 0o555 {
					t.Errorf("ro mode = %o, want 555", mode(t, ro))
				}
				if link, err := os.Readlink(filepath.Join(ro, "link")); err != nil || link != "deep/f" {
					t.Errorf("link = %q, %v", link, err)
				}
				if exists(filepath.Join(dst, "fifo")) {
					t.Error("the fifo was copied")
				}
			}},
		{name: "a missing source", wantErr: "no such file",
			src: func(t *testing.T, src string) {
				if err := os.RemoveAll(src); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "a destination that is a file", wantErr: "not a directory",
			src: func(t *testing.T, src string) {
				if err := os.WriteFile(filepath.Join(src, "f"), nil, 0o644); err != nil {
					t.Fatal(err)
				}
			},
			dst: func(t *testing.T, dst string) { stateFile(t, dst) }},
		{name: "a file where a directory goes", wantErr: "exists",
			src: func(t *testing.T, src string) {
				if err := os.Mkdir(filepath.Join(src, "d"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			dst: func(t *testing.T, dst string) { stateFile(t, filepath.Join(dst, "d")) }},
		{name: "a file where a symlink goes", wantErr: "exists",
			src: func(t *testing.T, src string) {
				if err := os.Symlink("x", filepath.Join(src, "l")); err != nil {
					t.Fatal(err)
				}
			},
			dst: func(t *testing.T, dst string) { stateFile(t, filepath.Join(dst, "l")) }},
		{name: "a file where a file goes", wantErr: "exists",
			src: func(t *testing.T, src string) {
				if err := os.WriteFile(filepath.Join(src, "f"), nil, 0o644); err != nil {
					t.Fatal(err)
				}
			},
			dst: func(t *testing.T, dst string) { stateFile(t, filepath.Join(dst, "f")) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := filepath.Join(t.TempDir(), "src")
			if err := os.Mkdir(src, 0o755); err != nil {
				t.Fatal(err)
			}
			tc.src(t, src)
			dst := filepath.Join(t.TempDir(), "dst")
			// A read-only directory is writable again for the temp
			// directories' cleanup, which runs after this.
			t.Cleanup(func() {
				_ = os.Chmod(filepath.Join(src, "ro"), 0o755)
				_ = os.Chmod(filepath.Join(dst, "ro"), 0o755)
			})
			if tc.dst != nil {
				tc.dst(t, dst)
			}
			err := copyTree(src, dst, rng)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("copyTree = %v, want an error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("copyTree: %v", err)
			}
			tc.check(t, dst)
		})
	}
}

// TestRestoreExtraRefusals checks that a restore refused before it
// prepares anything gives the fiber's hold back and leaves no copy. What
// a restore prepares is tests/integration/runc TestReleaseKeepsRestoredCopy.
func TestRestoreExtraRefusals(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T, l *launcher, spec *backend.WarmSpec)
		wantErr string
		wantIs  error
	}{
		{name: "another grant holds the slot", wantIs: ErrRangeCollision,
			setup: func(t *testing.T, l *launcher, spec *backend.WarmSpec) {
				if err := l.claims.acquire(colliding(identityPool, spec.GrantUID), true); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "the run directory cannot be made", wantErr: "not a directory",
			setup: func(t *testing.T, _ *launcher, spec *backend.WarmSpec) {
				stateFile(t, filepath.Dir(spec.WorkDir))
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := identityLauncher(t)
			spec := warmSpec(t, "g1")
			tc.setup(t, l, &spec)
			_, held, err := l.RestoreExtra(spec, t.TempDir())
			if held != nil {
				t.Fatalf("the failed RestoreExtra handed out %v", held)
			}
			if err == nil || (tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr)) || (tc.wantIs != nil && !errors.Is(err, tc.wantIs)) {
				t.Fatalf("RestoreExtra = %v, want %q %v", err, tc.wantErr, tc.wantIs)
			}
			if l.claims.release(spec.GrantUID, false) {
				t.Fatal("the failed RestoreExtra kept the fiber's hold")
			}
			if exists(l.rootfs(spec)) {
				t.Fatal("the failed RestoreExtra left the rootfs copy")
			}
		})
	}
}

// TestSysMountPoint checks that the /sys bind's mount point is made, or
// why it cannot be.
func TestSysMountPoint(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T, l *launcher)
		wantErr string
	}{
		{name: "made under the state directory"},
		{name: "a file in the way", wantErr: "/sys bind", setup: func(t *testing.T, l *launcher) { stateFile(t, l.sysDir()) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, _ := newLauncher(t, nil)
			if tc.setup != nil {
				tc.setup(t, l)
			}
			err := l.sysMountPoint()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("sysMountPoint = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if st, serr := os.Stat(l.sysDir()); err != nil || serr != nil || !st.IsDir() {
				t.Fatalf("sysMountPoint = %v, %s = %v %v, want a directory", err, l.sysDir(), st, serr)
			}
		})
	}
}

// TestPrepareWorkDir checks what stops the run directory from being
// prepared for the mapped root. What it is prepared as is tests/integration/runc
// TestWarmOwnership.
func TestPrepareWorkDir(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T, dir string)
		wantErr string
	}{
		{name: "a parent that is a file", wantErr: "not a directory", setup: func(t *testing.T, dir string) {
			stateFile(t, filepath.Dir(dir))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "run", "g1")
			tc.setup(t, dir)
			err := prepareWorkDir(dir, testPool.Range("g1"))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("prepareWorkDir = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestShareImages checks what stops the images from being shared with the
// restored tree. A directory nobody may chown and a file where the
// directory should be each fail, whoever runs the test. What sharing does
// is tests/integration/runc TestReleaseKeepsRestoredCopy, whose restored tree reads
// its images as the mapped root.
func TestShareImages(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T, dir string)
		wantErr string // "" for any error
	}{
		{name: "no images directory", wantErr: "share images ", setup: func(*testing.T, string) {}},
		{name: "the images directory is a file", setup: func(t *testing.T, dir string) { stateFile(t, dir) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "images")
			tc.setup(t, dir)
			err := shareImages(dir, testPool.Range("g1"))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("shareImages = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestWorkspaceMountpoint checks that every root filesystem copy holds
// /workspace as fiberd's own directory with mode 0, so a fiber without a
// workspace can neither write in it nor change its mode, that one the
// rootfs already had is taken over, and that a link or a file at the
// name is refused without touching what a link points at.
func TestWorkspaceMountpoint(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T, root, outside string)
		wantErr string
	}{
		{name: "made when absent", setup: func(*testing.T, string, string) {}},
		{name: "a directory the rootfs had is taken over", setup: func(t *testing.T, root, _ string) {
			if err := os.Mkdir(filepath.Join(root, "workspace"), 0o777); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a link is refused, never followed", wantErr: "not a directory", setup: func(t *testing.T, root, outside string) {
			if err := os.Symlink(outside, filepath.Join(root, "workspace")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a file is refused", wantErr: "not a directory", setup: func(t *testing.T, root, _ string) {
			if err := os.WriteFile(filepath.Join(root, "workspace"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, outside := t.TempDir(), t.TempDir()
			if err := os.Chmod(outside, 0o755); err != nil {
				t.Fatal(err)
			}
			tc.setup(t, root, outside)
			err := makeWorkspaceMountpoint(root)
			if st, serr := os.Stat(outside); serr != nil || st.Mode().Perm() != 0o755 {
				t.Fatalf("what a link pointed at changed: %v %v", st, serr)
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("makeWorkspaceMountpoint = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("makeWorkspaceMountpoint: %v", err)
			}
			fi, err := os.Lstat(filepath.Join(root, "workspace"))
			if err != nil {
				t.Fatal(err)
			}
			st, _ := fi.Sys().(*syscall.Stat_t)
			if !fi.IsDir() || fi.Mode().Perm() != 0 || st == nil || int(st.Uid) != os.Geteuid() {
				t.Fatalf("/workspace = %v uid %v, want a mode 0 directory of uid %d", fi.Mode(), st, os.Geteuid())
			}
		})
	}
}
