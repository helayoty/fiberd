//go:build linux

package runc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
)

// testPool is a small pool whose host ids a test can chown to as root.
var testPool = IDPool{Start: 1 << 20, Slots: 4}

// fakeRunc writes a runc stand-in that appends every call to a log and
// runs body with the subcommand in $sub. Successful unless body exits.

// needRoot skips a test that needs root. The launcher chowns into mapped
// id ranges and enters namespaces, so these run in the dev container.
func needRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root (run it with hack/dev/run.sh)")
	}
}
func fakeRunc(t *testing.T, body string) (bin, logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "calls.log")
	script := "#!/bin/sh\necho \"$@\" >> " + logPath + "\nsub=$3\n" + body + "\nexit 0\n"
	bin = filepath.Join(dir, "runc")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, logPath
}

// runcCalls are the launcher's fake runc invocations.
func runcCalls(t *testing.T, l *launcher) []string {
	t.Helper()
	return calls(t, filepath.Join(filepath.Dir(l.opt.Runc), "calls.log"))
}

// calls are the fake's logged invocations, without the --root prefix.
func calls(t *testing.T, logPath string) []string {
	t.Helper()
	b, err := os.ReadFile(logPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "--root" {
			f = f[2:]
		}
		out = append(out, strings.Join(f, " "))
	}
	return out
}

// templateRootfs makes a small root filesystem. It holds a directory with
// a file, a file owned by a low uid the copy shifts into the grant's
// range, a symlink, and a fifo the copy skips.
func templateRootfs(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "rootfs")
	for _, step := range []func() error{
		func() error { return os.MkdirAll(filepath.Join(dir, "bin"), 0o755) },
		func() error { return os.WriteFile(filepath.Join(dir, "bin", "zygote"), []byte("#!/bin/sh\n"), 0o755) },
		func() error { return os.WriteFile(filepath.Join(dir, "passwd"), []byte("root"), 0o600) },
		func() error { return os.Lchown(filepath.Join(dir, "passwd"), 5, 7) },
		func() error { return os.Symlink("bin/zygote", filepath.Join(dir, "z")) },
		func() error { return syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o600) },
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// newLauncher is a launcher over the fake runc and a template rootfs.
func newLauncher(t *testing.T, runcBody string) (*launcher, string) {
	t.Helper()
	bin, logPath := fakeRunc(t, runcBody)
	l := &launcher{opt: Options{Runc: bin, Rootfs: templateRootfs(t), StateDir: filepath.Join(t.TempDir(), "state"), Pool: testPool}, claims: newClaims(testPool)}
	if err := os.MkdirAll(l.opt.StateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return l, logPath
}

// warmSpec is a grant's spec with its run directory under a temp dir.
func warmSpec(t *testing.T, grant string) backend.WarmSpec {
	t.Helper()
	return backend.WarmSpec{GrantUID: grant, WorkDir: filepath.Join(t.TempDir(), "run", grant), CgroupFD: -1, ProbeCgroupFD: -1}
}

// registryTemplate writes a pulled template cache entry as the host
// leaves it (the executable, its config, digest and images) and returns
// the template the host hands Warm for it. Only the executable may ever
// reach a container.
func registryTemplate(t *testing.T, executable []byte) backend.Template {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "cache", strings.Repeat("ab", 32))
	if err := os.MkdirAll(filepath.Join(dir, "images"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"config.json": `{"args":[]}`, "DIGEST": "sha256:abab\n", "images/pages-1.img": "pages"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "zygote"), executable, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(executable)
	return backend.Template{Digest: "sha256:" + strings.Repeat("ab", 32), Argv: []string{filepath.Join(dir, "zygote"), "--heap-mb", "8"},
		Dir: dir, ZygoteSHA256: hex.EncodeToString(sum[:])}
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

// owner is the uid and gid of path.
func owner(t *testing.T, path string) (uid, gid uint32) {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	return st.Uid, st.Gid
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	return fi.Mode().Perm()
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

// cgroupDir makes a cgroup under the v2 root for the test and opens it.
func cgroupDir(t *testing.T, name string) *os.File {
	t.Helper()
	p := filepath.Join("/sys/fs/cgroup", name)
	if err := os.Mkdir(p, 0o755); err != nil {
		t.Skipf("cannot make a cgroup: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(p) })
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
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
		Readonly    []string            `json:"readonlyPaths"`
		Masked      []string            `json:"maskedPaths"`
	} `json:"linux"`
}

func readConfig(t *testing.T, bundle string) ociConfig {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(bundle, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg ociConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// TestCommand checks the bundle runc runs the zygote from, and what Command
// prepares around it. Every failure gives the grant's hold back.
func TestCommand(t *testing.T) {
	needRoot(t)
	cases := []struct {
		name    string
		grant   string
		setup   func(t *testing.T, l *launcher, spec *backend.WarmSpec, logf *os.File)
		wantErr string
		wantIs  error
		check   func(t *testing.T, l *launcher, spec backend.WarmSpec, cfg ociConfig, cmd *exec.Cmd)
	}{
		{name: "the spec: namespaces, mappings, mounts, read-only and masked paths", grant: "g1",
			check: func(t *testing.T, l *launcher, spec backend.WarmSpec, cfg ociConfig, _ *exec.Cmd) {
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
				if want := []string{"/proc=proc", "/dev=tmpfs", "/sys=sysfs", "/host=bind"}; !reflect.DeepEqual(dests, want) {
					t.Errorf("mounts = %v, want %v", dests, want)
				}
				if m := cfg.Mounts[3]; m.Source != spec.WorkDir || !reflect.DeepEqual(m.Options, []string{"rbind", "rw"}) {
					t.Errorf("/host mount = %+v, want a rw rbind of %s", m, spec.WorkDir)
				}
				if m := cfg.Mounts[2]; !reflect.DeepEqual(m.Options, []string{"nosuid", "noexec", "nodev", "ro"}) {
					t.Errorf("/sys options = %v, want read-only", m.Options)
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
				if cfg.Root.Path != l.rootfs(spec) || cfg.Root.Readonly {
					t.Errorf("root = %+v, want the writable copy at %s", cfg.Root, l.rootfs(spec))
				}
				if cfg.Hostname != "fiber" || cfg.OCIVersion != "1.0.2" {
					t.Errorf("hostname %q version %q", cfg.Hostname, cfg.OCIVersion)
				}
			}},
		{name: "the process: the zygote as root in its namespace, logging under /host", grant: "g1",
			check: func(t *testing.T, _ *launcher, _ backend.WarmSpec, cfg ociConfig, _ *exec.Cmd) {
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
		{name: "the command: runc run with the control socket as fd 3, in a session of its own", grant: "team/a:1",
			check: func(t *testing.T, l *launcher, spec backend.WarmSpec, _ ociConfig, cmd *exec.Cmd) {
				want := []string{l.opt.Runc, "--root", l.root(), "--log", l.runcLog(spec), "--debug",
					"run", "--preserve-fds", "1", "--bundle", l.bundle(spec), "w-team-a-1"}
				if !reflect.DeepEqual(cmd.Args, want) {
					t.Errorf("args = %v, want %v", cmd.Args, want)
				}
				if dir := filepath.Dir(l.runcLog(spec)); dir != filepath.Dir(l.bundle(spec)) || strings.HasPrefix(l.runcLog(spec), l.bundle(spec)+"/") {
					t.Errorf("runc log %s is not beside the bundle %s", l.runcLog(spec), l.bundle(spec))
				}
				if len(cmd.ExtraFiles) != 1 || cmd.ExtraFiles[0].Name() != "ctl" {
					t.Errorf("extra files = %v, want the control socket alone", cmd.ExtraFiles)
				}
				if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setsid {
					t.Error("runc is not started in its own session")
				}
				if cmd.Stdout != cmd.Stderr || filepath.Base(cmd.Stdout.(*os.File).Name()) != "zygote.log" {
					t.Error("runc's stdio does not go to the zygote log")
				}
				if _, ok := cmd.Stdin.(*os.File); !ok {
					t.Error("runc's stdin is not a file")
				}
				if st, err := os.Stat(l.root()); err != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
					t.Errorf("state root %s: %v %v", l.root(), st, err)
				}
			}},
		{name: "what the mapped root may touch: the log, the run directory and its rootfs copy", grant: "g1",
			check: func(t *testing.T, l *launcher, spec backend.WarmSpec, _ ociConfig, cmd *exec.Cmd) {
				rng := testPool.Range("g1")
				logPath := cmd.Stdout.(*os.File).Name()
				if _, gid := owner(t, logPath); gid != rng.Start || mode(t, logPath) != 0o664 {
					t.Errorf("zygote log: gid %d mode %o, want gid %d mode 664", gid, mode(t, logPath), rng.Start)
				}
				if uid, gid := owner(t, spec.WorkDir); uid != 0 || gid != rng.Start || mode(t, spec.WorkDir) != 0o775 {
					t.Errorf("run directory: %d:%d mode %o, want 0:%d mode 775", uid, gid, mode(t, spec.WorkDir), rng.Start)
				}
				copyDir := l.rootfs(spec)
				if uid, gid := owner(t, filepath.Join(copyDir, "passwd")); uid != rng.Start+5 || gid != rng.Start+7 {
					t.Errorf("passwd owner = %d:%d, want shifted 5:7", uid, gid)
				}
				if uid, _ := owner(t, filepath.Join(copyDir, "bin", "zygote")); uid != rng.Start {
					t.Errorf("zygote owner = %d, want the mapped root %d", uid, rng.Start)
				}
				if link, err := os.Readlink(filepath.Join(copyDir, "z")); err != nil || link != "bin/zygote" {
					t.Errorf("symlink z = %q, %v", link, err)
				}
				if exists(filepath.Join(copyDir, "fifo")) {
					t.Error("the fifo was copied")
				}
				for _, d := range mountpoints {
					if uid, _ := owner(t, filepath.Join(copyDir, d)); uid != rng.Start {
						t.Errorf("mountpoint %s owner = %d, want %d", d, uid, rng.Start)
					}
				}
				if have, err := readRootfsMarker(copyDir); err != nil || have != (rootfsRecord{Source: l.opt.Rootfs, Start: rng.Start, Count: rng.Count}) {
					t.Errorf("marker = %+v, %v", have, err)
				}
				if err := l.claims.check(colliding(testPool, "g1")); !errors.Is(err, ErrRangeCollision) {
					t.Errorf("the zygote does not hold the slot: %v", err)
				}
			}},
		{name: "a stale container of the grant is deleted first", grant: "g1",
			check: func(t *testing.T, l *launcher, _ backend.WarmSpec, _ ociConfig, _ *exec.Cmd) {
				if got := runcCalls(t, l); !reflect.DeepEqual(got, []string{"delete -f w-g1"}) {
					t.Errorf("runc calls = %v, want the stale delete alone", got)
				}
			}},
		{name: "runc's log from the last run is gone, so this run's is read alone", grant: "g1",
			setup: func(t *testing.T, l *launcher, spec *backend.WarmSpec, _ *os.File) {
				if err := os.MkdirAll(filepath.Dir(l.runcLog(*spec)), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(l.runcLog(*spec), []byte("from the last life\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			check: func(t *testing.T, l *launcher, spec backend.WarmSpec, _ ociConfig, _ *exec.Cmd) {
				if exists(l.runcLog(spec)) {
					t.Errorf("%s is still there", l.runcLog(spec))
				}
			}},
		{name: "the cgroup root maps to /", grant: "g1",
			setup: func(t *testing.T, _ *launcher, spec *backend.WarmSpec, _ *os.File) {
				f, err := os.Open("/sys/fs/cgroup")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = f.Close() })
				spec.CgroupFD = int(f.Fd())
			},
			check: func(t *testing.T, _ *launcher, _ backend.WarmSpec, cfg ociConfig, _ *exec.Cmd) {
				if cfg.Linux.CgroupsPath != "/" {
					t.Errorf("cgroupsPath = %q, want /", cfg.Linux.CgroupsPath)
				}
			}},
		{name: "a cgroup leaf maps to its path under the root", grant: "g1",
			setup: func(t *testing.T, _ *launcher, spec *backend.WarmSpec, _ *os.File) {
				spec.CgroupFD = int(cgroupDir(t, fmt.Sprintf("fiberd-unit-%d", os.Getpid())).Fd())
			},
			check: func(t *testing.T, _ *launcher, _ backend.WarmSpec, cfg ociConfig, _ *exec.Cmd) {
				if want := fmt.Sprintf("/fiberd-unit-%d", os.Getpid()); cfg.Linux.CgroupsPath != want {
					t.Errorf("cgroupsPath = %q, want %s", cfg.Linux.CgroupsPath, want)
				}
			}},
		{name: "a template from the rootfs gets no template mount and no staged copy", grant: "g1",
			check: func(t *testing.T, l *launcher, spec backend.WarmSpec, cfg ociConfig, _ *exec.Cmd) {
				if src := templateMountOf(t, cfg); src != "" || len(cfg.Mounts) != 4 {
					t.Errorf("mounts = %v, want the four without a template", cfg.Mounts)
				}
				if exists(l.templateDir(spec)) || l.stagedFor(spec) != "" {
					t.Error("a rootfs template left a staged directory")
				}
				// The mount point is in every copy, so a restore on a home
				// that never warmed the grant finds it.
				if uid, _ := owner(t, filepath.Join(l.rootfs(spec), "fiberd", "template")); uid != testPool.Range("g1").Start {
					t.Errorf("template mount point owner = %d, want the mapped root", uid)
				}
			}},
		{name: "a registry template: the verified copy alone, bound read-only, the command inside the mount", grant: "g1",
			setup: func(t *testing.T, _ *launcher, spec *backend.WarmSpec, _ *os.File) {
				spec.Template = registryTemplate(t, []byte("#!/bin/sh\nexit 0\n"))
			},
			check: func(t *testing.T, l *launcher, spec backend.WarmSpec, cfg ociConfig, _ *exec.Cmd) {
				staged := filepath.Join(l.templateDir(spec), "template")
				if src := templateMountOf(t, cfg); src != staged {
					t.Errorf("template mount source = %q, want the staged copy %q", src, staged)
				}
				if want := []string{"/fiberd/template/zygote", "--heap-mb", "8", "--log", "/host/zygote.log"}; !reflect.DeepEqual(cfg.Process.Args, want) {
					t.Errorf("args = %v, want %v", cfg.Process.Args, want)
				}
				if l.stagedFor(spec) != staged {
					t.Errorf("stagedFor = %q, want %q", l.stagedFor(spec), staged)
				}
				entries, err := os.ReadDir(staged)
				if err != nil || len(entries) != 1 || entries[0].Name() != "zygote" {
					t.Fatalf("staged directory holds %v (%v), want zygote alone", entries, err)
				}
				// The mapped root is an id outside the copy's owner, so the
				// other bits are what it gets: read and exec, no write.
				if uid, _ := owner(t, filepath.Join(staged, "zygote")); uid != 0 || mode(t, filepath.Join(staged, "zygote")) != 0o555 {
					t.Errorf("staged copy = uid %d mode %o, want root's 0555", uid, mode(t, filepath.Join(staged, "zygote")))
				}
				if mode(t, staged) != 0o755 {
					t.Errorf("staged directory mode %o, want 0755", mode(t, staged))
				}
				// The cache is not what is bound: a rewrite after the warm
				// changes nothing the container sees.
				if err := os.WriteFile(spec.Template.Argv[0], []byte("#!/bin/sh\nrm -rf /\n"), 0o755); err != nil {
					t.Fatal(err)
				}
				data, _ := os.ReadFile(filepath.Join(staged, "zygote"))
				if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != spec.Template.ZygoteSHA256 {
					t.Error("a cache rewrite reached the staged copy")
				}
			}},
		{name: "a registry template whose cache entry changed is refused before anything runs", grant: "g1", wantErr: "staged executable hashes to",
			setup: func(t *testing.T, _ *launcher, spec *backend.WarmSpec, _ *os.File) {
				spec.Template = registryTemplate(t, []byte("#!/bin/sh\nexit 0\n"))
				spec.Template.ZygoteSHA256 = strings.Repeat("0", 64)
			}},
		{name: "a registry template without a verified hash is refused", grant: "g1", wantErr: "without a verified executable hash",
			setup: func(t *testing.T, _ *launcher, spec *backend.WarmSpec, _ *os.File) {
				spec.Template = registryTemplate(t, []byte("#!/bin/sh\nexit 0\n"))
				spec.Template.ZygoteSHA256 = ""
			}},
		{name: "a missing rootfs", grant: "g1", wantErr: "unusable",
			setup: func(_ *testing.T, l *launcher, _ *backend.WarmSpec, _ *os.File) { l.opt.Rootfs += "-missing" }},
		{name: "a rootfs that is a file", grant: "g1", wantErr: "unusable",
			setup: func(t *testing.T, l *launcher, _ *backend.WarmSpec, _ *os.File) {
				l.opt.Rootfs = filepath.Join(l.opt.Rootfs, "passwd")
			}},
		{name: "another grant holds the slot", grant: "g1", wantIs: ErrRangeCollision,
			setup: func(t *testing.T, l *launcher, _ *backend.WarmSpec, _ *os.File) {
				if err := l.claims.acquire(colliding(testPool, "g1"), false); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "the rootfs copies directory is a file", grant: "g1", wantErr: "not a directory",
			setup: func(t *testing.T, l *launcher, _ *backend.WarmSpec, _ *os.File) {
				stateFile(t, filepath.Join(l.opt.StateDir, "rootfs"))
			}},
		{name: "the run directory cannot be made", grant: "g1", wantErr: "not a directory",
			setup: func(t *testing.T, _ *launcher, spec *backend.WarmSpec, _ *os.File) {
				stateFile(t, filepath.Dir(spec.WorkDir))
			}},
		{name: "the zygote log is closed", grant: "g1", wantErr: "chmod zygote log",
			setup: func(_ *testing.T, _ *launcher, _ *backend.WarmSpec, logf *os.File) { _ = logf.Close() }},
		{name: "a cgroup fd outside the cgroup mount", grant: "g1", wantErr: "is not under /sys/fs/cgroup",
			setup: func(t *testing.T, _ *launcher, spec *backend.WarmSpec, _ *os.File) {
				f, err := os.Open(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = f.Close() })
				spec.CgroupFD = int(f.Fd())
			}},
		{name: "a cgroup fd that is not open", grant: "g1", wantErr: "no such file",
			setup: func(_ *testing.T, _ *launcher, spec *backend.WarmSpec, _ *os.File) { spec.CgroupFD = 1 << 20 }},
		{name: "the bundles directory is a file", grant: "g1", wantErr: "not a directory",
			setup: func(t *testing.T, l *launcher, _ *backend.WarmSpec, _ *os.File) {
				stateFile(t, filepath.Join(l.opt.StateDir, "bundles"))
			}},
		{name: "the config cannot be written", grant: "g1", wantErr: "is a directory",
			setup: func(t *testing.T, l *launcher, spec *backend.WarmSpec, _ *os.File) {
				if err := os.MkdirAll(filepath.Join(l.bundle(*spec), "config.json"), 0o755); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "the state root is a file", grant: "g1", wantErr: "not a directory",
			setup: func(t *testing.T, l *launcher, _ *backend.WarmSpec, _ *os.File) { stateFile(t, l.root()) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, _ := newLauncher(t, "")
			spec := warmSpec(t, tc.grant)
			logf, err := os.Create(filepath.Join(t.TempDir(), "zygote.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = logf.Close() }()
			ctlFD, err := syscall.Open(os.DevNull, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			ctl := os.NewFile(uintptr(ctlFD), "ctl")
			defer func() { _ = ctl.Close() }()
			if tc.setup != nil {
				tc.setup(t, l, &spec, logf)
			}
			cmd, err := l.Command(spec, []string{"/bin/zygote", "-x"}, ctl, logf)
			if tc.wantErr != "" || tc.wantIs != nil {
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
				return
			}
			if err != nil {
				t.Fatalf("Command: %v", err)
			}
			if cmd.Stdin != nil {
				defer func() { _ = cmd.Stdin.(*os.File).Close() }()
			}
			tc.check(t, l, spec, readConfig(t, l.bundle(spec)), cmd)
		})
	}
}

// TestSweep checks that a new backend ends the containers a previous life
// left in runc's state and removes every bundle and rootfs copy.
func TestSweep(t *testing.T) {
	needRoot(t)
	cases := []struct {
		name      string
		runcBody  string
		stateRoot bool // runc's state root exists from before
		busy      bool // a leftover that cannot be removed
		wantCalls []string
	}{
		{name: "no state root: runc is not asked, leftovers go"},
		{name: "every container listed is killed and deleted", stateRoot: true,
			runcBody:  `[ "$sub" = list ] && printf 'c1\nc2\n'`,
			wantCalls: []string{"list -q", "kill c1 KILL", "delete -f c1", "kill c2 KILL", "delete -f c2"}},
		{name: "runc cannot list: nothing is killed", stateRoot: true,
			runcBody:  `[ "$sub" = list ] && exit 1`,
			wantCalls: []string{"list -q"}},
		{name: "a leftover that will not go is reported and kept", busy: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, logPath := newLauncher(t, tc.runcBody)
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
				if err := os.Mkdir(busy, 0o755); err != nil {
					t.Fatal(err)
				}
				// A mount point cannot be removed, however root one is.
				if err := syscall.Mount("tmpfs", busy, "tmpfs", 0, ""); err != nil {
					t.Skipf("cannot mount a tmpfs: %v", err)
				}
				t.Cleanup(func() { _ = syscall.Unmount(busy, 0) })
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
			if got := calls(t, logPath); !reflect.DeepEqual(got, tc.wantCalls) {
				t.Errorf("runc calls = %v, want %v", got, tc.wantCalls)
			}
		})
	}
}

// TestHoldDrop checks that the rootfs copy lives exactly as long as some user
// of the grant holds its range, and is remade when it is not the copy the
// grant needs.
func TestHoldDrop(t *testing.T) {
	needRoot(t)
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
			l.drop(spec, fiber)
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
			if have, err := readRootfsMarker(dir); err != nil || have.Start != testPool.Range(spec.GrantUID).Start {
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
			if err := l.claims.acquire(colliding(testPool, spec.GrantUID), warm); err != nil {
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
			other := warmSpec(t, colliding(testPool, spec.GrantUID))
			l.drop(other, warm)
			l.drop(spec, fiber)
			if !exists(dir) {
				t.Fatal("a stranger's drop removed the copy")
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, _ := newLauncher(t, "")
			tc.run(t, l, warmSpec(t, "g1"))
		})
	}
}

// TestCopyTree checks what the copy keeps, skips and shifts, and what it
// refuses.
func TestCopyTree(t *testing.T) {
	needRoot(t)
	rng := testPool.Range("g1")
	cases := []struct {
		name    string
		src     func(t *testing.T, src string)
		dst     func(t *testing.T, dst string) // what is at dst before
		wantErr string
		check   func(t *testing.T, dst string)
	}{
		{name: "files, modes, symlinks and shifted owners",
			src: func(t *testing.T, src string) {
				if err := os.MkdirAll(filepath.Join(src, "ro", "deep"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(src, "ro", "deep", "f"), []byte("data"), 0o640); err != nil {
					t.Fatal(err)
				}
				if err := os.Lchown(filepath.Join(src, "ro", "deep", "f"), 10, 20); err != nil {
					t.Fatal(err)
				}
				if err := os.Lchown(filepath.Join(src, "ro"), 70000, 70000); err != nil {
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
				if uid, gid := owner(t, f); uid != rng.Start+10 || gid != rng.Start+20 || mode(t, f) != 0o640 {
					t.Errorf("f = %d:%d %o, want shifted 10:20 mode 640", uid, gid, mode(t, f))
				}
				ro := filepath.Join(dst, "ro")
				if uid, gid := owner(t, ro); uid != 70000 || gid != 70000 || mode(t, ro) != 0o555 {
					t.Errorf("ro = %d:%d %o, want an id past the range kept and mode 555", uid, gid, mode(t, ro))
				}
				if link, err := os.Readlink(filepath.Join(ro, "link")); err != nil || link != "deep/f" {
					t.Errorf("link = %q, %v", link, err)
				}
				if uid, _ := owner(t, filepath.Join(ro, "link")); uid != rng.Start {
					t.Errorf("link owner = %d, want %d", uid, rng.Start)
				}
				if exists(filepath.Join(dst, "fifo")) {
					t.Error("the fifo was copied")
				}
				if uid, _ := owner(t, dst); uid != rng.Start {
					t.Errorf("root owner = %d, want %d", uid, rng.Start)
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
// runc wants.
func TestCgroupPath(t *testing.T) {
	cases := []struct {
		name    string
		open    func(t *testing.T) int
		want    string
		wantErr string
	}{
		{name: "the cgroup root", want: "/", open: func(t *testing.T) int {
			f, err := os.Open("/sys/fs/cgroup")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = f.Close() })
			return int(f.Fd())
		}},
		{name: "a leaf", want: fmt.Sprintf("/fiberd-unit-path-%d", os.Getpid()), open: func(t *testing.T) int {
			return int(cgroupDir(t, fmt.Sprintf("fiberd-unit-path-%d", os.Getpid())).Fd())
		}},
		{name: "a directory elsewhere", wantErr: "is not under /sys/fs/cgroup", open: func(t *testing.T) int {
			f, err := os.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = f.Close() })
			return int(f.Fd())
		}},
		{name: "a descriptor that is not open", wantErr: "no such file", open: func(*testing.T) int { return 1 << 20 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cgroupPath(tc.open(t))
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

// stateBody is a fake runc that reports pid as the container's init.
func stateBody(pid int) string {
	return fmt.Sprintf(`[ "$sub" = state ] && printf '{"pid": %d}'`, pid)
}

// startSleep is a stand-in for a `runc run` that stays up.
func startSleep(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return cmd
}

// TestChannel checks that the control conversation moves onto a pair made in
// the container's network namespace, sent to the zygote as REBIND.
func TestChannel(t *testing.T) {
	needRoot(t)
	cases := []struct {
		name      string
		runcBody  string
		run       func(t *testing.T) *exec.Cmd
		closeBoot bool
		wantErr   string
	}{
		{name: "REBIND carries the zygote's end and ours is returned", runcBody: stateBody(os.Getpid()), run: startSleep},
		{name: "runc run exited before the container was up", runcBody: "", wantErr: "exited before the container was up",
			run: func(t *testing.T) *exec.Cmd {
				cmd := exec.Command("true")
				if err := cmd.Run(); err != nil {
					t.Fatal(err)
				}
				return cmd
			}},
		{name: "the container's init is gone", runcBody: stateBody(1<<31 - 1), run: startSleep, wantErr: "no such file"},
		{name: "the bootstrap socket is closed", runcBody: stateBody(os.Getpid()), run: startSleep, closeBoot: true, wantErr: "send REBIND"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, _ := newLauncher(t, tc.runcBody)
			spec := warmSpec(t, "g1")
			fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			boot, zc := fileConn(t, fds[0], "boot"), fileConn(t, fds[1], "zygote")
			defer func() { _ = zc.Close() }()
			if tc.closeBoot {
				_ = boot.Close()
			} else {
				defer func() { _ = boot.Close() }()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := l.Channel(ctx, spec, tc.run(t), boot)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Channel = %v, want an error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Channel: %v", err)
			}
			defer func() { _ = conn.Close() }()
			// The zygote reads REBIND and the descriptor from its bootstrap end.
			buf, oob := make([]byte, 64), make([]byte, 64)
			_ = zc.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, oobn, _, _, err := zc.ReadMsgUnix(buf, oob)
			if err != nil {
				t.Fatal(err)
			}
			if string(buf[:n]) != "REBIND\n" {
				t.Fatalf("bootstrap message = %q, want REBIND", buf[:n])
			}
			msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
			if err != nil || len(msgs) != 1 {
				t.Fatalf("control messages = %v, %v, want one", msgs, err)
			}
			rights, err := syscall.ParseUnixRights(&msgs[0])
			if err != nil || len(rights) != 1 {
				t.Fatalf("rights = %v, %v, want one descriptor", rights, err)
			}
			theirs := os.NewFile(uintptr(rights[0]), "rebound")
			defer func() { _ = theirs.Close() }()
			// Both ends of the new pair talk to each other.
			if _, err := theirs.Write([]byte("READY\n")); err != nil {
				t.Fatal(err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err = conn.Read(buf)
			if err != nil || string(buf[:n]) != "READY\n" {
				t.Fatalf("read on the rebound channel = %q, %v", buf[:n], err)
			}
		})
	}
}

// fileConn wraps a unix socket descriptor as a UnixConn.
func fileConn(t *testing.T, fd int, name string) *net.UnixConn {
	t.Helper()
	f := os.NewFile(uintptr(fd), name)
	defer func() { _ = f.Close() }()
	c, err := net.FileConn(f)
	if err != nil {
		t.Fatal(err)
	}
	return c.(*net.UnixConn)
}

// TestPID checks that the container's init is read from `runc state`.
func TestPID(t *testing.T) {
	needRoot(t)
	cases := []struct {
		name     string
		runcBody string
		want     int
		wantErr  string
		wantExit bool // the error is runc's own failure
	}{
		{name: "the init pid", runcBody: stateBody(4242), want: 4242},
		{name: "runc fails", runcBody: `[ "$sub" = state ] && { echo "container does not exist" >&2; exit 1; }`, wantErr: "container does not exist", wantExit: true},
		{name: "no pid in the state", runcBody: `[ "$sub" = state ] && printf '{"status":"stopped"}'`, wantErr: "no init pid"},
		{name: "a state that is not json", runcBody: `[ "$sub" = state ] && echo nonsense`, wantErr: "no init pid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, _ := newLauncher(t, tc.runcBody)
			got, err := l.PID(context.Background(), warmSpec(t, "g1"), nil)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("PID = %d, %v, want an error containing %q", got, err, tc.wantErr)
				}
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) != tc.wantExit {
					t.Fatalf("PID = %v, want runc's exit error %v", err, tc.wantExit)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("PID = %d, %v, want %d", got, err, tc.want)
			}
		})
	}
}

// TestRelease checks that the container is ended, its bundle goes, and the
// zygote's hold is given back. The rootfs copy stays for a restored
// fiber that still runs in the range.
func TestRelease(t *testing.T) {
	needRoot(t)
	cases := []struct {
		name      string
		fiberLive bool
	}{
		{name: "the last user: the copy goes too"},
		{name: "a restored fiber still runs: the copy stays", fiberLive: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, logPath := newLauncher(t, "")
			spec := warmSpec(t, "g1")
			copyDir, err := l.hold(spec, true)
			if err != nil {
				t.Fatal(err)
			}
			if tc.fiberLive {
				if _, err := l.hold(spec, false); err != nil {
					t.Fatal(err)
				}
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
			if got, want := calls(t, logPath), []string{"kill w-g1 KILL", "delete -f w-g1"}; !reflect.DeepEqual(got, want) {
				t.Errorf("runc calls = %v, want %v", got, want)
			}
			if exists(l.bundle(spec)) {
				t.Error("the bundle survived Release")
			}
			if exists(l.templateDir(spec)) || l.stagedFor(spec) != "" {
				t.Error("the staged template survived Release")
			}
			if exists(copyDir) != tc.fiberLive {
				t.Errorf("rootfs copy exists = %v, want %v", exists(copyDir), tc.fiberLive)
			}
			if tc.fiberLive {
				l.RestoredGone(spec)
				if exists(copyDir) {
					t.Error("the copy survived the last fiber")
				}
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
	base := []string{"--external", "mnt[/host]:host", "--empty-ns", "net", "--network-lock", "skip"}
	for _, d := range []string{"null", "zero", "full", "random", "urandom", "tty"} {
		base = append(base, "--external", "mnt[/dev/"+d+"]:dev-"+d)
	}
	cases := []struct {
		name     string
		template backend.Template
		want     []string
		record   bool
	}{
		{name: "a template from the rootfs", want: base},
		{name: "a registry template names its bind", template: backend.Template{Dir: "/cache/x", Argv: []string{"/cache/x/zygote"}},
			want: append(append([]string{}, base...), "--external", "mnt["+backend.TemplateMount+"]:template"), record: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "images")
			got, err := (&launcher{}).DumpExtra(backend.WarmSpec{GrantUID: "g1", Template: tc.template}, dir)
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
		})
	}
}

// TestRestoreExtra checks that a restore takes a fiber's hold, prepares the run
// directory and the images for the mapped root, and names the copy and
// the external mounts. Every failure gives the hold back.
func TestRestoreExtra(t *testing.T) {
	needRoot(t)
	cases := []struct {
		name    string
		setup   func(t *testing.T, l *launcher, spec *backend.WarmSpec, images string)
		staged  string // this home's staged template copy, "" for none
		wantErr string
		wantIs  error
		// wantBind is what follows the device binds: the template bind
		// of this home's copy, or nothing.
		wantBind []string
	}{
		{name: "the restore arguments and what the mapped root may read"},
		{name: "another grant holds the slot", wantIs: ErrRangeCollision,
			setup: func(t *testing.T, l *launcher, spec *backend.WarmSpec, _ string) {
				if err := l.claims.acquire(colliding(testPool, spec.GrantUID), true); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "the run directory cannot be made", wantErr: "not a directory",
			setup: func(t *testing.T, _ *launcher, spec *backend.WarmSpec, _ string) {
				stateFile(t, filepath.Dir(spec.WorkDir))
			}},
		{name: "the images are gone", wantErr: "share images",
			setup: func(t *testing.T, _ *launcher, _ *backend.WarmSpec, images string) {
				if err := os.RemoveAll(images); err != nil {
					t.Fatal(err)
				}
			}},
		// A checkpoint taken with a template bind is restored with this
		// home's own verified copy, the one its warm instance staged.
		{name: "a checkpoint with a template bind, the grant warm here", staged: "/state/templates/w-g1/template",
			setup: func(t *testing.T, _ *launcher, _ *backend.WarmSpec, images string) {
				templateRecordIn(t, images, backend.TemplateMount)
			},
			wantBind: []string{"--external", "mnt[template]:/state/templates/w-g1/template"}},
		{name: "a checkpoint with a template bind, the grant not warm here", wantErr: "does not have here",
			setup: func(t *testing.T, _ *launcher, _ *backend.WarmSpec, images string) {
				templateRecordIn(t, images, backend.TemplateMount)
			}},
		{name: "a record naming another mount point is malformed", staged: "/state/templates/w-g1/template", wantErr: "malformed",
			setup: func(t *testing.T, _ *launcher, _ *backend.WarmSpec, images string) {
				templateRecordIn(t, images, "/elsewhere")
			}},
		{name: "a checkpoint without a template bind binds none, warm or not", staged: "/state/templates/w-g1/template"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, _ := newLauncher(t, "")
			spec := warmSpec(t, "g1")
			if tc.staged != "" {
				l.setStaged(spec, tc.staged)
			}
			rng := testPool.Range("g1")
			images := filepath.Join(t.TempDir(), "images")
			for _, p := range []string{"pages-1.img", "core-1.img"} {
				if err := os.MkdirAll(images, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(images, p), []byte("img"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Mkdir(filepath.Join(images, "sub"), 0o700); err != nil {
				t.Fatal(err)
			}
			if tc.setup != nil {
				tc.setup(t, l, &spec, images)
			}
			extra, err := l.RestoreExtra(spec, images)
			if tc.wantErr != "" || tc.wantIs != nil {
				if err == nil || (tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr)) || (tc.wantIs != nil && !errors.Is(err, tc.wantIs)) {
					t.Fatalf("RestoreExtra = %v, want %q %v", err, tc.wantErr, tc.wantIs)
				}
				if l.claims.release(spec.GrantUID, false) {
					t.Fatal("the failed RestoreExtra kept the fiber's hold")
				}
				if exists(l.rootfs(spec)) {
					t.Fatal("the failed RestoreExtra left the rootfs copy")
				}
				return
			}
			if err != nil {
				t.Fatalf("RestoreExtra: %v", err)
			}
			want := []string{"--root", l.rootfs(spec), "--external", "mnt[host]:" + spec.WorkDir, "--empty-ns", "net"}
			for _, d := range deviceBinds {
				want = append(want, "--external", "mnt[dev-"+d+"]:/dev/"+d)
			}
			want = append(want, tc.wantBind...)
			if !reflect.DeepEqual(extra, want) {
				t.Errorf("extra = %v, want %v", extra, want)
			}
			if _, gid := owner(t, images); gid != rng.Start || mode(t, images) != 0o750 {
				t.Errorf("images dir = gid %d mode %o, want gid %d mode 750", gid, mode(t, images), rng.Start)
			}
			for _, p := range []string{"pages-1.img", "core-1.img"} {
				if _, gid := owner(t, filepath.Join(images, p)); gid != rng.Start || mode(t, filepath.Join(images, p)) != 0o640 {
					t.Errorf("%s = gid %d mode %o, want gid %d mode 640", p, gid, mode(t, filepath.Join(images, p)), rng.Start)
				}
			}
			if _, gid := owner(t, filepath.Join(images, "sub")); gid != 0 || mode(t, filepath.Join(images, "sub")) != 0o700 {
				t.Error("a directory among the images was touched")
			}
			if uid, gid := owner(t, spec.WorkDir); uid != 0 || gid != rng.Start || mode(t, spec.WorkDir) != 0o775 {
				t.Errorf("run directory = %d:%d %o", uid, gid, mode(t, spec.WorkDir))
			}
			if err := l.claims.check(colliding(testPool, "g1")); !errors.Is(err, ErrRangeCollision) {
				t.Errorf("the restored fiber does not hold the slot: %v", err)
			}
			l.RestoredGone(spec)
			if exists(l.rootfs(spec)) {
				t.Error("the copy survived RestoredGone")
			}
		})
	}
}

// templateRecordIn writes the record a dump of a container with a
// template bind leaves beside its images.
func templateRecordIn(t *testing.T, images, mountpoint string) {
	t.Helper()
	b, err := json.Marshal(templateRecord{MountPoint: mountpoint})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(images, templateFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestSocketpair checks that a pair made in the instance's network
// namespace has both ends usable.
func TestSocketpair(t *testing.T) {
	needRoot(t)
	cases := []struct {
		name    string
		pid     int
		typ     int
		wantErr bool
	}{
		{name: "a stream pair", pid: os.Getpid(), typ: syscall.SOCK_STREAM},
		{name: "a seqpacket pair", pid: os.Getpid(), typ: syscall.SOCK_SEQPACKET},
		{name: "a process that does not exist", pid: 1<<31 - 1, typ: syscall.SOCK_STREAM, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fds, err := (&launcher{}).Socketpair(backend.WarmSpec{}, tc.pid, tc.typ)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Socketpair = %v, want an error", fds)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = syscall.Close(fds[0]); _ = syscall.Close(fds[1]) }()
			if _, err := syscall.Write(fds[0], []byte("x")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 1)
			if n, err := syscall.Read(fds[1], buf); err != nil || n != 1 || buf[0] != 'x' {
				t.Fatalf("read = %d %q %v", n, buf, err)
			}
		})
	}
}

// TestRestored checks that the loopback of a restored tree's fresh network
// namespace is brought up.
func TestRestored(t *testing.T) {
	needRoot(t)
	cases := []struct {
		name    string
		pid     func(t *testing.T) int
		wantErr bool
	}{
		{name: "a namespace with the loopback down", pid: func(t *testing.T) int {
			cmd := exec.Command("unshare", "-n", "sleep", "30")
			if err := cmd.Start(); err != nil {
				t.Skipf("unshare: %v", err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
			waitOwnNetns(t, cmd.Process.Pid)
			if loUp(t, cmd.Process.Pid) {
				t.Fatal("the loopback of a new namespace is up already")
			}
			return cmd.Process.Pid
		}},
		{name: "a process that does not exist", pid: func(*testing.T) int { return 1<<31 - 1 }, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pid := tc.pid(t)
			err := (&launcher{}).Restored(backend.WarmSpec{}, pid)
			if tc.wantErr {
				if err == nil {
					t.Fatal("Restored succeeded for a process that does not exist")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !loUp(t, pid) {
				t.Fatal("the loopback is still down after Restored")
			}
		})
	}
}

// waitOwnNetns waits until pid has left this test's network namespace.
func waitOwnNetns(t *testing.T, pid int) {
	t.Helper()
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if theirs, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid)); err == nil && theirs != self {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("process %d never entered a network namespace of its own", pid)
		}
	}
}

// loUp reads the loopback's flags inside pid's network namespace.
func loUp(t *testing.T, pid int) bool {
	t.Helper()
	out, err := exec.Command("nsenter", "-t", fmt.Sprint(pid), "-n", "ip", "-o", "link", "show", "lo").CombinedOutput()
	if err != nil {
		t.Fatalf("ip link in the namespace of %d: %v: %s", pid, err, out)
	}
	// "1: lo: <LOOPBACK,UP,LOWER_UP> mtu ..."
	lt, gt := strings.IndexByte(string(out), '<'), strings.IndexByte(string(out), '>')
	if lt < 0 || gt < lt {
		t.Fatalf("unexpected ip link output: %s", out)
	}
	for _, flag := range strings.Split(string(out[lt+1:gt]), ",") {
		if flag == "UP" {
			return true
		}
	}
	return false
}

// TestMappedRoot checks that the grant's mapped root is the start of its range,
// unless another grant holds the slot here.
func TestMappedRoot(t *testing.T) {
	needRoot(t)
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
			l, _ := newLauncher(t, "")
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

// mountReadOnly bind-mounts path over itself read-only, so a chown root
// could otherwise always do is refused.
func mountReadOnly(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mount(path, path, "", syscall.MS_BIND, ""); err != nil {
		t.Skipf("cannot bind mount: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Unmount(path, 0) })
	if err := syscall.Mount("", path, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY, ""); err != nil {
		t.Fatalf("remount read-only: %v", err)
	}
}

// TestPrepareWorkDir checks that the run directory is root's with the
// grant's mapped gid and group write, or the reason it cannot be.
func TestPrepareWorkDir(t *testing.T) {
	needRoot(t)
	rng := testPool.Range("g1")
	cases := []struct {
		name    string
		setup   func(t *testing.T, dir string)
		wantErr string
	}{
		{name: "a new directory"},
		{name: "a directory that exists with another mode", setup: func(t *testing.T, dir string) {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a parent that is a file", wantErr: "not a directory", setup: func(t *testing.T, dir string) {
			stateFile(t, filepath.Dir(dir))
		}},
		{name: "a read-only directory", wantErr: "chown run directory", setup: func(t *testing.T, dir string) {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			mountReadOnly(t, dir)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "run", "g1")
			if tc.setup != nil {
				tc.setup(t, dir)
			}
			err := prepareWorkDir(dir, rng)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("prepareWorkDir = %v, want an error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if uid, gid := owner(t, dir); uid != 0 || gid != rng.Start || mode(t, dir) != 0o775 {
				t.Fatalf("run directory = %d:%d %o, want 0:%d 775", uid, gid, mode(t, dir), rng.Start)
			}
		})
	}
}

// TestShareImages checks that the images the restored tree reads itself get the
// grant's mapped gid, and what stops that is reported.
func TestShareImages(t *testing.T) {
	needRoot(t)
	rng := testPool.Range("g1")
	cases := []struct {
		name    string
		setup   func(t *testing.T, dir string)
		wantErr string
	}{
		{name: "a file among the images is read-only", wantErr: "share image ", setup: func(t *testing.T, dir string) {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(dir, "pages-1.img")
			if err := os.WriteFile(p, []byte("img"), 0o600); err != nil {
				t.Fatal(err)
			}
			mountReadOnly(t, p)
		}},
		{name: "the images directory is a file", wantErr: "not a directory", setup: func(t *testing.T, dir string) {
			stateFile(t, dir)
		}},
		{name: "no images directory", wantErr: "share images ", setup: func(*testing.T, string) {}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "images")
			tc.setup(t, dir)
			err := shareImages(dir, rng)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("shareImages = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}
