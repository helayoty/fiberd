//go:build linux

// Package runc is the fork backend's zygote inside an OCI container. It
// is the proc backend with a launcher: `runc run` starts the zygote as
// the container's init with the control socket preserved as fd 3, the
// grant's run directory bind-mounted at /host and the zygote's cgroup as
// the container's. Everything else is the proc backend: fibers are
// forked by the zygote into their leaves (the container shares the
// host's cgroup namespace, so clone3 into a leaf works as it does for
// plain processes), checkpointed with criu from outside as trees living
// in the container's mount namespace (the root filesystem and /host are
// external mounts), and restored with the same root. Tier
// FIBER_CHECKPOINT, deltas over the zygote's self-checkpoint.
//
// What the container adds over proc is a root filesystem of its own and
// pid/mount/ipc/uts namespaces around the zygote and its fibers: the
// template ships as a rootfs, and a fiber cannot see the home.
package runc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/backend/proc"
)

// Options configure the runc backend.
type Options struct {
	// Runc names the runc binary (default "runc").
	Runc string
	// Rootfs is the directory every container uses as its root
	// filesystem; template commands are paths inside it. Required.
	Rootfs string
	// StateDir holds runc's container state and the bundles (default
	// /var/lib/fiberd/runc).
	StateDir string
	// CRIU names the criu binary (default "criu").
	CRIU string
}

// Backend is the proc backend with the runc launcher.
type Backend struct {
	*proc.Backend
	l *launcher
}

type launcher struct {
	opt Options
}

// New opens the backend. Without runc or the rootfs it opens as a
// backend that cannot warm anything.
func New(o Options) backend.Backend {
	if o.Runc == "" {
		o.Runc = "runc"
	}
	if o.StateDir == "" {
		o.StateDir = "/var/lib/fiberd/runc"
	}
	l := &launcher{opt: o}
	return &Backend{Backend: proc.NewBackend(proc.Options{CRIU: o.CRIU, Launcher: l}), l: l}
}

// Platform: the checkpoints depend on the host kernel like proc's, and
// on the rootfs the zygote was built against rather than the host libc.
func (b *Backend) Platform() artifact.Platform {
	return artifact.Platform{Libc: "rootfs-" + filepath.Base(b.l.opt.Rootfs)}
}

func (l *launcher) Name() string { return "runc" }

func (l *launcher) root() string { return filepath.Join(l.opt.StateDir, "root") }

func (l *launcher) cid(spec backend.WarmSpec) string {
	return "w-" + strings.NewReplacer("/", "-", ":", "-").Replace(spec.GrantUID)
}

func (l *launcher) bundle(spec backend.WarmSpec) string {
	return filepath.Join(l.opt.StateDir, "bundles", l.cid(spec))
}

func (l *launcher) runc(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, l.opt.Runc, append([]string{"--root", l.root()}, args...)...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("runc %s: %w: %s", args[0], err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// cgroupPath resolves an open cgroup directory fd to the path runc's
// cgroupsPath wants: relative to the cgroup v2 mount.
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

// Command writes the bundle and builds `runc run` with fd 3 preserved.
func (l *launcher) Command(spec backend.WarmSpec, argv []string, ctl, logf *os.File) (*exec.Cmd, error) {
	if st, err := os.Stat(l.opt.Rootfs); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("runc: rootfs %q unusable", l.opt.Rootfs)
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
	cfg := map[string]any{
		"ociVersion": "1.0.2",
		"process": map[string]any{
			"terminal": false,
			"user":     map[string]int{"uid": 0, "gid": 0},
			"cwd":      "/host", // criu's parasite scratch lands on the bind mount, not the rootfs
			"args":     append(append([]string{}, argv...), "--log", "/host/zygote.log"),
			"env":      []string{"PATH=/usr/bin:/bin"},
			"capabilities": map[string][]string{ // the zygote forks into cgroups and pid namespaces
				"bounding":    {"CAP_SYS_ADMIN", "CAP_KILL", "CAP_SETPCAP", "CAP_SETUID", "CAP_SETGID", "CAP_SYS_PTRACE", "CAP_DAC_OVERRIDE", "CAP_CHOWN", "CAP_FOWNER"},
				"effective":   {"CAP_SYS_ADMIN", "CAP_KILL", "CAP_SETPCAP", "CAP_SETUID", "CAP_SETGID", "CAP_SYS_PTRACE", "CAP_DAC_OVERRIDE", "CAP_CHOWN", "CAP_FOWNER"},
				"permitted":   {"CAP_SYS_ADMIN", "CAP_KILL", "CAP_SETPCAP", "CAP_SETUID", "CAP_SETGID", "CAP_SYS_PTRACE", "CAP_DAC_OVERRIDE", "CAP_CHOWN", "CAP_FOWNER"},
				"inheritable": {},
			},
			"noNewPrivileges": false,
		},
		"root":     map[string]any{"path": l.opt.Rootfs, "readonly": false},
		"hostname": "fiber",
		"mounts": []map[string]any{
			{"destination": "/proc", "type": "proc", "source": "proc"},
			{"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": []string{"nosuid", "strictatime", "mode=755", "size=65536k"}},
			{"destination": "/host", "type": "bind", "source": spec.WorkDir, "options": []string{"rbind", "rw"}},
		},
		"linux": map[string]any{
			// No cgroup namespace: the zygote's clone3 into a leaf needs
			// to see the host's hierarchy. No network namespace: fibers
			// serve unix sockets and there is nothing to checkpoint.
			"namespaces":  []map[string]string{{"type": "pid"}, {"type": "mount"}, {"type": "ipc"}, {"type": "uts"}},
			"cgroupsPath": cgPath,
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
	cmd := exec.Command(l.opt.Runc, "--root", l.root(), "run", "--preserve-fds", "1", "--bundle", b, l.cid(spec))
	cmd.ExtraFiles = []*os.File{ctl} // fd 3 in the container's init
	devnull, err := os.OpenFile(os.DevNull, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	// runc's own stdio; the zygote reopens its stdio inside (--log), so
	// no descriptor of a host file survives into the container.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd, nil
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

func (l *launcher) Release(spec backend.WarmSpec) {
	ctx := context.Background()
	_, _ = l.runc(ctx, "kill", l.cid(spec), "KILL")
	_, _ = l.runc(ctx, "delete", "-f", l.cid(spec))
	_ = os.RemoveAll(l.bundle(spec))
}

func (l *launcher) Endpoint(spec backend.WarmSpec, hostPath string) string {
	return "/host/" + strings.TrimPrefix(hostPath, spec.WorkDir+"/")
}

// DumpExtra: the run directory is a bind mount from outside the
// container's mount namespace.
func (l *launcher) DumpExtra(backend.WarmSpec) []string {
	return []string{"--external", "mnt[/host]:host"}
}

// RestoreExtra: the same root filesystem and run directory.
func (l *launcher) RestoreExtra(spec backend.WarmSpec) []string {
	return []string{"--root", l.opt.Rootfs, "--external", "mnt[host]:" + spec.WorkDir}
}

var (
	_ backend.Backend    = (*Backend)(nil)
	_ backend.Platformer = (*Backend)(nil)
	_ proc.Launcher      = (*launcher)(nil)
)
