package cgroup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Own is the cgroup this process runs in, under mount (normally
// /sys/fs/cgroup). In a private cgroup namespace that is the mount's root;
// in the host's (what a privileged Pod gets under containerd, or a Slurm
// job step under proctrack/cgroup) it is the path /proc/self/cgroup names.
// Returns the mount root when the named path does not exist under it.
func Own(mount string) Dir {
	pc, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return Root(mount)
	}
	return ownFrom(mount, string(pc))
}

// ownFrom is Own for a given /proc/self/cgroup text. A process found in
// the `fiberd` leaf Delegate made is a fiberd restarted in the same
// container or allocation. Its root is the leaf's parent, not the leaf,
// or every restart would nest one level deeper.
func ownFrom(mount, procCgroup string) Dir {
	scope := ScopeOf(procCgroup)
	if scope == "" {
		return Root(mount)
	}
	if filepath.Base(scope) == ownLeaf {
		scope = filepath.Dir(scope)
	}
	if scope == "/" || scope == "." {
		return Root(mount)
	}
	if st, err := os.Stat(filepath.Join(mount, scope)); err == nil && st.IsDir() {
		return Dir{Path: filepath.Join(mount, scope)}
	}
	return Root(mount)
}

const ownLeaf = "fiberd"

// ScopeOf reads the unified-hierarchy path out of /proc/self/cgroup
// ("0::/kubelet.slice/.../cri-containerd-<id>.scope"). "" for the root (a
// private namespace) or when there is no v2 line.
func ScopeOf(procCgroup string) string {
	for _, line := range strings.Split(procCgroup, "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			rest = strings.TrimSpace(rest)
			if rest == "/" {
				return ""
			}
			return rest
		}
	}
	return ""
}

// Delegate prepares root, the cgroup fiberd was started in, for the
// runtime to carve grants under. It needs controllers in
// cgroup.subtree_control, and a cgroup with processes may not enable any
// (the no-internal-process rule), so every process there first moves into
// a `fiberd` leaf. The memory limit whatever started fiberd put on root
// (a kubelet, Slurm's task/cgroup) stays the ceiling on everything below.
// Returns the `grants` subtree the runtime owns. Idempotent: an already
// delegated root is left alone. Controllers the root cannot offer (a
// Slurm step gets cpuset, cpu and memory, no pids) are skipped; memory
// is required. The root is live, so a process can enter it after the
// move and the kernel then refuses the controller. Delegate moves the
// newcomers and tries again a few times before it gives up.
func Delegate(root Dir, controllers ...string) (Dir, error) {
	if len(controllers) == 0 {
		controllers = []string{"memory", "pids"}
	}
	controllers, err := root.available(controllers)
	if err != nil {
		return Dir{}, err
	}
	sub, err := root.read("cgroup.subtree_control")
	if err != nil {
		return Dir{}, fmt.Errorf("cgroup: root %s: %w", root.Path, err)
	}
	have := map[string]bool{}
	for _, c := range strings.Fields(sub) {
		have[c] = true
	}
	var want []string
	for _, c := range controllers {
		if !have[c] {
			want = append(want, c)
		}
	}
	for try := 1; len(want) > 0; try++ {
		procs, err := root.read("cgroup.procs")
		if err != nil {
			return Dir{}, fmt.Errorf("cgroup: root %s: %w", root.Path, err)
		}
		if err := root.evacuate(strings.Fields(procs)); err != nil {
			return Dir{}, err
		}
		want, err = root.enable(want)
		switch {
		case err == nil:
		case !errors.Is(err, syscall.EBUSY):
			return Dir{}, err
		case try == delegateTries:
			return Dir{}, root.neverEmptied(want[0])
		default:
			time.Sleep(delegatePause)
		}
	}
	return root.Child("grants"), nil
}

// delegateWrite is the write Delegate makes. Tests replace it.
var delegateWrite = Dir.write

// delegateTries bounds the passes over a root that keeps refusing a
// controller. A burst of late arrivals fits, a root something keeps
// filling fails fast.
const delegateTries = 5

// delegatePause sits between passes. A process that is exiting stays
// listed and still counts, yet a move of it does nothing, so a pass
// straight after the last one would only spend a try on it.
const delegatePause = 10 * time.Millisecond

// evacuate moves pids, the processes in d, into the fiberd leaf, which it
// makes on first need. A process gone by then is skipped.
func (d Dir) evacuate(pids []string) error {
	if len(pids) == 0 {
		return nil
	}
	own := d.Child(ownLeaf)
	if err := os.Mkdir(own.Path, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("cgroup: fiberd leaf%s: %w", readOnlyHint(err), err)
	}
	for _, pid := range pids {
		err := delegateWrite(own, "cgroup.procs", pid)
		if err == nil || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ESRCH) {
			continue
		}
		return fmt.Errorf("cgroup: move pid %s into the fiberd leaf%s: %w", pid, readOnlyHint(err), err)
	}
	return nil
}

// enable writes controllers into d's cgroup.subtree_control in order and
// returns those still to enable, the refused one first.
func (d Dir) enable(controllers []string) ([]string, error) {
	for i, c := range controllers {
		if err := delegateWrite(d, "cgroup.subtree_control", "+"+c); err != nil {
			return controllers[i:], fmt.Errorf("cgroup: enable %s under %s%s: %w", c, d.Path, readOnlyHint(err), err)
		}
	}
	return nil, nil
}

// neverEmptied is the refusal for a root that still held processes on the
// last try. An exiting thread can keep a root busy with no pid left to
// list.
func (d Dir) neverEmptied(controller string) error {
	procs, _ := d.read("cgroup.procs")
	pids := strings.Join(strings.Fields(procs), " ")
	if pids == "" {
		pids = "none listed"
	}
	return fmt.Errorf("cgroup: enable %s under %s: processes still in it: %s: %w", controller, d.Path, pids, syscall.EBUSY)
}

// readOnlyHint names the one cause a read-only cgroup mount has. Every
// other error speaks for itself.
func readOnlyHint(err error) string {
	if errors.Is(err, syscall.EROFS) {
		return " (is the cgroup mount writable?)"
	}
	return ""
}

// available filters controllers to those cgroup.controllers lists for d
// (all of them when the file is absent, as on a fake root). memory is
// required: without it nothing below can be bounded.
func (d Dir) available(controllers []string) ([]string, error) {
	raw, err := os.ReadFile(d.file("cgroup.controllers"))
	if err != nil {
		return controllers, nil
	}
	has := map[string]bool{}
	for _, c := range strings.Fields(string(raw)) {
		has[c] = true
	}
	var out []string
	for _, c := range controllers {
		switch {
		case has[c]:
			out = append(out, c)
		case c == "memory":
			return nil, fmt.Errorf("cgroup: %s offers no memory controller (has: %s)", d.Path, strings.TrimSpace(string(raw)))
		}
	}
	return out, nil
}
