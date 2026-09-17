package cgroup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
// the `agent` leaf Delegate made is an agent restarted in the same
// container or allocation: its root is the leaf's parent, not the leaf,
// or every restart would nest one level deeper.
func ownFrom(mount, procCgroup string) Dir {
	scope := ScopeOf(procCgroup)
	if scope == "" {
		return Root(mount)
	}
	if filepath.Base(scope) == agentLeaf {
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

const agentLeaf = "agent"

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

// Delegate prepares root, the cgroup an agent was started in, for the
// runtime to carve leaves under: it needs controllers in
// cgroup.subtree_control, and a cgroup with processes may not enable any
// (the no-internal-process rule), so every process there first moves into
// an `agent` leaf. The memory limit whatever started the agent put on root
// (a kubelet, Slurm's task/cgroup) stays the ceiling on everything below.
// Returns the `fiberd` subtree the runtime owns. Idempotent: an already
// delegated root is left alone. Controllers the root cannot offer (a
// Slurm step gets cpuset, cpu and memory, no pids) are skipped; memory
// is required.
func Delegate(root Dir, controllers ...string) (Dir, error) {
	if len(controllers) == 0 {
		controllers = []string{"memory", "pids"}
	}
	controllers, err := root.available(controllers)
	if err != nil {
		return Dir{}, err
	}
	sub, err := os.ReadFile(root.file("cgroup.subtree_control"))
	if err != nil {
		return Dir{}, fmt.Errorf("cgroup: root %s: %w", root.Path, err)
	}
	have := map[string]bool{}
	for _, c := range strings.Fields(string(sub)) {
		have[c] = true
	}
	missing := false
	for _, c := range controllers {
		if !have[c] {
			missing = true
		}
	}
	if missing {
		procs, err := os.ReadFile(root.file("cgroup.procs"))
		if err != nil {
			return Dir{}, err
		}
		if pids := strings.Fields(string(procs)); len(pids) > 0 {
			agent := root.Child(agentLeaf)
			if err := os.Mkdir(agent.Path, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
				return Dir{}, fmt.Errorf("cgroup: agent leaf: %w", err)
			}
			for _, pid := range pids {
				if err := os.WriteFile(agent.file("cgroup.procs"), []byte(pid), 0o644); err != nil && !errors.Is(err, os.ErrNotExist) {
					return Dir{}, fmt.Errorf("cgroup: move pid %s into the agent leaf: %w", pid, err)
				}
			}
		}
		for _, c := range controllers {
			if have[c] {
				continue
			}
			if err := root.write("cgroup.subtree_control", "+"+c); err != nil {
				return Dir{}, fmt.Errorf("cgroup: enable %s under %s (is the cgroup mount writable?): %w", c, root.Path, err)
			}
		}
	}
	return root.Child("fiberd"), nil
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
