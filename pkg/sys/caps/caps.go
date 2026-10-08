// Package caps narrows the capabilities of the agent, and so of
// everything it starts (criu, the zygote, a backend's helpers): a process
// started as root gets exactly its bounding set, and one that execs a
// file with inheritable file capabilities gets what the inheritable and
// ambient sets allow, so those are narrowed with it.
package caps

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Capability numbers (linux/capability.h).
const (
	Chown         = 0
	DACOverride   = 1
	DACReadSearch = 2
	Kill          = 5
	SetGID        = 6
	SetUID        = 7
	SetPCAP       = 8
	NetAdmin      = 12
	SysChroot     = 18
	SysPtrace     = 19
	SysAdmin      = 21
	SysResource   = 24
	SysTime       = 25
)

// Proc is what the proc runtime needs, as hack/test/caps.sh measured it:
// namespaces, mounts and cgroups (SysAdmin), CRIU restoring a fiber's
// time and mount namespaces (SysTime, SysChroot), TCP repair (NetAdmin),
// and emptying each fiber's bounding set (SetPCAP). CRIU also attaches
// to fibers it did not start (SysPtrace), which Yama's default
// ptrace_scope 1 allows only with that capability, and raises its own
// open-file limit (SysResource).
var Proc = []int{SetPCAP, NetAdmin, SysChroot, SysPtrace, SysAdmin, SysResource, SysTime}

// Runc is what the runc runtime needs, measured by running tests/runc
// and the conformance suite under setpriv with each candidate left out.
// The grant's container runs in a user namespace, so its root is an
// unprivileged host uid and the agent crosses that line in a few places.
// runc writes the mapped root's uid and gid maps (SetUID, SetGID) and
// chowns exec.fifo to it (Chown), and runc, criu and the agent open
// files that uid owns with modes that keep root out (DACOverride, which
// covers what DAC_READ_SEARCH would). Kill is not needed, since fibers
// and the container's init are ended through their cgroups.
var Runc = append(append([]int{}, Proc...), Chown, DACOverride, SetGID, SetUID)

// Names is how Kubernetes spells a capability in a container's
// capabilities.
var Names = map[int]string{Chown: "CHOWN", DACOverride: "DAC_OVERRIDE", DACReadSearch: "DAC_READ_SEARCH", Kill: "KILL",
	SetGID: "SETGID", SetUID: "SETUID", SetPCAP: "SETPCAP", NetAdmin: "NET_ADMIN", SysChroot: "SYS_CHROOT", SysPtrace: "SYS_PTRACE",
	SysAdmin: "SYS_ADMIN", SysResource: "SYS_RESOURCE", SysTime: "SYS_TIME"}

// ForRuntime is the keep list for a runtime name, and false for a
// runtime whose needs are not measured.
func ForRuntime(name string) ([]int, bool) {
	switch name {
	case "proc":
		return Proc, true
	case "runc":
		return Runc, true
	}
	return nil, false
}

// ErrCannotNarrow: the process holds capabilities outside the set but not
// CAP_SETPCAP, which dropping them needs.
var ErrCannotNarrow = errors.New("caps: cannot narrow the bounding set without CAP_SETPCAP")

// statusCaps reads the inheritable (CapInh) and ambient (CapAmb) masks
// from the text of a /proc/<pid>/status file. A kernel without ambient
// capabilities has no CapAmb line, which reads as an empty set; a
// missing CapInh line is an error, since the file always has one.
func statusCaps(status string) (inh, amb uint64, err error) {
	haveInh := false
	for _, line := range strings.Split(status, "\n") {
		key, val, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		switch key {
		case "CapInh", "CapAmb":
		default:
			continue
		}
		mask, perr := strconv.ParseUint(strings.TrimSpace(val), 16, 64)
		if perr != nil {
			return 0, 0, fmt.Errorf("caps: %s in status: %w", key, perr)
		}
		if key == "CapInh" {
			inh, haveInh = mask, true
		} else {
			amb = mask
		}
	}
	if !haveInh {
		return 0, 0, errors.New("caps: no CapInh line in status")
	}
	return inh, amb, nil
}

// outside lists, ascending, the capabilities set in mask that keep does
// not name.
func outside(mask uint64, keep []int) []int {
	var out []int
	for c := 0; c < 64; c++ {
		if mask&(1<<uint(c)) != 0 && !slices.Contains(keep, c) {
			out = append(out, c)
		}
	}
	return out
}

// keepMask is keep as a capability mask.
func keepMask(keep []int) uint64 {
	var m uint64
	for _, c := range keep {
		if c >= 0 && c < 64 {
			m |= 1 << uint(c)
		}
	}
	return m
}
