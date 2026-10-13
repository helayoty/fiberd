//go:build !linux

package criu

import "syscall"

// sysProcAttr starts criu in a process group of its own. Only Linux has
// cgroups, so cgroupFD is ignored.
func sysProcAttr(int) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}
