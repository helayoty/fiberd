//go:build linux

package criu

import "syscall"

// sysProcAttr starts criu in a process group of its own, inside the
// cgroup cgroupFD names when it is not negative.
func sysProcAttr(cgroupFD int) *syscall.SysProcAttr {
	attr := &syscall.SysProcAttr{Setpgid: true}
	if cgroupFD >= 0 {
		attr.UseCgroupFD = true
		attr.CgroupFD = cgroupFD
	}
	return attr
}
