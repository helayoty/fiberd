//go:build linux

package home

import "golang.org/x/sys/unix"

// remountRW makes the cgroup mount writable in place. It is a bind
// remount, so the mount's other options stay.
func remountRW(mount string) error {
	return unix.Mount("", mount, "", unix.MS_REMOUNT|unix.MS_BIND, "")
}
