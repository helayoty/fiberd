package home

import (
	"errors"
	"fmt"
	"log"
	"syscall"
)

// criuSysctls are the files `criu check` must write. An unprivileged Pod
// gets all of /proc/sys read-only. Only these are made writable, and each
// belongs to the container's own pid or ipc namespace.
var criuSysctls = []string{
	"/proc/sys/kernel/ns_last_pid",
	"/proc/sys/kernel/sem_next_id",
	"/proc/sys/kernel/msg_next_id",
	"/proc/sys/kernel/shm_next_id",
}

// writableMounts makes the container's cgroupfs (in its own cgroup
// namespace) and criuSysctls writable. The runtime mounts them read-only in
// an unprivileged Pod, and the agent must write them. This needs
// CAP_SYS_ADMIN and a profile that allows mount, which containerd's default
// AppArmor profile does not. Without the sysctls the proc backend offers
// only FIBER_WARM, so failing to bind them is just a warning.
func writableMounts(cgroupfs string) error {
	if readOnly(cgroupfs) {
		const flags = syscall.MS_REMOUNT | syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC | syscall.MS_RELATIME
		if err := syscall.Mount("", cgroupfs, "", flags, ""); err != nil {
			return fmt.Errorf("remount %s read-write (a Pod that is not privileged needs CAP_SYS_ADMIN and an AppArmor profile that allows mount): %w", cgroupfs, err)
		}
		log.Printf("k8s: remounted %s read-write", cgroupfs)
	}
	for _, f := range criuSysctls {
		if !readOnly(f) {
			continue
		}
		if err := syscall.Mount(f, f, "", syscall.MS_BIND, ""); err != nil {
			log.Printf("WARNING: k8s: bind %s: %v; criu check will fail", f, err)
			continue
		}
		if err := syscall.Mount("", f, "", syscall.MS_REMOUNT|syscall.MS_BIND, ""); err != nil {
			log.Printf("WARNING: k8s: remount %s read-write: %v; criu check will fail", f, err)
			continue
		}
		log.Printf("k8s: made %s writable", f)
	}
	return nil
}

func readOnly(path string) bool { return errors.Is(syscall.Access(path, 2), syscall.EROFS) }
