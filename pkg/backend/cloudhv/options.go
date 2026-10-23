package cloudhv

// Options configure the Cloud Hypervisor backend.
type Options struct {
	// VMM is the cloud-hypervisor executable, or hack/cloudhv/fakevmm,
	// which speaks the same API subset without KVM. Required.
	VMM string
	// Kernel is the guest vmlinux and Rootfs the guest's read-only root
	// image, both built by hack/cloudhv/build.sh. The fake VMM takes a
	// directory as its rootfs. Required.
	Kernel string
	Rootfs string
	// StateDir holds the warm snapshots and each VMM's run directory.
	// Required.
	StateDir string
	// MemoryMiB is each guest's memory, 256 when zero.
	MemoryMiB uint64
	// VCPUs is each guest's vCPU count, 1 when zero.
	VCPUs int
	// RestoreMode is how a Clone restores the warm snapshot's memory:
	// "" or "copy" copies it in whole, "ondemand" faults it in lazily
	// through userfaultfd.
	// A Resume always copies, since a park directory is not fiberd's to
	// keep unchanged for the VM's lifetime.
	RestoreMode string
	// UsernsPool is fiberd's -userns-pool (START:SLOTS, the runc backend's
	// syntax) and EngineUID its -engine-uid. New refuses to open when
	// either reaches into the VMM uid range (jailIDs), since a VMM must
	// share no id with a container or the engine. "" is the default pool,
	// and 0 names no engine.
	UsernsPool string
	EngineUID  uint32
}
