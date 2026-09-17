// Package backend is the seam between fiberd's host runtime and a sandbox
// mechanism. A Backend knows how to warm one template instance, birth a
// fiber from it, checkpoint a fiber to a directory and bring one back.
// It knows nothing about grants, fences, cgroup budgets, W accounting,
// deltas travelling through a registry, or platform parity: the host
// runtime (pkg/runtime/host) owns all of that and calls the backend only
// for the mechanism.
//
// Backends today: proc (a fork zygote checkpointed with CRIU). Planned on
// the same interface: runc (the zygote in an OCI bundle), gvisor (runsc
// checkpoint/restore per fiber), hyperlight (micro-VM snapshots through a
// helper process speaking the zygote line protocol).
package backend

import (
	"context"
	"errors"
	"time"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/core"
)

// ErrUnsupported: this backend cannot run on this platform.
var ErrUnsupported = errors.New("backend: not supported on this platform")

// Template is a resolved template the host hands to Warm: either a bare
// command line, or an artifact directory with its checkpoint images.
type Template struct {
	Digest    string
	Argv      []string
	Dir       string // artifact directory; empty for a bare command
	ImagesDir string // checkpoint of the warm template, when the artifact has one
}

// WarmSpec asks for one warm instance of a template for a grant.
type WarmSpec struct {
	GrantUID string
	Template Template
	// CgroupFD is an open fd of the cgroup the warm instance must be born
	// in (its own leaf under the grant). -1 when the host has none.
	CgroupFD int
	// WorkDir is the grant's run directory: the instance's cwd, its log,
	// and where fiber endpoints live.
	WorkDir string
	// ProbeCgroupFD is an open fd of an empty cgroup a backend may use
	// to measure what one fiber of this template costs (Warm.Bytes), by
	// starting one there and reading the cgroup; the host removes it
	// afterwards. -1 when the host offers none.
	ProbeCgroupFD int
}

// Warm is a warm template instance.
type Warm struct {
	ID  string // backend's handle, passed back to Clone and Unwarm
	PID int    // the process, for logs; 0 when there is none
	// Bytes is what one fiber of this template costs in the W counter
	// (see WMeter) before it dirties anything, when the backend can
	// measure it (a sandbox restored from the template image); 0 lets the
	// host use the warm cgroup's count.
	Bytes uint64
	// TotalBytes is the same fiber's whole footprint (memory.current),
	// what its leaf's memory.max must leave room for besides the budget.
	// 0 means the same as Bytes.
	TotalBytes uint64
}

// FiberSpec asks for one fiber from a warm instance or a checkpoint.
type FiberSpec struct {
	Fence    string // the fiber's id; the backend reports exits under it
	Endpoint string // unix socket path the fiber must serve on
	CgroupFD int    // the fiber's leaf; -1 when the host has none
	Deadline time.Duration
	Payload  []byte
	// OwnPIDNS asks for the fiber to be the init of its own pid namespace
	// so its checkpoint restores anywhere. Backends that always isolate
	// ignore it.
	OwnPIDNS bool
}

// Fiber is a running fiber.
type Fiber struct {
	ID  string
	PID int // root process; 0 when the backend has no process per fiber
}

// ParkSpec asks for a checkpoint of a fiber into Dir. With Sync the
// fiber keeps running after the checkpoint (the host ends it once the
// images are durable); otherwise the checkpoint ends it.
type ParkSpec struct {
	Dir  string
	Sync bool
}

// ResumeSpec brings a checkpoint back as a new fiber.
type ResumeSpec struct {
	Dir      string
	Fence    string
	Endpoint string // the endpoint the checkpoint served on; recreated by the restore
	CgroupFD int
	Deadline time.Duration
	// WarmID names the grant's warm instance the fiber is resumed under
	// (its template, and for a launcher its container's root and mounts).
	WarmID string
}

// Exit reports the end of a fiber (FiberID set) or of a warm instance
// (WarmID set, FiberID empty: its fibers are gone with it).
type Exit struct {
	FiberID string
	WarmID  string
	Status  string // "exit:N" or "signal:NAME"; free text otherwise
}

// Backend is what a sandbox mechanism implements.
type Backend interface {
	// Name is the mechanism's name: "proc", "runc", "gvisor", "hyperlight".
	// It is a platform-parity fact: a checkpoint from one backend is
	// never offered to another.
	Name() string
	// Tier is the best this backend offers on this host, found at open.
	Tier() core.Tier
	Warm(ctx context.Context, spec WarmSpec) (Warm, error)
	// Unwarm ends a warm instance. Its fibers, if any survive it, are the
	// host's to kill through their cgroups.
	Unwarm(id string)
	Clone(ctx context.Context, warmID string, spec FiberSpec) (Fiber, error)
	Park(ctx context.Context, fiberID string, spec ParkSpec) error
	Resume(ctx context.Context, spec ResumeSpec) (Fiber, error)
	// Kill ends a fiber directly (the host also kills its cgroup).
	Kill(fiberID string) error
	// Exits delivers every fiber and warm-instance end, including those
	// the host asked for through Park or Kill: the host is what knows
	// whether an end was a death, and it cleans up on this signal.
	Exits() <-chan Exit
	Close()
}

// Platformer is implemented by backends whose checkpoints depend on
// something other than the host kernel and libc: the non-empty fields
// replace the host's own facts in every parity comparison (a gVisor image
// depends on the runsc release, not on the host kernel).
type Platformer interface {
	Platform() artifact.Platform
}

// DeadlineAdvisor is implemented by backends whose fork or restore is
// slower than a process fork: what a Clone without an explicit deadline
// gets. Zero keeps the agent's defaults.
type DeadlineAdvisor interface {
	DefaultDeadlines() (create, resume time.Duration)
}

// Overheader is implemented by backends whose fiber carries a fixed
// footprint of its own besides the working set (a sandbox kernel, the
// template's pages when they are not shared copy-on-write). The host adds
// it to the leaf's memory.max and subtracts it from the measured W. A
// backend that returns 0 asks the host to use the warm template's own
// resident size, measured once it is ready.
type Overheader interface {
	FiberOverheadBytes() uint64
}

// WMeter is implemented by backends whose fibers' working set is one
// counter of the leaf's memory.stat rather than memory.current: a
// sandbox keeps its guest memory in a memfd ("shmem") while its own
// kernel's heap varies from sandbox to sandbox and must not count as W.
// The host reads that counter for W, for the footprint probe and for
// budget enforcement.
type WMeter interface {
	WCounter() string
}

// WReporter is implemented by backends whose fibers are not processes in
// a cgroup of their own (sandboxes inside one helper process): the
// backend itself says what a fiber has dirtied, and the host uses that
// for W and for budget enforcement instead of the leaf's counters.
type WReporter interface {
	FiberW(fiberID string) (uint64, bool)
}

// SelfCheckpointer is implemented by backends that can checkpoint a
// warm instance while it keeps running, giving the host a parent for
// deltas when the template came without images.
type SelfCheckpointer interface {
	CheckpointWarm(ctx context.Context, warmID, dir string) error
}

// Parent is a loaded parent checkpoint a delta is computed against.
type Parent interface {
	SHA256() string
	Close()
}

// DeltaInfo describes a delta checkpoint.
type DeltaInfo struct {
	ParentSHA256 string
	Bytes        uint64 // what the delta costs to move
}

// DeltaCodec is implemented by backends whose checkpoint format lets the
// host drop every page the template already holds. Without one, a park
// is a full image and its size is what a move costs.
type DeltaCodec interface {
	ImageBytes(dir string) (uint64, error)
	LoadParent(dir string) (Parent, error)
	// Compute rewrites the checkpoint in dir as a delta over parent.
	Compute(dir string, parent Parent) (DeltaInfo, error)
	HasDelta(dir string) bool
	ReadDeltaInfo(dir string) (DeltaInfo, error)
	// Merge rebuilds the full checkpoint in dir from the delta and parent.
	Merge(dir string, parent Parent) error
}
