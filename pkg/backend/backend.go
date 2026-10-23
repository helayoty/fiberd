// Package backend is the seam between fiberd's host runtime and a sandbox
// mechanism. A Backend knows how to warm one template instance, birth a
// fiber from it, checkpoint a fiber to a directory and bring one back.
// It knows nothing about grants, fences, cgroup budgets, W accounting,
// deltas travelling through a registry, or platform parity: the host
// runtime (pkg/runtime/host) owns all of that and calls the backend only
// for the mechanism.
//
// The backends are proc (a fork zygote checkpointed with CRIU), runc (the
// zygote in an OCI container), gvisor (runsc checkpoint and restore per
// fiber) and hyperlight (micro-VM snapshots through a helper process that
// speaks the zygote line protocol).
package backend

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/core"
)

// ErrUnsupported: this backend cannot run on this platform.
var ErrUnsupported = errors.New("backend: not supported on this platform")

// ErrNoPool is Pool's answer for a warm instance whose template does not
// bind its identity late, so no sandbox of it can wait in a pool.
var ErrNoPool = errors.New("backend: the template does not bind late, no pool")

// ErrYielded is Pool's answer when a clone cut its restore short.
var ErrYielded = errors.New("backend: the pool restore yielded to a clone")

// Template is a resolved template the host hands to Warm: either a bare
// command line, or an artifact directory with its checkpoint images.
type Template struct {
	Digest    string
	Argv      []string
	Dir       string // artifact directory; empty for a bare command
	ImagesDir string // checkpoint of the warm template, when the artifact has one
	// ZygoteSHA256 is the hash the host verified the executable at
	// Argv[0] to have. A backend that runs the template somewhere other
	// than the host (gvisor binds a copy into the sandbox) checks what it
	// runs against it, so nothing between the host's check and the run
	// can swap the file.
	ZygoteSHA256 string
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
	// Devices names the devices the grant's device channel provisions for
	// its engine (device paths or ids), for the warm instance's
	// environment; nil when the grant has none.
	Devices []string
	// EnginePath is the host path of the grant's device engine socket,
	// which the warm instance gets as FIBERD_ENGINE_PATH and hands every
	// fiber as FIBERD_ENGINE. "" when the grant has no engine.
	EnginePath string
	// ProbeCgroupFD is an open fd of an empty cgroup a backend may use
	// to measure what one fiber of this template costs (Warm.Bytes), by
	// starting one there and reading the cgroup; the host removes it
	// afterwards. -1 when the host offers none.
	ProbeCgroupFD int
	// Hide lists absolute directories a fiber must not see. A backend
	// that gives fibers a mount namespace of their own covers them there.
	Hide []string
}

// MountSourcePrefix starts the source of every file system fiberd
// mounts, as the gVisor backend's templates tmpfs is mounted from
// "fiberd-templates". A proc zygote drops every mount whose source
// starts with it from its namespace before its first fiber, since one
// home's mount is no fiber's to keep: once that home unmounts it, a
// parked fiber that carried it cannot be restored, and a detached tmpfs
// lives on inside the fiber with its contents, which the next park
// would write out (sdk/c/template/core/src/prepare.rs,
// drop_fiberd_mounts). A bind of /, a proc home's restore root, is
// known by what it shows instead.
const MountSourcePrefix = "fiberd-"

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
	Fence string // the fiber's id; the backend reports exits under it
	// Endpoint is what the fiber must serve on: an absolute unix socket
	// path under the grant's run directory, or "tcp://host:port" for a
	// backend that lists "tcp" in EndpointSchemes.
	Endpoint string
	CgroupFD int // the fiber's leaf; -1 when the host has none
	Deadline time.Duration
	Payload  []byte
	// Session is the name the caller gave the Clone, "" for an anonymous
	// fiber. The fiber learns it at birth.
	Session string
	// Generation is the fiber's place in its lineage, which the host
	// counts. A fiber born from the warm instance, forked or restored
	// from its image, is 1. A fiber resumed from a park is the parked
	// one's plus one (ResumeSpec). A backend that tells its fibers who
	// they are hands the number over with the identity.
	Generation int
	// OwnPIDNS asks for the fiber to be the init of its own pid namespace
	// so its checkpoint restores anywhere. Backends that always isolate
	// ignore it.
	OwnPIDNS bool
	// Identity is a handoff fiber's TLS identity, which rides on its
	// incarnation record, and the fiber then serves the connections the
	// host passes over its channel instead of Endpoint. nil for every
	// other fiber. Only a Handoffer is given one.
	Identity *Identity
	// Workspace is the fiber's workspace root on the host, a directory
	// fiberd owns and the fiber will own every name under, which the
	// backend mounts at WorkspaceMount in the fiber. "" gives the fiber
	// no workspace. Only a WorkspaceHolder is given one.
	Workspace string
}

// WorkspaceMount is where a fiber sees its workspace, fixed for every
// fiber and every backend that holds workspaces.
const WorkspaceMount = "/workspace"

// Fiber is a running fiber.
type Fiber struct {
	ID  string
	PID int // root process; 0 when the backend has no process per fiber
	// Channel is the host's end of a handoff fiber's channel, on a
	// Handoffer. The backend made the pair where the fiber's checkpoint
	// can carry it, queued the incarnation record on it before the fiber
	// was born or was restored, and handed the fiber the other end. The
	// host owns this end from here, passes connections over it and
	// closes it when the fiber ends. nil for every other fiber, which
	// holds a pair of its own that the backend borrows an end of to
	// send a resume's record.
	Channel *os.File
	// Footprint is what the fiber's leaf counted on the backend's W
	// counter just before the fiber took its identity, for a backend
	// whose fibers carry a fixed footprint. The host subtracts it from
	// every later reading, because one restore of the same image can
	// settle MiB above or below another. 0 leaves the host to the
	// template's measured footprint.
	Footprint uint64
}

// ParkSpec asks for a checkpoint of a fiber into Dir. With Sync the
// fiber keeps running after the checkpoint (the host ends it once the
// images are durable); otherwise the checkpoint ends it. A park is
// cooperative. The backend signals the fiber, which stops serving and
// says so, and only then is it checkpointed. A fiber that never says
// so is not parked, and the error names it.
type ParkSpec struct {
	Dir  string
	Sync bool
	// Deadline bounds the wait for the fiber to stop serving, the
	// grant's resume deadline. Zero waits as long as the context allows.
	Deadline time.Duration
	// Channel is the host's end of a handoff fiber's channel, where
	// that fiber says it has stopped. nil for every other fiber, which
	// says so on a pair of its own that the backend borrows an end of.
	Channel *os.File
	// Capture, when set, runs after the checkpoint while the fiber is
	// stopped, before it is ended or runs on, so what it records matches
	// the images exactly. The host captures the fiber's workspace with
	// it. A Capture that fails fails the park, and the fiber runs on as
	// after any other failed park.
	Capture func() error
	// CgroupFD is an open fd of the fiber's leaf, which a backend that
	// stops the tree for a Capture continues or ends process by
	// process. -1 when the host has none.
	CgroupFD int
}

// ResumeSpec brings a checkpoint back as a new fiber.
type ResumeSpec struct {
	Dir      string
	Fence    string
	Endpoint string // the endpoint the checkpoint served on (as in FiberSpec); recreated by the restore
	CgroupFD int
	Deadline time.Duration
	// WarmID names the grant's warm instance the fiber is resumed under
	// (its template, and for a launcher its container's root and mounts).
	WarmID string
	// WorkDir is the grant's run directory (WarmSpec.WorkDir).
	WorkDir string
	// Session is the name the caller gave the Clone that resumes the
	// fiber, "" when anonymous. A backend whose resumed fiber takes a
	// fresh identity hands it over again.
	Session string
	// Generation is the parked fiber's generation plus one, read from
	// the park's manifest (FiberSpec.Generation).
	Generation int
	// Handoff says the checkpoint's fiber serves handoff, so it holds a
	// channel the restore replaces with a fresh one (Fiber.Channel). A
	// backend sends every resumed fiber its record, kind "resume" with
	// Fence, Generation and Session, on its channel, and waits for the
	// fiber's ack, which says it has taken the record and serves again.
	Handoff bool
	// Workspace is the resumed fiber's workspace root on the host,
	// filled from the park's capture, which the backend mounts at
	// WorkspaceMount where the parked fiber had its own. "" when the
	// parked fiber had none.
	Workspace string
}

// EndpointSchemer is implemented by backends that can serve fibers on
// more than unix sockets under the run directory. A backend without it
// speaks "unix" only. Under a tcp endpoint policy the host tells a "tcp"
// backend the address to bind, and relays a port of its own to the unix
// socket of any other.
type EndpointSchemer interface {
	EndpointSchemes() []string
}

// Handoffer is implemented by backends whose fibers read their
// incarnation record off a channel at birth, and whose handoff fibers
// (FiberSpec.Identity) keep that channel (Fiber.Channel) across park and
// resume for the connections the host passes them. The host refuses a
// handoff grant on any other backend.
type Handoffer interface {
	Handoff() bool
}

// Exit reports the end of a fiber (FiberID set), of a pooled sandbox
// that was never bound (PooledID set) or of a warm instance (WarmID set,
// the others empty: its fibers are gone with it).
type Exit struct {
	FiberID  string
	PooledID string
	WarmID   string
	Status   string // "exit:N" or "signal:NAME"; free text otherwise
}

// PoolSpec asks for one sandbox restored ahead of its identity.
type PoolSpec struct {
	CgroupFD int // the leaf it is born in, which the fiber keeps; -1 when the host has none
	Deadline time.Duration
}

// Pooled is a sandbox waiting in the pool, running the template with no
// fence, endpoint or payload until Bind hands it one.
type Pooled struct {
	ID  string
	PID int
}

// Pooler is implemented by backends that can restore a sandbox before
// its fiber exists and hand it an identity later. Pool restores one and
// holds the channel it dials. Bind writes the identity, with fresh
// entropy, on that channel and waits for the ack and the endpoint, so
// a Clone served from the pool skips the restore. Discard kills one.
// A pooled sandbox that dies before Bind, or whose Bind fails, is
// reported as Exit{PooledID}.
// Pool answers ErrNoPool for a warm instance whose template never
// dials the channel, and ErrYielded when a clone cut it short.
type Pooler interface {
	Pool(ctx context.Context, warmID string, spec PoolSpec) (Pooled, error)
	Bind(ctx context.Context, pooledID string, spec FiberSpec) (Fiber, error)
	Discard(pooledID string)
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
	// Park asks the fiber to stop serving and checkpoints it once it
	// has said so (ParkSpec). Resume brings a checkpoint back and
	// returns once the fiber says it serves again, under the spec's
	// deadline. A restored fiber that never says so is ended, and the
	// host routes nothing to it.
	Park(ctx context.Context, fiberID string, spec ParkSpec) error
	Resume(ctx context.Context, spec ResumeSpec) (Fiber, error)
	// Kill ends a fiber directly (the host also kills its cgroup).
	Kill(fiberID string) error
	// Exits delivers every fiber and warm-instance end, including those
	// the host asked for through Park or Kill: the host is what knows
	// whether an end was a death, and it cleans up on this signal. An
	// Unwarm may or may not be followed by the instance's Exit, so a host
	// that unwarms treats that Exit as cleanup it has already done.
	Exits() <-chan Exit
	Close()
}

// Isolator is implemented by backends whose fibers run behind a kernel
// of their own (gVisor's Sentry, a Hyperlight micro-VM) rather than on
// the host kernel under fiberd's uid. Only these serve untrusted
// grants. A backend that does not implement it does not isolate.
type Isolator interface {
	IsolatesTenants() bool
}

// WorkspaceHolder is implemented by backends that give each fiber a
// private workspace at WorkspaceMount (FiberSpec.Workspace), capture it
// at park under ParkSpec.Capture and mount it again at resume
// (ResumeSpec.Workspace). Only these serve a grant with a disk budget. A
// backend that does not implement it has none. Hyperlight never will,
// since its guest has no file system.
type WorkspaceHolder interface {
	HoldsWorkspaces() bool
}

// IDMapper is implemented by backends whose warm instance and fibers run
// in a user namespace of the grant's own, mapped to a range of host ids
// with the grant's root at its start. The host hands that uid the one
// thing the instance must write on its own, the cgroup.procs of the
// grant's cgroup and of each fiber leaf, so a birth into a leaf works.
// Every limit stays the host's.
type IDMapper interface {
	// MappedRoot is the host uid the grant's root maps to. It fails when
	// the grant cannot have its range on this home because another
	// admitted grant holds it.
	MappedRoot(grantUID string) (uint32, error)
}

// Platformer is implemented by backends whose checkpoints depend on
// something other than the host kernel and libc: the non-empty fields
// replace the host's own facts in every parity comparison (a gVisor image
// depends on the runsc release, not on the host kernel).
type Platformer interface {
	Platform() artifact.Platform
}

// Prober is implemented by backends that can say why they offer no
// tier. The host refuses to open over such a backend and names this
// reason in its error.
type Prober interface {
	// ProbeErr is why the backend offers no tier, nil when it offers one.
	ProbeErr() error
}

// DeadlineAdvisor is implemented by backends whose fork or restore is
// slower than a process fork: what a Clone without an explicit deadline
// gets, for the warm instance named, which a backend may size from what
// it measured at warm. An instance the backend does not have gets its
// floors. Zero keeps fiberd's defaults.
type DeadlineAdvisor interface {
	DefaultDeadlines(warmID string) (create, resume time.Duration)
}

// Overheader is implemented by backends whose fiber carries a fixed
// footprint of its own besides the working set (a sandbox kernel, the
// template's pages when they are not shared copy-on-write). The host adds
// it to the leaf's memory.max, and subtracts it from the measured W of a
// fiber that reported no Footprint of its own. A backend that returns 0
// asks the host to use the warm template's own resident size, measured
// once it is ready.
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
