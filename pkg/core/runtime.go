package core

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"time"
)

// Tier is advertised runtime capability. Values match api/grant/v1 Tier so
// a grant's min_tier compares directly. Conformance to the verbs does not
// imply the mechanics; grants are placed against the tier, and Clone(S) on
// a parked session MUST fail rather than silently fork a fresh amnesiac
// fiber when the runtime lacks TierCheckpoint.
type Tier int

const (
	TierUnspecified Tier = iota
	// TierBasic: create a worker in an existing warm sandbox. Correct
	// semantics, pod-class latency. Every runtime qualifies.
	TierBasic
	// TierWarm: zygote fork, copy-on-write. Millisecond activation and
	// density. Single-tenant per grant by definition.
	TierWarm
	// TierCheckpoint: per-fiber delta checkpoint + restore. Park/resume,
	// the entire session model, requires this.
	TierCheckpoint
	// TierSnapshot: microVM or gVisor snapshot-restore per fiber.
	// Multi-tenant per node.
	TierSnapshot
)

func (t Tier) String() string {
	switch t {
	case TierBasic:
		return "FIBER_BASIC"
	case TierWarm:
		return "FIBER_WARM"
	case TierCheckpoint:
		return "FIBER_CHECKPOINT"
	case TierSnapshot:
		return "FIBER_SNAPSHOT"
	default:
		return "TIER_UNSPECIFIED"
	}
}

// CloneSource selects the birth mechanism for a fiber.
type CloneSource int

const (
	SourceZygote CloneSource = iota // fork the warm template
	SourceDelta                     // restore a parked per-fiber delta
)

// CloneSpec is everything the runtime needs to birth one fiber. Grant
// carries the template digest and the W budget; Fence is the identity the
// child adopts after the fork, never before.
type CloneSpec struct {
	Grant    Grant
	Source   CloneSource
	Ref      string // delta ref when Source == SourceDelta
	Fence    Fence
	Deadline time.Duration // hard budget: exceeding it is an error, not a late fiber
	Payload  []byte        // opaque data handed to the fiber at birth
	Session  string        // the session the caller named, "" for an anonymous fiber
	// CallerCert is the DER certificate the clone arrived under, the one
	// a fresh handoff fiber is told to accept. A resumed fiber holds its
	// caller already and ignores it.
	CallerCert []byte
}

// FiberHandle is what the runtime knows about a running fiber. Endpoint is
// returned directly to the caller; fibers never join any service registry.
type FiberHandle struct {
	ID       string
	Endpoint string // host:port or unix socket path
	Pooled   bool   // born from a sandbox restored ahead of the clone
}

// HandoffRouter is implemented by runtimes that route callers'
// connections to fibers (endpoint mode handoff). HandsOff reports whether
// this home can, given its backend and configuration. HandoffRoute
// returns a handoff fiber's routing key, which the caller sends as the
// TLS server name, the pin of the key the fiber serves with and the DER
// certificate it presents.
type HandoffRouter interface {
	HandsOff() bool
	HandoffRoute(fiberID string) (routingKey, serverKeySHA256 string, serverCert []byte, ok bool)
}

// FiberStats is the runtime's measurement of one fiber. WUsedBytes is the
// dirtied working set: the fiber's private pages since fork.
type FiberStats struct {
	WUsedBytes uint64
	// DeviceUsedBytes is the fiber's slice of the engine's device state,
	// as the engine reports it; 0 when the grant has no device.
	DeviceUsedBytes uint64
}

// DeviceCapable is implemented by runtimes that start a device engine
// for a grant, which holds device state for its fibers and reports
// their slices. DeviceOffer is the class and capacity the grant's engine
// declared before READY, and capacity 0 when the grant has none. A grant
// with a device budget is admitted only where DeviceFits holds.
type DeviceCapable interface {
	DeviceOffer(grantUID string) (class string, capacity uint64)
}

// DeviceFits is the class rule. An empty class asked takes any engine,
// and otherwise the classes must be equal. An engine with no capacity
// fits nothing. The refusal wraps ErrNeedsDevice and names both classes.
func DeviceFits(asked, class string, capacity uint64) error {
	if capacity == 0 {
		return fmt.Errorf("%w: grant asks class %q, the engine declares class %q with no capacity", ErrNeedsDevice, asked, class)
	}
	if asked != "" && asked != class {
		return fmt.Errorf("%w: grant asks class %q, the engine declares class %q", ErrNeedsDevice, asked, class)
	}
	return nil
}

// Isolator is implemented by runtimes that can say whether their fibers
// are sandboxed from the host kernel (a user-space kernel, a micro-VM).
// An untrusted grant is admitted only where this answers true. A runtime
// that does not implement it does not isolate.
type Isolator interface {
	IsolatesTenants() bool
}

// WorkspaceHolder is implemented by runtimes that can give each fiber a
// private workspace. A grant with a disk budget is admitted only where
// this answers true. A runtime that does not implement it has none.
type WorkspaceHolder interface {
	HoldsWorkspaces() bool
}

// FileStore is implemented by runtimes that hold a workspace per fiber
// and move files into and out of it from the host side, never through
// the fiber. Paths are relative to the workspace. A fiber this runtime
// does not know answers ErrFiberUnknown, and one without a workspace
// ErrNoWorkspace. Any other error wraps a sentinel of the workspace
// file layer (pkg/runtime/host/wsfs) or fs.ErrNotExist, which the
// transport maps to its codes.
type FileStore interface {
	// Upload writes one regular file of size bytes read from r, with
	// the permission bits of mode, checked against sum when it is
	// not nil. Nothing of it appears until every check passed.
	Upload(ctx context.Context, fiberID, path string, size int64, mode fs.FileMode, sum []byte, r io.Reader) (FileInfo, error)
	// Download opens one regular file at offset. The reader ends at
	// the size the file had when opened.
	Download(ctx context.Context, fiberID, path string, offset int64) (FileReader, error)
	// ListFiles lists the regular files and directories of one
	// directory, "" for the workspace itself.
	ListFiles(ctx context.Context, fiberID, dir string) ([]FileInfo, error)
}

// FileInfo describes one entry of a fiber's workspace.
type FileInfo struct {
	// Path is relative to the workspace, with forward slashes.
	Path string
	// Size is the apparent size in bytes, zero for a directory.
	Size int64
	// Mode holds the permission bits, and fs.ModeDir for a directory.
	Mode fs.FileMode
	// ModTime is the last modification time.
	ModTime time.Time
	// SHA256 is the content hash, set by Upload only.
	SHA256 []byte
}

// FileReader is a downloaded file, its bytes and what it was when
// opened.
type FileReader interface {
	io.ReadCloser
	Info() FileInfo
}

// FiberExit is reported when a fiber dies on its own: the kernel killed it
// for exceeding its W budget (Reason "oom"), it exited, or was signalled.
type FiberExit struct {
	FiberID string
	Reason  string // "oom" | "exit" | "signal"
	Detail  string
}

// SessionDomain is the namespace a session name lives in when it is
// parked and when it moves between homes: the grant's tenant, then its
// session_class when the issuer set one, else the template digest. Two
// homes each hold their own grant; what they share is the tenant and
// the template (a session's state is a delta over its pages) or an
// issuer-chosen class. Grant UIDs cannot stand in for the tenant,
// because a session moves between homes whose grants differ. A grant
// without a tenant has no domain, so nothing named is ever filed under
// it or looked up for it.
func (g Grant) SessionDomain() (string, error) {
	if g.Tenant == "" {
		return "", fmt.Errorf("%w: grant %s", ErrNoTenant, g.UID)
	}
	if g.Policy.SessionClass != "" {
		return g.Tenant + "/" + g.Policy.SessionClass, nil
	}
	return g.Tenant + "/" + g.TemplateDigest, nil
}

// DeltaPublisher is implemented by runtimes that can put a parked delta
// where other homes can find it. fiberd calls it after every park of a
// named session; the returned handle is remembered with the session.
type DeltaPublisher interface {
	PublishDelta(ctx context.Context, deltaRef string, g Grant, session string) (remote string, err error)
}

// DeltaRetirer is implemented by runtimes that can withdraw a delta's
// published copy. fiberd calls it once the session resumes here, so
// the copy in the store no longer names state another home may take or
// a later Clone may fall back to, and again before a local delta is
// discarded. A delta never published, or whose tag a later park has
// replaced, is left alone.
type DeltaRetirer interface {
	RetireDelta(ctx context.Context, deltaRef string) error
}

// TemplateDropper is implemented by runtimes that can end a grant's warm
// template. fiberd calls it at the end of a yield, once the grant's
// fibers are released, so a revoked grant holds no pages. The next
// admission warms the template again.
type TemplateDropper interface {
	DropTemplate(grantUID string)
}

// RemoteDelta is what a finder learns about a parked session elsewhere
// without pulling it: how much it costs to move, and where it lives.
type RemoteDelta struct {
	WBytes uint64
	Home   string
	Handle string // opaque; passed back to Claim
}

// DeltaFinder is implemented by runtimes that can look a session up in
// the shared store and bring its delta here. Claim pulls the delta (and,
// if needed, the parent checkpoint it depends on), makes the remote copy
// unavailable to others, and returns a local delta ref for SourceDelta.
//
// FindDelta may return a *RemoteMiss as its error when the session exists
// but this home must not take it (the state was made on an incompatible
// platform); fiberd turns that into a miss naming the preferred home.
// One wrapping ErrDeviceMismatch is a FailedPrecondition instead. Any
// other error means the store is unreachable.
type DeltaFinder interface {
	FindDelta(ctx context.Context, g Grant, session string) (RemoteDelta, bool, error)
	ClaimDelta(ctx context.Context, g Grant, session string, rd RemoteDelta) (deltaRef string, err error)
	// Owned reports whether a locally parked delta is still ours: false
	// when another home has claimed the session since we published it.
	Owned(ctx context.Context, deltaRef string) bool
}

// Runtime is the seam between the invariant core and a mechanism. This
// interface is what keeps the core identical across homes and tiers.
type Runtime interface {
	Tier() Tier

	// PrepareTemplate makes the grant's template warm on this home (boots
	// the zygote, pulls the artifact). Idempotent. Grant readiness is this
	// call returning nil.
	PrepareTemplate(ctx context.Context, g Grant) error

	// Clone births a fiber. spec.Deadline is a hard budget.
	Clone(ctx context.Context, spec CloneSpec) (FiberHandle, error)

	// Park checkpoints the fiber's delta over the zygote and releases its
	// running-tier resources. sync means the delta is durable before the
	// call returns. Returns the delta ref for a later SourceDelta clone.
	Park(ctx context.Context, fiberID string, sync bool) (deltaRef string, err error)

	// Release destroys the fiber; discard also deletes any parked delta
	// belonging to the same session.
	Release(ctx context.Context, fiberID string, discard bool) error

	// List rebuilds the ledger's view of reality at startup; discrepancies
	// resolve in favor of what is actually running.
	List(ctx context.Context) ([]FiberHandle, error)

	// Stats measures one running fiber.
	Stats(ctx context.Context, fiberID string) (FiberStats, error)

	// Exits delivers fibers that died without a Park or Release. fiberd
	// frees their ledger slot and writes the audit record.
	Exits() <-chan FiberExit
}
