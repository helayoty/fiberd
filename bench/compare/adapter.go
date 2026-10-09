// Package compare is the head-to-head activation benchmark of
// docs/design/compare.md. One client, one clock, one adapter per
// system under test. The client times the request that activates an
// instance to the first byte of the first 200 from it, and writes one
// JSON line per activation.
//
// Every number is the client's monotonic clock. No server-side timestamp
// enters a latency record.
package compare

import (
	"context"
	"errors"
	"time"
)

// ErrUnsupported is what an adapter answers for an operation its system
// has no equivalent of, such as Resume on a plain Pod.
var ErrUnsupported = errors.New("compare: unsupported by this system")

// CPURequest is what a Pod or claim reserves on the node when it has a
// CPU limit. The limit keeps every instance's share fair. Left to
// default, the request equals the limit, and a burst of 50 at 250m asks
// for 12.5 cores, so kubelet refuses most of it on a small node. A fiber
// reserves nothing per instance either.
const CPURequest = "10m"

// Handle is one activated instance.
type Handle struct {
	// ID is what the system calls the instance (a Pod name, a fiber id,
	// a Firecracker slot).
	ID string
	// Addr is where the instance is reached, once the system said so. A
	// fiber's endpoint URL, a Pod IP and port, a microVM's address. Empty
	// until Ready learns it for systems that return an address late.
	Addr string
	// Meta carries whatever the adapter needs again later (a session
	// name, a cgroup path, a pid).
	Meta map[string]string
}

// Adapter is one system under test. The runner calls Setup once, then
// Activate, Ready and Release per instance. Park, Resume and Density are
// optional and answer ErrUnsupported otherwise.
type Adapter interface {
	// Setup pre-pulls, warms, fills the pool. It is timed and reported as
	// setup cost, never as activation latency.
	Setup(ctx context.Context) error
	// Activate asks the system for a new instance and returns something
	// to dial. It returns as soon as the system answered, which for Pods
	// and claims is before the instance listens.
	Activate(ctx context.Context, id string) (Handle, error)
	// Ready blocks until the first byte of the first 200 from the
	// instance and reports when that byte arrived. Systems that return an
	// address before the instance listens are polled at the runner's
	// interval. It returns the handle with Addr filled in.
	Ready(ctx context.Context, h Handle) (Handle, time.Time, error)
	// Release ends the instance.
	Release(ctx context.Context, h Handle) error
	// Park stops the instance and keeps what brings it back. It is not
	// timed.
	Park(ctx context.Context, h Handle) error
	// Resume brings a parked instance back under a new handle. The
	// caller times it, and the second half with Ready.
	Resume(ctx context.Context, h Handle) (Handle, error)
	// Density is the memory charged to the given idle instances, in
	// bytes. With no handles it is the standing cost the system keeps
	// between activations (a warm template, a pool), which density
	// amortizes over the instances.
	Density(ctx context.Context, hs []Handle) (int64, error)
}

// Preparer is an adapter with a step before each activation that is
// not timed, such as dropping the image for a cold Pod. The runner calls
// Prepare before it takes the activation's clock.
type Preparer interface {
	Prepare(ctx context.Context, id string) error
}

// Refiller is an adapter whose standing capacity a burst drains, such
// as a warm pool. The runner calls Refill before each burst, resume and
// density step, untimed, so each step starts from a full pool.
type Refiller interface {
	Refill(ctx context.Context) error
}

// Cleaner is an adapter that leaves something standing after its runs,
// such as a warm pool and its template, and takes it down. The runner
// calls Cleanup once after the last run, untimed.
type Cleaner interface {
	Cleanup(ctx context.Context) error
}
