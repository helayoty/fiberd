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
// Activate, Ready and Release per instance. Resume and Density are
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
	// Resume parks the instance and brings it back under a new handle.
	// The caller times the second half with Ready.
	Resume(ctx context.Context, h Handle) (Handle, error)
	// Density is the memory charged to the given idle instances, in
	// bytes. With no handles it is the standing cost the system keeps
	// between activations (a warm template, a pool), which density
	// amortizes over the instances.
	Density(ctx context.Context, hs []Handle) (int64, error)
}
