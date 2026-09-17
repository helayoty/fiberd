//go:build !linux

// Package proc is the fork backend; it needs Linux (clone3, cgroup v2,
// criu). Elsewhere it opens as a backend that refuses every call.
package proc

import (
	"context"

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
)

// Options configure the fork backend.
type Options struct {
	CRIU string
}

type unsupported struct{}

// New returns a backend whose every operation fails with
// backend.ErrUnsupported.
func New(Options) backend.Backend { return unsupported{} }

func (unsupported) Name() string    { return "proc" }
func (unsupported) Tier() core.Tier { return core.TierUnspecified }
func (unsupported) Warm(context.Context, backend.WarmSpec) (backend.Warm, error) {
	return backend.Warm{}, backend.ErrUnsupported
}
func (unsupported) Unwarm(string) {}
func (unsupported) Clone(context.Context, string, backend.FiberSpec) (backend.Fiber, error) {
	return backend.Fiber{}, backend.ErrUnsupported
}
func (unsupported) Park(context.Context, string, backend.ParkSpec) error {
	return backend.ErrUnsupported
}
func (unsupported) Resume(context.Context, backend.ResumeSpec) (backend.Fiber, error) {
	return backend.Fiber{}, backend.ErrUnsupported
}
func (unsupported) Kill(string) error          { return backend.ErrUnsupported }
func (unsupported) Exits() <-chan backend.Exit { return nil }
func (unsupported) Close()                     {}
