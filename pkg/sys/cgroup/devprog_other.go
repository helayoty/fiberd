//go:build !linux

package cgroup

import "errors"

// GPUGuard exists only on Linux, where cgroup device programs are.
type GPUGuard struct{}

// AttachGPUGuard is refused off Linux.
func AttachGPUGuard(string) (*GPUGuard, error) {
	return nil, errors.New("cgroup: gpu guard: only on Linux")
}

// Dir is empty off Linux.
func (g *GPUGuard) Dir() string { return "" }

// Close does nothing off Linux.
func (g *GPUGuard) Close() error { return nil }

// Covered is false off Linux.
func (g *GPUGuard) Covered(string) (bool, error) { return false, nil }
