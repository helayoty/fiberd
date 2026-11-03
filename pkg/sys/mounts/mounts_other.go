//go:build !linux

package mounts

// Prepare does nothing off Linux, where no container mounts anything for
// fiberd and no runtime but the stub runs.
func Prepare() error { return nil }
