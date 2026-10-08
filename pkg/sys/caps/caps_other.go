//go:build !linux

package caps

// Extra is empty off Linux: there are no capabilities.
func Extra([]int) []int { return nil }

// Narrow does nothing off Linux.
func Narrow([]int) error { return nil }
