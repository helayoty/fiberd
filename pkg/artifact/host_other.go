//go:build !linux

package artifact

import "runtime"

func unameRelease() string { return runtime.GOOS }
func libcVersion() string  { return "n/a" }
