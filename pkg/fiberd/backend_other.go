//go:build !linux

package fiberd

import procbackend "github.com/helayoty/fiberd/pkg/backend/proc"

// procOptions configures the fork backend, which refuses every call off
// Linux.
func (c *Config) procOptions() procbackend.Options {
	return procbackend.Options{CRIU: c.CRIUBin}
}
