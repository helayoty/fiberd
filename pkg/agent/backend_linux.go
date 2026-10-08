//go:build linux

package agent

import (
	"path/filepath"

	procbackend "github.com/helayoty/fiberd/pkg/backend/proc"
)

// procOptions configures the fork backend. The bind of the host's root a
// resume restores under lives in the private state directory, which
// fibers never see.
func (c *Config) procOptions() procbackend.Options {
	return procbackend.Options{CRIU: c.CRIUBin, RootBind: filepath.Join(c.PrivateDir(), "root")}
}
