//go:build !linux

package host

import (
	"os"

	"github.com/helayoty/fiberd/pkg/core"
)

// Runtime is a placeholder so callers build on platforms without cgroup
// v2. New never returns one here.
type Runtime struct{ core.Runtime }

// New fails on platforms without cgroup v2; the agent must use another
// runtime there.
func New(Config) (*Runtime, error) { return nil, ErrUnsupported }

func (*Runtime) Deliver(string, *os.File) error      { return ErrUnsupported }
func (*Runtime) PruneGrants(map[string]bool)         {}
func (*Runtime) DevicePressure() core.PressureSource { return nil }
func (*Runtime) Close()                              {}
