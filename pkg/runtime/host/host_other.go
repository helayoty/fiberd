//go:build !linux

package host

import "github.com/helayoty/fiberd/pkg/core"

// New fails on platforms without cgroup v2; the agent must use another
// runtime there.
func New(Config) (core.Runtime, error) { return nil, ErrUnsupported }
