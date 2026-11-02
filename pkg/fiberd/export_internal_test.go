package fiberd

import "github.com/helayoty/fiberd/pkg/core"

// SetAuditHealth replaces what /healthz reads as the spool's state, so a
// test can poison it.
func SetAuditHealth(c *Config, f func() error) { c.auditHealth = f }

// SetWrapRuntime wraps the runtime -runtime picks, so a test can hold a
// park.
func SetWrapRuntime(c *Config, f func(core.Runtime) core.Runtime) { c.wrapRuntime = f }
