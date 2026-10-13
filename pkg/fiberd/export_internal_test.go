package fiberd

// SetAuditHealth replaces what /healthz reads as the spool's state, so a
// test can poison it.
func SetAuditHealth(c *Config, f func() error) { c.auditHealth = f }
