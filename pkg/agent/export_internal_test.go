package agent

import "net"

// SetReady lets the external tests learn the addresses Run bound, since
// they listen on ":0".
func SetReady(c *Config, f func(grpc, http, handoff net.Addr)) { c.ready = f }

// SetAuditHealth replaces what /healthz reads as the spool's state, so a
// test can poison it.
func SetAuditHealth(c *Config, f func() error) { c.auditHealth = f }
