package agent

import "net"

// SetReady lets the external tests learn the addresses Run bound, since
// they listen on ":0".
func SetReady(c *Config, f func(grpc, http, handoff net.Addr)) { c.ready = f }
