//go:build linux && integration

// Package stormtest measures a clone storm on the proc, runc and gvisor
// backends through the host runtime, like for like: the same reference
// zygote forked on the host, inside an OCI container, or restored into a
// runsc sandbox. The numbers are printed, never asserted. FIBERD_BENCH=1
// enables the measurement and make bench runs it in the dev container.
package stormtest
