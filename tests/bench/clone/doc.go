//go:build linux && integration

// Package clonetest measures Clone end to end, as a consumer sees it over
// gRPC with a verified grant, and splits each round trip into the stages
// fiberd, the host runtime, the zygote and the audit spool take. The
// numbers are printed, never asserted. FIBERD_BENCH=1 enables the
// measurement and make bench-e2e runs it in the dev container.
package clonetest
