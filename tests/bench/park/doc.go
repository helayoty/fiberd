//go:build linux && integration

// Package parktest measures a park and a resume of one fiber on the proc
// backend through the host runtime, the two steps the clone signal
// touches: the dump that carries the fiber's channel and the restore
// that writes its resume record. The numbers are printed, never
// asserted. FIBERD_BENCH=1 enables the measurement, and an interleaved
// A/B against another tree runs this package in both.
package parktest
