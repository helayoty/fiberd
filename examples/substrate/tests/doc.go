//go:build linux && integration

// Package substratetest holds the Substrate example's integration tests.
// The actor lifecycle runs the whole worker in process over the real
// gVisor and proc backends, and the ateom-fiberd binary runs as a
// process. The suite needs root and the delegated cgroup root of the dev
// container (hack/dev/run.sh), so it builds only with the integration
// tag and skips itself when that root is not writable.
package substratetest
