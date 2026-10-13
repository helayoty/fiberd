//go:build linux && integration

// Package hosttest holds the integration tests of pkg/runtime/host
// against the kernel. What the unit tests run over a plain directory
// runs here over a real cgroup subtree. That is the kernel's ceilings
// and refusals, tasks killed in their leaves, the memory a live task
// charges, and ownership handed to a foreign uid. The suite needs root
// and the delegated cgroup root of the dev container (hack/dev/run.sh),
// so it builds only with the integration tag and skips itself when that
// root is not writable.
package hosttest
