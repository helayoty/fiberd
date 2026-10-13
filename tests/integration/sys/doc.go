//go:build linux && integration

// Package systest holds the integration tests of pkg/sys against the
// kernel. Cgroup leaves, criu restores, capability narrowing and network
// namespaces need root and the delegated cgroup root of the dev container
// (hack/dev/run.sh), so the suite builds only with the integration tag
// and skips itself when that root is not writable.
package systest
