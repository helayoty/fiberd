//go:build linux && integration

// Package kubernetestest holds the Kubernetes example's integration
// tests. They mount real filesystems to show the home making a Pod's
// read-only cgroupfs writable, so they need root and CAP_SYS_ADMIN, as
// in the dev container (hack/dev/run.sh). The suite builds only with the
// integration tag and skips itself when the container's delegated cgroup
// root is not writable.
package kubernetestest
