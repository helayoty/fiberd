//go:build linux && integration

// Package knativetest holds the Knative example's integration tests. They
// run the fiberd-activator binary as a process, so they build only with
// the integration tag.
package knativetest
