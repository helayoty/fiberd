//go:build linux && integration

// Package proctest exercises the process runtime against a real zygote,
// cgroups and the kernel OOM killer. It builds only with the integration
// tag and runs as root in the dev container (make integration-tests).
package proctest
