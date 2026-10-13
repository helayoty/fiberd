//go:build linux && integration

// Package slurmtest holds the Slurm example's integration tests. They
// run the fiberd-slurm binary and the job script as processes, probe the
// job through a real shell command and let the home's default SIGTERM
// land on the test process. The suite needs root and the delegated
// cgroup root of the dev container (hack/dev/run.sh), so it builds only
// with the integration tag and skips itself when that root is not
// writable.
package slurmtest
