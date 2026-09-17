// Package runctest holds the integration tests of the runc backend on the
// host runtime: the zygote as an OCI container's init, fibers forked
// inside it, checkpointed and restored across the container boundary.
// They run inside the Linux dev container (make linux-test) and skip
// elsewhere.
package runctest
