// Package proctest exercises the process runtime against a real zygote,
// cgroups and the kernel OOM killer. Its tests are Linux-only and skip
// themselves unless run inside the dev container (make linux-test).
package proctest
