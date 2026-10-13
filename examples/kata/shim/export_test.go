package shim

import "os/exec"

// SetStart replaces how Manager.Start runs the shim daemon and returns
// what puts the real one back.
func SetStart(f func(*exec.Cmd) error) (restore func()) {
	old := start
	start = f
	return func() { start = old }
}
