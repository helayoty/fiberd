//go:build linux

package criu

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// RestoreWith starts `criu restore` for the images in dir, inside the
// cgroup whose directory descriptor is cgroupFD (so the restored tree
// lands in that leaf), and returns once the tree is running or ctx ends.
// extra holds more criu arguments (external mounts, a new root filesystem
// for trees dumped inside a container). files[i] becomes criu's
// descriptor 3+i, which an "--inherit-fd fd[3+i]:<key>" in extra hands to
// the restored tree.
func (o Options) RestoreWith(ctx context.Context, dir string, cgroupFD int, extra []string, files []*os.File) (*Restored, error) {
	pidfile := filepath.Join(dir, "restore.pid")
	_ = os.Remove(pidfile)
	args := []string{"restore", "--no-default-config",
		"-D", dir, "--pidfile", pidfile,
		"--ext-unix-sk", "--manage-cgroups=ignore",
		"-v2", "--log-file", "restore.log"}
	args = append(args, extra...)
	cmd := exec.Command(o.bin(), args...)
	cmd.ExtraFiles = files
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if cgroupFD >= 0 {
		cmd.SysProcAttr.UseCgroupFD = true
		cmd.SysProcAttr.CgroupFD = cgroupFD
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("criu restore: %w", err)
	}
	// Wait for criu to write the pid file (the tree is up) or to exit
	// (the restore failed), or for ctx.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t := time.NewTicker(5 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case err := <-done:
			if err == nil {
				err = errors.New("exited")
			}
			return nil, fmt.Errorf("criu restore failed: %w%s", err, logTail(filepath.Join(dir, "restore.log")))
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			return nil, ctx.Err()
		case <-t.C:
			if b, err := os.ReadFile(pidfile); err == nil {
				pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
				if err == nil && pid > 0 {
					return &Restored{Cmd: cmd, PID: pid, done: done}, nil
				}
			}
		}
	}
}
