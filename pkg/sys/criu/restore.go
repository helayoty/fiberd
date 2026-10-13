package criu

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	p, err := o.commander().Start(restoreArgs(dir, extra), files, cgroupFD)
	if err != nil {
		return nil, fmt.Errorf("criu restore: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- p.Wait() }()
	pid, err := awaitRestore(ctx, pidfile, done)
	if err != nil {
		if errors.Is(err, ctx.Err()) {
			_ = p.Kill()
			return nil, err
		}
		return nil, fmt.Errorf("criu restore failed: %w%s", err, logTail(filepath.Join(dir, "restore.log")))
	}
	return &Restored{Process: p, PID: pid, done: done}, nil
}

// restoreArgs is criu's argument list for a restore of the images in dir.
func restoreArgs(dir string, extra []string) []string {
	args := []string{"restore", "--no-default-config",
		"-D", dir, "--pidfile", filepath.Join(dir, "restore.pid"),
		"--ext-unix-sk", "--manage-cgroups=ignore",
		"-v2", "--log-file", "restore.log"}
	return append(args, extra...)
}

// readPidfile reads the pid criu wrote, and false while the file is
// missing or not yet a whole pid.
func readPidfile(path string) (int, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

// awaitRestore waits for criu to write the pid file (the tree is up), or
// to exit first (the restore failed, with its exit error, or "exited"
// when it reported none), or for ctx to end.
func awaitRestore(ctx context.Context, pidfile string, done <-chan error) (int, error) {
	t := time.NewTicker(5 * time.Millisecond)
	defer t.Stop()
	for {
		if pid, ok := readPidfile(pidfile); ok {
			return pid, nil
		}
		select {
		case err := <-done:
			if err == nil {
				err = errors.New("exited")
			}
			return 0, err
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-t.C:
		}
	}
}
