// Package criu wraps the criu command line for the two things fiberd
// needs: dump one fiber's process tree into an image directory, and
// restore it later into a cgroup leaf of the runtime's choosing.
package criu

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Options select the binary and the flags common to every call.
type Options struct {
	Bin string // default "criu"
}

func (o Options) bin() string {
	if o.Bin != "" {
		return o.Bin
	}
	return "criu"
}

// Available reports whether criu is installed and `criu check` passes.
func (o Options) Available(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, o.bin(), "check", "--no-default-config").CombinedOutput()
	if err != nil {
		return fmt.Errorf("criu check: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Dump checkpoints the tree rooted at pid into dir. With leaveRunning the
// tree keeps running after the dump (the caller kills it once the images
// are durable); otherwise criu kills it as the dump completes.
func (o Options) Dump(ctx context.Context, pid int, dir string, leaveRunning bool) error {
	return o.DumpWith(ctx, pid, dir, leaveRunning, nil)
}

// DumpWith is Dump with extra criu arguments, for example
// "--external", "unix[<inode>]" to allow a socket whose peer lives outside
// the dumped tree (the zygote's control channel at build time).
func (o Options) DumpWith(ctx context.Context, pid int, dir string, leaveRunning bool, extra []string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	args := []string{"dump", "--no-default-config",
		"-t", strconv.Itoa(pid), "-D", dir,
		"--ext-unix-sk", "--manage-cgroups=ignore",
		"-v2", "--log-file", "dump.log"}
	if leaveRunning {
		args = append(args, "--leave-running")
	}
	args = append(args, extra...)
	out, err := exec.CommandContext(ctx, o.bin(), args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("criu dump pid %d: %w: %s%s", pid, err, strings.TrimSpace(string(out)), logTail(filepath.Join(dir, "dump.log")))
	}
	return nil
}

// Restored is a running `criu restore`: it stays alive as the restored
// tree's parent, so Wait returns when the tree exits.
type Restored struct {
	Cmd  *exec.Cmd
	PID  int // the restored root task
	done chan error
}

// Wait blocks until the restored tree (and criu) exit.
func (r *Restored) Wait() error { return <-r.done }

// SocketInode returns the inode of the unix socket a process holds on fd,
// formatted for --external unix[...].
func SocketInode(pid, fd int) (string, error) {
	link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(link, "socket:[") {
		return "", fmt.Errorf("criu: fd %d of %d is %q, not a socket", fd, pid, link)
	}
	return strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), nil
}

// ImageBytes sums the memory image files (pages-*.img) in dir: the size of
// the checkpointed working set until incremental dumps (phase 6) make it
// the delta over the zygote.
func ImageBytes(dir string) (uint64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	var total uint64
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "pages-") && strings.HasSuffix(e.Name(), ".img") {
			if info, err := e.Info(); err == nil {
				total += uint64(info.Size())
			}
		}
	}
	return total, nil
}

func logTail(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) > 8 {
		lines = lines[len(lines)-8:]
	}
	return "\n  " + strings.Join(lines, "\n  ")
}
