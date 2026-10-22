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
	// Wrap is a command a restore runs through, given criu and its
	// arguments after its own: for a restore that needs mounts of its
	// own (the runc backend's /sys bind). It must exec criu in place,
	// so the pid stays criu's.
	Wrap []string
	// Commander runs criu. Nil runs the binary Bin names, so a test can
	// stand in for criu without a process.
	Commander Commander
}

// Commander is how the package runs criu. Output runs a check or a dump
// to its end and returns what it printed. Start begins a restore with
// files as criu's descriptors 3 and up, inside the cgroup cgroupFD
// names when it is not negative, and returns the running process.
type Commander interface {
	Output(ctx context.Context, args []string) ([]byte, error)
	Start(args []string, files []*os.File, cgroupFD int) (Process, error)
}

// Process is a started criu. Wait returns its exit error, nil for a
// clean exit.
type Process interface {
	Pid() int
	Kill() error
	Wait() error
}

func (o Options) bin() string {
	if o.Bin != "" {
		return o.Bin
	}
	return "criu"
}

func (o Options) commander() Commander {
	if o.Commander != nil {
		return o.Commander
	}
	return execCommander{opt: o}
}

// restoreArgv is the command line of a restore, through Wrap when set.
func (o Options) restoreArgv(args []string) []string {
	return append(append(append([]string{}, o.Wrap...), o.bin()), args...)
}

// execCommander runs the real binary.
type execCommander struct{ opt Options }

func (e execCommander) Output(ctx context.Context, args []string) ([]byte, error) {
	return exec.CommandContext(ctx, e.opt.bin(), args...).CombinedOutput()
}

func (e execCommander) Start(args []string, files []*os.File, cgroupFD int) (Process, error) {
	argv := e.opt.restoreArgv(args)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.ExtraFiles = files
	cmd.SysProcAttr = sysProcAttr(cgroupFD)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmdProcess{cmd}, nil
}

// cmdProcess is a started exec.Cmd as a Process.
type cmdProcess struct{ cmd *exec.Cmd }

func (p cmdProcess) Pid() int    { return p.cmd.Process.Pid }
func (p cmdProcess) Kill() error { return p.cmd.Process.Kill() }
func (p cmdProcess) Wait() error { return p.cmd.Wait() }

// MinVersion is the oldest criu fiberd parks with. Older ones dump glibc's
// getrandom state page (2.41 and later) and restore it as plain memory,
// so every copy resumed from one park continues one keystream, and on
// recent kernels the dump of that page fails outright.
var MinVersion = [2]int{4, 2}

// Available reports whether criu is installed, at least MinVersion, and
// `criu check` passes.
func (o Options) Available(ctx context.Context) error {
	out, err := o.commander().Output(ctx, []string{"--version"})
	if err != nil {
		return fmt.Errorf("criu --version: %w: %s", err, strings.TrimSpace(string(out)))
	}
	v, ok := parseVersion(out)
	if !ok {
		return fmt.Errorf("criu --version printed no version: %q", strings.TrimSpace(string(out)))
	}
	if v[0] < MinVersion[0] || v[0] == MinVersion[0] && v[1] < MinVersion[1] {
		return fmt.Errorf("criu %d.%d is older than %d.%d, which fiberd needs so a resume never replays getrandom", v[0], v[1], MinVersion[0], MinVersion[1])
	}
	out, err = o.commander().Output(ctx, []string{"check", "--no-default-config"})
	if err != nil {
		return fmt.Errorf("criu check: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// parseVersion reads major and minor from `criu --version`, whose first
// line is "Version: 4.2.1".
func parseVersion(out []byte) ([2]int, bool) {
	for _, line := range strings.Split(string(out), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "Version:")
		if !ok {
			continue
		}
		parts := strings.SplitN(strings.TrimSpace(rest), ".", 3)
		if len(parts) < 2 {
			return [2]int{}, false
		}
		major, err1 := strconv.Atoi(parts[0])
		minor, err2 := strconv.Atoi(parts[1])
		return [2]int{major, minor}, err1 == nil && err2 == nil
	}
	return [2]int{}, false
}

// After says what becomes of the dumped tree once the images are
// written.
type After int

const (
	// Kill ends the tree as the dump completes.
	Kill After = iota
	// LeaveRunning lets the tree run on, and the caller ends it once the
	// images are durable.
	LeaveRunning
	// LeaveStopped leaves every task of the tree stopped, so nothing it
	// could write between the dump and what the caller records next is
	// missed. The caller continues or kills it. A tree with a pid
	// namespace of its own is continued task by task, since SIGCONT to
	// its root reaches that process alone.
	LeaveStopped
)

// DumpWith checkpoints the tree rooted at pid into dir, and after says
// what becomes of the tree once the images are written. extra holds
// more criu arguments, for example "--external", "unix[<inode>]" to
// allow a socket whose peer lives outside the dumped tree (the zygote's
// control channel at build time).
func (o Options) DumpWith(ctx context.Context, pid int, dir string, after After, extra []string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	args := []string{"dump", "--no-default-config",
		"-t", strconv.Itoa(pid), "-D", dir,
		"--ext-unix-sk", "--manage-cgroups=ignore",
		"-v2", "--log-file", "dump.log"}
	switch after {
	case LeaveRunning:
		args = append(args, "--leave-running")
	case LeaveStopped:
		args = append(args, "--leave-stopped")
	}
	args = append(args, extra...)
	out, err := o.commander().Output(ctx, args)
	if err != nil {
		return fmt.Errorf("criu dump pid %d: %w: %s%s", pid, err, strings.TrimSpace(string(out)), logTail(filepath.Join(dir, "dump.log")))
	}
	return nil
}

// Restored is a running `criu restore`: it stays alive as the restored
// tree's parent, so Wait returns when the tree exits.
type Restored struct {
	Process Process
	PID     int // the restored root task
	done    chan error
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
