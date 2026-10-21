//go:build linux

package artifact

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/helayoty/fiberd/pkg/sys/criu"
)

// checkpointZygote runs the zygote to READY, dumps it leaving it running,
// then ends it. The images are the zygote's memory exactly as every fiber
// inherits it at fork.
func checkpointZygote(ctx context.Context, o BuildOptions, imagesDir string) error {
	work := imagesDir + ".work" // criu's parasite uses the task's cwd for scratch
	if err := os.MkdirAll(work, 0o755); err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(work) }()
	return runZygote(ctx, o, work, func(pid int) error {
		_ = os.RemoveAll(imagesDir)
		// The control socket's peer is this process, outside the dumped
		// tree: tell criu it is external. These images are only ever read
		// for their pages; the zygote is never restored from them.
		var extra []string
		if ino, err := criu.SocketInode(pid, 3); err == nil {
			extra = []string{"--external", "unix[" + ino + "]"}
		}
		return o.CRIU.DumpWith(ctx, pid, imagesDir, true, extra)
	})
}

// smokeZygote runs the zygote to READY and ends it, with no criu. It is
// what a build without images checks, so an artifact whose zygote cannot
// start is refused here and not at its first warm on a home.
func smokeZygote(ctx context.Context, o BuildOptions) error {
	work, err := os.MkdirTemp("", "zygotectl-smoke-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(work) }()
	return runZygote(ctx, o, work, nil)
}

// runZygote starts the zygote the way a home does (control channel on fd
// 3, standard descriptors on /dev/null) in the directory work, tells it
// PREPARE none, since no fiber is forked here and it is to stay in this
// namespace, waits for READY, runs at (when set) with its pid, then ends
// it.
func runZygote(ctx context.Context, o BuildOptions, work string, at func(pid int) error) error {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	parent := os.NewFile(uintptr(fds[0]), "ctl")
	child := os.NewFile(uintptr(fds[1]), "ctl-child")
	defer func() { _ = parent.Close() }()
	cmd := exec.Command(ZygotePath(o.Out), o.Args...)
	cmd.ExtraFiles = []*os.File{child}
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	// A session leader, as criu requires of a dump root outside a shell job.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		_ = child.Close()
		return err
	}
	defer func() { _ = devnull.Close() }()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, devnull, devnull
	cmd.Dir = work
	if err := cmd.Start(); err != nil {
		_ = child.Close()
		return fmt.Errorf("artifact: start zygote: %w", err)
	}
	_ = child.Close()
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	defer func() {
		_ = cmd.Process.Kill()
		<-waited
	}()
	// fiberd speaks first (sdk/c/template/libfiberzygote.h). A zygote that
	// exited already fails the write, and is reported below as such.
	_, _ = parent.Write([]byte("PREPARE none\n"))
	if err := awaitReady(ctx, parent, waited, o.ReadyTimeout); err != nil {
		return err
	}
	if at == nil {
		return nil
	}
	return at(cmd.Process.Pid)
}
