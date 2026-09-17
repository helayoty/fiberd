//go:build linux

package artifact

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/helayoty/fiberd/pkg/sys/criu"
)

// checkpointZygote starts the zygote the way a home does (control channel
// on fd 3, standard descriptors on /dev/null), waits for READY, dumps it
// leaving it running, then ends it. The images are the zygote's memory
// exactly as every fiber inherits it at fork.
func checkpointZygote(ctx context.Context, o BuildOptions, imagesDir string) error {
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
		return err
	}
	defer func() { _ = devnull.Close() }()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, devnull, devnull
	cmd.Dir = imagesDir + ".work" // criu's parasite uses the task's cwd for scratch
	if err := os.MkdirAll(cmd.Dir, 0o755); err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(cmd.Dir) }()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("artifact: start zygote: %w", err)
	}
	_ = child.Close()
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	defer func() {
		_ = cmd.Process.Kill()
		<-waited
	}()

	ready := make(chan error, 1)
	go func() {
		line, err := bufio.NewReader(parent).ReadString('\n')
		if err != nil {
			ready <- err
			return
		}
		if strings.TrimSpace(line) != "READY" {
			ready <- fmt.Errorf("zygote said %q, not READY", strings.TrimSpace(line))
			return
		}
		ready <- nil
	}()
	select {
	case err := <-ready:
		if err != nil {
			return fmt.Errorf("artifact: zygote did not become ready: %w", err)
		}
	case err := <-waited:
		return fmt.Errorf("artifact: zygote exited before READY: %w", err)
	case <-time.After(o.ReadyTimeout):
		return errors.New("artifact: zygote did not become ready in time")
	case <-ctx.Done():
		return ctx.Err()
	}
	_ = os.RemoveAll(imagesDir)
	// The control socket's peer is this process, outside the dumped tree:
	// tell criu it is external. These images are only ever read for their
	// pages; the zygote is never restored from them.
	var extra []string
	if ino, err := criu.SocketInode(cmd.Process.Pid, 3); err == nil {
		extra = []string{"--external", "unix[" + ino + "]"}
	}
	return o.CRIU.DumpWith(ctx, cmd.Process.Pid, imagesDir, true, extra)
}
