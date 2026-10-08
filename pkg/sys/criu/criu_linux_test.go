//go:build linux

package criu_test

import (
	"errors"
	"io/fs"
	"math"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/helayoty/fiberd/pkg/sys/criu"
)

// TestSocketInode checks that the inode a unix socket's fd link names is the
// socket's inode, and anything else on the descriptor is refused.
func TestSocketInode(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(fds[0]); _ = syscall.Close(fds[1]) })
	var st syscall.Stat_t
	if err := syscall.Fstat(fds[0], &st); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })

	cases := []struct {
		name    string
		pid, fd int
		want    string
		wantErr string
		wantIs  error
	}{
		{name: "a unix socket", pid: os.Getpid(), fd: fds[0], want: strconv.FormatUint(st.Ino, 10)},
		{name: "not a socket", pid: os.Getpid(), fd: int(f.Fd()), wantErr: "not a socket"},
		{name: "no such descriptor", pid: os.Getpid(), fd: 1 << 20, wantIs: fs.ErrNotExist},
		{name: "no such process", pid: math.MaxInt32, fd: 0, wantIs: fs.ErrNotExist},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := criu.SocketInode(tc.pid, tc.fd)
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("SocketInode = %q, %v, want %v", got, err, tc.wantIs)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("SocketInode = %q, %v, want an error containing %q", got, err, tc.wantErr)
			}
			if tc.wantIs == nil && tc.wantErr == "" && (err != nil || got != tc.want) {
				t.Fatalf("SocketInode = %q, %v, want %q", got, err, tc.want)
			}
		})
	}
}
