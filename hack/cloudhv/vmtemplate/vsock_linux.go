//go:build linux

package main

import (
	"net"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// dialEngine connects to the engine on the host. Under the fake VMM,
// which names its guest side of the host's ports in FIBERD_FAKE_VSOCK,
// that is the unix socket <name>_<port>, which the fake forwards as a
// real VMM forwards AF_VSOCK. In a VM it is AF_VSOCK to the host, CID 2.
func dialEngine() (net.Conn, error) {
	port, err := hostPort()
	if err != nil {
		return nil, err
	}
	if fake := os.Getenv("FIBERD_FAKE_VSOCK"); fake != "" {
		return net.Dial("unix", fake+"_"+strconv.FormatUint(uint64(port), 10))
	}
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.Connect(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_HOST, Port: port}); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "vsock")
	defer func() { _ = f.Close() }()
	return net.FileConn(f)
}
