//go:build !linux

package main

import (
	"errors"
	"net"
	"os"
	"strconv"
)

// dialEngine reaches the engine only under the fake VMM off Linux, since
// AF_VSOCK is Linux's.
func dialEngine() (engineConn, error) {
	port, err := hostPort()
	if err != nil {
		return nil, err
	}
	fake := os.Getenv("FIBERD_FAKE_VSOCK")
	if fake == "" {
		return nil, errors.New("vsock needs Linux")
	}
	return net.Dial("unix", fake+"_"+strconv.FormatUint(uint64(port), 10))
}
