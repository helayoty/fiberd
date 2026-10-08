//go:build !linux

package host

import (
	"fmt"
	"net"
	"os"
	"time"
)

// dialFiberSocket connects to the unix socket at path. Only Linux runs
// fibers; here, for the relay's own tests, a link planted at the name is
// refused by a check before the dial, with the gap that leaves.
func dialFiberSocket(path string, timeout time.Duration) (net.Conn, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode()&os.ModeType != os.ModeSocket {
		return nil, fmt.Errorf("%s is not a socket (%s)", path, st.Mode().Type())
	}
	d := net.Dialer{Timeout: timeout}
	return d.Dial("unix", path)
}
