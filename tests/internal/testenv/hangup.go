//go:build linux && integration

package testenv

import (
	"io"
	"net"
)

// HangUp ends a conversation with a fiber so that the fiber has closed
// its end by the time it returns. It half-closes c, then reads r (the
// reader the reply came through) until the fiber's EOF, bounded by c's
// deadline. A park right after a plain Close can find the fiber still
// holding the connection, and criu refuses to dump a connected TCP
// socket. Every template here closes a connection once it reads EOF.
func HangUp(c net.Conn, r io.Reader) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok && cw.CloseWrite() == nil {
		_, _ = io.Copy(io.Discard, r)
	}
}
