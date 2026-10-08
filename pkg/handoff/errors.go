package handoff

import "errors"

var (
	// ErrShort means the bytes end before the ClientHello does. Read more.
	ErrShort = errors.New("handoff: ClientHello incomplete")
	// ErrNotTLS means the connection does not start with a TLS handshake
	// record.
	ErrNotTLS = errors.New("handoff: not a TLS ClientHello")
	// ErrMalformed means a length or field in the ClientHello is
	// inconsistent, or the ClientHello does not fit in its first record.
	ErrMalformed = errors.New("handoff: malformed ClientHello")
	// ErrNoServerName means the ClientHello names no server.
	ErrNoServerName = errors.New("handoff: ClientHello has no server name")
	// ErrUnknownRoute means the server name is not a routing key this agent
	// handed out, or the fiber behind it is gone.
	ErrUnknownRoute = errors.New("handoff: unknown routing key")
	// ErrKeyMismatch means the fiber's TLS key is not the one the home
	// pinned for it.
	ErrKeyMismatch = errors.New("handoff: fiber key does not match its pin")
)
