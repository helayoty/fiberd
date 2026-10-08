package host

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// A relay is the tcp face of a fiber that can only serve a unix socket.
// It listens on the home's address in the agent's network namespace and
// splices every accepted connection to the fiber's socket under the run
// directory. Bytes are copied, never read, so TLS end to end keeps the
// agent blind. It dials the one path the host minted for the fence and
// nothing a caller sends can change that.
//
//	caller --tcp--> relay (agent) --unix--> <run-dir>/<grant>/<epoch>-<seq>.sock
//
// gVisor (--network=none), Hyperlight (the helper serves the socket) and
// runc (a loopback-only network namespace) are reached this way under an
// inet family. proc binds the port itself and has no relay.
type relay struct {
	ln   net.Listener
	sock string

	// slots caps the connections open at once for this fiber. total is
	// the home's cap across fibers; nil means none.
	slots, total chan struct{}

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup

	// refused counts connections closed at the caps or before a dial,
	// for logs and tests.
	refused atomic.Int64
}

const (
	// relayMaxConns is one fiber's cap on open relayed connections, and
	// relayMaxTotal the home's across fibers. Beyond either a new
	// connection is closed at once, as the handoff router does past its
	// pending caps.
	relayMaxConns = 256
	relayMaxTotal = 4096
	// relayDialTimeout bounds the dial of the fiber's socket; it is local.
	relayDialTimeout = 5 * time.Second
	// relayKeepAlive is the TCP keepalive on accepted connections, so a
	// peer that vanished is noticed. There is no idle timeout: the fiber
	// decides when a connection ends.
	relayKeepAlive = 30 * time.Second
	// Accept backoff, as net/http and the handoff router do.
	relayBackoffMin = 5 * time.Millisecond
	relayBackoffMax = time.Second
)

// listenRelay binds addr on network ("tcp4" or "tcp6") and starts
// relaying to sock. maxConns caps one fiber's connections (relayMaxConns
// when 0); total is the home's shared cap, or nil.
func listenRelay(network, addr, sock string, maxConns int, total chan struct{}) (*relay, error) {
	if maxConns <= 0 {
		maxConns = relayMaxConns
	}
	lc := net.ListenConfig{KeepAlive: relayKeepAlive}
	ln, err := lc.Listen(context.Background(), network, addr)
	if err != nil {
		return nil, err
	}
	r := &relay{ln: ln, sock: sock, slots: make(chan struct{}, maxConns), total: total, conns: map[net.Conn]struct{}{}}
	r.wg.Add(1)
	go r.serve()
	return r, nil
}

// Addr is where the relay listens.
func (r *relay) Addr() net.Addr { return r.ln.Addr() }

// serve accepts until the listener is closed. Each connection takes a
// slot of the fiber's and one of the home's, or is closed at once.
func (r *relay) serve() {
	defer r.wg.Done()
	var backoff time.Duration
	for {
		c, err := r.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			backoff = min(2*backoff, relayBackoffMax)
			if backoff == 0 {
				backoff = relayBackoffMin
			}
			log.Printf("host: relay %s: accept: %v; retrying in %s", r.sock, err, backoff)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		if !r.take() {
			r.refused.Add(1)
			_ = c.Close()
			continue
		}
		if !r.track(c) { // closed meanwhile
			r.give()
			_ = c.Close()
			continue
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			defer r.give()
			r.splice(c)
		}()
	}
}

// take claims a slot of the fiber's and of the home's, or neither.
func (r *relay) take() bool {
	select {
	case r.slots <- struct{}{}:
	default:
		return false
	}
	if r.total == nil {
		return true
	}
	select {
	case r.total <- struct{}{}:
		return true
	default:
		<-r.slots
		return false
	}
}

func (r *relay) give() {
	<-r.slots
	if r.total != nil {
		<-r.total
	}
}

// splice copies c to the fiber's socket and back until both directions
// are done, then closes both.
func (r *relay) splice(c net.Conn) {
	defer r.untrack(c)
	d := net.Dialer{Timeout: relayDialTimeout}
	u, err := d.Dial("unix", r.sock)
	if err != nil {
		r.refused.Add(1)
		log.Printf("host: relay %s: %v", r.sock, err)
		return
	}
	if !r.track(u) {
		_ = u.Close()
		return
	}
	defer r.untrack(u)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); copyHalf(u, c) }()
	go func() { defer wg.Done(); copyHalf(c, u) }()
	wg.Wait()
}

// copyHalf copies src to dst. A clean end half-closes dst so the peer
// sees EOF and may still answer; a broken read ends both, so the other
// direction does not wait on a peer that is gone.
func copyHalf(dst, src net.Conn) {
	_, err := io.Copy(dst, src)
	if err != nil && !errors.Is(err, net.ErrClosed) {
		_ = dst.Close()
		_ = src.Close()
		return
	}
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	} else {
		_ = dst.Close()
	}
}

// track records an open connection so Close can end it. It reports
// false once the relay is closed.
func (r *relay) track(c net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	r.conns[c] = struct{}{}
	return true
}

// untrack forgets and closes a connection.
func (r *relay) untrack(c net.Conn) {
	r.mu.Lock()
	delete(r.conns, c)
	r.mu.Unlock()
	_ = c.Close()
}

// open is how many connections are open, for tests.
func (r *relay) open() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.conns)
}

// Close stops accepting, closes every open connection and waits for the
// copies to end. It is idempotent.
func (r *relay) Close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	conns := make([]net.Conn, 0, len(r.conns))
	for c := range r.conns {
		conns = append(conns, c)
	}
	r.mu.Unlock()
	_ = r.ln.Close()
	for _, c := range conns {
		_ = c.Close()
	}
	r.wg.Wait()
}
