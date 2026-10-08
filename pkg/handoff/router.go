package handoff

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Defaults for Router.
const (
	DefaultHelloTimeout = time.Second
	DefaultMaxPending   = 1024
)

// maxPendingPerIP bounds one source address's share of the pending
// slots. It is a fixed 32, not a fraction of MaxPending. Holding all 1024
// default slots then takes 32 addresses, and a host behind one NAT can
// still open 32 connections at once. An IPv6 caller with a /64 has many
// addresses, but the global cap still holds for it.
const maxPendingPerIP = 32

var keyEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Router owns the home's handoff listener. Routing keys live in memory
// only. An agent restart ends every fiber, so no key outlives the agent.
type Router struct {
	// Advertise is the address callers dial (tcp://host:port).
	Advertise string
	// Deliver passes a connected socket to the fiber. The router closes
	// its own copy afterwards.
	Deliver func(fiberID string, conn *os.File) error
	// HelloTimeout bounds how long a connection may take to send its
	// ClientHello (DefaultHelloTimeout when zero).
	HelloTimeout time.Duration
	// MaxPending bounds connections waiting for their ClientHello. Beyond
	// it, new ones are closed at once (DefaultMaxPending when zero).
	MaxPending int

	mu      sync.Mutex
	keys    map[string]string // routing key -> fiber id
	byFiber map[string]string // fiber id -> routing key
	perIP   map[string]int    // source IP -> connections pending

	routed, refused atomic.Uint64
}

// Stats counts connections passed to a fiber and connections closed
// without one.
type Stats struct {
	Routed, Refused uint64
}

func (r *Router) Stats() Stats { return Stats{Routed: r.routed.Load(), Refused: r.refused.Load()} }

// Add gives a fiber a fresh routing key and returns it.
func (r *Router) Add(fiberID string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	key := strings.ToLower(keyEncoding.EncodeToString(b))
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.keys == nil {
		r.keys, r.byFiber = map[string]string{}, map[string]string{}
	}
	if old, ok := r.byFiber[fiberID]; ok {
		delete(r.keys, old)
	}
	r.keys[key] = fiberID
	r.byFiber[fiberID] = key
	return key, nil
}

// Remove forgets a fiber's routing key.
func (r *Router) Remove(fiberID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if key, ok := r.byFiber[fiberID]; ok {
		delete(r.keys, key)
		delete(r.byFiber, fiberID)
	}
}

// Key returns a fiber's routing key.
func (r *Router) Key(fiberID string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key, ok := r.byFiber[fiberID]
	return key, ok
}

func (r *Router) lookup(serverName string) (string, bool) {
	key, ok := strings.CutSuffix(strings.ToLower(serverName), Suffix)
	if !ok {
		return "", false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.keys[key]
	return id, ok
}

// Accept backoff. A failed accept (out of file descriptors, say) is
// retried after a pause that doubles up to a cap, as net/http does.
const (
	acceptBackoffMin = 5 * time.Millisecond
	acceptBackoffMax = time.Second
)

// Serve accepts on l until it is closed.
func (r *Router) Serve(l net.Listener) error {
	max := r.MaxPending
	if max <= 0 {
		max = DefaultMaxPending
	}
	pending := make(chan struct{}, max)
	var backoff time.Duration
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			backoff = min(2*backoff, acceptBackoffMax)
			if backoff == 0 {
				backoff = acceptBackoffMin
			}
			log.Printf("handoff: accept: %v; retrying in %s", err, backoff)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		ip := sourceIP(c)
		if !r.hold(ip) {
			r.refused.Add(1)
			_ = c.Close()
			continue
		}
		select {
		case pending <- struct{}{}:
			go func() {
				defer func() { <-pending; r.release(ip) }()
				if err := r.route(c); err != nil {
					r.refused.Add(1)
				} else {
					r.routed.Add(1)
				}
			}()
		default:
			r.release(ip)
			r.refused.Add(1)
			_ = c.Close()
		}
	}
}

// hold takes one of ip's pending slots, if it has one free.
func (r *Router) hold(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.perIP[ip] >= maxPendingPerIP {
		return false
	}
	if r.perIP == nil {
		r.perIP = map[string]int{}
	}
	r.perIP[ip]++
	return true
}

func (r *Router) release(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.perIP[ip]--; r.perIP[ip] <= 0 {
		delete(r.perIP, ip)
	}
}

// sourceIP is the address c came from, without its port.
func sourceIP(c net.Conn) string {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return a.IP.String()
	}
	return c.RemoteAddr().String()
}

// route reads c's server name, passes c to its fiber and closes the
// router's copy either way.
func (r *Router) route(c net.Conn) error {
	defer func() { _ = c.Close() }()
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("handoff: %T is not a TCP connection", c)
	}
	timeout := r.HelloTimeout
	if timeout <= 0 {
		timeout = DefaultHelloTimeout
	}
	deadline := time.Now().Add(timeout)
	if err := tc.SetReadDeadline(deadline); err != nil {
		return err
	}
	name, err := peekServerName(tc, deadline)
	if err != nil {
		return err
	}
	fiberID, ok := r.lookup(name)
	if !ok {
		return ErrUnknownRoute
	}
	f, err := tc.File()
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	// The copy shares the socket's flags. Clear O_NONBLOCK so the fiber
	// gets it blocking, as from accept(2).
	if err := syscall.SetNonblock(int(f.Fd()), false); err != nil {
		return err
	}
	if r.Deliver == nil {
		return ErrUnknownRoute
	}
	return r.Deliver(fiberID, f)
}

// helloBackoff paces re-reads of a ClientHello that arrived in pieces.
const helloBackoff = 5 * time.Millisecond

// peekServerName reads the ClientHello with MSG_PEEK, leaving every byte
// in the socket for the fiber. It stops once the server name is known, the
// hello is refused, or deadline passes. It peeks the record header first,
// then only as much as the record it announces.
func peekServerName(tc *net.TCPConn, deadline time.Time) (string, error) {
	rc, err := tc.SyscallConn()
	if err != nil {
		return "", err
	}
	buf := make([]byte, 5)
	for {
		var n int
		var rerr error
		// The poller waits only while nothing at all has arrived.
		err := rc.Read(func(fd uintptr) bool {
			n, _, rerr = syscall.Recvfrom(int(fd), buf, syscall.MSG_PEEK)
			return !errors.Is(rerr, syscall.EAGAIN)
		})
		if err != nil {
			return "", err
		}
		if rerr != nil {
			return "", rerr
		}
		if n == 0 {
			return "", fmt.Errorf("%w: closed before the ClientHello", ErrShort)
		}
		name, err := ServerName(buf[:n])
		if !errors.Is(err, ErrShort) {
			return name, err
		}
		if n == 5 && len(buf) == 5 {
			// ServerName checked the header and bounded its length.
			buf = make([]byte, 5+int(binary.BigEndian.Uint16(buf[3:5])))
			continue
		}
		// Part of it is here. Peeking again returns the same bytes until
		// the rest arrives, so wait a little rather than spin.
		if time.Now().Add(helloBackoff).After(deadline) {
			return "", os.ErrDeadlineExceeded
		}
		time.Sleep(helloBackoff)
	}
}
