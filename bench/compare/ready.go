package compare

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Dialer opens one connection to an instance.
type Dialer func(ctx context.Context) (net.Conn, error)

// Framing is how the instance is asked to increment its counter. HTTP is
// POST /incr. Line is the reference workload's line protocol, "incr"
// and a line back, which the Hyperlight helper speaks and HTTP cannot
// reach. Proc runs under both in one run, so the framing gap is measured
// rather than assumed.
type Framing string

const (
	HTTP Framing = "http"
	Line Framing = "line"
)

// incrHTTP is the request the probe sends, written by hand so the first
// byte of the reply is timed as it leaves the kernel, not after a parser
// consumed the whole head.
const incrHTTP = "POST /incr HTTP/1.1\r\nHost: instance\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

// Probe is the ready detector shared by every adapter.
type Probe struct {
	Dial    Dialer
	Framing Framing
	// Poll is the pause between attempts while the instance refuses or
	// resets. It is the quantization bound of every polled system and is
	// recorded with each result. Zero means 1 ms.
	Poll time.Duration
}

// Result is what one successful probe learned.
type Result struct {
	// FirstByte is when the first byte of the first good reply arrived.
	FirstByte time.Time
	// Attempts counts connections that got no good reply before it. Zero
	// means the first request was the measurement, as with fiberd.
	Attempts int
	// Body is the reply's payload, trimmed (the counter).
	Body string
}

// Run polls until the instance answers "incr" with a success, or ctx
// ends. A connection refused, a reset, an empty reply or a non-200 are
// all "not yet". Any other dial error is also retried, since a Pod IP can
// be routable before its port opens.
func (p Probe) Run(ctx context.Context) (Result, error) {
	poll := p.Poll
	if poll <= 0 {
		poll = time.Millisecond
	}
	attempts := 0
	for {
		r, err := p.once(ctx)
		if err == nil {
			r.Attempts = attempts
			return r, nil
		}
		if ctx.Err() != nil {
			return Result{}, fmt.Errorf("compare: not ready after %d attempts: %w (last: %w)", attempts, ctx.Err(), err)
		}
		attempts++
		t := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			t.Stop()
			return Result{}, fmt.Errorf("compare: not ready after %d attempts: %w (last: %w)", attempts, ctx.Err(), err)
		case <-t.C:
		}
	}
}

var errNotReady = errors.New("not ready")

// once is one connection and one request.
func (p Probe) once(ctx context.Context) (Result, error) {
	c, err := p.Dial(ctx)
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = c.Close() }()
	if d, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(d)
	}
	req := incrHTTP
	if p.Framing == Line {
		req = "incr\n"
	}
	if _, err := c.Write([]byte(req)); err != nil {
		return Result{}, err
	}
	// The first byte is read alone, so its arrival is what is stamped.
	one := make([]byte, 1)
	if _, err := c.Read(one); err != nil {
		return Result{}, fmt.Errorf("%w: %w", errNotReady, err)
	}
	first := time.Now()
	r := bufio.NewReader(c)
	rest, _ := r.ReadString('\n')
	line := string(one) + strings.TrimRight(rest, "\r\n")
	if p.Framing == Line {
		if line == "" || strings.HasPrefix(line, "err") {
			return Result{}, fmt.Errorf("%w: reply %q", errNotReady, line)
		}
		return Result{FirstByte: first, Body: line}, nil
	}
	// HTTP: the status line, then the head, then the body.
	f := strings.Fields(line)
	if len(f) < 2 || f[1] != "200" {
		return Result{}, fmt.Errorf("%w: status %q", errNotReady, line)
	}
	for {
		h, err := r.ReadString('\n')
		if err != nil || strings.TrimRight(h, "\r\n") == "" {
			break
		}
	}
	body, _ := r.ReadString('\n')
	return Result{FirstByte: first, Body: strings.TrimSpace(body)}, nil
}

// TCP is a Dialer for host:port.
func TCP(addr string) Dialer {
	return func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
}
