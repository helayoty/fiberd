package handoff

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fiber stands in for a handoff fiber. It serves TLS with the grant's
// identity on every connection the router passes it, echoing one line.
func fiber(t *testing.T, id Identity) func(string, *os.File) error {
	t.Helper()
	pair, err := tls.X509KeyPair(id.CertPEM, id.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return func(_ string, f *os.File) error {
		c, err := net.FileConn(f) // a copy, since the router closes f
		if err != nil {
			return err
		}
		go func() {
			defer func() { _ = c.Close() }()
			s := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13})
			line, err := bufio.NewReader(s).ReadString('\n')
			if err == nil {
				_, _ = fmt.Fprintf(s, "echo %s", line)
			}
		}()
		return nil
	}
}

func TestRouter(t *testing.T) {
	id, err := Derive(bytes.Repeat([]byte{7}, 32), "g1")
	if err != nil {
		t.Fatal(err)
	}
	other, err := Derive(bytes.Repeat([]byte{8}, 32), "g1")
	if err != nil {
		t.Fatal(err)
	}
	// tlsCall dials the router as a caller does (ClientConfig), sending
	// serverName as the SNI. It returns the echoed line.
	tlsCall := func(serverName, pin string) func(t *testing.T, addr string) (string, error) {
		return func(t *testing.T, addr string) (string, error) {
			cfg := ClientConfig("", pin, tls.Certificate{})
			cfg.ServerName = serverName
			c, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, cfg)
			if err != nil {
				return "", err
			}
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := fmt.Fprintln(c, "hi"); err != nil {
				return "", err
			}
			return bufio.NewReader(c).ReadString('\n')
		}
	}
	// raw writes b (if any) and returns what comes back before the
	// router closes the connection.
	raw := func(b []byte) func(t *testing.T, addr string) (string, error) {
		return func(t *testing.T, addr string) (string, error) {
			c, err := net.Dial("tcp", addr)
			if err != nil {
				return "", err
			}
			defer func() { _ = c.Close() }()
			if len(b) > 0 {
				if _, err := c.Write(b); err != nil {
					return "", err
				}
			}
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			got, err := bufio.NewReader(c).ReadString('\n')
			return got, err
		}
	}

	cases := []struct {
		name string
		// setup returns the server name to use, given the router.
		setup       func(t *testing.T, r *Router) string
		call        func(name string) func(t *testing.T, addr string) (string, error)
		want        string
		wantErr     error
		wantRefused uint64
		noDeliver   bool // the router has no Deliver func
		hello       time.Duration
	}{
		{
			name:  "routed to the fiber, which terminates TLS",
			setup: func(t *testing.T, r *Router) string { return mustAdd(t, r, "g1/1/1") + Suffix },
			call:  func(n string) func(*testing.T, string) (string, error) { return tlsCall(n, id.KeySHA256) },
			want:  "echo hi\n",
		},
		{
			name:  "routed under the default hello timeout",
			setup: func(t *testing.T, r *Router) string { return mustAdd(t, r, "g1/1/1") + Suffix },
			call:  func(n string) func(*testing.T, string) (string, error) { return tlsCall(n, id.KeySHA256) },
			want:  "echo hi\n", hello: -1,
		},
		{
			name:        "a known key with nowhere to deliver is refused",
			setup:       func(t *testing.T, r *Router) string { return mustAdd(t, r, "g1/1/1") + Suffix },
			call:        func(n string) func(*testing.T, string) (string, error) { return tlsCall(n, id.KeySHA256) },
			noDeliver:   true,
			wantRefused: 1,
		},
		{
			name:        "a caller that resets before its hello is refused",
			setup:       func(*testing.T, *Router) string { return "" },
			call:        func(string) func(*testing.T, string) (string, error) { return reset },
			wantRefused: 1,
		},
		{
			name:  "server name case does not matter",
			setup: func(t *testing.T, r *Router) string { return strings.ToUpper(mustAdd(t, r, "g1/1/1")) + Suffix },
			call:  func(n string) func(*testing.T, string) (string, error) { return tlsCall(n, id.KeySHA256) },
			want:  "echo hi\n",
		},
		{
			name:    "caller refuses a fiber with another key",
			setup:   func(t *testing.T, r *Router) string { return mustAdd(t, r, "g1/1/1") + Suffix },
			call:    func(n string) func(*testing.T, string) (string, error) { return tlsCall(n, other.KeySHA256) },
			wantErr: ErrKeyMismatch,
		},
		{
			name:        "unknown key",
			setup:       func(t *testing.T, r *Router) string { mustAdd(t, r, "g1/1/1"); return "aaaa" + Suffix },
			call:        func(n string) func(*testing.T, string) (string, error) { return tlsCall(n, id.KeySHA256) },
			wantRefused: 1,
		},
		{
			name: "removed fiber",
			setup: func(t *testing.T, r *Router) string {
				k := mustAdd(t, r, "g1/1/1")
				r.Remove("g1/1/1")
				return k + Suffix
			},
			call:        func(n string) func(*testing.T, string) (string, error) { return tlsCall(n, id.KeySHA256) },
			wantRefused: 1,
		},
		{
			name: "re-added fiber drops its old key",
			setup: func(t *testing.T, r *Router) string {
				old := mustAdd(t, r, "g1/1/1")
				mustAdd(t, r, "g1/1/1")
				return old + Suffix
			},
			call:        func(n string) func(*testing.T, string) (string, error) { return tlsCall(n, id.KeySHA256) },
			wantRefused: 1,
		},
		{
			name:        "key without the suffix",
			setup:       func(t *testing.T, r *Router) string { return mustAdd(t, r, "g1/1/1") },
			call:        func(n string) func(*testing.T, string) (string, error) { return tlsCall(n, id.KeySHA256) },
			wantRefused: 1,
		},
		{
			name:        "plaintext is closed without a reply",
			setup:       func(*testing.T, *Router) string { return "" },
			call:        func(string) func(*testing.T, string) (string, error) { return raw([]byte("GET / HTTP/1.1\r\n\r\n")) },
			wantRefused: 1,
		},
		{
			name:        "silent caller is closed at the deadline",
			setup:       func(*testing.T, *Router) string { return "" },
			call:        func(string) func(*testing.T, string) (string, error) { return raw(nil) },
			wantRefused: 1,
		},
		{
			name:        "ClientHello in pieces past the deadline",
			setup:       func(*testing.T, *Router) string { return "" },
			call:        func(string) func(*testing.T, string) (string, error) { return raw(clientHello(t, "x.fiberd")[:20]) },
			wantRefused: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			r := &Router{Deliver: fiber(t, id), HelloTimeout: 200 * time.Millisecond}
			if tc.noDeliver {
				r.Deliver = nil
			}
			if tc.hello < 0 {
				r.HelloTimeout = 0
			}
			done := make(chan error, 1)
			go func() { done <- r.Serve(l) }()
			t.Cleanup(func() {
				_ = l.Close()
				if err := <-done; err != nil {
					t.Errorf("serve: %v", err)
				}
			})
			got, err := tc.call(tc.setup(t, r))(t, l.Addr().String())
			if got != tc.want {
				t.Fatalf("reply = %q (%v), want %q", got, err, tc.want)
			}
			if tc.want == "" && err == nil {
				t.Fatal("want the connection refused")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			// The refusal is counted once the router's goroutine ends.
			for i := 0; i < 100 && r.Stats().Refused < tc.wantRefused; i++ {
				time.Sleep(10 * time.Millisecond)
			}
			if st := r.Stats(); st.Refused != tc.wantRefused {
				t.Fatalf("stats = %+v, want refused %d", st, tc.wantRefused)
			}
		})
	}
}

// Callers that have not sent a ClientHello hold a pending slot. Once
// MaxPending of them wait, or maxPendingPerIP from one address, the next
// caller from that address is closed at once and counted as refused. A
// caller with a slot free waits for its hello.
func TestRouterMaxPending(t *testing.T) {
	cases := []struct {
		name        string
		maxPending  int
		holders     int    // silent callers dialled first, from 127.0.0.1
		nextFrom    string // the next caller's address (127.0.0.1 when empty)
		wantClosed  bool   // the next caller is closed at once
		wantRefused uint64
	}{
		{name: "one silent caller holds the only slot: the next is closed at once", maxPending: 1, holders: 1, wantClosed: true, wantRefused: 1},
		{name: "a slot left free: the next caller waits for its hello", maxPending: 2, holders: 1},
		{name: "two silent callers fill two slots: the next is closed at once", maxPending: 2, holders: 2, wantClosed: true, wantRefused: 1},
		{name: "one address at its own cap: its next caller is closed at once", maxPending: 2 * maxPendingPerIP, holders: maxPendingPerIP, wantClosed: true, wantRefused: 1},
		{name: "one address at its own cap: another address still waits for its hello", maxPending: 2 * maxPendingPerIP, holders: maxPendingPerIP, nextFrom: "127.0.0.2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			r := &Router{MaxPending: tc.maxPending, HelloTimeout: time.Second}
			go func() { _ = r.Serve(l) }()
			t.Cleanup(func() { _ = l.Close() })
			dial := func(from string) net.Conn {
				var d net.Dialer
				if from != "" {
					d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(from)}
				}
				c, err := d.Dial("tcp", l.Addr().String())
				if err != nil && from != "" {
					t.Skipf("cannot dial from %s on this host (Linux routes all of 127/8): %v", from, err)
				}
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = c.Close() })
				return c
			}
			for i := 0; i < tc.holders; i++ {
				dial("")
			}
			waitPending(t, r, "127.0.0.1", tc.holders)
			c := dial(tc.nextFrom)
			_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			_, err = c.Read(make([]byte, 1))
			closed := err != nil && !errors.Is(err, os.ErrDeadlineExceeded)
			if closed != tc.wantClosed {
				t.Fatalf("next caller: err = %v, closed at once = %v, want %v", err, closed, tc.wantClosed)
			}
			if st := r.Stats(); st.Refused != tc.wantRefused {
				t.Fatalf("stats = %+v, want refused %d", st, tc.wantRefused)
			}
		})
	}
}

// A failed accept (out of file descriptors, say) does not end Serve. It
// backs off and accepts again, and returns nil once the listener closes.
func TestRouterAcceptErrors(t *testing.T) {
	emfile := &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept", syscall.EMFILE)}
	timeout := &net.OpError{Op: "accept", Net: "tcp", Err: os.ErrDeadlineExceeded}
	cases := []struct {
		name string
		errs []error // Accept returns these first, then a connection
	}{
		{name: "no errors"},
		{name: "out of file descriptors three times", errs: []error{emfile, emfile, emfile}},
		{name: "a timeout", errs: []error{timeout}},
		{name: "some other error", errs: []error{errors.New("accept: boom")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			t.Cleanup(func() { _ = client.Close() })
			l := &fakeListener{errs: tc.errs, conn: server}
			r := &Router{}
			done := make(chan error, 1)
			go func() { done <- r.Serve(l) }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("serve = %v, want nil once closed", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("serve did not return after the listener closed")
			}
			// The connection was accepted after the errors. A pipe is not
			// TCP, so the router refuses it.
			for i := 0; i < 100 && r.Stats().Refused < 1; i++ {
				time.Sleep(10 * time.Millisecond)
			}
			if st := r.Stats(); st.Refused != 1 {
				t.Fatalf("stats = %+v, want the connection after the errors refused", st)
			}
		})
	}
}

// fakeListener returns errs, then conn, then net.ErrClosed.
type fakeListener struct {
	errs []error
	conn net.Conn
}

func (l *fakeListener) Accept() (net.Conn, error) {
	if len(l.errs) > 0 {
		err := l.errs[0]
		l.errs = l.errs[1:]
		return nil, err
	}
	if c := l.conn; c != nil {
		l.conn = nil
		return c, nil
	}
	return nil, net.ErrClosed
}

func (l *fakeListener) Close() error   { return nil }
func (l *fakeListener) Addr() net.Addr { return &net.TCPAddr{} }

// reset dials addr and aborts the connection with a RST before sending
// anything. It never gets a reply.
func reset(t *testing.T, addr string) (string, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return "", err
	}
	if err := c.(*net.TCPConn).SetLinger(0); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	return "", errors.New("reset by the caller")
}

// waitPending waits until n connections from ip hold a pending slot.
func waitPending(t *testing.T, r *Router, ip string, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.mu.Lock()
		got := r.perIP[ip]
		r.mu.Unlock()
		if got == n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d connections from %s pending, want %d", got, ip, n)
		}
		time.Sleep(time.Millisecond)
	}
}

// Each fiber has one live routing key. Add replaces it, Remove forgets it.
func TestRouterKeys(t *testing.T) {
	r := &Router{}
	first := mustAdd(t, r, "g1/1/1")
	steps := []struct {
		name    string
		op      func() string // returns the key the fiber should now have
		fiberID string
		wantOK  bool
	}{
		{name: "an added fiber has its key", op: func() string { return first }, fiberID: "g1/1/1", wantOK: true},
		{name: "an unknown fiber has none", op: func() string { return "" }, fiberID: "g9/9/9"},
		{name: "adding again replaces the key", op: func() string {
			k := mustAdd(t, r, "g1/1/1")
			if k == first {
				t.Fatal("re-add kept the old key")
			}
			if _, ok := r.lookup(first + Suffix); ok {
				t.Fatal("the old key still routes")
			}
			return k
		}, fiberID: "g1/1/1", wantOK: true},
		{name: "a removed fiber has none", op: func() string { r.Remove("g1/1/1"); return "" }, fiberID: "g1/1/1"},
		{name: "removing an unknown fiber is a no-op", op: func() string { r.Remove("g9/9/9"); return "" }, fiberID: "g9/9/9"},
	}
	for _, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			want := st.op()
			got, ok := r.Key(st.fiberID)
			if ok != st.wantOK || got != want {
				t.Fatalf("Key(%s) = %q, %v, want %q, %v", st.fiberID, got, ok, want, st.wantOK)
			}
			if ok {
				if id, routed := r.lookup(strings.ToUpper(got) + Suffix); !routed || id != st.fiberID {
					t.Fatalf("lookup(%s) = %q, %v, want %s", got, id, routed, st.fiberID)
				}
			}
		})
	}
}

func mustAdd(t *testing.T, r *Router, fiberID string) string {
	t.Helper()
	k, err := r.Add(fiberID)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
