package host

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fiberSocket is a unix listener standing in for a fiber. handler serves
// one connection and closes it.
type fiberSocket struct {
	path string
	ln   net.Listener
	wg   sync.WaitGroup
}

// echo copies a connection back to itself until the caller half-closes,
// then closes. A fiber serving a stream protocol.
func echo(c net.Conn) {
	_, _ = io.Copy(c, c)
	_ = c.Close()
}

// collect reads until EOF and answers with the upper case of everything
// it read. A fiber that needs the caller's half-close to know the request
// has ended.
func collect(c net.Conn) {
	b, _ := io.ReadAll(c)
	_, _ = c.Write(bytes.ToUpper(b))
	_ = c.Close()
}

// hold reads one byte and keeps the connection open until the caller
// goes away, then closes.
func hold(c net.Conn) {
	_, _ = io.Copy(io.Discard, c)
	_ = c.Close()
}

// newFiberSocket listens on a short socket path under the system temp
// directory (unix paths are limited to about 100 bytes).
func newFiberSocket(t *testing.T, handler func(net.Conn)) *fiberSocket {
	t.Helper()
	dir, err := os.MkdirTemp("", "relay")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	s := &fiberSocket{path: filepath.Join(dir, "f.sock")}
	s.ln, err = net.Listen("unix", s.path)
	if err != nil {
		t.Fatal(err)
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := s.ln.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func() { defer s.wg.Done(); handler(c) }()
		}
	}()
	t.Cleanup(func() { _ = s.ln.Close(); s.wg.Wait() })
	return s
}

// dialRelay connects to the relay's tcp address with a deadline.
func dialRelay(t *testing.T, r *relay) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", r.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// readAll reads until EOF or the deadline.
func readAll(c net.Conn) (string, error) {
	b, err := io.ReadAll(c)
	return string(b), err
}

// waitOpen polls until the relay has n open connections (two per spliced
// caller: the tcp side and the unix side).
func waitOpen(t *testing.T, r *relay, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for r.open() != n {
		if time.Now().After(deadline) {
			t.Fatalf("relay has %d connections open, want %d", r.open(), n)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestRelay checks the splice from a caller's tcp connection to the
// fiber's unix socket: bytes both ways, half-close, concurrency, the
// caps, and that closing the relay ends everything.
func TestRelay(t *testing.T) {
	cases := []struct {
		name string
		// handler serves the fiber's side.
		handler func(net.Conn)
		// maxConns caps the fiber's connections (0 is the default).
		maxConns int
		// total is the home's shared cap (0 for none).
		total int
		// noSocket relays to a path nothing listens on.
		noSocket bool
		check    func(t *testing.T, r *relay, sock string)
	}{
		{name: "bytes round trip both ways", handler: echo,
			check: func(t *testing.T, r *relay, _ string) {
				c := dialRelay(t, r)
				for _, msg := range []string{"hello", "fiber", strings.Repeat("x", 1<<20)} {
					if _, err := c.Write([]byte(msg)); err != nil {
						t.Fatal(err)
					}
					got := make([]byte, len(msg))
					if _, err := io.ReadFull(c, got); err != nil || string(got) != msg {
						t.Fatalf("echo of %d bytes = %q (%v)", len(msg), truncate(string(got)), err)
					}
				}
				waitOpen(t, r, 2)
			}},
		{name: "half-close: the fiber sees EOF and still answers", handler: collect,
			check: func(t *testing.T, r *relay, _ string) {
				c := dialRelay(t, r)
				if _, err := c.Write([]byte("shout")); err != nil {
					t.Fatal(err)
				}
				if err := c.(*net.TCPConn).CloseWrite(); err != nil {
					t.Fatal(err)
				}
				got, err := readAll(c)
				if err != nil || got != "SHOUT" {
					t.Fatalf("reply after half-close = %q %v, want SHOUT and EOF", got, err)
				}
				waitOpen(t, r, 0)
			}},
		{name: "concurrent connections each reach the fiber", handler: echo,
			check: func(t *testing.T, r *relay, _ string) {
				const n = 32
				var wg sync.WaitGroup
				errs := make(chan error, n)
				for i := 0; i < n; i++ {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						c, err := net.DialTimeout("tcp", r.Addr().String(), 2*time.Second)
						if err != nil {
							errs <- err
							return
						}
						defer func() { _ = c.Close() }()
						_ = c.SetDeadline(time.Now().Add(5 * time.Second))
						msg := fmt.Sprintf("conn-%d", i)
						if _, err := c.Write([]byte(msg)); err != nil {
							errs <- err
							return
						}
						got := make([]byte, len(msg))
						if _, err := io.ReadFull(c, got); err != nil || string(got) != msg {
							errs <- fmt.Errorf("conn %d: echo = %q (%w)", i, got, err)
						}
					}(i)
				}
				wg.Wait()
				close(errs)
				for err := range errs {
					t.Error(err)
				}
				waitOpen(t, r, 0)
				if r.refused.Load() != 0 {
					t.Fatalf("%d refused, want none", r.refused.Load())
				}
			}},
		{name: "the fiber's cap closes the extra connection at once", handler: hold, maxConns: 2,
			check: func(t *testing.T, r *relay, _ string) {
				c1, c2 := dialRelay(t, r), dialRelay(t, r)
				for _, c := range []net.Conn{c1, c2} {
					if _, err := c.Write([]byte("x")); err != nil {
						t.Fatal(err)
					}
				}
				waitOpen(t, r, 4)
				c3 := dialRelay(t, r)
				if got, err := readAll(c3); err != nil || got != "" {
					t.Fatalf("third connection read %q %v, want a clean close", got, err)
				}
				if r.refused.Load() != 1 {
					t.Fatalf("%d refused, want 1", r.refused.Load())
				}
				// A slot given back is a slot taken again.
				_ = c1.Close()
				waitOpen(t, r, 2)
				c4 := dialRelay(t, r)
				if _, err := c4.Write([]byte("x")); err != nil {
					t.Fatal(err)
				}
				waitOpen(t, r, 4)
			}},
		{name: "the home's cap is shared across fibers", handler: hold, total: 1,
			check: func(t *testing.T, r *relay, sock string) {
				c1 := dialRelay(t, r)
				if _, err := c1.Write([]byte("x")); err != nil {
					t.Fatal(err)
				}
				waitOpen(t, r, 2)
				other, err := listenRelay("tcp4", "127.0.0.1:0", sock, 0, r.total)
				if err != nil {
					t.Fatal(err)
				}
				defer other.Close()
				c2 := dialRelay(t, other)
				if got, err := readAll(c2); err != nil || got != "" {
					t.Fatalf("second fiber's connection read %q %v, want a clean close", got, err)
				}
				if other.refused.Load() != 1 || r.refused.Load() != 0 {
					t.Fatalf("refused: other %d, first %d", other.refused.Load(), r.refused.Load())
				}
			}},
		{name: "Close ends the listener and every open connection", handler: hold,
			check: func(t *testing.T, r *relay, _ string) {
				c := dialRelay(t, r)
				if _, err := c.Write([]byte("x")); err != nil {
					t.Fatal(err)
				}
				waitOpen(t, r, 2)
				done := make(chan struct{})
				go func() { r.Close(); close(done) }()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Fatal("Close did not return")
				}
				if got, err := readAll(c); got != "" || err != nil && !errors.Is(err, io.EOF) && !isReset(err) {
					t.Fatalf("read after Close = %q %v, want the connection ended", got, err)
				}
				if _, err := net.DialTimeout("tcp", r.Addr().String(), 500*time.Millisecond); err == nil {
					t.Fatal("the relay still accepts after Close")
				}
				if r.open() != 0 {
					t.Fatalf("%d connections tracked after Close", r.open())
				}
				r.Close() // idempotent
			}},
		{name: "no socket behind the relay: the connection is closed", noSocket: true,
			check: func(t *testing.T, r *relay, _ string) {
				c := dialRelay(t, r)
				if got, err := readAll(c); err != nil || got != "" {
					t.Fatalf("read = %q %v, want a clean close", got, err)
				}
				if r.refused.Load() != 1 {
					t.Fatalf("%d refused, want 1", r.refused.Load())
				}
				waitOpen(t, r, 0)
			}},
		{name: "a caller that resets ends the fiber's side too", handler: hold,
			check: func(t *testing.T, r *relay, _ string) {
				c := dialRelay(t, r)
				if _, err := c.Write([]byte("x")); err != nil {
					t.Fatal(err)
				}
				waitOpen(t, r, 2)
				_ = c.(*net.TCPConn).SetLinger(0) // close sends RST, not FIN
				_ = c.Close()
				waitOpen(t, r, 0)
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var sock string
			if tc.noSocket {
				sock = filepath.Join(t.TempDir(), "nothing.sock")
			} else {
				sock = newFiberSocket(t, tc.handler).path
			}
			var total chan struct{}
			if tc.total > 0 {
				total = make(chan struct{}, tc.total)
			}
			r, err := listenRelay("tcp4", "127.0.0.1:0", sock, tc.maxConns, total)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(r.Close)
			tc.check(t, r, sock)
		})
	}
}

// TestListenRelayRefusals checks what cannot be listened on.
func TestListenRelayRefusals(t *testing.T) {
	held, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	cases := []struct {
		name, network, addr string
	}{
		{name: "a port another process holds", network: "tcp4", addr: held.Addr().String()},
		{name: "an address of the other family", network: "tcp6", addr: "127.0.0.1:0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := listenRelay(tc.network, tc.addr, "/nonexistent.sock", 0, nil)
			if err == nil {
				r.Close()
				t.Fatal("listenRelay succeeded")
			}
		})
	}
}

func truncate(s string) string {
	if len(s) > 32 {
		return s[:32] + "..."
	}
	return s
}

func isReset(err error) bool {
	return err != nil && strings.Contains(err.Error(), "reset")
}

// listenAt listens on a unix socket at path and answers every connection
// with "LEAK", so a caller spliced there by mistake can tell.
func listenAt(t *testing.T, path string) net.Listener {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("LEAK"))
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// TestRelayRefusesPlantedNames checks that the relay reaches what is a
// socket at the fiber's name and never follows a link planted there. The
// fiber writes its grant's run directory, so a link at its own socket's
// name could point the relay at another grant's socket, the agent's, or
// any socket the agent can reach. A caller is closed instead.
func TestRelayRefusesPlantedNames(t *testing.T) {
	cases := []struct {
		name string
		// plant puts something at the socket name.
		plant func(t *testing.T, dir, name string)
		// served is whether a caller reaches a fiber: the echo at the name.
		served bool
	}{
		{name: "a link to another socket in the directory", plant: func(t *testing.T, dir, name string) {
			listenAt(t, filepath.Join(dir, "victim.sock"))
			if err := os.Symlink("victim.sock", filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a link to a socket outside the directory", plant: func(t *testing.T, dir, name string) {
			other, err := os.MkdirTemp("", "relay")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(other) })
			listenAt(t, filepath.Join(other, "admin.sock"))
			if err := os.Symlink(filepath.Join(other, "admin.sock"), filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a regular file", plant: func(t *testing.T, dir, name string) {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a directory", plant: func(t *testing.T, dir, name string) {
			if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "nothing at all", plant: func(*testing.T, string, string) {}},
		{name: "the fiber's own socket", plant: func(t *testing.T, dir, name string) {
			ln, err := net.Listen("unix", filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ln.Close() })
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go echo(c)
				}
			}()
		}, served: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := os.MkdirTemp("", "relay")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			tc.plant(t, dir, "1-7.sock")
			r, err := listenRelay("tcp4", "127.0.0.1:0", filepath.Join(dir, "1-7.sock"), 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(r.Close)
			c := dialRelay(t, r)
			if _, err := c.Write([]byte("hello")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 16)
			n, rerr := c.Read(buf)
			if tc.served {
				if rerr != nil || string(buf[:n]) != "hello" {
					t.Fatalf("read %q %v through the relay, want the echo", buf[:n], rerr)
				}
				return
			}
			if n != 0 || rerr == nil {
				t.Fatalf("the caller read %q (%v); want it closed with nothing", buf[:n], rerr)
			}
			if r.refused.Load() != 1 {
				t.Fatalf("refused = %d, want 1", r.refused.Load())
			}
		})
	}
}
