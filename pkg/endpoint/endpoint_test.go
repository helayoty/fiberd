package endpoint_test

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/helayoty/fiberd/pkg/endpoint"
)

// Parse accepts unix paths (with or without the scheme) and tcp addresses
// with a port and a bracketed IPv6 host. String round-trips what Parse
// accepted. UnixPath yields the path only for unix endpoints.
func TestParseAndFormat(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    endpoint.Endpoint
		wantErr bool
		wantIs  error // errors.Is target of the error, when set
	}{
		{name: "unix url", in: "unix:///run/fiberd/g/1-1.sock", want: endpoint.Endpoint{Scheme: "unix", Path: "/run/fiberd/g/1-1.sock"}},
		{name: "short unix url", in: "unix:///a.sock", want: endpoint.Endpoint{Scheme: "unix", Path: "/a.sock"}},
		{name: "bare absolute path is unix", in: "/run/fiberd/g/1-1.sock", want: endpoint.Endpoint{Scheme: "unix", Path: "/run/fiberd/g/1-1.sock"}},
		{name: "tcp with an IPv4 host", in: "tcp://10.0.0.7:30012", want: endpoint.Endpoint{Scheme: "tcp", Host: "10.0.0.7", Port: 30012}},
		{name: "tcp on the loopback", in: "tcp://127.0.0.1:1", want: endpoint.Endpoint{Scheme: "tcp", Host: "127.0.0.1", Port: 1}},
		{name: "tcp with a bracketed IPv6 host", in: "tcp://[fd00::7]:30012", want: endpoint.Endpoint{Scheme: "tcp", Host: "fd00::7", Port: 30012}},
		{name: "tcp with a host name", in: "tcp://fiber.local:8080", want: endpoint.Endpoint{Scheme: "tcp", Host: "fiber.local", Port: 8080}},
		{name: "unbracketed IPv6 is ambiguous", in: "tcp://fd00::7:30012", wantErr: true},
		{name: "tcp without a port", in: "tcp://10.0.0.7", wantErr: true},
		{name: "tcp port out of range", in: "tcp://10.0.0.7:70000", wantErr: true},
		{name: "tcp port zero", in: "tcp://10.0.0.7:0", wantErr: true},
		{name: "tcp port by service name", in: "tcp://10.0.0.7:http", wantErr: true},
		{name: "tcp without a host", in: "tcp://:30012", wantErr: true},
		{name: "http scheme is unsupported", in: "http://10.0.0.7:80", wantErr: true, wantIs: endpoint.ErrUnsupported},
		{name: "relative unix path", in: "unix://relative.sock", wantErr: true},
		{name: "opaque unix path", in: "unix:relative.sock", wantErr: true},
		{name: "a URL that does not parse", in: "tcp://10.0.0.7:%zz", wantErr: true},
		{name: "empty", in: "", wantErr: true, wantIs: endpoint.ErrUnsupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantPath := ""
			if tc.want.Scheme == "unix" {
				wantPath = tc.want.Path
			}
			if p := endpoint.UnixPath(tc.in); p != wantPath {
				t.Errorf("UnixPath(%q) = %q, want %q", tc.in, p, wantPath)
			}
			got, err := endpoint.Parse(tc.in)
			if tc.wantErr != (err != nil) {
				t.Fatalf("Parse(%q): err = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("Parse(%q): err = %v, want %v", tc.in, err, tc.wantIs)
			}
			if err != nil {
				if err := endpoint.Validate(tc.in); err == nil {
					t.Fatalf("Validate(%q) accepted what Parse refused", tc.in)
				}
				return
			}
			if got != tc.want {
				t.Fatalf("Parse(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
			// Formatting round-trips, with IPv6 bracketed. A bare path
			// formats with its scheme.
			want := tc.in
			if got.Scheme == "unix" {
				want = "unix://" + tc.want.Path
			}
			if s := got.String(); s != want {
				t.Errorf("String() = %q for %q, want %q", s, tc.in, want)
			}
			if err := endpoint.Validate(got.String()); err != nil {
				t.Errorf("Validate(%q): %v", got.String(), err)
			}
		})
	}
}

func TestParseFamily(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    endpoint.Family
		scheme  string
		wantErr bool
	}{
		{name: "empty defaults to unix", in: "", want: endpoint.Unix, scheme: "unix"},
		{name: "unix", in: " unix ", want: endpoint.Unix, scheme: "unix"},
		{name: "inet4 is case-insensitive", in: "INET4", want: endpoint.Inet4, scheme: "tcp"},
		{name: "inet6", in: "inet6", want: endpoint.Inet6, scheme: "tcp"},
		{name: "ipv4 is not a family name", in: "ipv4", wantErr: true, scheme: "unix"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := endpoint.ParseFamily(tc.in)
			if tc.wantErr != (err != nil) {
				t.Fatalf("ParseFamily(%q): err = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("ParseFamily(%q) = %v, want %v", tc.in, got, tc.want)
			}
			// The zero family a failed parse returns is unix, the default.
			if s := got.Scheme(); s != tc.scheme {
				t.Fatalf("%q.Scheme() = %q, want %q", got, s, tc.scheme)
			}
		})
	}
}

// A policy's host must be an IP literal of its family and its port range
// sane. An unset range is the NodePort default.
func TestPolicy(t *testing.T) {
	cases := []struct {
		name    string
		policy  endpoint.Policy
		wantErr bool
		lo, hi  int // Ports(), or 0, 0 to skip the check
	}{
		{name: "zero policy uses the default port range", policy: endpoint.Policy{}, lo: 30000, hi: 32767},
		{name: "unix", policy: endpoint.Policy{Family: endpoint.Unix}},
		{name: "inet4 with an IPv4 host", policy: endpoint.Policy{Family: endpoint.Inet4, Host: "127.0.0.1"}, lo: 30000, hi: 32767},
		{name: "inet6 with an explicit port range", policy: endpoint.Policy{Family: endpoint.Inet6, Host: "::1", PortMin: 40000, PortMax: 40010},
			lo: 40000, hi: 40010},
		{name: "inet4 with an IPv6 host", policy: endpoint.Policy{Family: endpoint.Inet4, Host: "::1"}, wantErr: true},
		{name: "inet6 with an IPv4 host", policy: endpoint.Policy{Family: endpoint.Inet6, Host: "127.0.0.1"}, wantErr: true},
		{name: "a host name is not an IP literal", policy: endpoint.Policy{Family: endpoint.Inet4, Host: "localhost"}, wantErr: true},
		{name: "a port range starting at zero", policy: endpoint.Policy{Family: endpoint.Inet4, Host: "127.0.0.1", PortMax: 10}, wantErr: true},
		{name: "a port range past 65535", policy: endpoint.Policy{Family: endpoint.Inet6, Host: "::1", PortMin: 65000, PortMax: 70000}, wantErr: true},
		{name: "inverted port range", policy: endpoint.Policy{Family: endpoint.Inet4, Host: "127.0.0.1", PortMin: 5, PortMax: 4}, wantErr: true},
		{name: "unknown family", policy: endpoint.Policy{Family: "inet5"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.policy.Validate(); tc.wantErr != (err != nil) {
				t.Fatalf("Validate(%+v) = %v, wantErr %v", tc.policy, err, tc.wantErr)
			}
			if tc.lo == 0 && tc.hi == 0 {
				return
			}
			if lo, hi := tc.policy.Ports(); lo != tc.lo || hi != tc.hi {
				t.Fatalf("Ports() = %d-%d, want %d-%d", lo, hi, tc.lo, tc.hi)
			}
		})
	}
}

// Validate refuses what Parse accepts but no home may return: a tcp
// host that is neither an IP literal nor a plain name.
func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{name: "a unix endpoint", in: "unix:///run/f.sock"},
		{name: "a tcp IPv6 literal", in: "tcp://[::1]:80"},
		{name: "a tcp name", in: "tcp://fiber.local:80"},
		{name: "a bracketed host with a zone is not an IP literal", in: "tcp://[fe80::1%25eth0]:80", wantErr: true},
		{name: "a bracketed host that is not an IP does not parse", in: "tcp://[fd00::zz]:80", wantErr: true},
		{name: "an unparsable endpoint", in: "ftp://x", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := endpoint.Validate(tc.in); (err != nil) != tc.wantErr {
				t.Fatalf("Validate(%q) = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
		})
	}
}

// Dial reaches unix endpoints and tcp endpoints on the loopback of
// whichever family is available, and refuses schemes it does not know.
func TestDial(t *testing.T) {
	cases := []struct {
		name    string
		network string // "unix" or "tcp" to serve "hi\n", or "" to dial ep instead
		listen  string // tcp address to listen on
		ep      string
		wantErr error // errors.Is target, when the dial must fail
	}{
		{name: "a unix socket", network: "unix"},
		{name: "tcp over the IPv4 loopback", network: "tcp", listen: "127.0.0.1:0"},
		{name: "tcp over the IPv6 loopback", network: "tcp", listen: "[::1]:0"},
		{name: "an http endpoint is refused", ep: "http://x", wantErr: endpoint.ErrUnsupported},
		{name: "a unix socket nobody serves", ep: "unix:///nonexistent/fiberd.sock", wantErr: syscall.ENOENT},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ep := tc.ep
			if tc.network != "" {
				addr := tc.listen
				if tc.network == "unix" {
					// A short directory keeps the path under the sun_path limit.
					dir, err := os.MkdirTemp("", "ep")
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = os.RemoveAll(dir) })
					addr = filepath.Join(dir, "f.sock")
				}
				l, err := net.Listen(tc.network, addr)
				if err != nil {
					t.Skipf("no %s %s: %v", tc.network, addr, err)
				}
				defer func() { _ = l.Close() }()
				go func() {
					c, err := l.Accept()
					if err == nil {
						_, _ = c.Write([]byte("hi\n"))
						_ = c.Close()
					}
				}()
				if tc.network == "unix" {
					ep = endpoint.Endpoint{Scheme: "unix", Path: addr}.String()
				} else {
					a := l.Addr().(*net.TCPAddr)
					ep = endpoint.Endpoint{Scheme: "tcp", Host: a.IP.String(), Port: a.Port}.String()
				}
			}
			c, err := endpoint.Dial(context.Background(), ep)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					if c != nil {
						_ = c.Close()
					}
					t.Fatalf("dial %s = %v, want %v", ep, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("dial %s: %v", ep, err)
			}
			defer func() { _ = c.Close() }()
			buf := make([]byte, 3)
			if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hi\n" {
				t.Fatalf("read over %s: %q %v", ep, buf, err)
			}
		})
	}
}
