package endpoint_test

import (
	"context"
	"net"
	"testing"

	"github.com/helayoty/fiberd/pkg/endpoint"
)

func TestParseAndFormat(t *testing.T) {
	cases := []struct {
		in      string
		want    endpoint.Endpoint
		wantErr bool
	}{
		{"unix:///run/fiberd/g/1-1.sock", endpoint.Endpoint{Scheme: "unix", Path: "/run/fiberd/g/1-1.sock"}, false},
		{"/run/fiberd/g/1-1.sock", endpoint.Endpoint{Scheme: "unix", Path: "/run/fiberd/g/1-1.sock"}, false},
		{"tcp://10.0.0.7:30012", endpoint.Endpoint{Scheme: "tcp", Host: "10.0.0.7", Port: 30012}, false},
		{"tcp://[fd00::7]:30012", endpoint.Endpoint{Scheme: "tcp", Host: "fd00::7", Port: 30012}, false},
		{"tcp://fd00::7:30012", endpoint.Endpoint{}, true}, // unbracketed v6 is ambiguous
		{"tcp://10.0.0.7", endpoint.Endpoint{}, true},
		{"tcp://10.0.0.7:70000", endpoint.Endpoint{}, true},
		{"http://10.0.0.7:80", endpoint.Endpoint{}, true},
		{"unix://relative.sock", endpoint.Endpoint{}, true},
		{"", endpoint.Endpoint{}, true},
	}
	for _, c := range cases {
		got, err := endpoint.Parse(c.in)
		if c.wantErr != (err != nil) {
			t.Errorf("Parse(%q): err = %v, wantErr %v", c.in, err, c.wantErr)
			continue
		}
		if err != nil {
			continue
		}
		if got != c.want {
			t.Errorf("Parse(%q) = %+v, want %+v", c.in, got, c.want)
		}
		// Formatting round-trips, with IPv6 bracketed; a bare path
		// formats with its scheme.
		want := c.in
		if got.Scheme == "unix" {
			want = "unix://" + c.want.Path
		}
		if s := got.String(); s != want {
			t.Errorf("String() = %q for %q, want %q", s, c.in, want)
		}
		if err := endpoint.Validate(got.String()); err != nil {
			t.Errorf("Validate(%q): %v", got.String(), err)
		}
	}
}

func TestFamilyAndPolicy(t *testing.T) {
	for in, want := range map[string]endpoint.Family{"": endpoint.Unix, "unix": endpoint.Unix, "INET4": endpoint.Inet4, "inet6": endpoint.Inet6} {
		got, err := endpoint.ParseFamily(in)
		if err != nil || got != want {
			t.Errorf("ParseFamily(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := endpoint.ParseFamily("ipv4"); err == nil {
		t.Error("ipv4 accepted")
	}
	good := []endpoint.Policy{
		{Family: endpoint.Unix},
		{Family: endpoint.Inet4, Host: "127.0.0.1"},
		{Family: endpoint.Inet6, Host: "::1", PortMin: 40000, PortMax: 40010},
	}
	for _, p := range good {
		if err := p.Validate(); err != nil {
			t.Errorf("%+v: %v", p, err)
		}
	}
	bad := []endpoint.Policy{
		{Family: endpoint.Inet4, Host: "::1"},
		{Family: endpoint.Inet6, Host: "127.0.0.1"},
		{Family: endpoint.Inet4, Host: "localhost"},
		{Family: endpoint.Inet4, Host: "127.0.0.1", PortMin: 5, PortMax: 4},
		{Family: "inet5"},
	}
	for _, p := range bad {
		if err := p.Validate(); err == nil {
			t.Errorf("%+v accepted", p)
		}
	}
	if lo, hi := (endpoint.Policy{}).Ports(); lo != 30000 || hi != 32767 {
		t.Errorf("default ports = %d-%d", lo, hi)
	}
}

func TestDialBothSchemes(t *testing.T) {
	// tcp on the loopback of whichever family is available.
	for _, addr := range []string{"127.0.0.1:0", "[::1]:0"} {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			t.Logf("no %s: %v", addr, err)
			continue
		}
		go func() {
			c, err := l.Accept()
			if err == nil {
				_, _ = c.Write([]byte("hi\n"))
				_ = c.Close()
			}
		}()
		host, port, _ := net.SplitHostPort(l.Addr().String())
		var p int
		_, _ = sscan(port, &p)
		ep := endpoint.Endpoint{Scheme: "tcp", Host: host, Port: p}.String()
		c, err := endpoint.Dial(context.Background(), ep)
		if err != nil {
			t.Fatalf("dial %s: %v", ep, err)
		}
		buf := make([]byte, 3)
		if _, err := c.Read(buf); err != nil || string(buf) != "hi\n" {
			t.Fatalf("read over %s: %q %v", ep, buf, err)
		}
		_ = c.Close()
		_ = l.Close()
	}
	if _, err := endpoint.Dial(context.Background(), "http://x"); err == nil {
		t.Fatal("dialled an http endpoint")
	}
	if endpoint.UnixPath("tcp://127.0.0.1:1") != "" || endpoint.UnixPath("unix:///a.sock") != "/a.sock" {
		t.Fatal("UnixPath")
	}
}

func sscan(s string, n *int) (int, error) {
	v := 0
	for _, ch := range s {
		v = v*10 + int(ch-'0')
	}
	*n = v
	return 1, nil
}
