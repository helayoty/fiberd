// Package endpoint is how a fiber's address is written, chosen and
// dialled. Clone returns one string; it is a URL with a scheme:
//
//	unix:///run/fiberd/<grant>/<epoch>-<seq>.sock   same-host callers
//	tcp://10.0.0.7:30012  tcp://[fd00::7]:30012      callers over the network
//
// Which family a home hands out is declared per deployment (a flag on
// the standalone home, the Pod's addresses under Kubernetes), never
// discovered by callers: they dial what they were given. Under a shared
// address, fibers are told apart by port, which is the model for IPv4
// and equally for one IPv6 address per grant. Per-fiber IPv6 addresses
// would be a further policy (a delegated prefix per grant, a network
// namespace per fiber) and are not built.
//
// The core never parses endpoints; this package serves the host runtime
// that mints them, the conformance suite that checks their form, and
// the tools that dial them.
package endpoint

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

// Family is the address family a home hands out.
type Family string

const (
	Unix  Family = "unix"  // unix sockets under the run directory
	Inet4 Family = "inet4" // tcp on one IPv4 address, a port per fiber
	Inet6 Family = "inet6" // tcp on one IPv6 address, a port per fiber
)

// ParseFamily reads a -endpoint-family value.
func ParseFamily(s string) (Family, error) {
	switch Family(strings.ToLower(strings.TrimSpace(s))) {
	case "", Unix:
		return Unix, nil
	case Inet4:
		return Inet4, nil
	case Inet6:
		return Inet6, nil
	}
	return "", fmt.Errorf("endpoint family %q: want unix, inet4 or inet6", s)
}

// Scheme is the URL scheme a family's endpoints carry.
func (f Family) Scheme() string {
	if f == Unix || f == "" {
		return "unix"
	}
	return "tcp"
}

// Policy is what a home declares about the endpoints it mints.
type Policy struct {
	Family Family
	// Host is the address advertised for Inet4 and Inet6: the one
	// address the grant's fibers share (a node address, a Pod IP).
	Host string
	// PortMin and PortMax bound the ports handed out, one per live
	// fiber; 0 means 30000-32767.
	PortMin, PortMax int
}

// Validate checks a policy before a runtime is opened with it.
func (p Policy) Validate() error {
	switch p.Family {
	case "", Unix:
		return nil
	case Inet4, Inet6:
		ip := net.ParseIP(p.Host)
		if ip == nil {
			return fmt.Errorf("endpoint host %q is not an IP literal", p.Host)
		}
		if (p.Family == Inet4) != (ip.To4() != nil) {
			return fmt.Errorf("endpoint host %s is not an %s address", p.Host, p.Family)
		}
		lo, hi := p.Ports()
		if lo < 1 || hi > 65535 || lo > hi {
			return fmt.Errorf("endpoint port range %d-%d is invalid", lo, hi)
		}
		return nil
	}
	return fmt.Errorf("endpoint family %q unknown", p.Family)
}

// Ports is the effective port range.
func (p Policy) Ports() (lo, hi int) {
	if p.PortMin == 0 && p.PortMax == 0 {
		return 30000, 32767
	}
	return p.PortMin, p.PortMax
}

// Endpoint is one parsed fiber address.
type Endpoint struct {
	Scheme string // "unix" or "tcp"
	Path   string // unix
	Host   string // tcp: an IP literal or name, never bracketed
	Port   int    // tcp
}

// String formats the endpoint as the URL Clone returns; IPv6 hosts are
// bracketed.
func (e Endpoint) String() string {
	if e.Scheme == "unix" {
		return "unix://" + e.Path
	}
	return "tcp://" + net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
}

// Network is what net.Dial takes.
func (e Endpoint) Network() (network, address string) {
	if e.Scheme == "unix" {
		return "unix", e.Path
	}
	return "tcp", net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
}

// Parse reads an endpoint URL. A bare absolute path is accepted as a
// unix endpoint, for the tools.
func Parse(s string) (Endpoint, error) {
	if strings.HasPrefix(s, "/") {
		return Endpoint{Scheme: "unix", Path: s}, nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return Endpoint{}, fmt.Errorf("endpoint %q: %w", s, err)
	}
	switch u.Scheme {
	case "unix":
		p := u.Path
		if u.Host != "" { // unix://relative/path is a malformed spelling; refuse
			return Endpoint{}, fmt.Errorf("endpoint %q: unix path must be absolute", s)
		}
		if !filepath.IsAbs(p) {
			return Endpoint{}, fmt.Errorf("endpoint %q: unix path must be absolute", s)
		}
		return Endpoint{Scheme: "unix", Path: p}, nil
	case "tcp":
		host, port, err := net.SplitHostPort(u.Host)
		if err != nil {
			return Endpoint{}, fmt.Errorf("endpoint %q: %w", s, err)
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return Endpoint{}, fmt.Errorf("endpoint %q: bad port %q", s, port)
		}
		if host == "" {
			return Endpoint{}, fmt.Errorf("endpoint %q: empty host", s)
		}
		return Endpoint{Scheme: "tcp", Host: host, Port: n}, nil
	}
	return Endpoint{}, fmt.Errorf("endpoint %q: scheme must be unix or tcp", s)
}

// Validate is what the conformance suite asks of every endpoint a home
// returns: it parses, its scheme is one of the two, and a tcp host is a
// well-formed host:port (an IPv6 literal bracketed).
func Validate(s string) error {
	e, err := Parse(s)
	if err != nil {
		return err
	}
	if e.Scheme == "tcp" && net.ParseIP(e.Host) == nil && strings.ContainsAny(e.Host, "[]:") {
		return fmt.Errorf("endpoint %q: host is neither an IP literal nor a name", s)
	}
	return nil
}

// ErrUnsupported: the endpoint's scheme is not one this dialer speaks.
var ErrUnsupported = errors.New("endpoint: unsupported scheme")

// Dial connects to a fiber endpoint of either scheme.
func Dial(ctx context.Context, s string) (net.Conn, error) {
	e, err := Parse(s)
	if err != nil {
		return nil, err
	}
	network, address := e.Network()
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

// UnixPath is the socket path of a unix endpoint, "" for any other.
func UnixPath(s string) string {
	e, err := Parse(s)
	if err != nil || e.Scheme != "unix" {
		return ""
	}
	return e.Path
}
