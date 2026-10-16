// Package ingress is the worker side of Substrate's actor routing, done
// for fibers. atenet-router reaches a worker Pod over mTLS (it presents
// its Pod certificate, the worker presents its own) and names the actor
// in the ate-target-actor header as "<atespace>/<actor>". It either sends
// plain HTTP on port 443, or opens a CONNECT tunnel on port 8443, its
// default since Substrate v0.5.0. This server verifies the router's
// identity, looks the actor up among the ones the herder activated, and
// proxies the request or relays the tunnel to that fiber's endpoint (a
// unix socket or a tcp address). Anything else is 421 with
// X-Ate-Assignment-Stale, the signal the router re-resolves on.
// Substrate's atunnel does the same with one active actor and a fixed
// upstream. This one keeps a map, so many actors per worker need no
// change here.
package ingress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	fiberendpoint "github.com/helayoty/fiberd/pkg/endpoint"
)

const (
	// TargetActorHeader names the actor a request is for.
	TargetActorHeader = "ate-target-actor"
	// TargetPortHeader would pick a port on the actor; a fiber has one
	// endpoint, so it is dropped.
	TargetPortHeader = "X-Ate-Target-Port"
	// StaleAssignmentHeader marks a rejection the router should re-resolve.
	StaleAssignmentHeader = "X-Ate-Assignment-Stale"
	// DefaultAllowedClientID is atenet-router's identity.
	DefaultAllowedClientID = "spiffe://cluster.local/ns/ate-system/sa/atenet-router"
)

// Config is the TLS material Substrate projects into the worker Pod.
// All three empty means plain HTTP (tests).
type Config struct {
	CredentialBundle string // PEM: the worker's key and certificate chain
	TrustBundle      string // PEM: the CAs the router's certificate chains to
	AllowedClientID  string // the SPIFFE URI the router's certificate must carry
}

type target struct {
	endpoint  string
	transport *http.Transport
	// gone ends when the actor is deactivated, which closes its tunnels.
	gone  context.Context
	leave context.CancelFunc
}

// Server routes requests to activated actors.
type Server struct {
	cfg       Config
	tlsConfig *tls.Config

	mu     sync.Mutex
	active map[string]*target
}

func New(cfg Config) (*Server, error) {
	s := &Server{cfg: cfg, active: map[string]*target{}}
	if cfg.CredentialBundle == "" && cfg.TrustBundle == "" {
		return s, nil
	}
	if _, err := loadBundle(cfg.CredentialBundle); err != nil {
		return nil, err
	}
	pem, err := os.ReadFile(cfg.TrustBundle)
	if err != nil {
		return nil, fmt.Errorf("ingress: trust bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("ingress: trust bundle %s holds no certificates", cfg.TrustBundle)
	}
	allowed := cfg.AllowedClientID
	if allowed == "" {
		allowed = DefaultAllowedClientID
	}
	s.tlsConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Reloaded per connection: the kubelet rotates the projected certificate.
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return loadBundle(cfg.CredentialBundle) },
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      pool,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("ingress: client certificate required")
			}
			for _, u := range cs.PeerCertificates[0].URIs {
				if u.String() == allowed {
					return nil
				}
			}
			return fmt.Errorf("ingress: client is not %s", allowed)
		},
		NextProtos: []string{"h2", "http/1.1"},
	}
	return s, nil
}

func loadBundle(path string) (*tls.Certificate, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ingress: credential bundle: %w", err)
	}
	cert, err := tls.X509KeyPair(pem, pem)
	if err != nil {
		return nil, fmt.Errorf("ingress: credential bundle %s: %w", path, err)
	}
	return &cert, nil
}

// Activate routes atespace/name to endpoint from now on.
func (s *Server) Activate(atespace, name, endpoint string) {
	tr := &http.Transport{
		DialContext:  func(ctx context.Context, _, _ string) (net.Conn, error) { return fiberendpoint.Dial(ctx, endpoint) },
		MaxIdleConns: 16, IdleConnTimeout: 30 * time.Second,
	}
	gone, leave := context.WithCancel(context.Background())
	s.mu.Lock()
	if old := s.active[atespace+"/"+name]; old != nil {
		old.transport.CloseIdleConnections()
		old.leave()
	}
	s.active[atespace+"/"+name] = &target{endpoint: endpoint, transport: tr, gone: gone, leave: leave}
	s.mu.Unlock()
}

// Deactivate stops routing to the actor. Requests in flight finish, and
// its tunnels close.
func (s *Server) Deactivate(atespace, name string) {
	s.mu.Lock()
	t := s.active[atespace+"/"+name]
	delete(s.active, atespace+"/"+name)
	s.mu.Unlock()
	if t != nil {
		t.transport.CloseIdleConnections()
		t.leave()
	}
}

// Endpoint reports where an activated actor is served.
func (s *Server) Endpoint(atespace, name string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.active[atespace+"/"+name]
	if !ok {
		return "", false
	}
	return t.endpoint, true
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ref := r.Header.Get(TargetActorHeader)
	atespace, name, ok := strings.Cut(ref, "/")
	if !ok || atespace == "" || name == "" || strings.Contains(name, "/") {
		w.Header().Set(StaleAssignmentHeader, "true")
		http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
		return
	}
	s.mu.Lock()
	t := s.active[atespace+"/"+name]
	s.mu.Unlock()
	if t == nil {
		w.Header().Set(StaleAssignmentHeader, "true")
		http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
		return
	}
	if r.Method == http.MethodConnect {
		s.relay(w, r, t)
		return
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(&url.URL{Scheme: "http", Host: "fiber"})
			pr.Out.Host = pr.In.Host
			pr.Out.Header.Del(TargetActorHeader)
			pr.Out.Header.Del(TargetPortHeader)
			pr.SetXForwarded()
		},
		Transport: t.transport,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			http.Error(w, "bad gateway: "+err.Error(), http.StatusBadGateway)
		},
	}
	proxy.ServeHTTP(w, r)
}

// relay serves a CONNECT tunnel to the actor's fiber. The authority must
// name a port, as atunnel requires, but a fiber has one endpoint, so
// every port reaches it. Bytes are copied both ways until either side
// stops, or until the actor is deactivated. The router's half-close
// reaches the fiber as one.
func (s *Server) relay(w http.ResponseWriter, r *http.Request, t *target) {
	if _, port, err := net.SplitHostPort(r.Host); err != nil || port == "" {
		http.Error(w, "CONNECT authority must include a port", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	up, err := fiberendpoint.Dial(ctx, t.endpoint)
	cancel()
	if err != nil {
		http.Error(w, "bad gateway: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = up.Close() }()
	var down io.ReadWriteCloser
	if r.ProtoMajor == 2 {
		// An HTTP/2 tunnel is the request body one way and the response
		// the other, flushed as it goes.
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		if err := rc.Flush(); err != nil {
			return
		}
		down = h2Stream{body: r.Body, w: w, rc: rc}
	} else {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "CONNECT hijacking unsupported", http.StatusInternalServerError)
			return
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			return
		}
		if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil || rw.Flush() != nil {
			_ = conn.Close()
			return
		}
		down = bufferedConn{Reader: rw.Reader, Conn: conn}
	}
	defer func() { _ = down.Close() }()
	stop := context.AfterFunc(t.gone, func() { _ = up.Close(); _ = down.Close() })
	defer stop()
	go func() {
		_, _ = io.Copy(up, down)
		if cw, ok := up.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	_, _ = io.Copy(down, up)
}

// h2Stream is an HTTP/2 CONNECT stream as one connection.
type h2Stream struct {
	body io.ReadCloser
	w    io.Writer
	rc   *http.ResponseController
}

func (s h2Stream) Read(p []byte) (int, error) { return s.body.Read(p) }

func (s h2Stream) Write(p []byte) (int, error) {
	n, err := s.w.Write(p)
	if err == nil {
		err = s.rc.Flush()
	}
	return n, err
}

func (s h2Stream) Close() error { return s.body.Close() }

// bufferedConn reads what the hijacked reader already buffered first.
type bufferedConn struct {
	io.Reader
	net.Conn
}

func (c bufferedConn) Read(p []byte) (int, error) { return c.Reader.Read(p) }

// Serve accepts on lis until ctx ends: mTLS when configured, plain otherwise.
func (s *Server) Serve(ctx context.Context, lis net.Listener) error {
	srv := &http.Server{Handler: s, TLSConfig: s.tlsConfig, ReadHeaderTimeout: 10 * time.Second}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = srv.Close()
		case <-done:
		}
	}()
	var err error
	if s.tlsConfig != nil {
		err = srv.ServeTLS(lis, "", "")
	} else {
		err = srv.Serve(lis)
	}
	close(done)
	if errors.Is(err, http.ErrServerClosed) && ctx.Err() != nil {
		return nil
	}
	return err
}
