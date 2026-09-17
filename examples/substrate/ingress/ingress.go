// Package ingress is the worker side of Substrate's actor routing, done
// for fibers. atenet-router reaches a worker Pod on port 443 over mTLS
// (it presents its Pod certificate, the worker presents its own) and
// sends plain HTTP with the actor named in the ate-target-actor header
// as "<atespace>/<actor>". This server verifies the router's identity,
// looks the actor up among the ones the herder activated and proxies the
// request to that fiber's endpoint (a unix socket or a tcp address);
// anything else is 421 with X-Ate-Assignment-Stale, the signal the
// router re-resolves on. Substrate's atunnel does the same with one
// active actor and a fixed upstream; this one keeps a map, so many
// actors per worker need no change here.
package ingress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
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
	s.mu.Lock()
	if old := s.active[atespace+"/"+name]; old != nil {
		old.transport.CloseIdleConnections()
	}
	s.active[atespace+"/"+name] = &target{endpoint: endpoint, transport: tr}
	s.mu.Unlock()
}

// Deactivate stops routing to the actor; requests in flight finish.
func (s *Server) Deactivate(atespace, name string) {
	s.mu.Lock()
	t := s.active[atespace+"/"+name]
	delete(s.active, atespace+"/"+name)
	s.mu.Unlock()
	if t != nil {
		t.transport.CloseIdleConnections()
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
