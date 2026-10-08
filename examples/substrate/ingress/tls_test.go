package ingress_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/helayoty/fiberd/examples/substrate/ingress"
)

// pki is a CA and what it issues, as Substrate projects it into Pods.
type pki struct {
	t    *testing.T
	ca   *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
	pem  []byte // the CA certificate
	next int64
}

func newPKI(t *testing.T) *pki {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &pki{t: t, ca: ca, key: key, pool: pool, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), next: 2}
}

// issue returns a key and certificate chain as one PEM bundle, and the
// certificate's serial. A server certificate is for 127.0.0.1, a client
// one carries the SPIFFE id.
func (p *pki) issue(spiffe string) ([]byte, int64) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		p.t.Fatal(err)
	}
	serial := p.next
	p.next++
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature}
	if spiffe == "" {
		tmpl.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		u, _ := url.Parse(spiffe)
		tmpl.URIs = []*url.URL{u}
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.key)
	if err != nil {
		p.t.Fatal(err)
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		p.t.Fatal(err)
	}
	return append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...), serial
}

func write(t *testing.T, dir, name string, b []byte) string {
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestNewReadsTheTLSMaterial checks every way the projected TLS material
// can be unusable at start.
func TestNewReadsTheTLSMaterial(t *testing.T) {
	p := newPKI(t)
	dir := t.TempDir()
	server, _ := p.issue("")
	cred := write(t, dir, "cred.pem", server)
	trust := write(t, dir, "trust.pem", p.pem)
	garbage := write(t, dir, "garbage.pem", []byte("not pem"))
	cases := []struct {
		name string
		cfg  ingress.Config
		err  string
		is   error
	}{
		{name: "a usable credential and trust bundle", cfg: ingress.Config{CredentialBundle: cred, TrustBundle: trust}},
		{name: "a credential bundle that is no key pair", cfg: ingress.Config{CredentialBundle: garbage, TrustBundle: trust},
			err: "ingress: credential bundle " + garbage},
		{name: "a trust bundle that is missing", cfg: ingress.Config{CredentialBundle: cred, TrustBundle: filepath.Join(dir, "none.pem")},
			err: "ingress: trust bundle", is: fs.ErrNotExist},
		{name: "a trust bundle without certificates", cfg: ingress.Config{CredentialBundle: cred, TrustBundle: garbage},
			err: "holds no certificates"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ingress.New(tc.cfg)
			if tc.err == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("New = %v, want an error with %q", err, tc.err)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("New = %v, want it to wrap %v", err, tc.is)
			}
		})
	}
}

// serve runs s on a loopback listener until the test ends, and reports
// what Serve returned once stopped.
func serve(t *testing.T, s *ingress.Server) (addr string, stop func() error) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, lis) }()
	var once sync.Once
	var stopped error
	stop = func() error {
		once.Do(func() {
			cancel()
			select {
			case stopped = <-done:
			case <-time.After(10 * time.Second):
				stopped = errors.New("Serve kept going after its context ended")
			}
		})
		return stopped
	}
	t.Cleanup(func() { _ = stop() })
	return lis.Addr().String(), stop
}

// TestMutualTLS checks that only the router's identity gets through, with
// the worker's current certificate, and that Serve stops cleanly.
func TestMutualTLS(t *testing.T) {
	p := newPKI(t)
	router, _ := p.issue(ingress.DefaultAllowedClientID)
	other, _ := p.issue("spiffe://cluster.local/ns/team-a/sa/intruder")
	custom, _ := p.issue("spiffe://cluster.local/ns/ate-system/sa/custom-router")
	cases := []struct {
		name    string
		allowed string // Config.AllowedClientID
		client  []byte // the client's bundle, or nil to present none
		rotate  bool   // the worker's certificate is rotated before the request
		ok      bool
	}{
		{name: "the router's identity reaches the actor", client: router, ok: true},
		{name: "another workload's certificate is refused", client: other},
		{name: "no client certificate is refused", client: nil},
		{name: "a configured router identity replaces the default", allowed: "spiffe://cluster.local/ns/ate-system/sa/custom-router",
			client: custom, ok: true},
		{name: "the default router is refused when another one is configured", allowed: "spiffe://cluster.local/ns/ate-system/sa/custom-router",
			client: router},
		{name: "a rotated worker certificate is served on the next connection", client: router, rotate: true, ok: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			server, serial := p.issue("")
			cred := write(t, dir, "cred.pem", server)
			s, err := ingress.New(ingress.Config{CredentialBundle: cred, TrustBundle: write(t, dir, "trust.pem", p.pem), AllowedClientID: tc.allowed})
			if err != nil {
				t.Fatal(err)
			}
			s.Activate("team-a", "counter", fakeFiberEndpoint(t))
			addr, stop := serve(t, s)
			if tc.rotate {
				var next []byte
				next, serial = p.issue("")
				write(t, dir, "cred.pem", next)
			}
			cfg := &tls.Config{RootCAs: p.pool, MinVersion: tls.VersionTLS12}
			if tc.client != nil {
				c, err := tls.X509KeyPair(tc.client, tc.client)
				if err != nil {
					t.Fatal(err)
				}
				cfg.Certificates = []tls.Certificate{c}
			}
			client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}}
			req, _ := http.NewRequest(http.MethodGet, "https://"+addr+"/count", nil)
			req.Header.Set(ingress.TargetActorHeader, "team-a/counter")
			resp, err := client.Do(req)
			if !tc.ok {
				if err == nil {
					_ = resp.Body.Close()
					t.Fatalf("request got through with %d", resp.StatusCode)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK || string(body) != "fiber GET /count" {
				t.Fatalf("response %d %q, want the fiber's", resp.StatusCode, body)
			}
			if got := resp.TLS.PeerCertificates[0].SerialNumber.Int64(); got != serial {
				t.Fatalf("the worker presented certificate %d, want %d", got, serial)
			}
			if err := stop(); err != nil {
				t.Fatalf("Serve = %v, want nil once stopped", err)
			}
		})
	}
}

// fakeFiberEndpoint stands in for a fiber. It answers with the method and
// path it got.
func fakeFiberEndpoint(t *testing.T) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "fiber "+r.Method+" "+r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	return "tcp://" + srv.Listener.Addr().String()
}

// TestServe checks that the plain-HTTP server routes until its context
// ends and then returns nil, and that a listener that cannot accept is an
// error.
func TestServe(t *testing.T) {
	cases := []struct {
		name   string
		closed bool // the listener is closed before Serve
	}{
		{name: "routes until stopped, then returns nil"},
		{name: "a closed listener is an error", closed: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := ingress.New(ingress.Config{})
			if err != nil {
				t.Fatal(err)
			}
			s.Activate("team-a", "counter", fakeFiberEndpoint(t))
			if tc.closed {
				lis, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				_ = lis.Close()
				if err := s.Serve(context.Background(), lis); err == nil || errors.Is(err, http.ErrServerClosed) {
					t.Fatalf("Serve on a closed listener = %v, want an accept error", err)
				}
				return
			}
			addr, stop := serve(t, s)
			req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/count", nil)
			req.Header.Set(ingress.TargetActorHeader, "team-a/counter")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if string(body) != "fiber GET /count" {
				t.Fatalf("body %q, want the fiber's", body)
			}
			if err := stop(); err != nil {
				t.Fatalf("Serve = %v, want nil once stopped", err)
			}
		})
	}
}
