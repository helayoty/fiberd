package tlsconf_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/fiberd/pkg/core"
	"github.com/Azure/fiberd/pkg/tlsconf"
	"github.com/Azure/fiberd/pkg/tlsconf/tlsconftest"
)

// files holds a CA and a leaf issued by it on disk, plus the broken
// files the error cases point at.
type files struct {
	caFile        string
	certFile      string
	keyFile       string
	empty         string // a CA bundle with no certificate in it
	missing       string // a path that does not exist
	mismatchedKey string // a valid key that is not the certificate's
}

func newFiles(t *testing.T, leaf func(ca tlsconftest.Pair) tlsconftest.Pair) files {
	t.Helper()
	dir, ca := t.TempDir(), tlsconftest.NewCA(t, "ca")
	var f files
	f.caFile, _ = ca.Write(t, dir, "ca")
	f.certFile, f.keyFile = leaf(ca).Write(t, dir, "leaf")
	_, f.mismatchedKey = leaf(ca).Write(t, dir, "other")
	f.empty = filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(f.empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f.missing = filepath.Join(dir, "nope.pem")
	return f
}

// thumbprint is Thumbprint of a certificate whose key has one.
func thumbprint(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	tp, err := tlsconf.Thumbprint(cert)
	if err != nil {
		t.Fatal(err)
	}
	return tp
}

func TestServerTransportChoice(t *testing.T) {
	f := newFiles(t, func(ca tlsconftest.Pair) tlsconftest.Pair { return ca.Server(t) })

	cases := []struct {
		name          string
		cert, key, ca string
		plaintext     bool
		wantErr       error
		wantMsg       string // substring of the error, when there is no sentinel
		wantNil       bool
	}{
		{name: "nothing set refuses to start", wantErr: tlsconf.ErrNoTransport},
		{name: "explicit plaintext", plaintext: true, wantNil: true},
		{name: "plaintext with tls files", cert: f.certFile, key: f.keyFile, ca: f.caFile, plaintext: true, wantErr: tlsconf.ErrPlaintextWithTLS},
		{name: "plaintext with only a client ca", ca: f.caFile, plaintext: true, wantErr: tlsconf.ErrPlaintextWithTLS},
		{name: "missing client ca", cert: f.certFile, key: f.keyFile, wantErr: tlsconf.ErrPartialTLS},
		{name: "missing key", cert: f.certFile, ca: f.caFile, wantErr: tlsconf.ErrPartialTLS},
		{name: "missing certificate", key: f.keyFile, ca: f.caFile, wantErr: tlsconf.ErrPartialTLS},
		{name: "ca bundle without certificates", cert: f.certFile, key: f.keyFile, ca: f.empty, wantMsg: "holds no PEM certificate"},
		{name: "unreadable ca bundle", cert: f.certFile, key: f.keyFile, ca: f.missing, wantMsg: "CA bundle"},
		{name: "unreadable certificate", cert: f.missing, key: f.keyFile, ca: f.caFile, wantMsg: "server certificate"},
		{name: "a key that is not the certificate's", cert: f.certFile, key: f.mismatchedKey, ca: f.caFile, wantMsg: "server certificate"},
		{name: "mutual tls", cert: f.certFile, key: f.keyFile, ca: f.caFile},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := tlsconf.Server(tc.cert, tc.key, tc.ca, tc.plaintext)
			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) || cfg != nil {
					t.Fatalf("Server = %v, %v, want %v", cfg, err, tc.wantErr)
				}
				return
			case tc.wantMsg != "":
				if err == nil || cfg != nil || !strings.Contains(err.Error(), tc.wantMsg) {
					t.Fatalf("Server = %v, %v, want an error containing %q", cfg, err, tc.wantMsg)
				}
				return
			case err != nil:
				t.Fatalf("err = %v", err)
			}
			if tc.wantNil {
				if cfg != nil {
					t.Fatalf("cfg = %+v, want nil (plaintext)", cfg)
				}
				return
			}
			if cfg.MinVersion != tls.VersionTLS13 || cfg.ClientAuth != tls.RequireAndVerifyClientCert || cfg.ClientCAs == nil {
				t.Fatalf("cfg = min %x auth %v cas %v, want TLS 1.3 requiring a verified client certificate", cfg.MinVersion, cfg.ClientAuth, cfg.ClientCAs)
			}
		})
	}
}

func TestClientTransportChoice(t *testing.T) {
	f := newFiles(t, func(ca tlsconftest.Pair) tlsconftest.Pair { return ca.Client(t, "c") })

	cases := []struct {
		name          string
		ca, cert, key string
		wantErr       error
		wantMsg       string // substring of the error, when there is no sentinel
		wantNil       bool
	}{
		{name: "nothing set dials plaintext", wantNil: true},
		{name: "ca only", ca: f.caFile, wantErr: tlsconf.ErrPartialTLS},
		{name: "certificate and key without a ca", cert: f.certFile, key: f.keyFile, wantErr: tlsconf.ErrPartialTLS},
		{name: "unreadable certificate", ca: f.caFile, cert: f.missing, key: f.keyFile, wantMsg: "client certificate"},
		{name: "a key that is not the certificate's", ca: f.caFile, cert: f.certFile, key: f.mismatchedKey, wantMsg: "client certificate"},
		{name: "ca bundle without certificates", ca: f.empty, cert: f.certFile, key: f.keyFile, wantMsg: "holds no PEM certificate"},
		{name: "unreadable ca bundle", ca: f.missing, cert: f.certFile, key: f.keyFile, wantMsg: "CA bundle"},
		{name: "mutual tls", ca: f.caFile, cert: f.certFile, key: f.keyFile},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := tlsconf.Client(tc.ca, tc.cert, tc.key)
			switch {
			case tc.wantMsg != "":
				if err == nil || cfg != nil || !strings.Contains(err.Error(), tc.wantMsg) {
					t.Fatalf("Client = %v, %v, want an error containing %q", cfg, err, tc.wantMsg)
				}
				return
			case !errors.Is(err, tc.wantErr):
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if (cfg == nil) != (tc.wantNil || tc.wantErr != nil) {
				t.Fatalf("cfg = %v, want nil=%v", cfg, tc.wantNil)
			}
			if cfg != nil && (cfg.MinVersion != tls.VersionTLS13 || len(cfg.Certificates) != 1 || cfg.RootCAs == nil) {
				t.Fatalf("cfg = %+v, want TLS 1.3 with a client certificate and roots", cfg)
			}
		})
	}
}

func TestHandshakeNamesCaller(t *testing.T) {
	dir := t.TempDir()
	ca := tlsconftest.NewCA(t, "ca")
	caFile, _ := ca.Write(t, dir, "ca")
	srvCert, srvKey := ca.Server(t).Write(t, dir, "fiberd")
	scfg, err := tlsconf.Server(srvCert, srvKey, caFile, false)
	if err != nil {
		t.Fatal(err)
	}

	spiffe, _ := url.Parse("spiffe://example.org/router")
	clientAuth := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	withURI := ca.Issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "router"}, URIs: []*url.URL{spiffe}, ExtKeyUsage: clientAuth})
	cnOnly := ca.Client(t, "activator")
	foreign := tlsconftest.NewCA(t, "other").Client(t, "intruder")

	cases := []struct {
		name     string
		client   tlsconftest.Pair
		wantFail bool
	}{
		{name: "a client with a uri san is named by its thumbprint", client: withURI},
		{name: "a client with only a distinguished name is named by its thumbprint", client: cnOnly},
		{name: "certificate from another ca is refused", client: foreign, wantFail: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert, key := tc.client.Write(t, t.TempDir(), "client")
			ccfg, err := tlsconf.Client(caFile, cert, key)
			if err != nil {
				t.Fatal(err)
			}
			ccfg.ServerName = "localhost"

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = ln.Close() }()
			got := make(chan tls.ConnectionState, 1)
			srvErr := make(chan error, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					got <- tls.ConnectionState{}
					srvErr <- err
					return
				}
				defer func() { _ = conn.Close() }()
				s := tls.Server(conn, scfg)
				err = s.Handshake()
				got <- s.ConnectionState()
				srvErr <- err
			}()
			conn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			cliErr := tls.Client(conn, ccfg).Handshake()
			st, serr := <-got, <-srvErr
			if tc.wantFail {
				if serr == nil {
					t.Fatal("server accepted a client certificate from another CA")
				}
				return
			}
			if cliErr != nil || serr != nil {
				t.Fatalf("handshake: client %v, server %v", cliErr, serr)
			}
			c, ok := tlsconf.CallerOf(st.PeerCertificates)
			if !ok || c.Thumbprint != thumbprint(t, tc.client.Cert) {
				t.Fatalf("caller = %+v ok=%v, want the client's thumbprint", c, ok)
			}
			// What grant-issuer -bind-cert puts in cnf is what the handshake sees.
			if fromFile, err := tlsconf.ThumbprintFile(cert); err != nil || fromFile != c.Thumbprint {
				t.Fatalf("ThumbprintFile = %q %v, want %q", fromFile, err, c.Thumbprint)
			}
		})
	}
}

// dialTLS runs one mutual-TLS handshake over loopback and returns the
// client's view of it, with the server's error first when it had one.
// It never fails the test itself, so goroutines may call it.
func dialTLS(scfg, ccfg *tls.Config) (tls.ConnectionState, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer func() { _ = ln.Close() }()
	srvErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer func() { _ = conn.Close() }()
		srvErr <- tls.Server(conn, scfg).Handshake()
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer func() { _ = conn.Close() }()
	c := tls.Client(conn, ccfg)
	cliErr := c.Handshake()
	if serr := <-srvErr; serr != nil {
		return c.ConnectionState(), serr
	}
	return c.ConnectionState(), cliErr
}

// touchLater moves every path's mtime one minute into the future, so
// the reloader sees a change whatever the filesystem's mtime
// granularity.
func touchLater(t *testing.T, paths ...string) {
	t.Helper()
	at := time.Now().Add(time.Minute)
	for _, p := range paths {
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
	}
}

// Server keeps serving from the files cert-manager renews in place. A
// handshake after the one-second check sees the new leaf, the new client
// CA is enforced, and a broken renewal leaves the old pair in service.
func TestServerReloadsWithoutRestart(t *testing.T) {
	const srvName = "fiberd"
	cases := []struct {
		name string
		// renew rewrites files under dir, given the CA and the leaf that
		// were in service, and returns the CA the client is issued by.
		renew      func(t *testing.T, dir string, ca, leaf tlsconftest.Pair) (clientCA tlsconftest.Pair, wantSerial int64)
		wait       bool // sleep past the check interval before the handshake
		foreignCA  bool // the client is issued by the CA that was replaced
		alpn       []string
		wantProto  string
		wantRefuse bool
	}{
		{name: "a renewed leaf is served", wait: true,
			renew: func(t *testing.T, dir string, ca, leaf tlsconftest.Pair) (tlsconftest.Pair, int64) {
				renewed := ca.Server(t)
				cert, key := renewed.Write(t, dir, srvName)
				touchLater(t, cert, key)
				return ca, renewed.Cert.SerialNumber.Int64()
			}},
		{name: "a client from the renewed ca is accepted", wait: true,
			renew: func(t *testing.T, dir string, ca, leaf tlsconftest.Pair) (tlsconftest.Pair, int64) {
				newCA := tlsconftest.NewCA(t, "ca2")
				caFile, _ := newCA.Write(t, dir, "ca")
				touchLater(t, caFile)
				return newCA, leaf.Cert.SerialNumber.Int64()
			}},
		{name: "a client from the replaced ca is refused", wait: true, foreignCA: true, wantRefuse: true,
			renew: func(t *testing.T, dir string, ca, leaf tlsconftest.Pair) (tlsconftest.Pair, int64) {
				newCA := tlsconftest.NewCA(t, "ca2")
				caFile, _ := newCA.Write(t, dir, "ca")
				touchLater(t, caFile)
				return newCA, 0
			}},
		{name: "a bad renewal keeps the old pair in service", wait: true,
			renew: func(t *testing.T, dir string, ca, leaf tlsconftest.Pair) (tlsconftest.Pair, int64) {
				_, otherKey := ca.Server(t).Write(t, t.TempDir(), "other")
				bad, err := os.ReadFile(otherKey)
				if err != nil {
					t.Fatal(err)
				}
				keyFile := filepath.Join(dir, srvName+".key")
				if err := os.WriteFile(keyFile, bad, 0o600); err != nil {
					t.Fatal(err)
				}
				touchLater(t, keyFile)
				return ca, leaf.Cert.SerialNumber.Int64()
			}},
		{name: "h2 is negotiated through the snapshot", alpn: []string{"h2"}, wantProto: "h2",
			renew: func(t *testing.T, dir string, ca, leaf tlsconftest.Pair) (tlsconftest.Pair, int64) {
				return ca, leaf.Cert.SerialNumber.Int64()
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			ca := tlsconftest.NewCA(t, "ca")
			caFile, _ := ca.Write(t, dir, "ca")
			leaf := ca.Server(t)
			srvCert, srvKey := leaf.Write(t, dir, srvName)
			scfg, err := tlsconf.Server(srvCert, srvKey, caFile, false)
			if err != nil {
				t.Fatal(err)
			}
			if len(scfg.Certificates) != 0 || scfg.GetCertificate == nil || scfg.GetConfigForClient == nil {
				t.Fatalf("cfg has %d static certificates, GetCertificate %v, GetConfigForClient %v, want none and both hooks", len(scfg.Certificates), scfg.GetCertificate != nil, scfg.GetConfigForClient != nil)
			}

			clientCA, wantSerial := tc.renew(t, dir, ca, leaf)
			if tc.foreignCA {
				clientCA = ca
			}
			// The client trusts the CA the server's leaf was issued by,
			// which every case leaves in place.
			ccfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: ca.Pool(), ServerName: "localhost",
				Certificates: []tls.Certificate{clientCA.Client(t, "c").TLS()}, NextProtos: tc.alpn}
			if tc.wait {
				time.Sleep(1100 * time.Millisecond)
			}
			st, err := dialTLS(scfg, ccfg)
			if tc.wantRefuse {
				// The server's certificate request names the new CA. Go's
				// client withholds a certificate that no named CA issued,
				// so the server refuses for a missing certificate. A
				// client that sent it anyway would be refused for an
				// unknown authority. Both prove the old CA is gone.
				refused := err != nil && (strings.Contains(err.Error(), "didn't provide a certificate") ||
					strings.Contains(err.Error(), "unknown certificate authority") ||
					strings.Contains(err.Error(), "unknown authority"))
				if !refused {
					t.Fatalf("handshake err = %v, want the old ca's client refused", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("handshake: %v", err)
			}
			if len(st.PeerCertificates) == 0 || st.PeerCertificates[0].SerialNumber.Int64() != wantSerial {
				t.Fatalf("served serial %v, want %d", st.PeerCertificates, wantSerial)
			}
			if st.NegotiatedProtocol != tc.wantProto {
				t.Fatalf("negotiated %q, want %q", st.NegotiatedProtocol, tc.wantProto)
			}
		})
	}
}

// serving is Server's config over a CA and a leaf on disk, the way
// fiberd holds it.
type serving struct {
	dir      string
	ca, leaf tlsconftest.Pair
	scfg     *tls.Config
	started  time.Time // when scfg was built, which starts its first check interval
}

func newServing(t *testing.T) serving {
	t.Helper()
	s := serving{dir: t.TempDir(), ca: tlsconftest.NewCA(t, "ca")}
	caFile, _ := s.ca.Write(t, s.dir, "ca")
	s.leaf = s.ca.Server(t)
	srvCert, srvKey := s.leaf.Write(t, s.dir, "fiberd")
	cfg, err := tlsconf.Server(srvCert, srvKey, caFile, false)
	if err != nil {
		t.Fatal(err)
	}
	s.scfg, s.started = cfg, time.Now()
	return s
}

// client is a mutual-TLS client of s issued by its CA.
func (s serving) client(t *testing.T, alpn ...string) *tls.Config {
	t.Helper()
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: s.ca.Pool(), ServerName: "localhost",
		Certificates: []tls.Certificate{s.ca.Client(t, "c").TLS()}, NextProtos: alpn}
}

// The config with no static certificate serves fiberd's HTTP gateway
// the way fiberd runs it, and a renewal lands while handshakes are in
// flight without failing any of them.
func TestServerReloadsWhileServing(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T, s serving)
	}{
		{name: "http.Server serves and negotiates h2 from the hooks alone", run: func(t *testing.T, s serving) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			hs := &http.Server{TLSConfig: s.scfg, ReadHeaderTimeout: time.Second,
				Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })}
			done := make(chan error, 1)
			go func() { done <- hs.ServeTLS(ln, "", "") }()
			defer func() {
				_ = hs.Close()
				if err := <-done; !errors.Is(err, http.ErrServerClosed) {
					t.Errorf("ServeTLS = %v, want ErrServerClosed", err)
				}
			}()
			tr := &http.Transport{TLSClientConfig: s.client(t), ForceAttemptHTTP2: true}
			defer tr.CloseIdleConnections()
			resp, err := (&http.Client{Transport: tr}).Get("https://" + ln.Addr().String() + "/")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusNoContent || resp.ProtoMajor != 2 {
				t.Fatalf("GET = %d over %s, want 204 over HTTP/2", resp.StatusCode, resp.Proto)
			}
			if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 || resp.TLS.PeerCertificates[0].SerialNumber.Cmp(s.leaf.Cert.SerialNumber) != 0 {
				t.Fatalf("served %+v, want the leaf on disk", resp.TLS)
			}
		}},
		{name: "a renewal lands under concurrent handshakes without failing one", run: func(t *testing.T, s serving) {
			ccfg := s.client(t)
			renewed := s.ca.Server(t)
			// One listener for every handshake, so the loopback port range
			// is not burned through. Failures on either side are counted.
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			var failed int
			var firstErr error
			record := func(err error) {
				mu.Lock()
				defer mu.Unlock()
				failed++
				if firstErr == nil {
					firstErr = err
				}
			}
			var servers sync.WaitGroup
			go func() {
				for {
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					servers.Add(1)
					go func() {
						defer servers.Done()
						defer func() { _ = conn.Close() }()
						if err := tls.Server(conn, s.scfg).Handshake(); err != nil {
							record(err)
						}
					}()
				}
			}()
			var sawNew atomic.Int64
			stop := make(chan struct{})
			var clients sync.WaitGroup
			for range 8 {
				clients.Add(1)
				go func() {
					defer clients.Done()
					for {
						select {
						case <-stop:
							return
						default:
						}
						conn, err := net.Dial("tcp", ln.Addr().String())
						if err != nil {
							record(err)
							continue
						}
						c := tls.Client(conn, ccfg)
						if err := c.Handshake(); err != nil {
							record(err)
						} else {
							if c.ConnectionState().PeerCertificates[0].SerialNumber.Cmp(renewed.Cert.SerialNumber) == 0 {
								sawNew.Add(1)
							}
							// Wait for the server to finish and close, so its
							// session tickets never hit a closed socket.
							_, _ = c.Read(make([]byte, 1))
						}
						_ = conn.Close()
						time.Sleep(5 * time.Millisecond)
					}
				}()
			}
			// The rewrite finishes well inside the first interval, so no
			// load can ever see it half done. The first check after the
			// interval, inside one of the racing handshakes, picks it up.
			time.Sleep(200 * time.Millisecond)
			cert, key := renewed.Write(t, s.dir, "fiberd")
			touchLater(t, cert, key)
			time.Sleep(time.Until(s.started.Add(1300 * time.Millisecond)))
			close(stop)
			clients.Wait()
			_ = ln.Close()
			servers.Wait()
			mu.Lock()
			n, first := failed, firstErr
			mu.Unlock()
			if n != 0 {
				t.Fatalf("%d handshakes failed across the renewal, first: %v", n, first)
			}
			if sawNew.Load() == 0 {
				t.Fatal("no concurrent handshake saw the renewed leaf")
			}
			st, err := dialTLS(s.scfg, ccfg)
			if err != nil || st.PeerCertificates[0].SerialNumber.Cmp(renewed.Cert.SerialNumber) != 0 {
				t.Fatalf("final handshake = %v, serial %v, want the renewed serial %v", err, st.PeerCertificates, renewed.Cert.SerialNumber)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.run(t, newServing(t))
		})
	}
}

// A caller is named by its key, not by its certificate. The name is the
// RFC 7638 thumbprint, so any JWT library derives the same one, and a
// renewal over the same key keeps it.
func TestThumbprint(t *testing.T) {
	// The RSA key of RFC 7638 section 3.1.
	const rfcRSAModulus = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	// The P-521 key of RFC 7520 section 3.1, whose x starts with a zero byte.
	const (
		rfcP521X = "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt"
		rfcP521Y = "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"
	)
	b64 := base64.RawURLEncoding
	decode := func(s string) []byte {
		t.Helper()
		b, err := b64.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	// hashOf over a canonical JWK written out by hand is the thumbprint
	// RFC 7638 defines. Over a DER certificate it is the certificate
	// hash, which a renewal changes.
	hashOf := func(b []byte) string {
		sum := sha256.Sum256(b)
		return b64.EncodeToString(sum[:])
	}

	rfcRSA := &rsa.PublicKey{N: new(big.Int).SetBytes(decode(rfcRSAModulus)), E: 65537} // "AQAB"
	rfcP521, err := ecdsa.ParseUncompressedPublicKey(elliptic.P521(), slices.Concat([]byte{4}, decode(rfcP521X), decode(rfcP521Y)))
	if err != nil {
		t.Fatal(err)
	}
	rfcEd := ed25519.PublicKey(decode("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"))
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ca := tlsconftest.NewCA(t, "ca")
	p256 := ca.Client(t, "c")
	// The uncompressed point, a 0x04 byte before the two 32-byte
	// coordinates, already padded the way a JWK wants them.
	point, err := p256.Key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	first := ca.Client(t, "first")
	renewed := ca.Renew(t, first)

	cases := []struct {
		name    string
		cert    *x509.Certificate
		want    string            // the exact thumbprint, when it is known
		same    *x509.Certificate // a second certificate over cert's key
		differs *x509.Certificate // a certificate over another key
		wantErr bool
	}{
		{name: "the RFC 7638 section 3.1 RSA vector", cert: &x509.Certificate{PublicKey: rfcRSA},
			want: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"},
		{name: "the RFC 8037 appendix A.3 Ed25519 vector", cert: &x509.Certificate{PublicKey: rfcEd},
			want: "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"},
		{name: "an Ed25519 key hand-computed through its canonical form", cert: &x509.Certificate{PublicKey: edPub},
			want: hashOf([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + b64.EncodeToString(edPub) + `"}`))},
		{name: "a P-256 key hand-computed through its canonical form", cert: p256.Cert,
			want: hashOf([]byte(`{"crv":"P-256","kty":"EC","x":"` + b64.EncodeToString(point[1:33]) + `","y":"` + b64.EncodeToString(point[33:]) + `"}`))},
		{name: "a P-521 key whose coordinate starts with a zero byte keeps its padding", cert: &x509.Certificate{PublicKey: rfcP521},
			want: hashOf([]byte(`{"crv":"P-521","kty":"EC","x":"` + rfcP521X + `","y":"` + rfcP521Y + `"}`))},
		{name: "two certificates from one key give one thumbprint", cert: first.Cert, same: renewed.Cert},
		{name: "two keys give two thumbprints", cert: p256.Cert, differs: ca.Client(t, "other").Cert},
		{name: "a key without a canonical JWK form is an error", cert: ca.UnnamedClient(t).Cert, wantErr: true},
		{name: "a certificate without a key is an error", cert: &x509.Certificate{}, wantErr: true},
	}
	// A grant's callerThumbprint must fit this pattern.
	wellFormed := regexp.MustCompile(core.CallerThumbprintPattern)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tlsconf.Thumbprint(tc.cert)
			if tc.wantErr {
				if err == nil || got != "" {
					t.Fatalf("Thumbprint = %q, %v, want an error and no thumbprint", got, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !wellFormed.MatchString(got) {
				t.Fatalf("Thumbprint = %q, want 43 base64url characters", got)
			}
			if tc.want != "" && got != tc.want {
				t.Fatalf("Thumbprint = %q, want %q", got, tc.want)
			}
			if tc.same != nil {
				if again := thumbprint(t, tc.same); again != got {
					t.Fatalf("Thumbprint = %q then %q, want one thumbprint for one key", got, again)
				}
				for _, c := range []*x509.Certificate{tc.cert, tc.same} {
					if got == hashOf(c.Raw) {
						t.Fatalf("Thumbprint = %q, the hash of a certificate, want the key's", got)
					}
				}
			}
			if tc.differs != nil && thumbprint(t, tc.differs) == got {
				t.Fatalf("Thumbprint = %q for two keys, want two thumbprints", got)
			}
		})
	}
}

// A connection without a verified chain has no caller. With one, the
// caller is the leaf, never an intermediate. A leaf that no grant can
// name is no caller either.
func TestCallerOf(t *testing.T) {
	ca := tlsconftest.NewCA(t, "ca")
	leaf := ca.Client(t, "c")
	cases := []struct {
		name   string
		chain  []*x509.Certificate
		want   string
		wantOK bool
	}{
		{name: "no chain is no caller", chain: nil},
		{name: "an empty chain is no caller", chain: []*x509.Certificate{}},
		{name: "the leaf names the caller", chain: []*x509.Certificate{leaf.Cert, ca.Cert}, want: thumbprint(t, leaf.Cert), wantOK: true},
		{name: "a leaf whose key has no canonical form is no caller", chain: []*x509.Certificate{ca.UnnamedClient(t).Cert, ca.Cert}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, ok := tlsconf.CallerOf(tc.chain)
			if ok != tc.wantOK || c.Thumbprint != tc.want {
				t.Fatalf("CallerOf = %+v, %v, want %q, %v", c, ok, tc.want, tc.wantOK)
			}
			var wantCert []byte
			if tc.wantOK {
				wantCert = tc.chain[0].Raw
			}
			if !bytes.Equal(c.Cert, wantCert) {
				t.Fatalf("CallerOf cert = %d bytes, want the leaf's %d", len(c.Cert), len(wantCert))
			}
		})
	}
}

// ThumbprintFile takes the first certificate in the file, skipping any
// other PEM block before it, and refuses a file without one.
func TestThumbprintFile(t *testing.T) {
	ca := tlsconftest.NewCA(t, "ca")
	leaf := ca.Client(t, "c")
	keyDER, err := x509.MarshalECPrivateKey(leaf.Key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cat := func(parts ...[]byte) []byte {
		var out []byte
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}

	cases := []struct {
		name    string
		content []byte // nil means no file
		want    string
		wantErr string
	}{
		{name: "a single certificate", content: leaf.CertPEM(), want: thumbprint(t, leaf.Cert)},
		{name: "a key before the certificate is skipped", content: cat(keyPEM, leaf.CertPEM()), want: thumbprint(t, leaf.Cert)},
		{name: "the first of a chain is the leaf", content: cat(leaf.CertPEM(), ca.CertPEM()), want: thumbprint(t, leaf.Cert)},
		{name: "a missing file", content: nil, wantErr: "no such file"},
		{name: "a file of only a key", content: keyPEM, wantErr: "holds no PEM certificate"},
		{name: "a file that is not PEM", content: []byte("hello"), wantErr: "holds no PEM certificate"},
		{name: "a certificate block that is not DER", content: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}), wantErr: "x509"},
		{name: "a certificate whose key has no canonical form", content: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.UnnamedClient(t).Cert.Raw}), wantErr: "no JWK thumbprint"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "c.pem")
			if tc.content != nil {
				if err := os.WriteFile(path, tc.content, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := tlsconf.ThumbprintFile(path)
			if tc.wantErr != "" {
				if err == nil || got != "" || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("ThumbprintFile = %q, %v, want an error containing %q", got, err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("ThumbprintFile = %q, %v, want %q", got, err, tc.want)
			}
		})
	}
}
