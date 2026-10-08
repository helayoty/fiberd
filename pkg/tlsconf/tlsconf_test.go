package tlsconf_test

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/helayoty/fiberd/pkg/tlsconf"
	"github.com/helayoty/fiberd/pkg/tlsconf/tlsconftest"
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
	srvCert, srvKey := ca.Server(t).Write(t, dir, "agent")
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
			if !ok || c.Thumbprint != tlsconf.Thumbprint(tc.client.Cert) {
				t.Fatalf("caller = %+v ok=%v, want the client's thumbprint", c, ok)
			}
			// What grant-issuer -bind-cert puts in cnf is what the handshake sees.
			if fromFile, err := tlsconf.ThumbprintFile(cert); err != nil || fromFile != c.Thumbprint {
				t.Fatalf("ThumbprintFile = %q %v, want %q", fromFile, err, c.Thumbprint)
			}
		})
	}
}

// A connection without a verified chain has no caller. With one, the
// caller is the leaf, never an intermediate.
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
		{name: "the leaf names the caller", chain: []*x509.Certificate{leaf.Cert, ca.Cert}, want: tlsconf.Thumbprint(leaf.Cert), wantOK: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, ok := tlsconf.CallerOf(tc.chain)
			if ok != tc.wantOK || c.Thumbprint != tc.want {
				t.Fatalf("CallerOf = %+v, %v, want %q, %v", c, ok, tc.want, tc.wantOK)
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
		{name: "a single certificate", content: leaf.CertPEM(), want: tlsconf.Thumbprint(leaf.Cert)},
		{name: "a key before the certificate is skipped", content: cat(keyPEM, leaf.CertPEM()), want: tlsconf.Thumbprint(leaf.Cert)},
		{name: "the first of a chain is the leaf", content: cat(leaf.CertPEM(), ca.CertPEM()), want: tlsconf.Thumbprint(leaf.Cert)},
		{name: "a missing file", content: nil, wantErr: "no such file"},
		{name: "a file of only a key", content: keyPEM, wantErr: "holds no PEM certificate"},
		{name: "a file that is not PEM", content: []byte("hello"), wantErr: "holds no PEM certificate"},
		{name: "a certificate block that is not DER", content: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}), wantErr: "x509"},
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
