package kube

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// pemOf is a server's certificate as a PEM bundle.
func pemOf(srv *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
}

// strangerPEM is a self-signed CA that signed nothing the tests serve.
func strangerPEM(t *testing.T) []byte {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "stranger"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestInCluster checks the client a Pod gets from its environment and its
// projected service account. It pins the API server's address, the token,
// and TLS that trusts only the projected CA.
func TestInCluster(t *testing.T) {
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"auth":"`+r.Header.Get("Authorization")+`"}`)
	}))
	t.Cleanup(api.Close)
	u, _ := url.Parse(api.URL)
	host, port, _ := net.SplitHostPort(u.Host)

	cases := []struct {
		name       string
		host, port string
		ca         []byte // nil means no CA file
		wantErr    string
		wantBase   string
		wantGetErr string // "" means a Get through the client succeeds
	}{
		{name: "no service host is not a cluster", port: port, ca: pemOf(api), wantErr: "not in a cluster"},
		{name: "no service port is not a cluster", host: host, ca: pemOf(api), wantErr: "not in a cluster"},
		{name: "no CA file is an error", host: host, port: port, wantErr: "kube: open"},
		{name: "a CA file without a certificate is an error", host: host, port: port, ca: []byte("not pem"), wantErr: "kube: no certificate in"},
		{name: "the projected CA is trusted", host: host, port: port, ca: pemOf(api), wantBase: api.URL},
		{name: "a server the projected CA did not sign is refused", host: host, port: port, ca: strangerPEM(t), wantBase: api.URL,
			wantGetErr: "certificate signed by unknown authority"},
		{name: "an IPv6 service host is bracketed", host: "fd00::1", port: "443", ca: pemOf(api), wantBase: "https://[fd00::1]:443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KUBERNETES_SERVICE_HOST", tc.host)
			t.Setenv("KUBERNETES_SERVICE_PORT", tc.port)
			dir := t.TempDir()
			old := caFile
			caFile = filepath.Join(dir, "ca.crt")
			t.Cleanup(func() { caFile = old })
			if tc.ca != nil {
				if err := os.WriteFile(caFile, tc.ca, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			c, err := InCluster()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("InCluster = %+v, %v; want %q", c, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.Base != tc.wantBase || c.TokenFile != TokenFile || c.HTTP.Timeout != 30*time.Second {
				t.Fatalf("client = %+v, want base %s, the projected token and a 30s timeout", c, tc.wantBase)
			}
			if strings.HasPrefix(tc.host, "fd00") {
				return
			}
			c.TokenFile = filepath.Join(dir, "token")
			if err := os.WriteFile(c.TokenFile, []byte("sa-token"), 0o600); err != nil {
				t.Fatal(err)
			}
			var got struct{ Auth string }
			err = c.Get(context.Background(), "/api", &got)
			if tc.wantGetErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantGetErr) {
					t.Fatalf("Get = %v, want %q", err, tc.wantGetErr)
				}
				return
			}
			if err != nil || got.Auth != "Bearer sa-token" {
				t.Fatalf("Get = %+v, %v", got, err)
			}
		})
	}
}

// TestNamespace checks the Pod's namespace read from the projected file.
func TestNamespace(t *testing.T) {
	cases := []struct {
		name    string
		content *string // nil means no file
		want    string
		wantErr string
	}{
		{name: "the namespace is trimmed", content: ptr("tenant-a\n"), want: "tenant-a"},
		{name: "no file is an error", wantErr: "kube: namespace"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := namespaceFile
			namespaceFile = filepath.Join(t.TempDir(), "namespace")
			t.Cleanup(func() { namespaceFile = old })
			if tc.content != nil {
				if err := os.WriteFile(namespaceFile, []byte(*tc.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := Namespace()
			if got != tc.want || (tc.wantErr == "") != (err == nil) || err != nil && !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Namespace = %q, %v; want %q, %q", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func ptr(s string) *string { return &s }
