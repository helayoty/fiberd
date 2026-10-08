package handoff

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
)

func TestDerive(t *testing.T) {
	keyA := bytes.Repeat([]byte{1}, 32)
	keyB := bytes.Repeat([]byte{2}, 32)
	cases := []struct {
		name       string
		key        []byte
		grant      string
		other      []byte // a second derivation to compare with
		otherGrant string
		same       bool
		wantErr    bool
	}{
		{name: "same key and grant on another home", key: keyA, grant: "g1", other: keyA, otherGrant: "g1", same: true},
		{name: "another grant", key: keyA, grant: "g1", other: keyA, otherGrant: "g2"},
		{name: "another key", key: keyA, grant: "g1", other: keyB, otherGrant: "g1"},
		{name: "short key", key: keyA[:16], grant: "g1", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := Derive(tc.key, tc.grant)
			if tc.wantErr {
				if err == nil {
					t.Fatal("want an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			// A usable server identity whose pin is its own key.
			pair, err := tls.X509KeyPair(id.CertPEM, id.KeyPEM)
			if err != nil {
				t.Fatalf("key pair: %v", err)
			}
			blk, _ := pem.Decode(id.CertPEM)
			cert, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if err := cert.VerifyHostname("anykey" + Suffix); err != nil {
				t.Fatalf("certificate does not cover %s names: %v", Suffix, err)
			}
			if got := KeyPin(cert.RawSubjectPublicKeyInfo); got != id.KeySHA256 {
				t.Fatalf("pin %s, certificate key hashes to %s", id.KeySHA256, got)
			}
			if pair.Leaf != nil && !bytes.Equal(pair.Leaf.Raw, cert.Raw) {
				t.Fatal("key pair leaf differs from the certificate")
			}
			other, err := Derive(tc.other, tc.otherGrant)
			if err != nil {
				t.Fatal(err)
			}
			same := other.KeySHA256 == id.KeySHA256 && bytes.Equal(other.CertPEM, id.CertPEM) && bytes.Equal(other.KeyPEM, id.KeyPEM)
			if same != tc.same {
				t.Fatalf("same identity = %v, want %v", same, tc.same)
			}
		})
	}
}

// ClientConfig names the fiber by its routing key, presents the caller's
// certificate when there is one, and accepts only the pinned server key.
func TestClientConfig(t *testing.T) {
	id, err := Derive(bytes.Repeat([]byte{1}, 32), "g1")
	if err != nil {
		t.Fatal(err)
	}
	other, err := Derive(bytes.Repeat([]byte{2}, 32), "g1")
	if err != nil {
		t.Fatal(err)
	}
	der := func(i Identity) []byte {
		blk, _ := pem.Decode(i.CertPEM)
		return blk.Bytes
	}
	caller, err := tls.X509KeyPair(other.CertPEM, other.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name      string
		cert      tls.Certificate
		raw       [][]byte // what the fiber presented
		wantErr   error
		wantCerts int
	}{
		{name: "the pinned key is accepted", raw: [][]byte{der(id)}},
		{name: "the caller's certificate is presented", cert: caller, raw: [][]byte{der(id)}, wantCerts: 1},
		{name: "another key is refused", raw: [][]byte{der(other)}, wantErr: ErrKeyMismatch},
		{name: "no certificate is refused", raw: nil, wantErr: ErrKeyMismatch},
		{name: "a certificate that does not parse is refused", raw: [][]byte{[]byte("junk")}, wantErr: ErrKeyMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ClientConfig("k1", id.KeySHA256, tc.cert)
			if cfg.ServerName != "k1"+Suffix || cfg.MinVersion != tls.VersionTLS13 || len(cfg.Certificates) != tc.wantCerts {
				t.Fatalf("config = name %q min %x certs %d, want k1%s TLS 1.3 with %d certs",
					cfg.ServerName, cfg.MinVersion, len(cfg.Certificates), Suffix, tc.wantCerts)
			}
			if err := cfg.VerifyPeerCertificate(tc.raw, nil); !errors.Is(err, tc.wantErr) {
				t.Fatalf("verify = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
