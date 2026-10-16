package grant

import "testing"

// checkJWKSURI keeps the key fetch on https when the issuer is, and
// refuses a jwks_uri that is not an absolute http(s) URL at all.
func TestCheckJWKSURI(t *testing.T) {
	cases := []struct {
		name    string
		issuer  string
		jwksURI string
		ok      bool
	}{
		{name: "https issuer, https keys", issuer: "https://issuer.test", jwksURI: "https://keys.test/jwks", ok: true},
		{name: "http issuer, http keys", issuer: "http://127.0.0.1:8080", jwksURI: "http://127.0.0.1:8080/jwks", ok: true},
		{name: "http issuer, https keys", issuer: "http://127.0.0.1:8080", jwksURI: "https://keys.test/jwks", ok: true},
		{name: "https issuer, http keys", issuer: "https://issuer.test", jwksURI: "http://keys.test/jwks"},
		{name: "https issuer in upper case, http keys", issuer: "HTTPS://issuer.test", jwksURI: "http://keys.test/jwks"},
		{name: "a relative jwks_uri", issuer: "https://issuer.test", jwksURI: "/jwks"},
		{name: "a file jwks_uri", issuer: "http://127.0.0.1:8080", jwksURI: "file:///etc/jwks.json"},
		{name: "a jwks_uri without a host", issuer: "http://127.0.0.1:8080", jwksURI: "http:///jwks"},
		{name: "a jwks_uri that does not parse", issuer: "http://127.0.0.1:8080", jwksURI: "http://bad\x00host/jwks"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := checkJWKSURI(c.issuer, c.jwksURI); (err == nil) != c.ok {
				t.Fatalf("checkJWKSURI(%q, %q) = %v, want ok %v", c.issuer, c.jwksURI, err, c.ok)
			}
		})
	}
}
