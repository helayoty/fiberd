package grant_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/helayoty/fiberd/pkg/grant"
)

func TestGenerateKey(t *testing.T) {
	cases := []struct {
		name    string
		alg     jose.SignatureAlgorithm
		wantErr bool
	}{
		{name: "EdDSA", alg: jose.EdDSA},
		{name: "ES256", alg: jose.ES256},
		{name: "RS256 is not a protocol algorithm", alg: jose.RS256, wantErr: true},
		{name: "HS256 is not a protocol algorithm", alg: jose.HS256, wantErr: true},
		{name: "none is not a protocol algorithm", alg: "none", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k, err := grant.GenerateKey(tc.alg)
			if tc.wantErr {
				if err == nil || k != nil || !strings.Contains(err.Error(), "unsupported algorithm") {
					t.Fatalf("GenerateKey(%s) = %v, %v, want a refusal", tc.alg, k, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if k.IsPublic() || !k.Valid() || k.Algorithm != string(tc.alg) || k.Use != "sig" || k.KeyID == "" {
				t.Fatalf("key = %+v, want a valid private %s signing key with a kid", k, tc.alg)
			}
		})
	}
}

// SaveKey leaves the private key readable by its owner only, even when
// it replaces a file that was readable by others.
func TestSaveKey(t *testing.T) {
	key, err := grant.GenerateKey(jose.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		existing os.FileMode // mode of a file already at the path, 0 for none
		path     func(dir string) string
		key      *jose.JSONWebKey
		wantErr  string
	}{
		{name: "a new file is owner-only", key: key},
		{name: "an existing world-readable file is tightened", existing: 0o644, key: key},
		{name: "a missing directory fails", key: key, wantErr: "no such file",
			path: func(dir string) string { return filepath.Join(dir, "missing", "key.json") }},
		{name: "a key that cannot be encoded fails and writes nothing", key: &jose.JSONWebKey{Key: "not a key"}, wantErr: "unknown key type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "key.json")
			if tc.path != nil {
				path = tc.path(dir)
			}
			if tc.existing != 0 {
				if err := os.WriteFile(path, []byte("old"), tc.existing); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, tc.existing); err != nil {
					t.Fatal(err)
				}
			}
			err := grant.SaveKey(path, tc.key)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("SaveKey = %v, want an error containing %q", err, tc.wantErr)
				}
				if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
					t.Fatalf("SaveKey failed but left %s behind", path)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			fi, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0o600 {
				t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
			}
			back, err := grant.LoadKey(path)
			if err != nil || back.KeyID != tc.key.KeyID {
				t.Fatalf("LoadKey after SaveKey = %v, %v, want kid %s", back, err, tc.key.KeyID)
			}
		})
	}
}

func TestLoadKey(t *testing.T) {
	key, err := grant.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	full, err := key.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public()
	pubJSON, err := pub.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	without := func(field string) []byte {
		k := *key
		switch field {
		case "kid":
			k.KeyID = ""
		case "alg":
			k.Algorithm = ""
		}
		b, err := k.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	cases := []struct {
		name    string
		content []byte // nil means no file
		wantErr string
		wantPub bool
	}{
		{name: "a private key loads", content: full},
		{name: "a public key loads as public", content: pubJSON, wantPub: true},
		{name: "a missing file fails", content: nil, wantErr: "no such file"},
		{name: "a file that is not JSON fails", content: []byte("-----BEGIN"), wantErr: "parse key"},
		{name: "an unknown key type fails", content: []byte(`{"kty":"XYZ"}`), wantErr: "parse key"},
		{name: "a symmetric key is not a signing key", content: []byte(`{"kty":"oct","k":"c2VjcmV0","kid":"k","alg":"HS256"}`), wantErr: "not valid"},
		{name: "a key without a kid fails", content: without("kid"), wantErr: "no kid"},
		{name: "a key without an alg fails", content: without("alg"), wantErr: "no alg"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key.json")
			if tc.content != nil {
				if err := os.WriteFile(path, tc.content, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			k, err := grant.LoadKey(path)
			if tc.wantErr != "" {
				if err == nil || k != nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("LoadKey = %v, %v, want an error containing %q", k, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if k.KeyID != key.KeyID || k.IsPublic() != tc.wantPub {
				t.Fatalf("LoadKey = kid %s public %v, want kid %s public %v", k.KeyID, k.IsPublic(), key.KeyID, tc.wantPub)
			}
		})
	}
}
