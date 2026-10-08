package artifact_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/grant"
)

func genKey(t *testing.T, alg jose.SignatureAlgorithm) *jose.JSONWebKey {
	t.Helper()
	k, err := grant.GenerateKey(alg)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func jwkJSON(t *testing.T, k jose.JSONWebKey) string {
	t.Helper()
	b, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func jwksJSON(t *testing.T, keys ...jose.JSONWebKey) string {
	t.Helper()
	b, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestLoadKeys(t *testing.T) {
	signer, peer, ec := genKey(t, jose.EdDSA), genKey(t, jose.EdDSA), genKey(t, jose.ES256)
	noKID := *signer
	noKID.KeyID = ""
	peerNoKID := peer.Public()
	peerNoKID.KeyID = ""
	good := jwkJSON(t, *signer)
	cases := []struct {
		name          string
		signer, trust string // file contents; "-" for no file
		wantTrust     []string
		ok            bool
	}{
		{name: "a private Ed25519 signer alone", signer: good, ok: true},
		{name: "a signer and a trust bundle", signer: good, trust: jwksJSON(t, peer.Public()), wantTrust: []string{peer.KeyID}, ok: true},
		{name: "a private key in the bundle is trusted by its public half", signer: good,
			trust: jwksJSON(t, *peer), wantTrust: []string{peer.KeyID}, ok: true},
		{name: "a missing signer file", signer: "-"},
		{name: "a signer that is not JSON", signer: "not json"},
		{name: "a public signer", signer: jwkJSON(t, signer.Public())},
		{name: "a signer without a kid", signer: jwkJSON(t, noKID)},
		{name: "an ECDSA signer", signer: jwkJSON(t, *ec)},
		{name: "a missing trust bundle", signer: good, trust: "-"},
		{name: "a trust bundle that is not JSON", signer: good, trust: "not json"},
		{name: "an ECDSA key in the bundle", signer: good, trust: jwksJSON(t, ec.Public())},
		{name: "a bundle key without a kid", signer: good, trust: jwksJSON(t, peerNoKID)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			signerPath, trustPath := filepath.Join(dir, "signer.jwk"), ""
			if c.signer != "-" {
				writeFile(t, signerPath, c.signer)
			}
			if c.trust != "" {
				trustPath = filepath.Join(dir, "trust.jwks")
				if c.trust != "-" {
					writeFile(t, trustPath, c.trust)
				}
			}
			k, err := artifact.LoadKeys(signerPath, trustPath)
			if !c.ok {
				if err == nil {
					t.Fatal("LoadKeys accepted it")
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadKeys: %v", err)
			}
			if k.Signer == nil || k.Signer.KeyID != signer.KeyID || len(k.Trust) != len(c.wantTrust) {
				t.Fatalf("keys = %+v, want signer %s and trust %v", k, signer.KeyID, c.wantTrust)
			}
			for i, kid := range c.wantTrust {
				if _, pub := k.Trust[i].Key.(ed25519.PublicKey); !pub || k.Trust[i].KeyID != kid {
					t.Fatalf("trust[%d] = %+v, want the public key %s", i, k.Trust[i], kid)
				}
			}
		})
	}
}

// TestPushDirSigner checks that a push signs only with a private Ed25519
// key that has a kid, whichever kind of registry it goes to.
func TestPushDirSigner(t *testing.T) {
	ed := genKey(t, jose.EdDSA)
	noKID := *ed
	noKID.KeyID = ""
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "pages-1.img"), "pages")
	reg := newRegistry(t)
	cases := []struct {
		name   string
		signer *jose.JSONWebKey
		signed bool
		ok     bool
	}{
		{name: "an Ed25519 key signs", signer: ed, signed: true, ok: true},
		{name: "no key pushes unsigned", ok: true},
		{name: "an ECDSA key is refused", signer: genKey(t, jose.ES256)},
		{name: "a key without a kid is refused", signer: &noKID},
	}
	for _, c := range cases {
		for _, ref := range []string{
			artifact.FileScheme + filepath.Join(t.TempDir(), "r") + ":t",
			reg + "/signer/r:t",
		} {
			t.Run(c.name+" to "+ref[:4], func(t *testing.T) {
				ctx := context.Background()
				_, err := artifact.PushDir(ctx, src, ref, artifact.ArtifactTypeDelta, nil, c.signer, true)
				if !c.ok {
					if err == nil {
						t.Fatal("PushDir signed with a bad key")
					}
					return
				}
				if err != nil {
					t.Fatalf("PushDir: %v", err)
				}
				loc, found, err := artifact.Resolve(ctx, ref, true)
				if err != nil || !found {
					t.Fatalf("Resolve: %v %v", found, err)
				}
				// A registry push stamps the time it was made, and the
				// signature covers it.
				if !artifact.IsFileRef(ref) && loc.Annotations["org.opencontainers.image.created"] == "" {
					t.Fatalf("annotations %v carry no created time", loc.Annotations)
				}
				err = artifact.Keys{Signer: ed}.Verify(loc)
				if c.signed != (err == nil) || (!c.signed && !errors.Is(err, artifact.ErrUntrusted)) {
					t.Fatalf("Verify = %v, signed %v", err, c.signed)
				}
			})
		}
	}
}

func TestVerifyDirNeedsTheDirectory(t *testing.T) {
	k := artifact.Keys{Signer: genKey(t, jose.EdDSA)}
	cases := []struct {
		name string
		dir  string
	}{
		{name: "a missing directory", dir: filepath.Join(t.TempDir(), "missing")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := k.VerifyDir(c.dir, artifact.ArtifactTypeDelta, map[string]string{})
			if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("VerifyDir = %v, want ErrNotExist", err)
			}
		})
	}
}
