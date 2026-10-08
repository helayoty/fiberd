package artifact

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

// Signed directory artifacts. A home signs every delta and parent
// checkpoint it pushes with an Ed25519 key. It takes one from a registry
// or an export only when a key it trusts signed it. The signature covers
// the artifact type, every annotation but itself, and every file's name,
// digest and size, so neither the manifest nor a layer can change without
// breaking it. It travels as two manifest annotations, which OCI
// registries and file:// alike preserve.

const (
	AnnotationSignature = "io.fiberd.signature"
	AnnotationSigner    = "io.fiberd.signer"

	signingContext = "fiberd-artifact-v1\n"
)

// File is one file of a directory artifact as its manifest lists it.
type File struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

// Keys is what a home signs with and what it accepts.
type Keys struct {
	// Signer is the private Ed25519 JWK pushes are signed with.
	Signer *jose.JSONWebKey
	// Trust holds the public keys whose signatures are accepted, by kid.
	// Signer's own public half is always accepted.
	Trust []jose.JSONWebKey
	// Seal is the master key deltas are sealed under (seal.go).
	Seal *SealKey
}

// LoadKeys reads the signing key (a private Ed25519 JWK, as
// `grant-issuer keygen -alg EdDSA` writes) and, when trustPath is set,
// a JWKS of further public keys to accept.
func LoadKeys(signerPath, trustPath string) (Keys, error) {
	var k Keys
	b, err := os.ReadFile(signerPath)
	if err != nil {
		return k, err
	}
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(b, &jwk); err != nil {
		return k, fmt.Errorf("artifact: signing key %s: %w", signerPath, err)
	}
	if _, ok := jwk.Key.(ed25519.PrivateKey); !ok || jwk.KeyID == "" {
		return k, fmt.Errorf("artifact: signing key %s must be a private Ed25519 JWK with a kid", signerPath)
	}
	k.Signer = &jwk
	if trustPath == "" {
		return k, nil
	}
	if b, err = os.ReadFile(trustPath); err != nil {
		return k, err
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(b, &set); err != nil {
		return k, fmt.Errorf("artifact: trust bundle %s: %w", trustPath, err)
	}
	for _, t := range set.Keys {
		pub := t.Public()
		if _, ok := pub.Key.(ed25519.PublicKey); !ok || pub.KeyID == "" {
			return k, fmt.Errorf("artifact: trust bundle %s: key %q is not an Ed25519 key with a kid", trustPath, t.KeyID)
		}
		k.Trust = append(k.Trust, pub)
	}
	return k, nil
}

// Verify checks that a located artifact is signed by a trusted key.
func (k Keys) Verify(loc Located) error {
	return k.verify(loc.ArtifactType, loc.Annotations, loc.Files)
}

// VerifyDir checks a signature against the files in dir, for artifacts
// that arrive as files rather than from a registry (an import).
func (k Keys) VerifyDir(dir, artifactType string, annotations map[string]string) error {
	files, err := dirFiles(dir)
	if err != nil {
		return err
	}
	return k.verify(artifactType, annotations, files)
}

func (k Keys) verify(artifactType string, annotations map[string]string, files []File) error {
	sig, kid := annotations[AnnotationSignature], annotations[AnnotationSigner]
	if sig == "" || kid == "" {
		return fmt.Errorf("%w: unsigned", ErrUntrusted)
	}
	pub, ok := k.trusted(kid)
	if !ok {
		return fmt.Errorf("%w: signer %q is not trusted here", ErrUntrusted, kid)
	}
	raw, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return fmt.Errorf("%w: malformed signature", ErrUntrusted)
	}
	msg, err := signingPayload(artifactType, annotations, files)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, raw) {
		return fmt.Errorf("%w: signature by %q does not match the artifact", ErrUntrusted, kid)
	}
	return nil
}

func (k Keys) trusted(kid string) (ed25519.PublicKey, bool) {
	if k.Signer != nil && k.Signer.KeyID == kid {
		if priv, ok := k.Signer.Key.(ed25519.PrivateKey); ok {
			return priv.Public().(ed25519.PublicKey), true
		}
	}
	for _, t := range k.Trust {
		if t.KeyID == kid {
			pub, ok := t.Key.(ed25519.PublicKey)
			return pub, ok
		}
	}
	return nil, false
}

// signed returns annotations plus the signer and signature over the
// artifact. A nil signer pushes unsigned.
func signed(signer *jose.JSONWebKey, artifactType string, annotations map[string]string, files []File) (map[string]string, error) {
	if signer == nil {
		return annotations, nil
	}
	priv, ok := signer.Key.(ed25519.PrivateKey)
	if !ok || signer.KeyID == "" {
		return nil, fmt.Errorf("artifact: signing key %q is not a private Ed25519 key with a kid", signer.KeyID)
	}
	out := make(map[string]string, len(annotations)+2)
	for k, v := range annotations {
		out[k] = v
	}
	out[AnnotationSigner] = signer.KeyID
	msg, err := signingPayload(artifactType, out, files)
	if err != nil {
		return nil, err
	}
	out[AnnotationSignature] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, msg))
	return out, nil
}

// signingPayload is the canonical encoding a signature covers. JSON
// sorts map keys and files are sorted by name, so it is stable.
func signingPayload(artifactType string, annotations map[string]string, files []File) ([]byte, error) {
	ann := make(map[string]string, len(annotations))
	for k, v := range annotations {
		if k != AnnotationSignature {
			ann[k] = v
		}
	}
	fs := append([]File(nil), files...)
	sort.Slice(fs, func(i, j int) bool { return fs[i].Name < fs[j].Name })
	b, err := json.Marshal(struct {
		ArtifactType string            `json:"artifactType"`
		Annotations  map[string]string `json:"annotations"`
		Files        []File            `json:"files"`
	}{artifactType, ann, fs})
	if err != nil {
		return nil, err
	}
	return append([]byte(signingContext), b...), nil
}

// pushable reports whether a directory entry travels in a directory
// artifact. Only regular files do, except logs and temporaries.
func pushable(e os.DirEntry) bool {
	return e.Type().IsRegular() && !strings.HasSuffix(e.Name(), ".log") && !strings.HasSuffix(e.Name(), ".tmp")
}

// pushableNames lists the files PushDir would push from dir, sorted.
func pushableNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if pushable(e) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// dirFiles lists and hashes the files PushDir would push from dir.
func dirFiles(dir string) ([]File, error) {
	names, err := pushableNames(dir)
	if err != nil {
		return nil, err
	}
	files := make([]File, 0, len(names))
	for _, n := range names {
		path := filepath.Join(dir, n)
		sum, err := fileSHA256(path)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		files = append(files, File{Name: n, Digest: "sha256:" + sum, Size: info.Size()})
	}
	return files, nil
}
