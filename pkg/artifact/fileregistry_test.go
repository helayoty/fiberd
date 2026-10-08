package artifact

import (
	"context"
	"encoding/binary"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/helayoty/fiberd/pkg/grant"
)

func newKey(t *testing.T) *jose.JSONWebKey {
	t.Helper()
	k, err := grant.GenerateKey(jose.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// sealHead is a sealed file's prefix claiming an n-byte header, then body.
func sealHead(n uint32, body string) string {
	return string(binary.BigEndian.AppendUint32([]byte(sealMagic), n)) + body
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestFileRegistryRoundTrip pushes one directory to a file registry,
// then resolves and pulls it back, in order.
func TestFileRegistryRoundTrip(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	src := filepath.Join(root, "src")
	writeFiles(t, src, map[string]string{"pages-1.img": "pages", "manifest.json": "{}", "dump.log": "noise"})
	ref := FileScheme + filepath.Join(root, "reg", "tmpl-abcd") + ":s-1234"
	ann := map[string]string{AnnotationSession: "S", AnnotationWBytes: "5"}
	dst := filepath.Join(root, "dst")
	signer, other := newKey(t), newKey(t)
	ecKey, err := grant.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	var digest string
	var loc Located
	byDigest := func() string { return FileScheme + filepath.Join(root, "reg", "tmpl-abcd") + "@" + digest }

	steps := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"push then resolve by tag returns the digest, type, annotations and files", func(t *testing.T) {
			var err error
			if digest, err = PushDir(ctx, src, ref, ArtifactTypeDelta, ann, signer, false); err != nil {
				t.Fatalf("push: %v", err)
			}
			var found bool
			loc, found, err = Resolve(ctx, ref, false)
			if err != nil || !found {
				t.Fatalf("resolve: found=%v err=%v", found, err)
			}
			if loc.Digest != digest || loc.ArtifactType != ArtifactTypeDelta || loc.Annotations[AnnotationSession] != "S" {
				t.Fatalf("resolved %+v, want digest %s", loc, digest)
			}
			if len(loc.Files) != 2 || loc.Annotations[AnnotationSigner] != signer.KeyID {
				t.Fatalf("resolved files %+v, signer %q", loc.Files, loc.Annotations[AnnotationSigner])
			}
		}},
		{"the signature covers the type, the annotations and every file", func(t *testing.T) {
			cases := []struct {
				name   string
				keys   Keys
				mutate func(*Located)
				ok     bool
			}{
				{name: "own key", keys: Keys{Signer: signer}, ok: true},
				{name: "trusted key", keys: Keys{Signer: other, Trust: []jose.JSONWebKey{signer.Public()}}, ok: true},
				{name: "untrusted key", keys: Keys{Signer: other}},
				{name: "annotation changed", keys: Keys{Signer: signer}, mutate: func(l *Located) { l.Annotations[AnnotationWBytes] = "6" }},
				{name: "annotation added", keys: Keys{Signer: signer}, mutate: func(l *Located) { l.Annotations[AnnotationHome] = "elsewhere" }},
				{name: "file changed", keys: Keys{Signer: signer}, mutate: func(l *Located) { l.Files[0].Digest = "sha256:" + strings.Repeat("0", 64) }},
				{name: "file dropped", keys: Keys{Signer: signer}, mutate: func(l *Located) { l.Files = l.Files[1:] }},
				{name: "type changed", keys: Keys{Signer: signer}, mutate: func(l *Located) { l.ArtifactType = ArtifactTypeParent }},
				{name: "unsigned", keys: Keys{Signer: signer}, mutate: func(l *Located) { delete(l.Annotations, AnnotationSignature) }},
				{name: "signer swapped", keys: Keys{Signer: signer, Trust: []jose.JSONWebKey{other.Public()}},
					mutate: func(l *Located) { l.Annotations[AnnotationSigner] = other.KeyID }},
				{name: "a signature that is not base64", keys: Keys{Signer: signer},
					mutate: func(l *Located) { l.Annotations[AnnotationSignature] = "!!" }},
				// A kid matching a key that is not Ed25519 trusts nothing.
				{name: "trusted kid on an ECDSA key", keys: Keys{Trust: []jose.JSONWebKey{{KeyID: signer.KeyID, Key: ecKey.Public().Key}}}},
				{name: "own kid on an ECDSA key", keys: Keys{Signer: &jose.JSONWebKey{KeyID: signer.KeyID, Key: ecKey.Key}}},
			}
			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					l := loc
					l.Annotations = maps.Clone(loc.Annotations)
					l.Files = slices.Clone(loc.Files)
					if c.mutate != nil {
						c.mutate(&l)
					}
					err := c.keys.Verify(l)
					if c.ok && err != nil {
						t.Fatalf("verify: %v", err)
					}
					if !c.ok && !errors.Is(err, ErrUntrusted) {
						t.Fatalf("verify = %v, want ErrUntrusted", err)
					}
				})
			}
			if err := (Keys{Signer: signer}).VerifyDir(src, ArtifactTypeDelta, loc.Annotations); err != nil {
				t.Fatalf("verify the pushed directory: %v", err)
			}
		}},
		{"the same content pushed again is the same digest", func(t *testing.T) {
			if again, err := PushDir(ctx, src, ref, ArtifactTypeDelta, ann, signer, false); err != nil || again != digest {
				t.Fatalf("second push: %s %v, want %s", again, err, digest)
			}
		}},
		{"a digest reference resolves", func(t *testing.T) {
			if _, found, err := Resolve(ctx, byDigest(), false); err != nil || !found {
				t.Fatalf("resolve by digest: found=%v err=%v", found, err)
			}
		}},
		{"pull by digest restores the files", func(t *testing.T) {
			if got, err := PullDir(ctx, byDigest(), dst, false); err != nil || got != digest {
				t.Fatalf("pull: %s %v", got, err)
			}
			if b, err := os.ReadFile(filepath.Join(dst, "pages-1.img")); err != nil || string(b) != "pages" {
				t.Fatalf("pulled pages-1.img = %q %v", b, err)
			}
		}},
		// The artifact's own manifest.json is a file like any other. The
		// registry's bookkeeping must not shadow it.
		{"the artifact's own manifest.json is not shadowed", func(t *testing.T) {
			if b, err := os.ReadFile(filepath.Join(dst, "manifest.json")); err != nil || string(b) != "{}" {
				t.Fatalf("pulled manifest.json = %q %v, want the pushed file", b, err)
			}
		}},
		{"logs do not travel", func(t *testing.T) {
			if _, err := os.Stat(filepath.Join(dst, "dump.log")); err == nil {
				t.Fatal("logs must not travel")
			}
		}},
		{"a file rewritten in the store fails the pull", func(t *testing.T) {
			files := filepath.Join(blobDir(filepath.Join(root, "reg", "tmpl-abcd"), digest), "files")
			stored, _ := os.ReadFile(filepath.Join(files, "pages-1.img"))
			writeFiles(t, files, map[string]string{"pages-1.img": "evil!"})
			defer writeFiles(t, files, map[string]string{"pages-1.img": string(stored)})
			if _, err := PullDir(ctx, byDigest(), filepath.Join(root, "tampered"), false); err == nil {
				t.Fatal("pull of a rewritten file succeeded")
			}
		}},
		{"a sealed directory travels and opens only with its key, for its session, before it expires", func(t *testing.T) {
			big := strings.Repeat("0123456789abcdef", (5*sealChunk/2)/16) + "end"
			plain := filepath.Join(root, "plain")
			writeFiles(t, plain, map[string]string{"pages-1.img": big, "empty.img": "", "manifest.json": `{"fence":"g/1/1"}`, "dump.log": "noise"})
			key, other := &SealKey{ID: "k1", Key: make([]byte, 32)}, &SealKey{ID: "k2", Key: make([]byte, 32)}
			other.Key[0] = 1
			now := time.Now()
			sc := SealContext{Domain: "D", Session: "S", Fence: "g/1/1", Expires: now.Add(time.Hour).Truncate(time.Second)}
			sealed := filepath.Join(root, "sealed")
			if err := SealDir(plain, sealed, key, sc); err != nil {
				t.Fatalf("seal: %v", err)
			}
			repo := FileScheme + filepath.Join(root, "reg", "sealed")
			sd, err := PushDir(ctx, sealed, repo+":s", ArtifactTypeDelta, nil, signer, false)
			if err != nil {
				t.Fatalf("push sealed: %v", err)
			}
			lastLen := int64(len(big)%sealChunk + 16)
			resize := func(t *testing.T, path string, f func(b []byte) []byte) {
				b, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, f(b), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			cases := []struct {
				name            string
				key             *SealKey
				domain, session string
				at              time.Time
				mutate          func(t *testing.T, dir string)
				want            error
			}{
				{name: "opens with its key, domain and session", key: key, domain: "D", session: "S", at: now},
				{name: "another key", key: other, domain: "D", session: "S", at: now, want: ErrSealed},
				{name: "another domain", key: key, domain: "D2", session: "S", at: now, want: ErrSealed},
				{name: "another session", key: key, domain: "D", session: "S2", at: now, want: ErrSealed},
				{name: "expired", key: key, domain: "D", session: "S", at: sc.Expires, want: ErrExpired},
				{name: "a flipped byte", key: key, domain: "D", session: "S", at: now, want: ErrSealed,
					mutate: func(t *testing.T, dir string) {
						resize(t, filepath.Join(dir, "pages-1.img"), func(b []byte) []byte { b[len(b)-100] ^= 1; return b })
					}},
				{name: "the last chunk cut short", key: key, domain: "D", session: "S", at: now, want: ErrSealed,
					mutate: func(t *testing.T, dir string) {
						resize(t, filepath.Join(dir, "pages-1.img"), func(b []byte) []byte { return b[:len(b)-10] })
					}},
				{name: "the last chunk dropped", key: key, domain: "D", session: "S", at: now, want: ErrSealed,
					mutate: func(t *testing.T, dir string) {
						resize(t, filepath.Join(dir, "pages-1.img"), func(b []byte) []byte { return b[:int64(len(b))-lastLen] })
					}},
				{name: "two chunks swapped", key: key, domain: "D", session: "S", at: now, want: ErrSealed,
					mutate: func(t *testing.T, dir string) {
						resize(t, filepath.Join(dir, "pages-1.img"), func(b []byte) []byte {
							n := sealChunk + 16
							p := len(b) - 2*n - int(lastLen)
							c0 := slices.Clone(b[p : p+n])
							copy(b[p:p+n], b[p+n:p+2*n])
							copy(b[p+n:p+2*n], c0)
							return b
						})
					}},
				{name: "files swapped", key: key, domain: "D", session: "S", at: now, want: ErrSealed,
					mutate: func(t *testing.T, dir string) {
						a, b := filepath.Join(dir, "empty.img"), filepath.Join(dir, "manifest.json")
						if err := os.Rename(a, a+".x"); err != nil {
							t.Fatal(err)
						}
						if err := os.Rename(b, a); err != nil {
							t.Fatal(err)
						}
						if err := os.Rename(a+".x", b); err != nil {
							t.Fatal(err)
						}
					}},
				{name: "a plaintext file", key: key, domain: "D", session: "S", at: now, want: ErrSealed,
					mutate: func(t *testing.T, dir string) { writeFiles(t, dir, map[string]string{"empty.img": ""}) }},
				{name: "a header longer than the limit", key: key, domain: "D", session: "S", at: now, want: ErrSealed,
					mutate: func(t *testing.T, dir string) {
						writeFiles(t, dir, map[string]string{"empty.img": sealHead(1<<16+1, "")})
					}},
				{name: "a header cut short", key: key, domain: "D", session: "S", at: now, want: ErrSealed,
					mutate: func(t *testing.T, dir string) {
						writeFiles(t, dir, map[string]string{"empty.img": sealHead(100, "{}")})
					}},
				{name: "a header that is not JSON", key: key, domain: "D", session: "S", at: now, want: ErrSealed,
					mutate: func(t *testing.T, dir string) {
						writeFiles(t, dir, map[string]string{"empty.img": sealHead(5, "nope!")})
					}},
				{name: "a directory where the plaintext goes", key: key, domain: "D", session: "S", at: now, want: syscall.EISDIR,
					mutate: func(t *testing.T, dir string) {
						writeFiles(t, filepath.Join(dir, "empty.img.open.tmp"), map[string]string{"inner": ""})
					}},
			}
			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					dir := filepath.Join(t.TempDir(), "pulled")
					if _, err := PullDir(ctx, repo+"@"+sd, dir, false); err != nil {
						t.Fatal(err)
					}
					if b, _ := os.ReadFile(filepath.Join(dir, "pages-1.img")); strings.Contains(string(b), "0123456789abcdef") {
						t.Fatal("the registry holds plaintext")
					}
					if c.mutate != nil {
						c.mutate(t, dir)
					}
					got, err := OpenDir(dir, c.key, c.domain, c.session, c.at)
					if c.want != nil {
						if !errors.Is(err, c.want) {
							t.Fatalf("open = %v, want %v", err, c.want)
						}
						return
					}
					if err != nil || got.Domain != sc.Domain || got.Session != sc.Session || got.Fence != sc.Fence || !got.Expires.Equal(sc.Expires) {
						t.Fatalf("open = %+v %v, want %+v", got, err, sc)
					}
					for name, body := range map[string]string{"pages-1.img": big, "empty.img": "", "manifest.json": `{"fence":"g/1/1"}`} {
						if b, err := os.ReadFile(filepath.Join(dir, name)); err != nil || string(b) != body {
							t.Fatalf("%s opened to %d bytes %v, want %d", name, len(b), err, len(body))
						}
						if fi, err := os.Stat(filepath.Join(dir, name)); err != nil || fi.Mode().Perm() != 0o600 {
							t.Fatalf("%s opened with mode %v %v, want 0600 plaintext", name, fi.Mode().Perm(), err)
						}
					}
					if _, err := os.Stat(filepath.Join(dir, "dump.log")); err == nil {
						t.Fatal("logs were sealed")
					}
				})
			}
		}},
		{"a manifest rewritten in the store fails the resolve", func(t *testing.T) {
			blob := blobDir(filepath.Join(root, "reg", "tmpl-abcd"), digest)
			mb, _ := os.ReadFile(filepath.Join(blob, "manifest.json"))
			writeFiles(t, blob, map[string]string{"manifest.json": strings.Replace(string(mb), `"5"`, `"6"`, 1)})
			defer writeFiles(t, blob, map[string]string{"manifest.json": string(mb)})
			if _, _, err := Resolve(ctx, byDigest(), false); err == nil {
				t.Fatal("resolve of a rewritten manifest succeeded")
			}
		}},
	}
	for _, st := range steps {
		if !t.Run(st.name, st.run) {
			return // later steps build on this one
		}
	}
}

// TestFileRegistryDelete checks that deleting a tag drops it and the
// content nothing else points at. Content another tag shares stays.
// Deleting a tag that is not there is fine.
func TestFileRegistryDelete(t *testing.T) {
	cases := []struct {
		name        string
		typ         string
		ann         map[string]string
		tags        []string // pushed in order, all with the same content
		del         string
		kept, gone  []string // tags that must and must not resolve afterwards
		contentGone bool     // the pushed digest no longer resolves
	}{
		{name: "deleting the only tag drops the tag and its content", typ: ArtifactTypeDelta,
			ann:  map[string]string{AnnotationSession: "S", AnnotationWBytes: "5"},
			tags: []string{"s-1234"}, del: "s-1234", gone: []string{"s-1234"}, contentGone: true},
		{name: "deleting one of two tags keeps the content the other points at", typ: ArtifactTypeParent,
			tags: []string{"one", "two"}, del: "one", kept: []string{"two"}, gone: []string{"one"}},
		{name: "deleting a missing tag is fine", typ: ArtifactTypeDelta,
			del: "missing", gone: []string{"missing"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			src := filepath.Join(root, "src")
			writeFiles(t, src, map[string]string{"pages-1.img": "pages", "dump.log": "noise"})
			repo := FileScheme + filepath.Join(root, "reg", "r")
			var digest string
			for _, tag := range tc.tags {
				d, err := PushDir(ctx, src, repo+":"+tag, tc.typ, tc.ann, nil, false)
				if err != nil || (digest != "" && d != digest) {
					t.Fatalf("push %s: %s %v, want the same digest as before %s", tag, d, err, digest)
				}
				digest = d
			}
			if err := Delete(ctx, repo+":"+tc.del, false); err != nil {
				t.Fatalf("delete: %v", err)
			}
			for _, tag := range tc.kept {
				if _, found, _ := Resolve(ctx, repo+":"+tag, false); !found {
					t.Fatalf("tag %s no longer resolves", tag)
				}
			}
			for _, tag := range tc.gone {
				if _, found, _ := Resolve(ctx, repo+":"+tag, false); found {
					t.Fatalf("tag %s still resolves after delete", tag)
				}
			}
			if _, found, _ := Resolve(ctx, repo+"@"+digest, false); digest != "" && found == tc.contentGone {
				t.Fatalf("content resolves = %v, want %v", found, !tc.contentGone)
			}
		})
	}
}

func TestFileRefParsing(t *testing.T) {
	cases := []struct {
		name, ref, repo, target string
		bad                     bool
	}{
		{name: "a tag", ref: "file:///r/x/y:tag", repo: "/r/x/y", target: "tag"},
		{name: "a digest", ref: "file:///r/x/y@sha256:ab", repo: "/r/x/y", target: "sha256:ab"},
		{name: "a bare repository", ref: "file:///r/x/y", repo: "/r/x/y"},
		{name: "a relative path is refused", ref: "file://rel/x:tag", bad: true},
		{name: "a tag that climbs out is refused", ref: "file:///r/x:..", bad: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			repo, target, err := fileRef(c.ref)
			if c.bad {
				if err == nil {
					t.Fatalf("%s: want an error", c.ref)
				}
				return
			}
			if err != nil || repo != c.repo || target != c.target {
				t.Fatalf("%s: got %q %q %v, want %q %q", c.ref, repo, target, err, c.repo, c.target)
			}
		})
	}
}

// TestFileRegistryFaults checks each operation against a store someone
// changed under it, and against references it must refuse. Every case
// starts from one artifact pushed as tag t.
func TestFileRegistryFaults(t *testing.T) {
	mkdir := func(t *testing.T, path string) {
		t.Helper()
		writeFiles(t, path, map[string]string{"inner": ""})
	}
	file := func(t *testing.T, path string) {
		t.Helper()
		if err := os.RemoveAll(path); err != nil {
			t.Fatal(err)
		}
		writeFiles(t, filepath.Dir(path), map[string]string{filepath.Base(path): ""})
	}
	cases := []struct {
		name    string
		corrupt func(t *testing.T, repoDir, digest string)
		op      string // push, resolve, pull or delete
		// ref is the reference the operation takes, given the repository
		// reference and the pushed digest; tag t by default.
		ref   func(repo, digest string) string
		noSrc bool // the source directory is gone
		ok    bool
		found bool // resolve: whether the artifact was found
		after func(t *testing.T, repoDir, digest string)
	}{
		{name: "push refuses a relative reference", op: "push", ref: func(string, string) string { return "file://rel/r:t" }},
		{name: "resolve refuses a relative reference", op: "resolve", ref: func(string, string) string { return "file://rel/r:t" }},
		{name: "pull refuses a relative reference", op: "pull", ref: func(string, string) string { return "file://rel/r:t" }},
		{name: "delete refuses a relative reference", op: "delete", ref: func(string, string) string { return "file://rel/r:t" }},

		{name: "push needs its source directory", op: "push", noSrc: true},
		{name: "push fails over a blob directory left without a manifest", op: "push",
			corrupt: func(t *testing.T, repoDir, digest string) {
				if err := os.RemoveAll(blobDir(repoDir, digest)); err != nil {
					t.Fatal(err)
				}
				mkdir(t, filepath.Join(blobDir(repoDir, digest), "files"))
			}},
		{name: "push fails when the blob store is a file", op: "push",
			corrupt: func(t *testing.T, repoDir, _ string) { file(t, filepath.Join(repoDir, "blobs")) }},
		{name: "push fails when the tag directory is a file", op: "push",
			corrupt: func(t *testing.T, repoDir, _ string) { file(t, filepath.Join(repoDir, "tags")) }},
		{name: "push fails when the tag's staging file is a directory", op: "push",
			corrupt: func(t *testing.T, repoDir, _ string) { mkdir(t, tagFile(repoDir, "t")+".tmp") }},
		{name: "push fails when the tag is a directory", op: "push",
			corrupt: func(t *testing.T, repoDir, _ string) {
				if err := os.Remove(tagFile(repoDir, "t")); err != nil {
					t.Fatal(err)
				}
				mkdir(t, tagFile(repoDir, "t"))
			}},

		{name: "a tag never pushed is not found", op: "resolve", ok: true,
			ref: func(repo, _ string) string { return repo + ":never" }},
		{name: "a dangling tag is no tag", op: "resolve", ok: true,
			corrupt: func(t *testing.T, repoDir, digest string) {
				if err := os.RemoveAll(blobDir(repoDir, digest)); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "a tag that is a directory fails the resolve", op: "resolve",
			corrupt: func(t *testing.T, repoDir, _ string) {
				if err := os.Remove(tagFile(repoDir, "t")); err != nil {
					t.Fatal(err)
				}
				mkdir(t, tagFile(repoDir, "t"))
			}},
		{name: "a digest under a blob store that is a file fails the resolve", op: "resolve",
			corrupt: func(t *testing.T, repoDir, _ string) { file(t, filepath.Join(repoDir, "blobs")) },
			ref:     func(repo, digest string) string { return repo + "@" + digest }},
		{name: "a manifest that is a directory fails the resolve", op: "resolve",
			corrupt: func(t *testing.T, repoDir, digest string) {
				if err := os.Remove(filepath.Join(blobDir(repoDir, digest), "manifest.json")); err != nil {
					t.Fatal(err)
				}
				mkdir(t, filepath.Join(blobDir(repoDir, digest), "manifest.json"))
			}},

		{name: "pull of a dangling tag is not found", op: "pull",
			corrupt: func(t *testing.T, repoDir, digest string) {
				if err := os.RemoveAll(blobDir(repoDir, digest)); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "pull fails when the tag cannot be read", op: "pull",
			corrupt: func(t *testing.T, repoDir, _ string) {
				if err := os.Remove(tagFile(repoDir, "t")); err != nil {
					t.Fatal(err)
				}
				mkdir(t, tagFile(repoDir, "t"))
			}},
		{name: "pull fails on a manifest that does not hash to its digest", op: "pull",
			corrupt: func(t *testing.T, repoDir, digest string) {
				writeFiles(t, blobDir(repoDir, digest), map[string]string{"manifest.json": "{}"})
			}},
		{name: "pull fails when a listed file is missing", op: "pull",
			corrupt: func(t *testing.T, repoDir, digest string) {
				if err := os.Remove(filepath.Join(blobDir(repoDir, digest), "files", "pages-1.img")); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "pull fails when the destination is under a file", op: "pull",
			corrupt: func(t *testing.T, repoDir, _ string) { file(t, filepath.Join(repoDir, "..", "..", "dst")) }},

		{name: "delete of a tag that cannot be read fails", op: "delete",
			corrupt: func(t *testing.T, repoDir, _ string) {
				if err := os.Remove(tagFile(repoDir, "t")); err != nil {
					t.Fatal(err)
				}
				mkdir(t, tagFile(repoDir, "t"))
			}},
		{name: "delete by digest drops the content and every tag on it", op: "delete", ok: true,
			corrupt: func(t *testing.T, repoDir, digest string) {
				writeFiles(t, filepath.Join(repoDir, "tags"), map[string]string{"u": digest + "\n", "other": "sha256:00\n"})
				mkdir(t, filepath.Join(repoDir, "tags", "unreadable"))
			},
			ref: func(repo, digest string) string { return repo + "@" + digest },
			after: func(t *testing.T, repoDir, digest string) {
				for _, gone := range []string{tagFile(repoDir, "t"), tagFile(repoDir, "u"), blobDir(repoDir, digest)} {
					if _, err := os.Stat(gone); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("%s survived the delete: %v", gone, err)
					}
				}
				if _, err := os.Stat(tagFile(repoDir, "other")); err != nil {
					t.Fatalf("a tag on other content went with it: %v", err)
				}
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			src := filepath.Join(root, "src")
			writeFiles(t, src, map[string]string{"pages-1.img": "pages"})
			repoDir := filepath.Join(root, "reg", "r")
			repo := FileScheme + repoDir
			digest, err := PushDir(ctx, src, repo+":t", ArtifactTypeDelta, nil, nil, false)
			if err != nil {
				t.Fatal(err)
			}
			if c.corrupt != nil {
				c.corrupt(t, repoDir, digest)
			}
			if c.noSrc {
				if err := os.RemoveAll(src); err != nil {
					t.Fatal(err)
				}
			}
			ref := repo + ":t"
			if c.ref != nil {
				ref = c.ref(repo, digest)
			}
			var found bool
			switch c.op {
			case "push":
				_, err = PushDir(ctx, src, ref, ArtifactTypeDelta, nil, nil, false)
			case "resolve":
				_, found, err = Resolve(ctx, ref, false)
			case "pull":
				_, err = PullDir(ctx, ref, filepath.Join(root, "dst", "out"), false)
			case "delete":
				err = Delete(ctx, ref, false)
			}
			if c.ok != (err == nil) || found != c.found {
				t.Fatalf("%s %s = found %v, %v; want ok %v, found %v", c.op, ref, found, err, c.ok, c.found)
			}
			if c.after != nil {
				c.after(t, repoDir, digest)
			}
		})
	}
}
