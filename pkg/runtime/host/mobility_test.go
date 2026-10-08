package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/core"
)

// signingKey is a private Ed25519 JWK with a kid, as a home signs with.
func signingKey(t *testing.T, kid string) *jose.JSONWebKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &jose.JSONWebKey{Key: priv, KeyID: kid, Algorithm: string(jose.EdDSA)}
}

func write(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// A delta published by one home (a file registry standing in for it)
// exported as files, then imported by another home under a new session
// name: the second registry resolves the new name, with the parent, and
// the first no longer holds the session. Steps run in order, each
// building on the last.
func TestExportImportDelta(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	// Each home signs with its own key. b and d trust a, and c trusts no
	// one else. a and b share a seal key, and d has one of its own.
	keyA, keyB, keyC := signingKey(t, "home-a"), signingKey(t, "home-b"), signingKey(t, "home-c")
	sealAB, sealD := &artifact.SealKey{ID: "seal-ab", Key: make([]byte, 32)}, &artifact.SealKey{ID: "seal-d", Key: make([]byte, 32)}
	sealD.Key[0] = 1
	a := Config{DeltaRegistry: artifact.FileScheme + filepath.Join(root, "a"), DeltaKeys: artifact.Keys{Signer: keyA, Seal: sealAB}, HomeID: "home-a"}
	b := Config{DeltaRegistry: artifact.FileScheme + filepath.Join(root, "b"), DeltaDir: filepath.Join(root, "b-deltas"),
		DeltaKeys: artifact.Keys{Signer: keyB, Trust: []jose.JSONWebKey{keyA.Public()}, Seal: sealAB}, HomeID: "home-b"}
	c := Config{DeltaRegistry: artifact.FileScheme + filepath.Join(root, "c"), DeltaKeys: artifact.Keys{Signer: keyC, Seal: sealAB}, HomeID: "home-c"}
	d := Config{DeltaRegistry: artifact.FileScheme + filepath.Join(root, "d"),
		DeltaKeys: artifact.Keys{Signer: signingKey(t, "home-d"), Trust: []jose.JSONWebKey{keyA.Public()}, Seal: sealD}, HomeID: "home-d"}
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl"}
	g2 := core.Grant{UID: "g2", TemplateDigest: "sha256:tmpl"}                                                    // another grant, same domain
	g3 := core.Grant{UID: "g3", TemplateDigest: "sha256:tmpl", Policy: core.Policy{SessionClass: "other-domain"}} // another domain

	parentSHA := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	repo := domainRepoFor(a.DeltaRegistry, g)
	write(t, filepath.Join(root, "parent"), map[string]string{"pages-1.img": "template pages"})
	if _, err := artifact.PushDir(ctx, filepath.Join(root, "parent"), repo+":"+parentTag(parentSHA), artifact.ArtifactTypeParent,
		map[string]string{artifact.AnnotationParent: parentSHA}, keyA, false); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "delta"), map[string]string{"pages-1.img": "dirty pages", "manifest.json": `{"fence":"g1/1/1"}`, "dump.log": "x"})
	ann := map[string]string{artifact.AnnotationGrant: "g1", artifact.AnnotationHome: "home-a",
		artifact.AnnotationParent: parentSHA, artifact.AnnotationWBytes: "11", "io.fiberd.arch": "arm64"}
	if _, err := pushDelta(ctx, a, filepath.Join(root, "delta"), repo+":"+sessionTag("S"), ann, a.sealContext(g, "S", "g1/1/1", time.Now())); err != nil {
		t.Fatal(err)
	}
	// The same delta parked two days ago under E, past the default TTL.
	if _, err := pushDelta(ctx, a, filepath.Join(root, "delta"), repo+":"+sessionTag("E"), ann,
		a.sealContext(g, "E", "g1/1/1", time.Now().Add(-2*deltaTTL))); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(root, "out")
	repoB := domainRepoFor(b.DeltaRegistry, g2)
	var loc artifact.Located
	steps := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"export without a registry is refused", func(t *testing.T) {
			if _, err := ExportDelta(ctx, Config{}, core.Grant{}, "S", t.TempDir()); err == nil {
				t.Fatal("want an error without a registry")
			}
		}},
		{"import without a registry is refused", func(t *testing.T) {
			if err := ImportDelta(ctx, Config{}, core.Grant{}, "S", t.TempDir()); err == nil {
				t.Fatal("want an error without a registry")
			}
		}},
		{"a registry without a signing or a seal key is refused", func(t *testing.T) {
			cases := []struct {
				name string
				keys artifact.Keys
			}{
				{name: "no keys"},
				{name: "no seal key", keys: artifact.Keys{Signer: keyA}},
				{name: "no signing key", keys: artifact.Keys{Seal: sealAB}},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					if _, err := ExportDelta(ctx, Config{DeltaRegistry: a.DeltaRegistry, DeltaKeys: tc.keys}, g, "S", t.TempDir()); err == nil {
						t.Fatal("export: want an error")
					}
					if err := ImportDelta(ctx, Config{DeltaRegistry: b.DeltaRegistry, DeltaKeys: tc.keys}, g2, "S", t.TempDir()); err == nil {
						t.Fatal("import: want an error")
					}
				})
			}
		}},
		{"the registry holds no plaintext of the delta", func(t *testing.T) {
			err := filepath.WalkDir(filepath.Join(root, "a"), func(path string, e os.DirEntry, err error) error {
				if err != nil || e.IsDir() {
					return err
				}
				if b, err := os.ReadFile(path); err != nil || strings.Contains(string(b), "dirty pages") {
					t.Errorf("%s holds the delta's plaintext (%v)", path, err)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}},
		// Someone who can write the registry but holds no key copies a
		// signed manifest onto another session's tag or domain's repo.
		{"a signed delta copied to another session or domain is refused", func(t *testing.T) {
			sloc, found, err := artifact.Resolve(ctx, repo+":"+sessionTag("S"), false)
			if err != nil || !found {
				t.Fatalf("resolve S: %v", err)
			}
			pulled := filepath.Join(t.TempDir(), "copy")
			if _, err := artifact.PullDir(ctx, repo+"@"+sloc.Digest, pulled, false); err != nil {
				t.Fatal(err)
			}
			cases := []struct {
				name    string
				grant   core.Grant
				session string
			}{
				{name: "another session, same domain", grant: g, session: "T"},
				{name: "the same session, another domain", grant: g3, session: "S"},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					ref := domainRepoFor(a.DeltaRegistry, tc.grant) + ":" + sessionTag(tc.session)
					if _, err := artifact.PushDir(ctx, pulled, ref, artifact.ArtifactTypeDelta, sloc.Annotations, nil, false); err != nil {
						t.Fatal(err)
					}
					if cloc, _, _ := artifact.Resolve(ctx, ref, false); a.DeltaKeys.Verify(cloc) != nil {
						t.Fatal("the copy must still carry a valid signature for the test to mean anything")
					}
					if _, err := ExportDelta(ctx, a, tc.grant, tc.session, t.TempDir()); !errors.Is(err, artifact.ErrUntrusted) {
						t.Fatalf("export = %v, want ErrUntrusted", err)
					}
				})
			}
		}},
		{"an expired delta is refused", func(t *testing.T) {
			if _, err := ExportDelta(ctx, a, g, "E", t.TempDir()); !errors.Is(err, artifact.ErrExpired) {
				t.Fatalf("export = %v, want ErrExpired", err)
			}
		}},
		// The parent travels with the export and the importing home signs
		// it as its own, so the exporter must only ship a parent a trusted
		// home signed as that very checkpoint.
		{"a delta whose parent is not trusted here is not exported", func(t *testing.T) {
			cases := []struct {
				name     string
				sha      string
				signedAs string // the checkpoint the parent's manifest names ("" = sha)
				signer   *jose.JSONWebKey
			}{
				{name: "an unsigned parent", sha: strings.Repeat("1", 64)},
				{name: "a parent signed by a home not trusted here", sha: strings.Repeat("2", 64), signer: keyC},
				{name: "a signed parent copied onto another checkpoint's tag", sha: strings.Repeat("3", 64), signedAs: parentSHA, signer: keyA},
			}
			for i, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					signedAs := tc.signedAs
					if signedAs == "" {
						signedAs = tc.sha
					}
					if _, err := artifact.PushDir(ctx, filepath.Join(root, "parent"), repo+":"+parentTag(tc.sha), artifact.ArtifactTypeParent,
						map[string]string{artifact.AnnotationParent: signedAs}, tc.signer, false); err != nil {
						t.Fatal(err)
					}
					session := "P" + strconv.Itoa(i)
					dann := maps.Clone(ann)
					dann[artifact.AnnotationParent] = tc.sha
					if _, err := pushDelta(ctx, a, filepath.Join(root, "delta"), repo+":"+sessionTag(session), dann, a.sealContext(g, session, "g1/1/1", time.Now())); err != nil {
						t.Fatal(err)
					}
					if _, err := ExportDelta(ctx, a, g, session, t.TempDir()); !errors.Is(err, artifact.ErrUntrusted) {
						t.Fatalf("export = %v, want ErrUntrusted", err)
					}
					if _, found, _ := artifact.Resolve(ctx, repo+":"+sessionTag(session), false); !found {
						t.Fatal("a refused export retired the session")
					}
				})
			}
		}},
		{"export writes the delta, parent and info files and releases the session", func(t *testing.T) {
			files, err := ExportDelta(ctx, a, g, "S", out)
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			want := map[string]bool{ExportDeltaFile: true, ExportParentFile: true, ExportInfoFile: true}
			for _, f := range files {
				if !want[f] {
					t.Errorf("unexpected export file %s", f)
				}
				delete(want, f)
				if _, err := os.Stat(filepath.Join(out, f)); err != nil {
					t.Errorf("%s: %v", f, err)
				}
			}
			if len(want) > 0 {
				t.Errorf("missing export files: %v", want)
			}
			if _, found, _ := artifact.Resolve(ctx, repo+":"+sessionTag("S"), false); found {
				t.Fatal("the exporting home still holds the session")
			}
		}},
		{"exporting a session no longer published fails", func(t *testing.T) {
			if _, err := ExportDelta(ctx, a, g, "S", out); err == nil {
				t.Fatal("exporting an unpublished session must fail")
			}
		}},
		{"a home that does not trust the exporter refuses the import", func(t *testing.T) {
			if err := ImportDelta(ctx, c, g2, "S2", out); !errors.Is(err, artifact.ErrUntrusted) {
				t.Fatalf("import = %v, want ErrUntrusted", err)
			}
		}},
		{"an export rewritten after signing is refused", func(t *testing.T) {
			path := filepath.Join(out, ExportInfoFile)
			orig, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = os.WriteFile(path, orig, 0o644) }()
			if err := os.WriteFile(path, []byte(strings.Replace(string(orig), `"11"`, `"1"`, 1)), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := ImportDelta(ctx, b, g2, "S2", out); !errors.Is(err, artifact.ErrUntrusted) {
				t.Fatalf("import = %v, want ErrUntrusted", err)
			}
		}},
		// The parent's files and its signed manifest travel in the clear.
		// An import must take neither a parent rewritten in transit (same
		// pages, rearranged) nor one shipped without the manifest the
		// exporter signed it under.
		{"an export whose parent does not verify is refused", func(t *testing.T) {
			cases := []struct {
				name   string
				tamper func(t *testing.T)
			}{
				{name: "a parent file rewritten after signing", tamper: func(t *testing.T) {
					dir := filepath.Join(t.TempDir(), "parent")
					if err := artifact.Untar(filepath.Join(out, ExportParentFile), dir); err != nil {
						t.Fatal(err)
					}
					write(t, dir, map[string]string{"pages-1.img": "template pages, rearranged"})
					if err := artifact.TarDir(dir, filepath.Join(out, ExportParentFile)); err != nil {
						t.Fatal(err)
					}
				}},
				{name: "an info file without the parent's signed manifest", tamper: func(t *testing.T) {
					path := filepath.Join(out, ExportInfoFile)
					var m map[string]json.RawMessage
					if b, err := os.ReadFile(path); err != nil {
						t.Fatal(err)
					} else if err := json.Unmarshal(b, &m); err != nil {
						t.Fatal(err)
					}
					delete(m, "parent_annotations")
					b, err := json.Marshal(m)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, b, 0o644); err != nil {
						t.Fatal(err)
					}
				}},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					for _, f := range []string{ExportParentFile, ExportInfoFile} {
						orig, err := os.ReadFile(filepath.Join(out, f))
						if err != nil {
							t.Fatal(err)
						}
						defer func() { _ = os.WriteFile(filepath.Join(out, f), orig, 0o644) }()
					}
					tc.tamper(t)
					if err := ImportDelta(ctx, b, g2, "S2", out); !errors.Is(err, artifact.ErrUntrusted) {
						t.Fatalf("import = %v, want ErrUntrusted", err)
					}
					for _, tag := range []string{parentTag(parentSHA), sessionTag("S2")} {
						if _, found, _ := artifact.Resolve(ctx, repoB+":"+tag, false); found {
							t.Fatalf("%s was published by a refused import", tag)
						}
					}
				})
			}
		}},
		{"a home without the exporter's seal key cannot import", func(t *testing.T) {
			if err := ImportDelta(ctx, d, g2, "S2", out); !errors.Is(err, artifact.ErrSealed) {
				t.Fatalf("import = %v, want ErrSealed", err)
			}
		}},
		// The info file says which domain the session came from. A grant
		// of another domain must not take it, whatever the file claims.
		{"importing into a grant of another domain is refused", func(t *testing.T) {
			if err := ImportDelta(ctx, b, g3, "S2", out); !errors.Is(err, artifact.ErrUntrusted) {
				t.Fatalf("import = %v, want ErrUntrusted", err)
			}
			repo3 := strings.TrimPrefix(domainRepoFor(b.DeltaRegistry, g3), artifact.FileScheme)
			if _, err := os.Stat(repo3); !os.IsNotExist(err) {
				t.Fatalf("the other domain's repository %s exists after a refused import (%v)", repo3, err)
			}
		}},
		{"import publishes the delta under the new name with this home's annotations", func(t *testing.T) {
			if err := ImportDelta(ctx, b, g2, "S2", out); err != nil {
				t.Fatalf("import: %v", err)
			}
			var found bool
			var err error
			loc, found, err = artifact.Resolve(ctx, repoB+":"+sessionTag("S2"), false)
			if err != nil || !found {
				t.Fatalf("imported session not found: %v", err)
			}
			if loc.ArtifactType != artifact.ArtifactTypeDelta || loc.Annotations[artifact.AnnotationSession] != "S2" ||
				loc.Annotations[artifact.AnnotationGrant] != "g2" || loc.Annotations[artifact.AnnotationHome] != "home-b" ||
				loc.Annotations[artifact.AnnotationParent] != parentSHA || loc.Annotations[artifact.AnnotationWBytes] != "11" ||
				loc.Annotations["io.fiberd.arch"] != "arm64" || loc.Annotations[artifact.AnnotationDomain] != g2.SessionDomain() ||
				loc.Annotations[artifact.AnnotationSealKey] != sealAB.ID {
				t.Fatalf("imported annotations %v", loc.Annotations)
			}
			if err := b.DeltaKeys.Verify(loc); err != nil || loc.Annotations[artifact.AnnotationSigner] != keyB.KeyID {
				t.Fatalf("imported delta must be signed by home-b: signer %q, %v", loc.Annotations[artifact.AnnotationSigner], err)
			}
		}},
		{"import brings the parent along, signed by the importer", func(t *testing.T) {
			ploc, found, err := artifact.Resolve(ctx, repoB+":"+parentTag(parentSHA), false)
			if err != nil || !found || ploc.ArtifactType != artifact.ArtifactTypeParent {
				t.Fatalf("parent not imported: found=%v %+v %v", found, ploc, err)
			}
			if err := b.DeltaKeys.Verify(ploc); err != nil {
				t.Fatalf("imported parent: %v", err)
			}
		}},
		{"the imported delta is resealed for its new name and opens with its pages and without logs", func(t *testing.T) {
			dst := filepath.Join(root, "pulled")
			if _, err := artifact.PullDir(ctx, repoB+"@"+loc.Digest, dst, false); err != nil {
				t.Fatal(err)
			}
			if got, _ := os.ReadFile(filepath.Join(dst, "pages-1.img")); strings.Contains(string(got), "dirty pages") {
				t.Fatal("the imported delta was pushed in the clear")
			}
			sc, err := artifact.OpenDir(dst, sealAB, g2.SessionDomain(), "S2", time.Now())
			if err != nil || sc.Fence != "g1/1/1" {
				t.Fatalf("open the imported delta: %+v %v", sc, err)
			}
			if got, _ := os.ReadFile(filepath.Join(dst, "pages-1.img")); string(got) != "dirty pages" {
				t.Fatalf("pulled delta pages = %q", got)
			}
			if _, err := os.Stat(filepath.Join(dst, "dump.log")); err == nil {
				t.Fatal("logs travelled")
			}
		}},
		// The same snapshot restored a second time, under a third name.
		{"importing again reuses the parent already there", func(t *testing.T) {
			if err := ImportDelta(ctx, b, g2, "S3", out); err != nil {
				t.Fatalf("second import: %v", err)
			}
		}},
		// The import opens the delta in the clear while it reseals it, and
		// fibers share the system temp dir, so the work happens under
		// DeltaDir, which they never see, and is gone afterwards.
		{"the import works under DeltaDir, never in the system temp dir, and leaves nothing behind", func(t *testing.T) {
			// Anything made in the system temp dir fails from here on.
			t.Setenv("TMPDIR", filepath.Join(root, "no-such-tmp"))
			cases := []struct {
				name     string
				deltaDir string
				workDir  string // where the import may work, "" when it must fail
			}{
				{name: "a usable DeltaDir", deltaDir: b.DeltaDir, workDir: b.DeltaDir},
				{name: "a DeltaDir that cannot be made", deltaDir: filepath.Join(out, ExportInfoFile, "deltas")},
				{name: "no DeltaDir, as a control plane importing from its own directory", workDir: out},
			}
			for i, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					cfg := b
					cfg.DeltaDir = tc.deltaDir
					err := ImportDelta(ctx, cfg, g2, "S4"+strconv.Itoa(i), out)
					if tc.workDir == "" {
						if err == nil {
							t.Fatal("imported with a working directory outside DeltaDir")
						}
						return
					}
					if err != nil {
						t.Fatalf("import: %v", err)
					}
					entries, err := os.ReadDir(tc.workDir)
					if err != nil {
						t.Fatal(err)
					}
					for _, e := range entries {
						if strings.HasPrefix(e.Name(), ".import-") {
							t.Fatalf("%s left behind in %s", e.Name(), tc.workDir)
						}
					}
				})
			}
		}},
	}
	for _, st := range steps {
		if !t.Run(st.name, st.run) {
			return // later steps build on this one
		}
	}
}

// TestRepositoryNames checks where a grant's sessions live in the registry, a
// name safe for any registry and distinct per domain.
func TestRepositoryNames(t *testing.T) {
	long := strings.Repeat("abcdefghij", 5)
	cases := []struct {
		name  string
		grant core.Grant
		// prefix is the repository name before the hash suffix.
		prefix string
	}{
		{name: "a template digest loses its algorithm prefix", grant: core.Grant{TemplateDigest: "sha256:ABC123"}, prefix: "abc123"},
		{name: "a session class is used as is, lower-cased and made safe", grant: core.Grant{TemplateDigest: "sha256:x", Policy: core.Policy{SessionClass: "Team/Alpha Models"}}, prefix: "team-alpha-models"},
		{name: "a long domain is cut to 40 characters", grant: core.Grant{Policy: core.Policy{SessionClass: long}}, prefix: long[:40]},
		{name: "a domain with no safe characters is named g", grant: core.Grant{Policy: core.Policy{SessionClass: "///"}}, prefix: "g"},
		{name: "an empty domain is named g", grant: core.Grant{}, prefix: "g"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := domainRepoFor("reg.example/deltas/", tc.grant)
			sum := sha256.Sum256([]byte(tc.grant.SessionDomain()))
			want := "reg.example/deltas/" + tc.prefix + "-" + hex.EncodeToString(sum[:4])
			if repo != want {
				t.Fatalf("domainRepoFor = %s, want %s", repo, want)
			}
			if other := domainRepoFor("reg.example/deltas", core.Grant{Policy: core.Policy{SessionClass: "other"}}); other == repo {
				t.Fatal("two domains share a repository")
			}
			if sessionTag("S") == sessionTag("T") || !strings.HasPrefix(sessionTag("S"), "s-") || len(sessionTag("S")) != 26 {
				t.Fatalf("sessionTag = %s", sessionTag("S"))
			}
			if parentTag("abc") != "p-abc" || parentTag(strings.Repeat("f", 64)) != "p-"+strings.Repeat("f", 24) {
				t.Fatalf("parentTag = %s %s", parentTag("abc"), parentTag(strings.Repeat("f", 64)))
			}
		})
	}
}

// TestCheckSigned checks what a verified manifest must still say before its
// delta is believed to be the session asked for.
func TestCheckSigned(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	ann := func(domain, session, expires string) map[string]string {
		return map[string]string{artifact.AnnotationDomain: domain, artifact.AnnotationSession: session, artifact.AnnotationExpires: expires}
	}
	cases := []struct {
		name    string
		ann     map[string]string
		wantErr error
		errText string
	}{
		{name: "the session asked for, not yet expired", ann: ann("d", "s", "2026-10-07T12:00:00Z")},
		{name: "another session", ann: ann("d", "t", "2026-10-07T12:00:00Z"), wantErr: artifact.ErrUntrusted, errText: "signed for d/t, not d/s"},
		{name: "another domain", ann: ann("e", "s", "2026-10-07T12:00:00Z"), wantErr: artifact.ErrUntrusted},
		{name: "no expiry", ann: ann("d", "s", ""), wantErr: artifact.ErrUntrusted, errText: "no expiry"},
		{name: "an expiry that is not a time", ann: ann("d", "s", "tomorrow"), wantErr: artifact.ErrUntrusted, errText: "no expiry"},
		{name: "expired this second", ann: ann("d", "s", "2026-10-06T12:00:00Z"), wantErr: artifact.ErrExpired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkSigned(tc.ann, "d", "s", now)
			if !errors.Is(err, tc.wantErr) || (tc.errText != "" && !strings.Contains(err.Error(), tc.errText)) {
				t.Fatalf("checkSigned = %v, want %v mentioning %q", err, tc.wantErr, tc.errText)
			}
		})
	}
}

// TestExportImportRefusals checks what ExportDelta and ImportDelta refuse
// before they touch the registry or the files, and the files they need.
func TestExportImportRefusals(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	keyA := signingKey(t, "home-a")
	seal := &artifact.SealKey{ID: "seal", Key: make([]byte, 32)}
	a := Config{DeltaRegistry: artifact.FileScheme + filepath.Join(root, "a"), DeltaKeys: artifact.Keys{Signer: keyA, Seal: seal}, HomeID: "home-a"}
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl"}
	repo := domainRepoFor(a.DeltaRegistry, g)
	parentSHA := strings.Repeat("ab", 32)
	write(t, filepath.Join(root, "parent"), map[string]string{"pages-1.img": "template pages"})
	write(t, filepath.Join(root, "delta"), map[string]string{"pages-1.img": "dirty pages", "manifest.json": `{"fence":"g1/1/1"}`})
	// A session whose tag holds a parent, not a delta.
	if _, err := artifact.PushDir(ctx, filepath.Join(root, "parent"), repo+":"+sessionTag("P"), artifact.ArtifactTypeParent, nil, keyA, false); err != nil {
		t.Fatal(err)
	}
	// A delta whose parent is not published, and one whose parent tag
	// holds a delta.
	for _, tc := range []struct{ session, parent, typ string }{{"NP", strings.Repeat("0a", 32), ""}, {"MT", strings.Repeat("cd", 32), artifact.ArtifactTypeDelta}} {
		ann := map[string]string{artifact.AnnotationParent: tc.parent}
		if _, err := pushDelta(ctx, a, filepath.Join(root, "delta"), repo+":"+sessionTag(tc.session), ann, a.sealContext(g, tc.session, "g1/1/1", time.Now())); err != nil {
			t.Fatal(err)
		}
		if tc.typ != "" {
			if _, err := artifact.PushDir(ctx, filepath.Join(root, "parent"), repo+":"+parentTag(tc.parent), tc.typ, ann, keyA, false); err != nil {
				t.Fatal(err)
			}
		}
	}
	// A full export, to break in various ways.
	if _, err := pushDelta(ctx, a, filepath.Join(root, "delta"), repo+":"+sessionTag("F"), map[string]string{}, a.sealContext(g, "F", "g1/1/1", time.Now())); err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(root, "full")
	if _, err := ExportDelta(ctx, a, g, "F", full); err != nil {
		t.Fatalf("export F: %v", err)
	}
	unwritable := filepath.Join(root, "file")
	if err := os.WriteFile(unwritable, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// A session with a parent that carries platform facts of its own,
	// exported in full, and the same parent signed under another hash.
	withParent := "WP"
	parentAnn := map[string]string{artifact.AnnotationParent: parentSHA, artifact.AnnotationArch: "arm64", artifact.AnnotationKernel: "6.10.0"}
	if _, err := artifact.PushDir(ctx, filepath.Join(root, "parent"), repo+":"+parentTag(parentSHA), artifact.ArtifactTypeParent, parentAnn, keyA, false); err != nil {
		t.Fatal(err)
	}
	otherSHA := strings.Repeat("ef", 32)
	if _, err := artifact.PushDir(ctx, filepath.Join(root, "parent"), repo+":"+parentTag(otherSHA), artifact.ArtifactTypeParent,
		map[string]string{artifact.AnnotationParent: otherSHA}, keyA, false); err != nil {
		t.Fatal(err)
	}
	otherLoc, _, err := artifact.Resolve(ctx, repo+":"+parentTag(otherSHA), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pushDelta(ctx, a, filepath.Join(root, "delta"), repo+":"+sessionTag(withParent),
		map[string]string{artifact.AnnotationParent: parentSHA, "io.fiberd.libc": "glibc"}, a.sealContext(g, withParent, "g1/1/1", time.Now())); err != nil {
		t.Fatal(err)
	}
	exported := filepath.Join(root, "exported")
	if _, err := ExportDelta(ctx, a, g, withParent, exported); err != nil {
		t.Fatalf("export %s: %v", withParent, err)
	}
	// A home that trusts a, with a registry of its own, and one whose
	// registry cannot be reached.
	trustA := []jose.JSONWebKey{keyA.Public()}
	b := Config{DeltaRegistry: artifact.FileScheme + filepath.Join(root, "b"), DeltaDir: filepath.Join(root, "b-deltas"),
		DeltaKeys: artifact.Keys{Signer: signingKey(t, "home-b"), Trust: trustA, Seal: seal}, HomeID: "home-b"}
	far := b
	far.DeltaRegistry = artifact.FileScheme + filepath.Join(unwritable, "registry")
	// A home that trusts nobody but a's registry is its own.
	c := Config{DeltaRegistry: a.DeltaRegistry, DeltaKeys: artifact.Keys{Signer: signingKey(t, "home-c"), Seal: seal}, HomeID: "home-c"}
	// copyExport copies the full export and lets a case rewrite its info.
	copyExport := func(t *testing.T, edit func(info *ExportInfo), drop ...string) string {
		t.Helper()
		dir := t.TempDir()
		for _, f := range []string{ExportDeltaFile, ExportParentFile, ExportInfoFile} {
			if slices.Contains(drop, f) {
				continue
			}
			b, err := os.ReadFile(filepath.Join(exported, f))
			if err != nil {
				t.Fatal(err)
			}
			if f == ExportInfoFile && edit != nil {
				var info ExportInfo
				if err := json.Unmarshal(b, &info); err != nil {
					t.Fatal(err)
				}
				edit(&info)
				if b, err = json.Marshal(info); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(dir, f), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	// breakBlob removes the stored files of the artifact at ref so a pull
	// of it fails after its manifest still resolves.
	breakBlob := func(t *testing.T, ref string) {
		t.Helper()
		loc, found, err := artifact.Resolve(ctx, ref, false)
		if err != nil || !found {
			t.Fatalf("resolve %s: %v %v", ref, found, err)
		}
		files := filepath.Join(strings.TrimPrefix(repo, artifact.FileScheme), "blobs", "sha256", strings.TrimPrefix(loc.Digest, "sha256:"), "files")
		if err := os.RemoveAll(files); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name string
		run  func(t *testing.T) error
		// wantErr is matched with errors.Is when set. errText is a fragment.
		wantErr error
		errText string
	}{
		{name: "export: a home that does not trust the publisher", run: func(t *testing.T) error {
			_, err := ExportDelta(ctx, c, g, "NP", t.TempDir())
			return err
		}, wantErr: artifact.ErrUntrusted, errText: "refusing to export"},
		{name: "export: a registry that cannot be reached", run: func(t *testing.T) error {
			_, err := ExportDelta(ctx, far, g, "NP", t.TempDir())
			return err
		}, errText: "not a directory"},
		{name: "import: the parent is looked up in a registry that cannot be reached", run: func(t *testing.T) error {
			return ImportDelta(ctx, far, g, "S", exported)
		}, errText: "not a directory"},
		{name: "import: the parent archive is missing", run: func(t *testing.T) error {
			return ImportDelta(ctx, b, g, "S", copyExport(t, nil, ExportParentFile))
		}, errText: "import parent"},
		{name: "import: the parent's manifest is signed for another checkpoint", run: func(t *testing.T) error {
			return ImportDelta(ctx, b, g, "S", copyExport(t, func(info *ExportInfo) { info.ParentAnnotations = otherLoc.Annotations }))
		}, wantErr: artifact.ErrUntrusted, errText: "signed as checkpoint"},
		{name: "import: the parent carries its own platform facts into the new registry", run: func(t *testing.T) error {
			if err := ImportDelta(ctx, b, g, "S", exported); err != nil {
				return err
			}
			ploc, found, err := artifact.Resolve(ctx, domainRepoFor(b.DeltaRegistry, g)+":"+parentTag(parentSHA), false)
			if err != nil || !found {
				return fmt.Errorf("imported parent: found %v: %w", found, err)
			}
			if ploc.Annotations[artifact.AnnotationArch] != "arm64" || ploc.Annotations[artifact.AnnotationKernel] != "6.10.0" || ploc.Annotations[artifact.AnnotationLibc] != "glibc" {
				return fmt.Errorf("imported parent annotations = %v, want the parent's arch and kernel and the delta's libc", ploc.Annotations)
			}
			return errors.New("imported")
		}, errText: "imported"},
		{name: "export: the delta's files are gone from the registry", run: func(t *testing.T) error {
			if _, err := pushDelta(ctx, a, filepath.Join(root, "delta"), repo+":"+sessionTag("LD"), map[string]string{}, a.sealContext(g, "LD", "g1/1/1", time.Now())); err != nil {
				t.Fatal(err)
			}
			breakBlob(t, repo+":"+sessionTag("LD"))
			_, err := ExportDelta(ctx, a, g, "LD", t.TempDir())
			return err
		}, errText: "pull"},
		{name: "export: the parent's files are gone from the registry", run: func(t *testing.T) error {
			lost := strings.Repeat("1a", 32)
			if _, err := artifact.PushDir(ctx, filepath.Join(root, "parent"), repo+":"+parentTag(lost), artifact.ArtifactTypeParent,
				map[string]string{artifact.AnnotationParent: lost}, keyA, false); err != nil {
				t.Fatal(err)
			}
			if _, err := pushDelta(ctx, a, filepath.Join(root, "delta"), repo+":"+sessionTag("LP"), map[string]string{artifact.AnnotationParent: lost}, a.sealContext(g, "LP", "g1/1/1", time.Now())); err != nil {
				t.Fatal(err)
			}
			breakBlob(t, repo+":"+parentTag(lost))
			_, err := ExportDelta(ctx, a, g, "LP", t.TempDir())
			return err
		}, errText: "delta needs parent"},
		{name: "export: the session tag holds a parent", run: func(t *testing.T) error {
			_, err := ExportDelta(ctx, a, g, "P", t.TempDir())
			return err
		}, errText: "not a delta"},
		{name: "export: the delta's parent is not published", run: func(t *testing.T) error {
			_, err := ExportDelta(ctx, a, g, "NP", t.TempDir())
			return err
		}, errText: "is not published"},
		{name: "export: the parent tag holds a delta", run: func(t *testing.T) error {
			_, err := ExportDelta(ctx, a, g, "MT", t.TempDir())
			return err
		}, errText: "not a parent checkpoint"},
		{name: "export: the directory cannot be made", run: func(t *testing.T) error {
			_, err := ExportDelta(ctx, a, g, "MT", filepath.Join(unwritable, "out"))
			return err
		}, errText: "not a directory"},
		{name: "import: no info file", run: func(t *testing.T) error { return ImportDelta(ctx, a, g, "S", t.TempDir()) }, wantErr: os.ErrNotExist},
		{name: "import: an info file that is not JSON", run: func(t *testing.T) error {
			dir := t.TempDir()
			write(t, dir, map[string]string{ExportInfoFile: "{"})
			return ImportDelta(ctx, a, g, "S", dir)
		}, errText: ExportInfoFile},
		{name: "import: no delta archive", run: func(t *testing.T) error {
			dir := t.TempDir()
			write(t, dir, map[string]string{ExportInfoFile: "{}"})
			return ImportDelta(ctx, a, g, "S", dir)
		}, errText: "import delta"},
		{name: "import: the info file names a parent the signed delta does not", run: func(t *testing.T) error {
			dir := t.TempDir()
			for _, f := range []string{ExportDeltaFile, ExportInfoFile} {
				b, err := os.ReadFile(filepath.Join(full, f))
				if err != nil {
					t.Fatal(err)
				}
				if f == ExportInfoFile {
					var info ExportInfo
					if err := json.Unmarshal(b, &info); err != nil {
						t.Fatal(err)
					}
					info.Parent = parentSHA
					if b, err = json.Marshal(info); err != nil {
						t.Fatal(err)
					}
				}
				write(t, dir, map[string]string{f: string(b)})
			}
			return ImportDelta(ctx, a, g, "S", dir)
		}, errText: "names parent"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run(t)
			if err == nil || (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) || !strings.Contains(err.Error(), tc.errText) {
				t.Fatalf("got %v, want %v mentioning %q", err, tc.wantErr, tc.errText)
			}
		})
	}
}

// TestPushDeltaErrors checks that a delta that cannot be sealed is not pushed.
func TestPushDeltaErrors(t *testing.T) {
	cfg := Config{DeltaKeys: artifact.Keys{Signer: signingKey(t, "k"), Seal: &artifact.SealKey{ID: "seal", Key: make([]byte, 32)}}}
	cases := []struct {
		name string
		src  func(t *testing.T) string
	}{
		{name: "a source whose parent directory is missing", src: func(t *testing.T) string { return filepath.Join(t.TempDir(), "none", "delta") }},
		{name: "a source that is missing", src: func(t *testing.T) string { return filepath.Join(t.TempDir(), "delta") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := pushDelta(context.Background(), cfg, tc.src(t), "file:///nowhere/repo:tag", nil, artifact.SealContext{}); err == nil {
				t.Fatal("pushed a delta that does not exist")
			}
		})
	}
}
