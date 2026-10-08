//go:build linux

package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
)

// mobilityHome is a runtime for the registry protocol alone, with a codec
// and a parent store but no cgroups or warm instance.
func mobilityHome(t *testing.T, name string, be backend.Backend, keys artifact.Keys, host artifact.Platform, registry string) *Runtime {
	t.Helper()
	root := t.TempDir()
	return &Runtime{
		cfg: Config{DeltaRegistry: registry, DeltaKeys: keys, HomeID: name, DeltaDir: filepath.Join(root, "deltas"),
			TemplateCache: filepath.Join(root, "cache")},
		be: be, host: host, tier: core.TierCheckpoint, parents: map[string]backend.Parent{},
	}
}

// parkedDelta writes what a park leaves behind, which is the images, the
// fake delta naming its parent, a log and the manifest.
func parkedDelta(t *testing.T, dir string, m manifest, parent string) {
	t.Helper()
	write(t, dir, map[string]string{"pages-1.img": "dirty pages", "dump.log": "x"})
	if err := writeJSON(filepath.Join(dir, fakeDeltaFile), fakeDelta{Parent: parent, Bytes: m.WBytes}); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(dir, "manifest.json"), m); err != nil {
		t.Fatal(err)
	}
}

// TestRegistryMobility checks that home A publishes a parked session to the
// shared registry, home B finds and claims it, and nothing unsigned,
// unsealed, foreign or stale is taken. Steps run in order, each building on
// the last.
func TestRegistryMobility(t *testing.T) {
	ctx := context.Background()
	registry := artifact.FileScheme + filepath.Join(t.TempDir(), "registry")
	keyA, keyB, keyC := signingKey(t, "home-a"), signingKey(t, "home-b"), signingKey(t, "home-c")
	seal := &artifact.SealKey{ID: "seal", Key: make([]byte, 32)}
	otherSeal := &artifact.SealKey{ID: "seal-d", Key: append([]byte{1}, make([]byte, 31)...)}
	platform := artifact.Platform{Arch: "arm64", Kernel: "6.10.0", Libc: "glibc 2.40", Backend: "fake"}
	trustA := []jose.JSONWebKey{keyA.Public()}
	a := mobilityHome(t, "home-a", newCodecBackend(core.TierCheckpoint), artifact.Keys{Signer: keyA, Seal: seal}, platform, registry)
	b := mobilityHome(t, "home-b", newCodecBackend(core.TierCheckpoint), artifact.Keys{Signer: keyB, Trust: trustA, Seal: seal}, platform, registry)
	// c trusts nobody, d has another seal key, e runs another architecture,
	// f has no codec.
	c := mobilityHome(t, "home-c", newCodecBackend(core.TierCheckpoint), artifact.Keys{Signer: keyC, Seal: seal}, platform, registry)
	d := mobilityHome(t, "home-d", newCodecBackend(core.TierCheckpoint), artifact.Keys{Signer: signingKey(t, "home-d"), Trust: trustA, Seal: otherSeal}, platform, registry)
	e := mobilityHome(t, "home-e", newCodecBackend(core.TierCheckpoint), artifact.Keys{Signer: signingKey(t, "home-e"), Trust: trustA, Seal: seal},
		artifact.Platform{Arch: "amd64", Kernel: "6.10.0", Libc: "glibc 2.40", Backend: "fake"}, registry)
	f := mobilityHome(t, "home-f", newFakeBackend(core.TierCheckpoint), artifact.Keys{Signer: signingKey(t, "home-f"), Trust: trustA, Seal: seal}, platform, registry)

	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl"}
	parentPages := "template pages"
	parentSHA := shaOf(parentPages)
	repo := a.domainRepo(g)
	deltaA := filepath.Join(a.cfg.DeltaDir, "g1", "1-1")
	m := manifest{Fence: "g1/1/1", GrantUID: "g1", Endpoint: "unix:///run/g1/1-1.sock", Template: g.TemplateDigest, Backend: "fake",
		WBytes: 7, Delta: true, Parent: parentSHA, ParkedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	var remote string
	var found core.RemoteDelta
	steps := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"a home without a registry publishes nothing and finds nothing", func(t *testing.T) {
			none := mobilityHome(t, "none", newCodecBackend(core.TierCheckpoint), artifact.Keys{}, platform, "")
			if _, err := none.PublishDelta(ctx, deltaA, g, "S"); err == nil {
				t.Fatal("published without a registry")
			}
			rd, ok, err := none.FindDelta(ctx, g, "S")
			if ok || err != nil || rd != (core.RemoteDelta{}) {
				t.Fatalf("FindDelta = %+v %v %v, want nothing", rd, ok, err)
			}
		}},
		{"a delta without a manifest cannot be published", func(t *testing.T) {
			if _, err := a.PublishDelta(ctx, t.TempDir(), g, "S"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("PublishDelta = %v", err)
			}
		}},
		{"a delta whose parent is not in the store cannot be published", func(t *testing.T) {
			parkedDelta(t, deltaA, m, parentSHA)
			if _, err := a.PublishDelta(ctx, deltaA, g, "S"); err == nil || !strings.Contains(err.Error(), "not in the store") {
				t.Fatalf("PublishDelta = %v", err)
			}
		}},
		{"publish: the parent once, the delta sealed and signed, the remote recorded", func(t *testing.T) {
			if err := writeParentDir(filepath.Join(a.parentsDir(), parentSHA), parentPages); err != nil {
				t.Fatal(err)
			}
			var err error
			remote, err = a.PublishDelta(ctx, deltaA, g, "S")
			if err != nil {
				t.Fatalf("PublishDelta: %v", err)
			}
			var rec remoteRecord
			if err := readJSON(filepath.Join(deltaA, remoteFile), &rec); err != nil || rec.Ref != repo+":"+sessionTag("S") || remote != rec.Ref+"@"+rec.Digest {
				t.Fatalf("remote record = %+v %v, published as %s", rec, err, remote)
			}
			ploc, pfound, err := artifact.Resolve(ctx, repo+":"+parentTag(parentSHA), false)
			if err != nil || !pfound || ploc.ArtifactType != artifact.ArtifactTypeParent || a.cfg.DeltaKeys.Verify(ploc) != nil ||
				ploc.Annotations[artifact.AnnotationParent] != parentSHA || ploc.Annotations[artifact.AnnotationHome] != "home-a" ||
				ploc.Annotations[artifact.AnnotationArch] != "arm64" || ploc.Annotations[artifact.AnnotationBackend] != "fake" {
				t.Fatalf("parent = %+v %v %v", ploc, pfound, err)
			}
			loc, sfound, err := artifact.Resolve(ctx, rec.Ref, false)
			if err != nil || !sfound || loc.Digest != rec.Digest || loc.ArtifactType != artifact.ArtifactTypeDelta || a.cfg.DeltaKeys.Verify(loc) != nil {
				t.Fatalf("session = %+v %v %v", loc, sfound, err)
			}
			want := map[string]string{artifact.AnnotationWBytes: "7", artifact.AnnotationParent: parentSHA, artifact.AnnotationHome: "home-a",
				artifact.AnnotationFence: "g1/1/1", artifact.AnnotationGrant: "g1", artifact.AnnotationArch: "arm64", artifact.AnnotationKernel: "6.10.0",
				artifact.AnnotationLibc: "glibc 2.40", artifact.AnnotationBackend: "fake", artifact.AnnotationDomain: g.SessionDomain(),
				artifact.AnnotationSession: "S", artifact.AnnotationSealKey: "seal"}
			for k, v := range want {
				if loc.Annotations[k] != v {
					t.Fatalf("annotation %s = %q, want %q (all: %v)", k, loc.Annotations[k], v, loc.Annotations)
				}
			}
			if _, err := time.Parse(time.RFC3339, loc.Annotations[artifact.AnnotationExpires]); err != nil {
				t.Fatalf("expiry %q: %v", loc.Annotations[artifact.AnnotationExpires], err)
			}
			// Published again after another park, the parent is already there.
			remote2, err := a.PublishDelta(ctx, deltaA, g, "S")
			if err != nil {
				t.Fatalf("second publish: %v", err)
			}
			if ploc2, _, _ := artifact.Resolve(ctx, repo+":"+parentTag(parentSHA), false); ploc2.Digest != ploc.Digest {
				t.Fatal("the parent was pushed again")
			}
			remote = remote2
		}},
		{"the registry holds no plaintext", func(t *testing.T) {
			err := filepath.WalkDir(strings.TrimPrefix(registry, artifact.FileScheme), func(path string, e os.DirEntry, err error) error {
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
		{"owned while the tag holds what was pushed", func(t *testing.T) {
			if !a.Owned(ctx, deltaA) {
				t.Fatal("a just-published delta is not owned")
			}
			unpublished := filepath.Join(t.TempDir(), "local")
			if !a.Owned(ctx, unpublished) {
				t.Fatal("a never-published delta is not owned")
			}
			unreachable := t.TempDir()
			if err := writeJSON(filepath.Join(unreachable, remoteFile), remoteRecord{Ref: "bogus ref with spaces", Digest: "x"}); err != nil {
				t.Fatal(err)
			}
			if !a.Owned(ctx, unreachable) {
				t.Fatal("a delta whose registry cannot be asked must stay ours")
			}
		}},
		{"found by a home that trusts the publisher", func(t *testing.T) {
			var ok bool
			var err error
			found, ok, err = b.FindDelta(ctx, g, "S")
			if err != nil || !ok || found.WBytes != 7 || found.Home != "home-a" || found.Handle != strings.SplitN(remote, "@", 2)[1] {
				t.Fatalf("FindDelta = %+v %v %v", found, ok, err)
			}
			if rd, ok, err := b.FindDelta(ctx, g, "unknown"); ok || err != nil || rd != (core.RemoteDelta{}) {
				t.Fatalf("FindDelta of an unknown session = %+v %v %v", rd, ok, err)
			}
		}},
		{"found but refused: untrusted signer, other platform, expired, not a delta", func(t *testing.T) {
			if _, err := pushDelta(ctx, a.cfg, deltaA, repo+":"+sessionTag("E"), map[string]string{artifact.AnnotationHome: "home-a"},
				a.cfg.sealContext(g, "E", "g1/1/1", time.Now().Add(-2*deltaTTL))); err != nil {
				t.Fatal(err)
			}
			if _, err := artifact.PushDir(ctx, filepath.Join(a.parentsDir(), parentSHA), repo+":"+sessionTag("X"), artifact.ArtifactTypeParent, nil, keyA, false); err != nil {
				t.Fatal(err)
			}
			cases := []struct {
				name    string
				home    *Runtime
				session string
				wantErr error
				// miss is whether the error is a RemoteMiss (found, not taken).
				miss      bool
				preferred string
			}{
				{name: "a home that does not trust the publisher", home: c, session: "S", wantErr: artifact.ErrUntrusted, miss: true},
				{name: "a home on another architecture", home: e, session: "S", wantErr: core.ErrIncompatible, miss: true, preferred: "home-a"},
				{name: "an expired delta", home: b, session: "E", wantErr: artifact.ErrExpired, miss: true},
				{name: "a tag that is not a delta", home: b, session: "X"},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					_, ok, err := tc.home.FindDelta(ctx, g, tc.session)
					var miss *core.RemoteMiss
					if err == nil || errors.As(err, &miss) != tc.miss || (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) {
						t.Fatalf("FindDelta = %v %v, want %v (miss %v)", ok, err, tc.wantErr, tc.miss)
					}
					if tc.miss && (!ok || miss.PreferredHome != tc.preferred) {
						t.Fatalf("FindDelta = %v, miss %+v, want found with preferred home %q", ok, miss, tc.preferred)
					}
				})
			}
		}},
		{"a claim that cannot pull, open or complete leaves nothing behind", func(t *testing.T) {
			// A delta over a parent nobody published, and parents published
			// wrongly under other hashes.
			unpublished, foreign, mistyped, mismatched := shaOf("u"), shaOf("f"), shaOf("m"), shaOf("mm")
			for i, sha := range []string{unpublished, foreign, mistyped, mismatched} {
				dir := filepath.Join(t.TempDir(), "d")
				parkedDelta(t, dir, m, sha)
				if _, err := pushDelta(ctx, a.cfg, dir, repo+":"+sessionTag("P"+string(rune('0'+i))), map[string]string{artifact.AnnotationHome: "home-a"},
					a.cfg.sealContext(g, "P"+string(rune('0'+i)), "g1/1/1", time.Now())); err != nil {
					t.Fatal(err)
				}
			}
			pdir := filepath.Join(a.parentsDir(), parentSHA)
			for _, p := range []struct {
				sha, typ string
				key      *jose.JSONWebKey
			}{{foreign, artifact.ArtifactTypeParent, keyC}, {mistyped, artifact.ArtifactTypeDelta, keyA}, {mismatched, artifact.ArtifactTypeParent, keyA}} {
				if _, err := artifact.PushDir(ctx, pdir, repo+":"+parentTag(p.sha), p.typ, map[string]string{artifact.AnnotationParent: p.sha}, p.key, false); err != nil {
					t.Fatal(err)
				}
			}
			bInfoErr := mobilityHome(t, "home-b2", newCodecBackend(core.TierCheckpoint), b.cfg.DeltaKeys, platform, registry)
			bInfoErr.be.(*codecBackend).infoErr = errors.New("fake: bad delta header")
			cases := []struct {
				name    string
				home    *Runtime
				session string
				rd      func(rd core.RemoteDelta) core.RemoteDelta
				wantErr error
				errText string
			}{
				{name: "a handle the registry does not hold", home: b, session: "S",
					rd: func(rd core.RemoteDelta) core.RemoteDelta {
						rd.Handle = "sha256:" + strings.Repeat("ab", 32)
						return rd
					}},
				{name: "a home with another seal key", home: d, session: "S", wantErr: artifact.ErrSealed, errText: "claim g1/S"},
				{name: "a delta whose info cannot be read", home: bInfoErr, session: "S", errText: "bad delta header"},
				{name: "a parent nobody published", home: b, session: "P0", errText: "is not published"},
				{name: "a parent signed by a home not trusted here", home: b, session: "P1", wantErr: artifact.ErrUntrusted},
				{name: "a parent tag holding a delta", home: b, session: "P2", errText: "not a parent checkpoint"},
				{name: "a parent whose pages hash differently", home: b, session: "P3", errText: "hashes to"},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					rd, ok, err := tc.home.FindDelta(ctx, g, tc.session)
					if err != nil || !ok {
						t.Fatalf("FindDelta = %v %v", ok, err)
					}
					if tc.rd != nil {
						rd = tc.rd(rd)
					}
					dst, err := tc.home.ClaimDelta(ctx, g, tc.session, rd)
					if err == nil || dst != "" || (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) || !strings.Contains(err.Error(), tc.errText) {
						t.Fatalf("ClaimDelta = %q, %v; want %v mentioning %q", dst, err, tc.wantErr, tc.errText)
					}
					entries, _ := os.ReadDir(filepath.Join(tc.home.cfg.DeltaDir, "g1"))
					if len(entries) != 0 {
						t.Fatalf("a refused claim left %v behind", entries)
					}
					store, _ := os.ReadDir(tc.home.parentsDir())
					for _, e := range store {
						if strings.HasSuffix(e.Name(), ".pull") {
							t.Fatalf("a refused claim left %s in the parent store", e.Name())
						}
					}
					if _, still, _ := artifact.Resolve(ctx, repo+":"+sessionTag(tc.session), false); !still {
						t.Fatal("a refused claim took the session")
					}
				})
			}
		}},
		{"a session re-parked between find and claim is not taken", func(t *testing.T) {
			rd, _, err := b.FindDelta(ctx, g, "S")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := a.PublishDelta(ctx, deltaA, g, "S"); err != nil {
				t.Fatal(err)
			}
			if _, err := b.ClaimDelta(ctx, g, "S", rd); err == nil || !strings.Contains(err.Error(), "claimed or re-parked elsewhere") {
				t.Fatalf("ClaimDelta = %v", err)
			}
			if !a.Owned(ctx, deltaA) {
				t.Fatal("the publisher lost the session to a failed claim")
			}
			found, _, err = b.FindDelta(ctx, g, "S")
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"claim: pulled, opened, the parent fetched into the store, the tag retired", func(t *testing.T) {
			dst, err := b.ClaimDelta(ctx, g, "S", found)
			if err != nil {
				t.Fatalf("ClaimDelta: %v", err)
			}
			if rel, err := filepath.Rel(filepath.Join(b.cfg.DeltaDir, "g1"), dst); err != nil || !strings.HasPrefix(rel, "claimed-"+sessionTag("S")) {
				t.Fatalf("claimed into %s", dst)
			}
			if pages, _ := os.ReadFile(filepath.Join(dst, "pages-1.img")); string(pages) != "dirty pages" {
				t.Fatalf("claimed pages = %q", pages)
			}
			if exists(filepath.Join(dst, remoteFile)) || exists(filepath.Join(dst, "dump.log")) {
				t.Fatal("the publisher's record or its logs travelled")
			}
			if !b.HasDelta(dst) {
				t.Fatal("the claimed delta has no manifest")
			}
			p, err := b.parent(parentSHA)
			if err != nil || p.SHA256() != parentSHA || !exists(filepath.Join(b.parentsDir(), parentSHA, fakePagesFile)) {
				t.Fatalf("parent after the claim: %v %v", p, err)
			}
			if _, still, _ := artifact.Resolve(ctx, repo+":"+sessionTag("S"), false); still {
				t.Fatal("the claimed session is still published")
			}
			if a.Owned(ctx, deltaA) {
				t.Fatal("the publisher still believes it owns the session")
			}
			if _, ok, err := b.FindDelta(ctx, g, "S"); ok || err != nil {
				t.Fatalf("FindDelta after the claim = %v %v", ok, err)
			}
			if err := b.DiscardDelta(ctx, dst); err != nil || exists(dst) {
				t.Fatalf("DiscardDelta = %v, exists %v", err, exists(dst))
			}
		}},
		{"a claim by a home without a codec takes the delta as it is", func(t *testing.T) {
			if _, err := a.PublishDelta(ctx, deltaA, g, "S"); err != nil {
				t.Fatal(err)
			}
			rd, _, err := f.FindDelta(ctx, g, "S")
			if err != nil {
				t.Fatal(err)
			}
			dst, err := f.ClaimDelta(ctx, g, "S", rd)
			if err != nil || !exists(filepath.Join(dst, fakeDeltaFile)) {
				t.Fatalf("ClaimDelta = %s %v", dst, err)
			}
			if entries, _ := os.ReadDir(f.parentsDir()); len(entries) != 0 {
				t.Fatal("a home without a codec pulled a parent")
			}
		}},
		{"a registry that cannot be reached: nothing is published, found or pulled", func(t *testing.T) {
			blocker := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(blocker, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			far := mobilityHome(t, "home-far", newCodecBackend(core.TierCheckpoint), a.cfg.DeltaKeys, platform, artifact.FileScheme+filepath.Join(blocker, "registry"))
			if err := writeParentDir(filepath.Join(far.parentsDir(), parentSHA), parentPages); err != nil {
				t.Fatal(err)
			}
			withParent := filepath.Join(far.cfg.DeltaDir, "g1", "1-1")
			parkedDelta(t, withParent, m, parentSHA)
			if _, err := far.PublishDelta(ctx, withParent, g, "S"); !errors.Is(err, syscall.ENOTDIR) || !strings.Contains(err.Error(), "publish parent") {
				t.Fatalf("PublishDelta with a parent = %v, want the registry's error from the parent lookup", err)
			}
			full := m
			full.Delta, full.Parent = false, ""
			fullDir := filepath.Join(far.cfg.DeltaDir, "g1", "1-2")
			parkedDelta(t, fullDir, full, "")
			if _, err := far.PublishDelta(ctx, fullDir, g, "S"); !errors.Is(err, syscall.ENOTDIR) {
				t.Fatalf("PublishDelta of a full image = %v, want the registry's error from the push", err)
			}
			if exists(filepath.Join(fullDir, remoteFile)) {
				t.Fatal("a failed publish recorded a remote")
			}
			if _, ok, err := far.FindDelta(ctx, g, "S"); ok || !errors.Is(err, syscall.ENOTDIR) {
				t.Fatalf("FindDelta = %v %v", ok, err)
			}
			if err := far.pullParent(ctx, far.domainRepo(g), parentSHA); !errors.Is(err, syscall.ENOTDIR) {
				t.Fatalf("pullParent = %v", err)
			}
		}},
		{"a published parent whose files the registry lost cannot be pulled", func(t *testing.T) {
			lost := shaOf("lost")
			ploc, _, err := artifact.Resolve(ctx, repo+":"+parentTag(parentSHA), false)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := artifact.PushDir(ctx, filepath.Join(a.parentsDir(), parentSHA), repo+":"+parentTag(lost), artifact.ArtifactTypeParent,
				map[string]string{artifact.AnnotationParent: lost}, keyA, false); err != nil {
				t.Fatal(err)
			}
			lloc, _, err := artifact.Resolve(ctx, repo+":"+parentTag(lost), false)
			if err != nil || lloc.Digest == ploc.Digest {
				t.Fatalf("the lost parent must be its own blob: %v", err)
			}
			blob := filepath.Join(strings.TrimPrefix(repo, artifact.FileScheme), "blobs", "sha256", strings.TrimPrefix(lloc.Digest, "sha256:"), "files")
			if err := os.RemoveAll(blob); err != nil {
				t.Fatal(err)
			}
			if err := b.pullParent(ctx, repo, lost); err == nil || !strings.Contains(err.Error(), "pull") {
				t.Fatalf("pullParent = %v, want the pull's error", err)
			}
			if exists(filepath.Join(b.parentsDir(), lost+".pull")) || exists(filepath.Join(b.parentsDir(), lost)) {
				t.Fatal("a failed pull left files in the store")
			}
		}},
		{"pulling a parent the codec cannot load, or without a codec", func(t *testing.T) {
			odd := shaOf("odd")
			if _, err := artifact.PushDir(ctx, filepath.Join(a.cfg.DeltaDir, "g1", "1-1"), repo+":"+parentTag(odd), artifact.ArtifactTypeParent,
				map[string]string{artifact.AnnotationParent: odd}, keyA, false); err != nil {
				t.Fatal(err)
			}
			if err := b.pullParent(ctx, repo, odd); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("pullParent of a checkpoint without pages = %v", err)
			}
			if err := f.pullParent(ctx, repo, odd); err == nil || !strings.Contains(err.Error(), "no delta codec") {
				t.Fatalf("pullParent without a codec = %v", err)
			}
			for _, home := range []*Runtime{b, f} {
				if exists(filepath.Join(home.parentsDir(), odd)) || exists(filepath.Join(home.parentsDir(), odd+".pull")) {
					t.Fatalf("%s kept a parent it could not use", home.cfg.HomeID)
				}
			}
		}},
	}
	for _, st := range steps {
		if !t.Run(st.name, st.run) {
			return // later steps build on this one
		}
	}
}

// TestRetireDelta checks how a home withdraws the copy it published of a
// delta, which a local resume does. The tag goes while it still holds the
// digest this home pushed, and the publish record goes with it. A tag a
// later park moved on stays. A registry that cannot be asked leaves the
// record, so a later discard can try again.
func TestRetireDelta(t *testing.T) {
	ctx := context.Background()
	registry := artifact.FileScheme + filepath.Join(t.TempDir(), "registry")
	seal := &artifact.SealKey{ID: "seal", Key: make([]byte, 32)}
	platform := artifact.Platform{Arch: "arm64", Kernel: "6.10.0", Libc: "glibc 2.40", Backend: "fake"}
	a := mobilityHome(t, "home-a", newCodecBackend(core.TierCheckpoint), artifact.Keys{Signer: signingKey(t, "home-a"), Seal: seal}, platform, registry)
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl"}
	parentPages := "template pages"
	parentSHA := shaOf(parentPages)
	if err := writeParentDir(filepath.Join(a.parentsDir(), parentSHA), parentPages); err != nil {
		t.Fatal(err)
	}
	tag := a.domainRepo(g) + ":" + sessionTag("S")
	// park writes and publishes a delta of S under the fence.
	park := func(t *testing.T, fence string) string {
		t.Helper()
		dir := filepath.Join(a.cfg.DeltaDir, "g1", strings.ReplaceAll(strings.TrimPrefix(fence, "g1/"), "/", "-"))
		parkedDelta(t, dir, manifest{Fence: fence, GrantUID: "g1", Endpoint: "unix:///run/g1/x.sock", Template: g.TemplateDigest, Backend: "fake",
			WBytes: 7, Delta: true, Parent: parentSHA, ParkedAt: time.Now().UTC().Format(time.RFC3339Nano)}, parentSHA)
		if _, err := a.PublishDelta(ctx, dir, g, "S"); err != nil {
			t.Fatalf("publish %s: %v", fence, err)
		}
		return dir
	}
	cases := []struct {
		name string
		// setup leaves the registry and the delta store as the case
		// needs them and returns the delta to retire.
		setup   func(t *testing.T) string
		wantErr bool
		wantTag string // "" for no tag, "own" for the retired delta's digest, "later" for the later park's
		wantRec bool   // the publish record is still beside the delta
	}{
		{name: "a delta never published needs nothing", setup: func(t *testing.T) string {
			dir := filepath.Join(a.cfg.DeltaDir, "g1", "1-1")
			parkedDelta(t, dir, manifest{Fence: "g1/1/1", GrantUID: "g1", Backend: "fake", WBytes: 7}, parentSHA)
			return dir
		}},
		{name: "the tag this home pushed is deleted with its record", setup: func(t *testing.T) string {
			return park(t, "g1/1/2")
		}},
		{name: "a tag a later park moved on stays, and only the record goes", setup: func(t *testing.T) string {
			dir := park(t, "g1/1/3")
			park(t, "g1/1/4")
			return dir
		}, wantTag: "later"},
		{name: "a registry that cannot be asked keeps the record and reports it", setup: func(t *testing.T) string {
			dir := filepath.Join(a.cfg.DeltaDir, "g1", "1-5")
			parkedDelta(t, dir, manifest{Fence: "g1/1/5", GrantUID: "g1", Backend: "fake", WBytes: 7}, parentSHA)
			if err := writeJSON(filepath.Join(dir, remoteFile), remoteRecord{Ref: "bogus ref with spaces", Digest: "sha256:x"}); err != nil {
				t.Fatal(err)
			}
			return dir
		}, wantErr: true, wantRec: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_ = artifact.Delete(ctx, tag, false)
			dir := tc.setup(t)
			var before remoteRecord
			_ = readJSON(filepath.Join(dir, remoteFile), &before)
			err := a.RetireDelta(ctx, dir)
			if (err != nil) != tc.wantErr {
				t.Fatalf("RetireDelta = %v, want error %v", err, tc.wantErr)
			}
			if _, serr := os.Stat(filepath.Join(dir, remoteFile)); (serr == nil) != tc.wantRec {
				t.Fatalf("publish record present = %v, want %v", serr == nil, tc.wantRec)
			}
			if _, serr := os.Stat(filepath.Join(dir, "manifest.json")); serr != nil {
				t.Fatalf("the delta itself was touched: %v", serr)
			}
			loc, found, rerr := artifact.Resolve(ctx, tag, false)
			if rerr != nil {
				t.Fatal(rerr)
			}
			switch tc.wantTag {
			case "":
				if found {
					t.Fatalf("tag %s still resolves to %s", tag, loc.Digest)
				}
			case "later":
				if !found || loc.Digest == before.Digest {
					t.Fatalf("tag found = %v at %s, want the later park's digest, not %s", found, loc.Digest, before.Digest)
				}
			}
			if !a.Owned(ctx, dir) {
				t.Fatal("a retired delta must read as never published")
			}
		})
	}
}
