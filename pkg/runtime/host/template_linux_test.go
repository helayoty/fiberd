//go:build linux

package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/registry"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/core"
)

// TestResolveTemplateDigest checks that a registry template's digest names its
// directory in the template cache, so only "sha256:" and 64 lowercase hex
// characters may reach the path. Anything else is refused before the
// cache is touched. "sha256:.." would name the cache's parent, which a
// failed pull removes.
func TestResolveTemplateDigest(t *testing.T) {
	hex64 := strings.Repeat("0123456789abcdef", 4)
	cases := []struct {
		name   string
		digest string
		// refused means the digest is rejected for its form, before any pull.
		refused bool
	}{
		{name: "valid", digest: "sha256:" + hex64},
		{name: "dot dot", digest: "sha256:..", refused: true},
		{name: "a slash", digest: "sha256:" + hex64[:31] + "/" + hex64[:32], refused: true},
		{name: "uppercase", digest: "sha256:" + strings.ToUpper(hex64), refused: true},
		{name: "short", digest: "sha256:" + hex64[:63], refused: true},
		{name: "other algorithm", digest: "sha512:" + hex64 + hex64, refused: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			cache := filepath.Join(root, "cache")
			sentinel := filepath.Join(root, "sentinel")
			if err := os.MkdirAll(cache, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(sentinel, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			// Nothing listens on port 1, so a pull fails at once.
			r := &Runtime{cfg: Config{Registry: "127.0.0.1:1/tmpl", TemplateCache: cache}}
			_, err := r.resolveTemplate(context.Background(), tc.digest)
			if _, serr := os.Stat(sentinel); serr != nil {
				t.Fatalf("resolveTemplate(%q) removed a file beside the template cache: %v", tc.digest, serr)
			}
			if !errors.Is(err, ErrNoTemplate) {
				t.Fatalf("resolveTemplate(%q) = %v, want ErrNoTemplate", tc.digest, err)
			}
			if got := strings.Contains(err.Error(), "64 lowercase hex"); got != tc.refused {
				t.Fatalf("resolveTemplate(%q) = %v, refused for its form %v, want %v", tc.digest, err, got, tc.refused)
			}
		})
	}
}

// TestParentHash checks that a parent checkpoint's hash comes from a pulled
// delta and is joined into the parent store, so only 64 lowercase hex
// characters may reach the path. Anything else is refused before the store is
// touched.
func TestParentHash(t *testing.T) {
	hex64 := strings.Repeat("0123456789abcdef", 4)
	cases := []struct {
		name string
		sha  string
		ok   bool
	}{
		{name: "64 lowercase hex", sha: hex64, ok: true},
		{name: "parent directory", sha: ".."},
		{name: "a path", sha: "../" + hex64[:61]},
		{name: "upper case", sha: strings.ToUpper(hex64)},
		{name: "short, which once panicked when sliced", sha: "abc"},
		{name: "with the algorithm prefix", sha: "sha256:" + hex64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isHex64(tc.sha); got != tc.ok {
				t.Fatalf("isHex64(%q) = %v, want %v", tc.sha, got, tc.ok)
			}
			if tc.ok {
				return
			}
			r := &Runtime{cfg: Config{TemplateCache: t.TempDir()}}
			if _, err := r.parent(tc.sha); err == nil || !strings.Contains(err.Error(), "not a sha256") {
				t.Fatalf("parent(%q) = %v, want a refusal", tc.sha, err)
			}
			if err := r.pullParent(context.Background(), "unused", tc.sha); err == nil || !strings.Contains(err.Error(), "not a sha256") {
				t.Fatalf("pullParent(%q) = %v, want a refusal", tc.sha, err)
			}
		})
	}
}

// templateMaster is the fleet's master seal key in these tests. Author
// images are sealed to the wrap key it derives.
var templateMaster = &artifact.SealKey{ID: "template-master", Key: []byte("0123456789abcdef0123456789abcdef")}

// templateArtifact writes a zygote artifact directory by hand (an
// executable, its config, images sealed to templateMaster's fleet key
// when asked) and pushes it to reg, returning its digest. linking is what
// the config says about the executable ("" for a config from before the
// fact was recorded).
func templateArtifact(t *testing.T, reg string, p artifact.Platform, images bool, linking string) string {
	t.Helper()
	dir := t.TempDir()
	zygote := []byte("#!/bin/sh\nexit 0\n" + linking)
	sum := sha256.Sum256(zygote)
	if err := os.WriteFile(artifact.ZygotePath(dir), zygote, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := map[string]any{"args": []string{"--heap", "8"}, "arch": p.Arch, "kernel": p.Kernel, "libc": p.Libc,
		"zygote_sha256": hex.EncodeToString(sum[:]), "built_at": "2026-10-01T00:00:00Z", "linking": linking}
	if images {
		pages, plain := t.TempDir(), filepath.Join(t.TempDir(), "images.tar")
		if err := writeParentDir(pages, "artifact pages"); err != nil {
			t.Fatal(err)
		}
		if err := artifact.TarDir(pages, plain); err != nil {
			t.Fatal(err)
		}
		w, err := artifact.DeriveWrapKey(templateMaster)
		if err != nil {
			t.Fatal(err)
		}
		s, err := artifact.SealImages(plain, filepath.Join(dir, "images.tar"), w.Public())
		if err != nil {
			t.Fatal(err)
		}
		cfg["images"] = s
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	digest, err := artifact.Push(context.Background(), dir, reg+"/tmpl/x:"+fmt.Sprintf("%v-%s-%s", images, p.Kernel, linking))
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	return digest
}

// TestResolveTemplateRegistry checks that a digest not in the Templates
// map is pulled from the registry into the cache once, re-verified on
// every later use, and gated on platform parity. The architecture always
// counts, and the kernel and libc only when the artifact carries images.
func TestResolveTemplateRegistry(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	reg := srv.URL
	host := artifact.Platform{Arch: "arm64", Kernel: "6.10.0-here", Libc: "glibc 2.40", Backend: "fake"}
	bare := templateArtifact(t, reg, artifact.Platform{Arch: "arm64", Kernel: "5.4.0-elsewhere", Libc: "musl"}, false, artifact.LinkDynamic)
	static := templateArtifact(t, reg, artifact.Platform{Arch: "arm64", Kernel: "5.4.0-elsewhere", Libc: "musl"}, false, artifact.LinkStatic)
	unknown := templateArtifact(t, reg, artifact.Platform{Arch: "arm64", Kernel: "5.4.0-elsewhere", Libc: "musl"}, false, "")
	foreign := templateArtifact(t, reg, artifact.Platform{Arch: "amd64", Kernel: "6.10.0-here", Libc: "glibc 2.40"}, false, artifact.LinkDynamic)
	imaged := templateArtifact(t, reg, host, true, artifact.LinkDynamic)
	imagedElsewhere := templateArtifact(t, reg, artifact.Platform{Arch: "arm64", Kernel: "6.9.0-elsewhere", Libc: "glibc 2.40"}, true, artifact.LinkDynamic)
	cache := t.TempDir()
	// r makes parents for deltas, so it opens author images with the
	// fleet's master.
	r := &Runtime{cfg: Config{Registry: reg + "/tmpl/x", TemplateCache: cache, Templates: map[string]string{"sha256:local": "/zyg/local --x"},
		DeltaKeys: artifact.Keys{Seal: templateMaster}}, host: host, be: newCodecBackend(core.TierCheckpoint), tier: core.TierCheckpoint}
	cacheDir := func(digest string) string { return filepath.Join(cache, strings.TrimPrefix(digest, "sha256:")) }
	steps := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"an entry in the templates map is never pulled", func(t *testing.T) {
			tpl, err := r.resolveTemplate(ctx, "sha256:local")
			if err != nil || strings.Join(tpl.Argv, " ") != "/zyg/local --x" || tpl.Dir != "" || tpl.ImagesDir != "" {
				t.Fatalf("resolveTemplate = %+v %v", tpl, err)
			}
		}},
		{"a bare template is pulled and needs only the architecture to match", func(t *testing.T) {
			tpl, err := r.resolveTemplate(ctx, bare)
			if err != nil {
				t.Fatalf("resolveTemplate: %v", err)
			}
			dir := cacheDir(bare)
			if strings.Join(tpl.Argv, " ") != artifact.ZygotePath(dir)+" --heap 8" || tpl.Digest != bare || tpl.Dir != dir || tpl.ImagesDir != "" {
				t.Fatalf("template = %+v", tpl)
			}
			if sum, _ := artifact.ReadConfig(dir); tpl.ZygoteSHA256 != sum.ZygoteSHA256 || len(tpl.ZygoteSHA256) != 64 {
				t.Fatalf("template hash = %q, want the verified executable's %q", tpl.ZygoteSHA256, sum.ZygoteSHA256)
			}
			if st, err := os.Stat(artifact.ZygotePath(dir)); err != nil || st.Mode().Perm() != 0o755 {
				t.Fatalf("pulled zygote: %v %v", st, err)
			}
			if d, err := artifact.ReadDigest(dir); err != nil || d != bare {
				t.Fatalf("recorded digest = %s %v", d, err)
			}
		}},
		{"a cached template rewritten on disk is pulled again", func(t *testing.T) {
			zygote := artifact.ZygotePath(cacheDir(bare))
			orig, err := os.ReadFile(zygote)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(zygote, []byte("#!/bin/sh\nrm -rf /\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			if _, err := r.resolveTemplate(ctx, bare); err != nil {
				t.Fatalf("resolveTemplate: %v", err)
			}
			if got, _ := os.ReadFile(zygote); string(got) != string(orig) {
				t.Fatalf("the cache still runs the rewritten zygote: %q", got)
			}
			// Intact, it is verified and kept.
			if _, err := r.resolveTemplate(ctx, bare); err != nil {
				t.Fatalf("resolveTemplate: %v", err)
			}
		}},
		{"another architecture is refused", func(t *testing.T) {
			if _, err := r.resolveTemplate(ctx, foreign); !errors.Is(err, ErrParity) || !strings.Contains(err.Error(), "arch amd64") {
				t.Fatalf("resolveTemplate = %v, want ErrParity on the architecture", err)
			}
		}},
		{"a template with images needs this kernel and libc", func(t *testing.T) {
			tpl, err := r.resolveTemplate(ctx, imaged)
			if err != nil || tpl.ImagesDir != artifact.ImagesDir(cacheDir(imaged)) {
				t.Fatalf("resolveTemplate = %+v %v", tpl, err)
			}
			if got, _ := os.ReadFile(filepath.Join(tpl.ImagesDir, fakePagesFile)); string(got) != "artifact pages" {
				t.Fatalf("images = %q", got)
			}
			if _, err := r.resolveTemplate(ctx, imagedElsewhere); !errors.Is(err, ErrParity) || !strings.Contains(err.Error(), "kernel 6.9.0-elsewhere") {
				t.Fatalf("resolveTemplate = %v, want ErrParity on the kernel", err)
			}
			relaxed := &Runtime{cfg: r.cfg, host: r.host, be: r.be, tier: r.tier}
			relaxed.cfg.Parity = artifact.Parity{Kernel: artifact.ParityOff, Libc: artifact.ParityOff}
			if _, err := relaxed.resolveTemplate(ctx, imagedElsewhere); err != nil {
				t.Fatalf("resolveTemplate with parity off = %v", err)
			}
		}},
		// Author images are sealed to the fleet. Regression: they were
		// unpacked in the clear, 0755 and 0644, from a plain tar.
		{"sealed images are opened with the master and unpacked owner-only, or not at all", func(t *testing.T) {
			other := &artifact.SealKey{ID: "other", Key: []byte("fedcba9876543210fedcba9876543210")}
			cases := []struct {
				name     string
				rt       func() *Runtime
				wantErr  string // "" opens
				unpacked bool
			}{
				{name: "a home with the master", rt: func() *Runtime { return r }, unpacked: true},
				{name: "a home without a seal key says which flag it needs", wantErr: "-delta-seal-key", rt: func() *Runtime {
					c := r.cfg
					c.DeltaKeys = artifact.Keys{}
					return &Runtime{cfg: c, host: r.host, be: r.be, tier: r.tier}
				}},
				{name: "a home with another master", wantErr: "this home derives", rt: func() *Runtime {
					c := r.cfg
					c.DeltaKeys = artifact.Keys{Seal: other}
					return &Runtime{cfg: c, host: r.host, be: r.be, tier: r.tier}
				}},
				{name: "a home that makes no parents leaves them sealed and needs no key", rt: func() *Runtime {
					c := r.cfg
					c.DeltaKeys = artifact.Keys{}
					return &Runtime{cfg: c, host: r.host, tier: core.TierSnapshot}
				}},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					_ = os.RemoveAll(artifact.ImagesDir(cacheDir(imaged)))
					tpl, err := tc.rt().resolveTemplate(ctx, imaged)
					if tc.wantErr != "" {
						if !errors.Is(err, ErrNoTemplate) || !strings.Contains(err.Error(), tc.wantErr) {
							t.Fatalf("resolveTemplate = %v, want ErrNoTemplate saying %q", err, tc.wantErr)
						}
					} else if err != nil {
						t.Fatalf("resolveTemplate = %v", err)
					}
					images := artifact.ImagesDir(cacheDir(imaged))
					if (tpl.ImagesDir != "") != tc.unpacked || exists(images) != tc.unpacked {
						t.Fatalf("template images %q, unpacked %v; want unpacked %v", tpl.ImagesDir, exists(images), tc.unpacked)
					}
					if !tc.unpacked {
						return
					}
					for path, want := range map[string]os.FileMode{images: 0o700, filepath.Join(images, fakePagesFile): 0o600} {
						if st, err := os.Stat(path); err != nil || st.Mode().Perm() != want {
							t.Fatalf("%s: %v %v, want %v", path, st.Mode(), err, want)
						}
					}
					if exists(filepath.Join(cacheDir(imaged), "images.tar.open")) {
						t.Fatal("the opened tar was left in the cache")
					}
				})
			}
		}},
		{"a backend with a root filesystem of its own takes only static bare templates", func(t *testing.T) {
			// The sandbox loads the executable against its rootfs's
			// libraries, which the home cannot inspect. Static needs
			// none. Dynamic, or a config that does not say, is refused
			// unless libc parity is off. Nothing changes for a backend
			// that runs templates on the host.
			sandboxed := &Runtime{cfg: r.cfg, host: artifact.Platform{Arch: "arm64", Kernel: "gvisor-20260817.0", Libc: "rootfs-rootfs", Backend: "gvisor"}, ownRootfs: true}
			relaxed := &Runtime{cfg: sandboxed.cfg, host: sandboxed.host, ownRootfs: true}
			relaxed.cfg.Parity = artifact.Parity{Libc: artifact.ParityOff}
			cases := []struct {
				name    string
				rt      *Runtime
				digest  string
				refused bool
			}{
				{name: "static on a sandboxed backend", rt: sandboxed, digest: static},
				{name: "dynamic on a sandboxed backend", rt: sandboxed, digest: bare, refused: true},
				{name: "unknown linking on a sandboxed backend", rt: sandboxed, digest: unknown, refused: true},
				{name: "dynamic with libc parity off", rt: relaxed, digest: bare},
				{name: "dynamic on the host's own libc", rt: r, digest: bare},
				{name: "unknown linking on the host's own libc", rt: r, digest: unknown},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					_, err := tc.rt.resolveTemplate(ctx, tc.digest)
					if tc.refused {
						if !errors.Is(err, ErrParity) || !strings.Contains(err.Error(), "not a static executable") || !strings.Contains(err.Error(), "gvisor") || !strings.Contains(err.Error(), "-parity libc=off") {
							t.Fatalf("resolveTemplate = %v, want ErrParity naming the linking, the backend and the way out", err)
						}
						return
					}
					if err != nil {
						t.Fatalf("resolveTemplate = %v", err)
					}
				})
			}
		}},
		{"a digest the registry lacks leaves no cache entry", func(t *testing.T) {
			missing := "sha256:" + strings.Repeat("9", 64)
			if _, err := r.resolveTemplate(ctx, missing); !errors.Is(err, ErrNoTemplate) {
				t.Fatalf("resolveTemplate = %v, want ErrNoTemplate", err)
			}
			if exists(cacheDir(missing)) {
				t.Fatal("a failed pull left its directory")
			}
		}},
		{"a warm from an artifact with images takes them as the delta parent", func(t *testing.T) {
			cb := newCodecBackend(core.TierCheckpoint)
			rt := newTestRuntime(t, cb, func(c *Config) {
				c.Templates, c.Registry = nil, reg+"/tmpl/x"
				c.Platform = artifact.Platform{Arch: host.Arch, Kernel: host.Kernel, Libc: host.Libc}
				c.DeltaKeys.Seal = templateMaster
			})
			g := core.Grant{UID: "g1", TemplateDigest: imaged, WBudgetBytes: 64 << 20}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatalf("PrepareTemplate: %v", err)
			}
			sha := shaOf("artifact pages")
			if z := rt.warmOf("g1"); z.parentSHA != sha || cb.calls.Load() != 0 {
				t.Fatalf("parent = %q, %d self-checkpoints; want the artifact's images and none", z.parentSHA, cb.calls.Load())
			}
			if st, err := os.Lstat(filepath.Join(rt.parentsDir(), sha)); err != nil || st.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("store entry = %v %v, want a link to the images", st, err)
			}
			spec, _ := cb.warmSpec("g1")
			if spec.Template.ImagesDir == "" || spec.Template.Argv[0] != artifact.ZygotePath(spec.Template.Dir) {
				t.Fatalf("warm spec template = %+v", spec.Template)
			}
		}},
		{"images the codec cannot read leave the warm instance without a parent", func(t *testing.T) {
			cb := newCodecBackend(core.TierCheckpoint)
			cb.failLoadAt = 1
			rt := newTestRuntime(t, cb, func(c *Config) {
				c.Templates, c.Registry = nil, reg+"/tmpl/x"
				c.Platform = artifact.Platform{Arch: host.Arch, Kernel: host.Kernel, Libc: host.Libc}
				c.DeltaKeys.Seal = templateMaster
			})
			g := core.Grant{UID: "g1", TemplateDigest: imaged, WBudgetBytes: 64 << 20}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatalf("PrepareTemplate: %v", err)
			}
			if z := rt.warmOf("g1"); z == nil || z.parentSHA != "" {
				t.Fatalf("warm = %+v, want one without a parent", z)
			}
			if entries, _ := os.ReadDir(rt.parentsDir()); len(entries) != 0 {
				t.Fatalf("the store holds %v after a refused parent", entries)
			}
		}},
	}
	for _, st := range steps {
		if !t.Run(st.name, st.run) {
			return
		}
	}
}

// TestPruneAuthorImages checks the life of an artifact's unpacked images
// in the template cache. They go with the last warm that names them and
// a later resolve unpacks them again (regression: the prune took the
// store link and left the images in the clear for good). Two grants of
// one template share them, and the first's drop leaves what the second
// uses. A resolve in flight keeps them through a prune until its warm
// names them. Images a warm never came to name go at the next prune.
func TestPruneAuthorImages(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	host := artifact.Platform{Arch: "arm64", Kernel: "6.10.0-here", Libc: "glibc 2.40", Backend: "fake"}
	imaged := templateArtifact(t, srv.URL, host, true, artifact.LinkDynamic)
	sha := shaOf("artifact pages")
	grant := func(uid string) core.Grant {
		return core.Grant{UID: uid, TemplateDigest: imaged, WBudgetBytes: 64 << 20}
	}
	home := func(t *testing.T, cb *codecBackend) (*Runtime, string, string) {
		rt := newTestRuntime(t, cb, func(c *Config) {
			c.Templates, c.Registry = nil, srv.URL+"/tmpl/x"
			c.Platform = artifact.Platform{Arch: host.Arch, Kernel: host.Kernel, Libc: host.Libc}
			c.DeltaKeys.Seal = templateMaster
		})
		images := artifact.ImagesDir(filepath.Join(rt.cfg.TemplateCache, strings.TrimPrefix(imaged, "sha256:")))
		return rt, images, filepath.Join(rt.parentsDir(), sha)
	}
	cases := []struct {
		name     string
		failLoad bool // the codec cannot read the images, so no warm names them
		run      func(t *testing.T, rt *Runtime, images, link string)
	}{
		{name: "the images go with the last warm that names them, and a resolve unpacks them again", run: func(t *testing.T, rt *Runtime, images, link string) {
			if err := rt.PrepareTemplate(ctx, grant("g1")); err != nil {
				t.Fatalf("PrepareTemplate: %v", err)
			}
			pruned(t, rt)
			if !exists(images) || !exists(link) {
				t.Fatalf("images %v, link %v after a prune with the warm up; want both", exists(images), exists(link))
			}
			rt.DropTemplate("g1")
			waitFor(t, "the images and their link to go", func() bool { return !exists(images) && !exists(link) })
			if err := rt.PrepareTemplate(ctx, grant("g1")); err != nil {
				t.Fatalf("PrepareTemplate again: %v", err)
			}
			if z := rt.warmOf("g1"); z == nil || z.parentSHA != sha || !exists(images) || !exists(link) {
				t.Fatalf("after the second warm: parent %q, images %v, link %v", z.parentSHA, exists(images), exists(link))
			}
			if got, _ := os.ReadFile(filepath.Join(images, fakePagesFile)); string(got) != "artifact pages" {
				t.Fatalf("images = %q", got)
			}
		}},
		{name: "two grants of one template: the first's drop leaves what the second uses", run: func(t *testing.T, rt *Runtime, images, link string) {
			for _, uid := range []string{"g1", "g2"} {
				if err := rt.PrepareTemplate(ctx, grant(uid)); err != nil {
					t.Fatalf("PrepareTemplate %s: %v", uid, err)
				}
			}
			rt.DropTemplate("g1")
			pruned(t, rt)
			if !exists(images) || !exists(link) {
				t.Fatalf("images %v, link %v after the first drop; want both for the second warm", exists(images), exists(link))
			}
			if p, err := rt.parent(sha); err != nil || p.SHA256() != sha {
				t.Fatalf("the second warm's parent = %v %v", p, err)
			}
			rt.DropTemplate("g2")
			waitFor(t, "the images to go with the second warm", func() bool { return !exists(images) && !exists(link) })
		}},
		{name: "a resolve in flight keeps its images through a prune until its warm names them", run: func(t *testing.T, rt *Runtime, images, _ string) {
			tpl, err := rt.resolveTemplate(ctx, imaged)
			if err != nil || tpl.ImagesDir != images {
				t.Fatalf("resolveTemplate = %+v %v", tpl, err)
			}
			pruned(t, rt)
			if !exists(images) {
				t.Fatal("a prune took the images of a warm in the making")
			}
			rt.releaseImages(images)
			pruned(t, rt)
			if exists(images) {
				t.Fatal("the images stayed after the warm in the making let them go")
			}
		}},
		{name: "images a warm never came to name go at the next prune", failLoad: true, run: func(t *testing.T, rt *Runtime, images, link string) {
			if err := rt.PrepareTemplate(ctx, grant("g1")); err != nil {
				t.Fatalf("PrepareTemplate: %v", err)
			}
			if z := rt.warmOf("g1"); z == nil || z.parentSHA != "" {
				t.Fatalf("warm = %+v, want one without a parent", z)
			}
			waitFor(t, "the images nothing names to go", func() bool { return !exists(images) && !exists(link) })
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cb := newCodecBackend(core.TierCheckpoint)
			if tc.failLoad {
				cb.failLoadAt = 1
			}
			rt, images, link := home(t, cb)
			tc.run(t, rt, images, link)
		})
	}
}
