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
			r := &Runtime{cfg: Config{Registry: "127.0.0.1:1/tmpl", RegistryPlainHTTP: true, TemplateCache: cache}}
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

// templateArtifact writes a zygote artifact directory by hand (an
// executable, its config, images when asked) and pushes it to reg,
// returning its digest. linking is what the config says about the
// executable ("" for a config from before the fact was recorded).
func templateArtifact(t *testing.T, reg string, p artifact.Platform, images bool, linking string) string {
	t.Helper()
	dir := t.TempDir()
	zygote := []byte("#!/bin/sh\nexit 0\n" + linking)
	sum := sha256.Sum256(zygote)
	if err := os.WriteFile(artifact.ZygotePath(dir), zygote, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := map[string]any{"args": []string{"--heap", "8"}, "arch": p.Arch, "kernel": p.Kernel, "libc": p.Libc,
		"zygote_sha256": hex.EncodeToString(sum[:]), "has_images": images, "built_at": "2026-10-01T00:00:00Z", "linking": linking}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if images {
		if err := writeParentDir(artifact.ImagesDir(dir), "artifact pages"); err != nil {
			t.Fatal(err)
		}
		if err := artifact.TarDir(artifact.ImagesDir(dir), filepath.Join(dir, "images.tar")); err != nil {
			t.Fatal(err)
		}
	}
	digest, err := artifact.Push(context.Background(), dir, reg+"/tmpl/x:"+fmt.Sprintf("%v-%s-%s", images, p.Kernel, linking), true)
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
	reg := strings.TrimPrefix(srv.URL, "http://")
	host := artifact.Platform{Arch: "arm64", Kernel: "6.10.0-here", Libc: "glibc 2.40", Backend: "fake"}
	bare := templateArtifact(t, reg, artifact.Platform{Arch: "arm64", Kernel: "5.4.0-elsewhere", Libc: "musl"}, false, artifact.LinkDynamic)
	static := templateArtifact(t, reg, artifact.Platform{Arch: "arm64", Kernel: "5.4.0-elsewhere", Libc: "musl"}, false, artifact.LinkStatic)
	unknown := templateArtifact(t, reg, artifact.Platform{Arch: "arm64", Kernel: "5.4.0-elsewhere", Libc: "musl"}, false, "")
	foreign := templateArtifact(t, reg, artifact.Platform{Arch: "amd64", Kernel: "6.10.0-here", Libc: "glibc 2.40"}, false, artifact.LinkDynamic)
	imaged := templateArtifact(t, reg, host, true, artifact.LinkDynamic)
	imagedElsewhere := templateArtifact(t, reg, artifact.Platform{Arch: "arm64", Kernel: "6.9.0-elsewhere", Libc: "glibc 2.40"}, true, artifact.LinkDynamic)
	cache := t.TempDir()
	r := &Runtime{cfg: Config{Registry: reg + "/tmpl/x", RegistryPlainHTTP: true, TemplateCache: cache, Templates: map[string]string{"sha256:local": "/zyg/local --x"}}, host: host}
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
			relaxed := &Runtime{cfg: r.cfg, host: r.host}
			relaxed.cfg.Parity = artifact.Parity{Kernel: artifact.ParityOff, Libc: artifact.ParityOff}
			if _, err := relaxed.resolveTemplate(ctx, imagedElsewhere); err != nil {
				t.Fatalf("resolveTemplate with parity off = %v", err)
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
				c.Templates, c.Registry, c.RegistryPlainHTTP = nil, reg+"/tmpl/x", true
				c.Platform = artifact.Platform{Arch: host.Arch, Kernel: host.Kernel, Libc: host.Libc}
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
				c.Templates, c.Registry, c.RegistryPlainHTTP = nil, reg+"/tmpl/x", true
				c.Platform = artifact.Platform{Arch: host.Arch, Kernel: host.Kernel, Libc: host.Libc}
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
