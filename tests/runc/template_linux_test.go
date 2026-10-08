//go:build linux

package runctest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/registry"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/backend"
	runcbackend "github.com/helayoty/fiberd/pkg/backend/runc"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/runtime/host"
)

// pushTemplate builds a bare artifact (no CRIU images) from the static
// refzygote in the rootfs and pushes it to a registry that lives as long
// as the test. It returns the repository the home pulls from and the
// digest a grant names.
func pushTemplate(t *testing.T) (repo, digest string) {
	t.Helper()
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "art")
	digest, err := artifact.Build(ctx, artifact.BuildOptions{Zygote: filepath.Join(rootfs, "bin", "refzygote"), Args: []string{"--heap-mb", "32"}, Out: out, SkipImages: true})
	if err != nil {
		t.Fatalf("build artifact: %v", err)
	}
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	repo = strings.TrimPrefix(srv.URL, "http://") + "/zygotes/ref"
	if _, err := artifact.Push(ctx, out, repo+":v1", true); err != nil {
		t.Fatalf("push artifact: %v", err)
	}
	return repo, digest
}

// registryHome is a runc home that resolves templates from repo, with a
// template cache of its own under its state directory unless mod says
// otherwise.
func registryHome(t *testing.T, repo string, mod func(*host.Config)) *home {
	t.Helper()
	return newHome(t, func(ro *runcbackend.Options, cfg *host.Config) {
		cfg.Templates = nil
		cfg.Registry, cfg.RegistryPlainHTTP = repo, true
		cfg.TemplateCache = filepath.Join(ro.StateDir, "cache")
		if mod != nil {
			mod(cfg)
		}
	})
}

// stagedCopy is where a home's runc launcher keeps the verified copy of
// grant g's template executable, the directory every container binds.
func stagedCopy(h *home, grant string) string {
	return filepath.Join(h.stateDir, "templates", "w-"+grant, "template", "zygote")
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// TestRegistryTemplate is a registry template on runc: the home pulls the
// artifact, the launcher binds a verified copy of its executable into the
// grant's container read-only at /fiberd/template, the mapped root runs
// it, and the container sees that one file and nothing of the host's
// cache. The copy is what runs even when the cache is rewritten, a
// rewritten cache entry is pulled again before another home stages it,
// a park resumes on a home whose cache and state live elsewhere, and a
// home that has not warmed the grant refuses the park by name.
func TestRegistryTemplate(t *testing.T) {
	ctx := context.Background()
	repo, digest := pushTemplate(t)
	a := registryHome(t, repo, nil)
	cacheA := filepath.Join(a.stateDir, "cache", strings.TrimPrefix(digest, "sha256:"))
	g := core.Grant{UID: "rt1", TemplateDigest: digest, FiberMax: 4, WBudgetBytes: 64 << 20}
	var h core.FiberHandle
	var zygoteSum string
	// view checks what a fiber at ep sees of the template and the host.
	view := func(t *testing.T, ep string) {
		t.Helper()
		cases := []struct{ probe, want string }{
			{"stat " + backend.TemplateMount, "dir"},
			{"stat " + backend.TemplateMount + "/zygote", "file"},
			{"stat " + backend.TemplateMount + "/config.json", "ENOENT"},
			{"stat " + cacheA, "ENOENT"},
			{"stat " + filepath.Dir(cacheA), "ENOENT"},
		}
		for _, tc := range cases {
			if got := talk(t, ep, tc.probe); got != tc.want {
				t.Fatalf("%s = %q, want %q", tc.probe, got, tc.want)
			}
		}
		// The bind is read-only, and the copy and its directory are an
		// unmapped owner's with the other bits alone, so neither the ro
		// flag nor a lifted one lets the fiber write.
		for _, probe := range []string{"wopen " + backend.TemplateMount + "/zygote", "mkdir " + backend.TemplateMount + "/x"} {
			if got := talk(t, ep, probe); got == "ok" {
				t.Fatalf("%s = ok, want a refusal", probe)
			}
		}
		// A runc fiber keeps the container's capabilities inside its
		// user namespace and the mounts runc made there are not locked,
		// so it can lift the read-only flag of the bind. The copy stays
		// unwritable all the same, by ownership: an unmapped owner with
		// the other bits alone. That is the guard the test pins.
		t.Logf("remount %s = %s", backend.TemplateMount, talk(t, ep, "remount "+backend.TemplateMount))
		for _, probe := range []string{"wopen " + backend.TemplateMount + "/zygote", "mkdir " + backend.TemplateMount + "/x"} {
			if got := talk(t, ep, probe); got == "ok" {
				t.Fatalf("%s = ok after a remount attempt, want a refusal", probe)
			}
		}
	}
	steps := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"the home pulls the template and binds a verified copy the mapped root runs", func(t *testing.T) {
			t0 := time.Now()
			if err := a.rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatalf("prepare: %v", err)
			}
			t.Logf("template pulled, staged and warm in %s", time.Since(t0).Round(time.Millisecond))
			cfg, err := artifact.ReadConfig(cacheA)
			if err != nil || cfg.Linking != artifact.LinkStatic {
				t.Fatalf("cached config = %+v (%v), want a static template", cfg, err)
			}
			zygoteSum = cfg.ZygoteSHA256
			if sum := sha256File(t, stagedCopy(a, "rt1")); sum != zygoteSum {
				t.Fatalf("staged copy hashes to %s, want the artifact's %s", sum, zygoteSum)
			}
			if st, err := os.Stat(stagedCopy(a, "rt1")); err != nil || st.Mode().Perm() != 0o555 {
				t.Fatalf("staged copy mode = %v (%v), want 0555", st.Mode(), err)
			}
			if h, err = a.rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "rt1", Epoch: 1, Seq: 1}, Deadline: 5 * time.Second}); err != nil {
				t.Fatalf("clone: %v", err)
			}
			if got := talk(t, h.Endpoint, "ping"); got != "pong" {
				t.Fatalf("ping = %q", got)
			}
			if got := talk(t, h.Endpoint, "read /proc/self/uid_map"); !strings.HasPrefix(fields(got), "0 ") || strings.HasPrefix(fields(got), "0 0 ") {
				t.Fatalf("uid_map = %q, want the mapped root", got)
			}
		}},
		{"the container sees the executable alone, read-only", func(t *testing.T) {
			view(t, h.Endpoint)
			if _, err := os.Stat(filepath.Join(filepath.Dir(stagedCopy(a, "rt1")), "x")); err == nil {
				t.Fatal("a write inside the container reached the host copy")
			}
		}},
		{"a rewritten cache does not reach running or new fibers", func(t *testing.T) {
			if err := os.WriteFile(artifact.ZygotePath(cacheA), []byte("#!/bin/sh\nexit 7\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			h2, err := a.rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "rt1", Epoch: 1, Seq: 2}, Deadline: 5 * time.Second})
			if err != nil {
				t.Fatalf("clone after the cache was rewritten: %v", err)
			}
			if got := talk(t, h2.Endpoint, "ping"); got != "pong" {
				t.Fatalf("ping = %q", got)
			}
			if sum := sha256File(t, stagedCopy(a, "rt1")); sum != zygoteSum {
				t.Fatalf("the rewrite reached the staged copy: %s", sum)
			}
			_ = a.rt.Release(ctx, h2.ID, false)
		}},
		{"another home pulls the rewritten entry again before it stages it", func(t *testing.T) {
			b := registryHome(t, repo, func(cfg *host.Config) { cfg.TemplateCache = filepath.Join(a.stateDir, "cache") })
			if err := b.rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatalf("prepare on the second home: %v", err)
			}
			if sum := sha256File(t, artifact.ZygotePath(cacheA)); sum != zygoteSum {
				t.Fatalf("cache entry hashes to %s after the second warm, want it pulled again to %s", sum, zygoteSum)
			}
			if sum := sha256File(t, stagedCopy(b, "rt1")); sum != zygoteSum {
				t.Fatalf("second home's copy hashes to %s, want %s", sum, zygoteSum)
			}
		}},
		{"a park resumes on a home with another cache and state path, and is refused where the grant is not warm", func(t *testing.T) {
			for i := 0; i < 3; i++ {
				talk(t, h.Endpoint, "incr")
			}
			ref, err := a.rt.Park(ctx, h.ID, true)
			if err != nil {
				t.Fatalf("park: %v", err)
			}
			// A home that never warmed the grant has neither the parent
			// checkpoint the delta names nor a staged copy to bind. The
			// host refuses on the first; the launcher's own refusal is
			// pinned in its unit test (TestRestoreExtra).
			cold := registryHome(t, repo, nil)
			_, err = cold.rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: "rt1", Epoch: 3, Seq: 1}, Deadline: 10 * time.Second})
			if err == nil {
				t.Fatal("resume on a home that never warmed the grant succeeded, want a refusal")
			}
			t.Logf("cold home refused the park: %v", err)
			c := registryHome(t, repo, nil)
			if err := c.rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatalf("prepare on the resuming home: %v", err)
			}
			// The park is a delta over A's zygote self-checkpoint, which
			// travels to another home through the delta registry as
			// p-<sha> (artifact.md). Here it is copied into C's parent
			// store by hand, since every home's zygote pages differ in
			// their stack and data pages. The template bind is C's own.
			copyParent(t, filepath.Join(a.stateDir, "cache", "parents"), filepath.Join(c.stateDir, "cache", "parents"), ref)
			t0 := time.Now()
			h3, err := c.rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: "rt1", Epoch: 2, Seq: 1}, Deadline: 10 * time.Second})
			if err != nil {
				t.Fatalf("resume on another home: %v", err)
			}
			t.Logf("resumed on a home with another cache path in %s", time.Since(t0).Round(time.Millisecond))
			if got := talk(t, h3.Endpoint, "get"); got != "3" {
				t.Fatalf("counter after the move = %q, want 3", got)
			}
			if c.stateDir == a.stateDir || sha256File(t, stagedCopy(c, "rt1")) != zygoteSum {
				t.Fatal("the resuming home must bind its own verified copy")
			}
			view(t, h3.Endpoint)
			_ = c.rt.Release(ctx, h3.ID, true)
		}},
	}
	for _, st := range steps {
		if !t.Run(st.name, st.run) {
			return
		}
	}
}

// TestBakedSpecUnchanged pins that a grant on a template from the rootfs
// gets the container spec it always had: four mounts and no template
// bind, and nothing staged.
func TestBakedSpecUnchanged(t *testing.T) {
	hm := newHome(t, nil)
	ctx := context.Background()
	g := core.Grant{UID: "baked", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20}
	if err := hm.rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(hm.stateDir, "bundles", "w-baked", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		want bool
		text string
	}{
		{name: "the run directory mount", want: true, text: `"destination": "/host"`},
		{name: "no template mount", want: false, text: backend.TemplateMount},
		{name: "the rootfs command", want: true, text: `"/bin/refzygote"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := strings.Contains(string(data), tc.text); got != tc.want {
				t.Fatalf("config.json contains %q: %v, want %v\n%s", tc.text, got, tc.want, data)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(hm.stateDir, "templates", "w-baked")); err == nil {
		t.Fatal("a rootfs template left a staged directory")
	}
}

// copyParent copies the parent checkpoint the delta at ref names from
// one home's parent store into another's, as a claim through the delta
// registry would.
func copyParent(t *testing.T, from, to, ref string) {
	t.Helper()
	var info struct {
		ParentSHA256 string `json:"parent_sha256"`
	}
	b, err := os.ReadFile(filepath.Join(ref, "delta.json"))
	if err != nil {
		t.Fatalf("delta info: %v", err)
	}
	if err := json.Unmarshal(b, &info); err != nil || info.ParentSHA256 == "" {
		t.Fatalf("delta info = %s (%v), want a parent", b, err)
	}
	src := filepath.Join(from, info.ParentSHA256)
	dst := filepath.Join(to, info.ParentSHA256)
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("parent %s: %v", src, err)
	}
	for _, e := range ents {
		data, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
