//go:build linux

package gvisor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
)

// fileSHA256 is the hex SHA-256 of a file.
func fileSHA256(p string) (string, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// artifactDir writes a pulled template cache entry as the host leaves
// it: the executable, its config, its digest and unpacked images. Only
// the executable may ever reach a sandbox.
func artifactDir(t *testing.T, executable []byte) (dir, sha string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "cache", strings.Repeat("ab", 32))
	if err := os.MkdirAll(filepath.Join(dir, "images"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"config.json": `{"args":[]}`, "DIGEST": "sha256:abab\n", "manifest.json": "{}", "images/pages-1.img": "pages"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "zygote"), executable, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(executable)
	return dir, hex.EncodeToString(sum[:])
}

// registryTemplate is what the host hands Warm for a pulled artifact.
func registryTemplate(dir, sha string) backend.Template {
	return backend.Template{Digest: "sha256:" + strings.Repeat("ab", 32), Argv: []string{filepath.Join(dir, "zygote"), "--heap-mb", "8", "--gvisor"},
		Dir: dir, ZygoteSHA256: sha}
}

// templateMountOf returns the source of the template mount in a bundle,
// or "" when the bundle has none.
func templateMountOf(t *testing.T, bundle string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(bundle, "config.json"))
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	var s spec
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	for _, m := range s.Mounts {
		if m.Destination == backend.TemplateMount {
			if m.Type != "bind" || strings.Join(m.Options, ",") != strings.Join(backend.TemplateMountOptions, ",") {
				t.Fatalf("template mount = %+v, want a bind with %v", m, backend.TemplateMountOptions)
			}
			return m.Source
		}
	}
	return ""
}

// TestStageTemplate checks that a registry template is bound from the
// backend's own verified copy of its executable alone, that the copy is
// checked against the host's hash before anything binds it, and that the
// executable must be a file directly in the artifact directory.
func TestStageTemplate(t *testing.T) {
	cases := []struct {
		name     string
		template func(t *testing.T, dir, sha string) backend.Template
		wantText string // in Warm's error, "" for success
	}{
		{name: "verified copy, bound read-only", template: func(_ *testing.T, dir, sha string) backend.Template {
			return registryTemplate(dir, sha)
		}},
		{name: "hash the host did not verify", template: func(_ *testing.T, dir, _ string) backend.Template {
			return registryTemplate(dir, strings.Repeat("0", 64))
		}, wantText: "staged executable hashes to"},
		{name: "no hash at all", template: func(_ *testing.T, dir, _ string) backend.Template {
			return registryTemplate(dir, "")
		}, wantText: "without a verified executable hash"},
		{name: "executable outside the artifact directory", template: func(t *testing.T, dir, sha string) backend.Template {
			tpl := registryTemplate(dir, sha)
			tpl.Argv[0] = filepath.Join(t.TempDir(), "zygote")
			return tpl
		}, wantText: "not a file directly in the artifact directory"},
		{name: "executable in a subdirectory", template: func(_ *testing.T, dir, sha string) backend.Template {
			tpl := registryTemplate(dir, sha)
			tpl.Argv[0] = filepath.Join(dir, "images", "zygote")
			return tpl
		}, wantText: "not a file directly in the artifact directory"},
		{name: "the artifact directory itself", template: func(_ *testing.T, dir, sha string) backend.Template {
			tpl := registryTemplate(dir, sha)
			tpl.Argv[0] = dir
			return tpl
		}, wantText: "not a file directly in the artifact directory"},
		{name: "executable missing", template: func(_ *testing.T, dir, sha string) backend.Template {
			tpl := registryTemplate(dir, sha)
			tpl.Argv[0] = filepath.Join(dir, "gone")
			return tpl
		}, wantText: "stage template"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, f := newFake(t, knobs{})
			dir, sha := artifactDir(t, []byte("#!/bin/sh\nexec sleep 600\n"))
			tpl := tc.template(t, dir, sha)
			workDir := filepath.Join(t.TempDir(), "g")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			w, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "g", Template: tpl, CgroupFD: -1, ProbeCgroupFD: -1, WorkDir: workDir})
			if tc.wantText != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantText) {
					t.Fatalf("Warm = %v, want %q", err, tc.wantText)
				}
				if findCall(f.calls(), "run") != "" {
					t.Fatal("a refused template started a sandbox")
				}
				if ents, _ := os.ReadDir(filepath.Join(b.opt.StateDir, "templates")); len(ents) != 0 {
					t.Fatalf("a refused template left %v behind", ents)
				}
				return
			}
			if err != nil {
				t.Fatalf("Warm: %v", err)
			}
			tdir := filepath.Join(b.opt.StateDir, "templates", warmCID(t, b, "g"))
			staged := filepath.Join(tdir, "template")
			b.mu.Lock()
			got := b.warms[w.ID]
			b.mu.Unlock()
			if got.template != staged || strings.Join(got.argv, " ") != "/fiberd/template/zygote --heap-mb 8 --gvisor" {
				t.Fatalf("warm template = %q argv = %q, want the staged copy and the in-sandbox path", got.template, got.argv)
			}
			// The copy is the executable alone, read-only, byte for byte.
			entries, err := os.ReadDir(staged)
			if err != nil || len(entries) != 1 || entries[0].Name() != "zygote" {
				t.Fatalf("staged directory holds %v (%v), want zygote alone", entries, err)
			}
			st, err := os.Stat(filepath.Join(staged, "zygote"))
			if err != nil || st.Mode().Perm() != 0o555 {
				t.Fatalf("staged copy mode = %v (%v), want 0555", st.Mode(), err)
			}
			if sum, _ := fileSHA256(filepath.Join(staged, "zygote")); sum != sha {
				t.Fatalf("staged copy hashes to %s, want %s", sum, sha)
			}
			// Every bundle of the instance binds it at the fixed path.
			if src := templateMountOf(t, filepath.Join(tdir, "bundle")); src != staged {
				t.Fatalf("template bundle binds %q, want %q", src, staged)
			}
			fb, err := b.Clone(ctx, w.ID, backend.FiberSpec{Fence: "g/1-1", Endpoint: filepath.Join(workDir, "ep.sock"), CgroupFD: -1, Deadline: 2 * time.Second})
			if err != nil {
				t.Fatalf("Clone: %v", err)
			}
			if src := templateMountOf(t, b.bundleDir(boxCID(t, b, fb.ID))); src != staged {
				t.Fatalf("fiber bundle binds %q, want %q", src, staged)
			}
			// The cache is not what is bound: rewriting it after the warm
			// changes nothing a sandbox sees.
			if err := os.WriteFile(filepath.Join(dir, "zygote"), []byte("#!/bin/sh\nrm -rf /\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			if sum, _ := fileSHA256(filepath.Join(staged, "zygote")); sum != sha {
				t.Fatalf("a cache rewrite reached the staged copy: %s", sum)
			}
		})
	}
}

// TestResumeTemplateMount checks that a park taken with a registry template
// resumes on a home whose copy lives at another path, bound at the same
// sandbox path, and that a park and a home that disagree about having a
// template are refused by name rather than failing inside runsc.
func TestResumeTemplateMount(t *testing.T) {
	cases := []struct {
		name         string
		parkRegistry bool // the parking home warmed a registry template
		homeRegistry bool // the resuming home did
		noWarm       bool // the resuming home has no warm instance for the grant
		wantText     string
	}{
		{name: "registry template on both, copies at different paths", parkRegistry: true, homeRegistry: true},
		{name: "baked template on both", parkRegistry: false, homeRegistry: false},
		{name: "park with a template, home without", parkRegistry: true, homeRegistry: false, wantText: "does not have here"},
		{name: "park without a template, home with", parkRegistry: false, homeRegistry: true, wantText: "binds here"},
		{name: "park with a template, home not warm", parkRegistry: true, noWarm: true, wantText: "does not have here"},
	}
	executable := []byte("#!/bin/sh\nexec sleep 600\n")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			warmOn := func(b *Backend, registry bool) (backend.Warm, string) {
				t.Helper()
				tpl := backend.Template{Argv: []string{"/bin/refzygote", "--gvisor"}}
				if registry {
					dir, sha := artifactDir(t, executable)
					tpl = registryTemplate(dir, sha)
				}
				workDir := filepath.Join(t.TempDir(), "g")
				w, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "g", Template: tpl, CgroupFD: -1, ProbeCgroupFD: -1, WorkDir: workDir})
				if err != nil {
					t.Fatalf("Warm: %v", err)
				}
				return w, workDir
			}
			a, _ := newFake(t, knobs{})
			wa, workA := warmOn(a, tc.parkRegistry)
			if _, err := a.Clone(ctx, wa.ID, backend.FiberSpec{Fence: "g/1-1", Endpoint: filepath.Join(workA, "ep.sock"), CgroupFD: -1, Deadline: 2 * time.Second}); err != nil {
				t.Fatalf("Clone: %v", err)
			}
			park := filepath.Join(t.TempDir(), "park")
			if err := a.Park(ctx, "g/1-1", backend.ParkSpec{Dir: park}); err != nil {
				t.Fatalf("Park: %v", err)
			}
			waitExit(t, a)
			parkedSrc := templateMountOf(t, park)
			if (parkedSrc != "") != tc.parkRegistry {
				t.Fatalf("parked bundle template mount = %q, registry %v", parkedSrc, tc.parkRegistry)
			}

			// Another home: its own state directory, cache and run directory.
			h, _ := newFake(t, knobs{})
			workH := filepath.Join(t.TempDir(), "g")
			staged := ""
			if !tc.noWarm {
				wh, w := warmOn(h, tc.homeRegistry)
				workH = w
				h.mu.Lock()
				staged = h.warms[wh.ID].template
				h.mu.Unlock()
			}
			ep := filepath.Join(workH, "ep2.sock")
			f, err := h.Resume(ctx, backend.ResumeSpec{Dir: park, Fence: "g/2-1", Endpoint: ep, CgroupFD: -1, Deadline: 2 * time.Second, WarmID: "g", WorkDir: workH})
			if tc.wantText != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantText) {
					t.Fatalf("Resume = %v, want %q", err, tc.wantText)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resume: %v", err)
			}
			bundle := h.bundleDir(boxCID(t, h, f.ID))
			if src := templateMountOf(t, bundle); src != staged {
				t.Fatalf("resumed bundle binds %q, want this home's copy %q", src, staged)
			}
			if tc.homeRegistry && (staged == parkedSrc || !strings.HasPrefix(staged, h.opt.StateDir)) {
				t.Fatalf("resuming home's copy %q should be its own, not the parking home's %q", staged, parkedSrc)
			}
			data, _ := os.ReadFile(filepath.Join(bundle, "config.json"))
			wantArgs := `"/bin/refzygote"`
			if tc.parkRegistry {
				wantArgs = `"/fiberd/template/zygote"`
			}
			if !strings.Contains(string(data), wantArgs) {
				t.Fatalf("resumed bundle args do not name %s:\n%s", wantArgs, data)
			}
		})
	}
}
