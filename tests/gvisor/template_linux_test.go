//go:build linux

package gvisortest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/registry"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/runtime/host"
)

// pushTemplate builds a bare artifact (no CRIU images: a gVisor template
// is restored from the sandbox checkpoint the backend takes) from the
// executable and pushes it to a registry that lives as long as the test.
// It returns the repository the home pulls from and the digest a grant
// names.
func pushTemplate(t *testing.T, executable string, args ...string) (repo, digest string) {
	t.Helper()
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "art")
	digest, err := artifact.Build(ctx, artifact.BuildOptions{Zygote: executable, Args: args, Out: out, SkipImages: true})
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

// registryHome is a runtime that resolves templates from repo, with
// its own template cache, state and run directory. mods apply last.
func registryHome(t *testing.T, repo string, mods ...func(*host.Config)) (core.Runtime, string) {
	t.Helper()
	var state string
	rt := newRuntimeWith(t, "", append([]func(*host.Config){func(cfg *host.Config) {
		cfg.Templates = nil
		cfg.Registry, cfg.RegistryPlainHTTP = repo, true
		state = filepath.Join(work, name)
		cfg.TemplateCache = filepath.Join(state, "cache")
	}}, mods...)...)
	return rt, state
}

// probe runs the static probe inside the one fiber sandbox of a home
// (runsc exec) and returns its one-line answer.
func probe(t *testing.T, state string, args ...string) string {
	t.Helper()
	root := filepath.Join(state, "root")
	out, err := exec.Command("runsc", "--root="+root, "list", "-quiet").Output()
	if err != nil {
		t.Fatalf("runsc list: %v", err)
	}
	var fibers []string
	for _, id := range strings.Fields(string(out)) {
		if strings.HasPrefix(id, "f-") {
			fibers = append(fibers, id)
		}
	}
	if len(fibers) != 1 {
		t.Fatalf("fiber sandboxes in %s = %v, want one", root, fibers)
	}
	cmd := exec.Command("runsc", append([]string{"--root=" + root, "exec", fibers[0], "/bin/probe"}, args...)...)
	res, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("runsc exec probe %v: %v: %s", args, err, res)
	}
	return strings.TrimSpace(string(res))
}

// stagedCopy is where a home's gvisor backend keeps the verified copy of
// grant g's template executable, the directory every sandbox binds. The
// directory is the template sandbox's own, named by its cid, and one
// instance of the grant is warm at a time.
func stagedCopy(t *testing.T, state, grant string) string {
	t.Helper()
	matches, _ := filepath.Glob(filepath.Join(state, "templates", "w-"+grant+"-*", "template", "zygote"))
	if len(matches) != 1 {
		t.Fatalf("staged copies of %s in %s = %v, want one", grant, state, matches)
	}
	return matches[0]
}

// TestRegistryTemplate is a registry template on gVisor: the home pulls
// the artifact, the backend binds a verified copy of its executable into
// every sandbox read-only at /fiberd/template, and the sandbox sees that
// one file and nothing else of the host. The copy is what runs even when
// the cache is rewritten, a rewritten cache entry is pulled again before
// another home binds it, and a park resumes on a home whose cache and
// state live elsewhere.
func TestRegistryTemplate(t *testing.T) {
	ctx := context.Background()
	repo, digest := pushTemplate(t, filepath.Join(rootfs, "bin", "refzygote"), "--heap-mb", "64", "--gvisor")
	a, stateA := registryHome(t, repo)
	cacheA := filepath.Join(stateA, "cache", strings.TrimPrefix(digest, "sha256:"))
	g := core.Grant{UID: "rt1", TemplateDigest: digest, FiberMax: 4, WBudgetBytes: 64 << 20}
	var h core.FiberHandle
	var zygoteSum string
	steps := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"the home pulls the template and binds a verified copy", func(t *testing.T) {
			t0 := time.Now()
			if err := a.PrepareTemplate(ctx, g); err != nil {
				t.Fatalf("prepare: %v", err)
			}
			t.Logf("template pulled, staged and warm in %s", time.Since(t0).Round(time.Millisecond))
			cfg, err := artifact.ReadConfig(cacheA)
			if err != nil || cfg.Linking != artifact.LinkStatic {
				t.Fatalf("cached config = %+v (%v), want a static template", cfg, err)
			}
			zygoteSum = cfg.ZygoteSHA256
			if sum := sha256File(t, stagedCopy(t, stateA, "rt1")); sum != zygoteSum {
				t.Fatalf("staged copy hashes to %s, want the artifact's %s", sum, zygoteSum)
			}
			if h, err = a.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "rt1", Epoch: 1, Seq: 1}, Deadline: 5 * time.Second}); err != nil {
				t.Fatalf("clone: %v", err)
			}
			if got := talk(t, h.Endpoint, "ping"); got != "pong" {
				t.Fatalf("ping = %q", got)
			}
		}},
		{"the sandbox sees the executable alone", func(t *testing.T) {
			cases := []struct{ dir, want string }{
				{"/fiberd/template", "zygote"},
				{"/fiberd", "template"},
			}
			for _, tc := range cases {
				if got := probe(t, stateA, "ls", tc.dir); got != tc.want {
					t.Fatalf("ls %s = %q, want %q (the cache holds %v)", tc.dir, got, tc.want, lsNames(t, cacheA))
				}
			}
			// The cache entry has more, and the cache has room for other
			// templates. None of it is in the sandbox.
			if names := lsNames(t, cacheA); len(names) < 3 {
				t.Fatalf("cache entry holds only %v", names)
			}
		}},
		{"the template is read-only inside the sandbox", func(t *testing.T) {
			cases := []struct{ args, want string }{
				{"write /fiberd/template/x", "error:"},
				{"write /fiberd/template/zygote", "error:"},
				{"remount /fiberd/template", "error:"},
				{"write /host/scratch", "ok"}, // the run directory stays writable, as fibers need
			}
			for _, tc := range cases {
				if got := probe(t, stateA, strings.Fields(tc.args)...); !strings.HasPrefix(got, tc.want) {
					t.Fatalf("probe %s = %q, want %s", tc.args, got, tc.want)
				}
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(stagedCopy(t, stateA, "rt1")), "x")); err == nil {
				t.Fatal("a write inside the sandbox reached the host copy")
			}
		}},
		{"a rewritten cache does not reach running or new sandboxes", func(t *testing.T) {
			if err := os.WriteFile(artifact.ZygotePath(cacheA), []byte("#!/bin/sh\nexit 7\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			h2, err := a.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "rt1", Epoch: 1, Seq: 2}, Deadline: 5 * time.Second})
			if err != nil {
				t.Fatalf("clone after the cache was rewritten: %v", err)
			}
			if got := talk(t, h2.Endpoint, "ping"); got != "pong" {
				t.Fatalf("ping = %q", got)
			}
			if sum := sha256File(t, stagedCopy(t, stateA, "rt1")); sum != zygoteSum {
				t.Fatalf("the rewrite reached the staged copy: %s", sum)
			}
			_ = a.Release(ctx, h2.ID, false)
		}},
		{"another home pulls the rewritten entry again before it binds it", func(t *testing.T) {
			b, stateB := registryHome(t, repo, func(cfg *host.Config) { cfg.TemplateCache = filepath.Join(stateA, "cache") })
			if err := b.PrepareTemplate(ctx, g); err != nil {
				t.Fatalf("prepare on the second home: %v", err)
			}
			if sum := sha256File(t, artifact.ZygotePath(cacheA)); sum != zygoteSum {
				t.Fatalf("cache entry hashes to %s after the second warm, want it pulled again to %s", sum, zygoteSum)
			}
			if sum := sha256File(t, stagedCopy(t, stateB, "rt1")); sum != zygoteSum {
				t.Fatalf("second home's copy hashes to %s, want %s", sum, zygoteSum)
			}
		}},
		{"a park resumes on a home with another cache and state path", func(t *testing.T) {
			for i := 0; i < 3; i++ {
				talk(t, h.Endpoint, "incr")
			}
			ref, err := a.Park(ctx, h.ID, true)
			if err != nil {
				t.Fatalf("park: %v", err)
			}
			c, stateC := registryHome(t, repo)
			if err := c.PrepareTemplate(ctx, g); err != nil {
				t.Fatalf("prepare on the resuming home: %v", err)
			}
			t0 := time.Now()
			h3, err := c.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: "rt1", Epoch: 2, Seq: 1}, Deadline: 10 * time.Second})
			if err != nil {
				t.Fatalf("resume on another home: %v", err)
			}
			t.Logf("resumed on a home with another cache path in %s", time.Since(t0).Round(time.Millisecond))
			if got := talk(t, h3.Endpoint, "get"); got != "3" {
				t.Fatalf("counter after the move = %q, want 3", got)
			}
			if got := probe(t, stateC, "ls", "/fiberd/template"); got != "zygote" {
				t.Fatalf("ls on the resuming home = %q", got)
			}
			if stateC == stateA || sha256File(t, stagedCopy(t, stateC, "rt1")) != zygoteSum {
				t.Fatal("the resuming home must bind its own verified copy")
			}
			_ = c.Release(ctx, h3.ID, true)
		}},
	}
	for _, st := range steps {
		if !t.Run(st.name, st.run) {
			return
		}
	}
}

// TestDynamicTemplateRefused: a template that is not a static executable
// would load against the sandbox rootfs's libraries, which the home
// cannot inspect. It is refused at warm with parity's error, and only
// libc=off lets it through to fail inside the sandbox.
func TestDynamicTemplateRefused(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil || artifact.Linking(sh) != artifact.LinkDynamic {
		t.Skipf("no dynamically linked sh here: %s %v", sh, err)
	}
	repo, digest := pushTemplate(t, sh, "-c", "exit 0")
	cases := []struct {
		name   string
		parity artifact.Parity
		want   error  // errors.Is
		text   string // in the error
	}{
		{name: "strict parity refuses before anything runs", parity: artifact.Strict, want: host.ErrParity, text: "not a static executable"},
		// runsc cannot find the interpreter the executable names, so the
		// run fails. The refusal above says why, and before anything ran.
		{name: "libc parity off lets it fail in the sandbox", parity: artifact.Parity{Libc: artifact.ParityOff}, text: "runsc run"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, _ := registryHome(t, repo, func(cfg *host.Config) { cfg.Parity = tc.parity })
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			t0 := time.Now()
			err := rt.PrepareTemplate(ctx, core.Grant{UID: "dyn", TemplateDigest: digest, FiberMax: 4, WBudgetBytes: 64 << 20})
			t.Logf("refused in %s: %v", time.Since(t0).Round(time.Millisecond), err)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) || !strings.Contains(err.Error(), tc.text) {
				t.Fatalf("PrepareTemplate = %v, want %q (errors.Is %v)", err, tc.text, tc.want)
			}
		})
	}
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

func lsNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ls %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}
