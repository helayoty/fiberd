//go:build linux

package proctest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/registry"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/runtime/host"
)

// pushTemplates builds one bare artifact per args list from the test
// zygote and pushes them to a registry that lives as long as the test.
// It returns the repository and the digests, in order.
func pushTemplates(t *testing.T, args ...[]string) (repo string, digests []string) {
	t.Helper()
	ctx := context.Background()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	repo = strings.TrimPrefix(srv.URL, "http://") + "/zygotes/ref"
	for i, a := range args {
		out := filepath.Join(t.TempDir(), "art")
		digest, err := artifact.Build(ctx, artifact.BuildOptions{Zygote: zygoteBin, Args: a, Out: out, SkipImages: true})
		if err != nil {
			t.Fatalf("build artifact: %v", err)
		}
		if _, err := artifact.Push(ctx, out, fmt.Sprintf("%s:v%d", repo, i), true); err != nil {
			t.Fatalf("push artifact: %v", err)
		}
		digests = append(digests, digest)
	}
	return repo, digests
}

// TestRegistryTemplateHidden pins that the template cache is hidden
// from proc fibers, which run as the agent's uid and could otherwise
// read or rewrite a cached template between the host's check and the
// exec. A fiber sees the cache covered, with its own template's
// executable alone bound back read-only at its path, because CRIU names
// a mapped file by its path. It sees no other template, no config and
// no parent checkpoint, cannot write or remount, and a park and resume
// keep the view and the state. The zygote's self-checkpoint, the parent
// every delta is computed against, still works with the cache hidden.
func TestRegistryTemplateHidden(t *testing.T) {
	cases := []struct {
		name string
	}{
		{name: "current library"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			repo, digests := pushTemplates(t, []string{"--heap-mb", "16"}, []string{"--heap-mb", "24"})
			cache := t.TempDir()
			rt, err := newHost(host.Config{
				Registry: repo, RegistryPlainHTTP: true, TemplateCache: cache,
				CgroupRoot: filepath.Join(cgRoot, fmt.Sprintf("tpl%d-%d", os.Getpid(), time.Now().UnixNano()%1_000_000)),
				RunDir:     filepath.Join("/tmp", "fz-tpl-"+fmt.Sprint(os.Getpid())), DeltaDir: t.TempDir(),
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(rt.(interface{ Close() }).Close)
			if rt.Tier() < core.TierCheckpoint {
				t.Skip("criu not usable here")
			}
			entry := func(i int) string { return filepath.Join(cache, strings.TrimPrefix(digests[i], "sha256:")) }
			ga := core.Grant{UID: "tpa", TemplateDigest: digests[0], WBudgetBytes: 64 << 20}
			gb := core.Grant{UID: "tpb", TemplateDigest: digests[1], WBudgetBytes: 64 << 20}
			for _, g := range []core.Grant{ga, gb} {
				if err := rt.PrepareTemplate(ctx, g); err != nil {
					t.Fatalf("prepare %s: %v", g.UID, err)
				}
			}
			// The host's own view: the whole entry, as pulled.
			for _, name := range []string{"zygote", "config.json", "DIGEST"} {
				if _, err := os.Stat(filepath.Join(entry(0), name)); err != nil {
					t.Fatalf("the host's cache entry lacks %s: %v", name, err)
				}
			}
			ha, err := rt.Clone(ctx, core.CloneSpec{Grant: ga, Fence: core.Fence{GrantUID: "tpa", Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
			if err != nil {
				t.Fatalf("clone A: %v", err)
			}
			hb, err := rt.Clone(ctx, core.CloneSpec{Grant: gb, Fence: core.Fence{GrantUID: "tpb", Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
			if err != nil {
				t.Fatalf("clone B: %v", err)
			}
			// view checks what a fiber of grant i sees of the cache.
			view := func(when, ep string, i int) {
				t.Helper()
				other := 1 - i
				want := map[string]string{
					cache:                                      "dir", // the cover
					filepath.Join(entry(i), "zygote"):          "file",
					filepath.Join(entry(i), "config.json"):     "ENOENT",
					filepath.Join(entry(i), "DIGEST"):          "ENOENT",
					filepath.Join(cache, "parents"):            "ENOENT",
					filepath.Join(cache, "zygote-images"):      "ENOENT",
					entry(other):                               "ENOENT",
					filepath.Join(entry(other), "zygote"):      "ENOENT",
					filepath.Join(entry(other), "config.json"): "ENOENT",
				}
				for path, kind := range want {
					if got := talk(t, ep, "stat "+path); got != kind {
						t.Errorf("%s: fiber %d sees %s as %q, want %q", when, i, path, got, kind)
					}
				}
				refused := []string{
					"wopen " + filepath.Join(entry(i), "zygote"),
					"mkdir " + filepath.Join(entry(i), "x"),
					"mkdir " + filepath.Join(cache, "x"),
					"remount " + filepath.Join(entry(i), "zygote"),
					"remount " + cache,
				}
				for _, probe := range refused {
					if got := talk(t, ep, probe); got == "ok" {
						t.Errorf("%s: fiber %d: %s = ok, want a refusal", when, i, probe)
					}
				}
				if got := talk(t, ep, "read "+filepath.Join(entry(i), "config.json")); got != "-" {
					t.Errorf("%s: fiber %d read the template config: %q", when, i, got)
				}
			}
			view("born A", ha.Endpoint, 0)
			view("born B", hb.Endpoint, 1)
			if got := talk(t, ha.Endpoint, "ping"); got != "pong" {
				t.Fatalf("A ping = %q", got)
			}
			// Across a park and resume of A, with B still running. The
			// park is a delta, so the zygote's self-checkpoint worked with
			// the cache hidden.
			talk(t, ha.Endpoint, "incr")
			ref, err := rt.Park(ctx, ha.ID, true)
			if err != nil {
				t.Fatalf("park A: %v", err)
			}
			var m struct {
				Delta bool `json:"delta"`
			}
			mb, _ := os.ReadFile(filepath.Join(ref, "manifest.json"))
			if err := json.Unmarshal(mb, &m); err != nil || !m.Delta {
				t.Fatalf("park manifest = %s (%v), want a delta over the self-checkpoint", mb, err)
			}
			ha2, err := rt.Clone(ctx, core.CloneSpec{Grant: ga, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: "tpa", Epoch: 1, Seq: 2}, Deadline: 5 * time.Second})
			if err != nil {
				t.Fatalf("resume A: %v", err)
			}
			if got := talk(t, ha2.Endpoint, "get"); got != "1" {
				t.Fatalf("resumed A counter = %q, want 1", got)
			}
			view("resumed A", ha2.Endpoint, 0)
			view("B after A resumed", hb.Endpoint, 1)
			for _, h := range []core.FiberHandle{ha2, hb} {
				if err := rt.Release(ctx, h.ID, true); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
