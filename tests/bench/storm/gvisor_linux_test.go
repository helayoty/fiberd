//go:build linux && integration

package stormtest

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/registry"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/runtime/host"
	"github.com/helayoty/fiberd/tests/internal/testenv"
)

// stormGvisor is the storm on the gVisor backend: a clone here is a
// whole sandbox restored from the template image, so the storm is 10-way
// (each sandbox costs about 90 MiB) and the numbers are expected to sit
// two orders of magnitude above a fork's. FIBERD_BENCH_REGISTRY=1 takes
// the template from a registry artifact, bound into every sandbox,
// instead of the rootfs.
func stormGvisor(t *testing.T) {
	var rt core.Runtime
	g := core.Grant{UID: "bench", TemplateDigest: "sha256:ref"}
	if os.Getenv("FIBERD_BENCH_REGISTRY") != "" {
		repo, digest := pushTemplate(t, filepath.Join(rootfs(t), "bin", "refzygote"), "--heap-mb", "64", "--gvisor")
		rt, _ = gvisorRuntime(t, func(cfg *host.Config) {
			cfg.Templates = nil
			cfg.Registry = repo
			cfg.TemplateCache = filepath.Join(work, "cache-"+filepath.Base(cfg.CgroupRoot))
		})
		g.TemplateDigest = digest
		t.Logf("template: registry artifact %s", digest)
	} else {
		rt, _ = gvisorRuntime(t)
		t.Logf("template: baked into the rootfs")
	}
	ctx := context.Background()
	t0 := time.Now()
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	t.Logf("warm (sandbox + template image + probe, paid once): %s", time.Since(t0).Round(time.Millisecond))

	var seq uint64
	var single []time.Duration
	var warm []core.FiberHandle
	for i := 0; i < 10; i++ {
		seq++
		start := time.Now()
		h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "bench", Epoch: 1, Seq: seq}, Deadline: 5 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		single = append(single, time.Since(start))
		warm = append(warm, h)
	}
	for _, h := range warm {
		_ = rt.Release(ctx, h.ID, false)
	}
	testenv.Report(t, "single clone, restore-to-ready (n=10)", single)

	const n = 10
	var mu sync.Mutex
	var lat []time.Duration
	var hs []core.FiberHandle
	var wg sync.WaitGroup
	base := seq
	storm0 := time.Now()
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			start := time.Now()
			h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "bench", Epoch: 1, Seq: base + uint64(i) + 1},
				Deadline: 10 * time.Second, Payload: []byte(`{"dirty_bytes": 4194304}`)})
			d := time.Since(start)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				t.Errorf("storm clone %d: %v", i, err)
				return
			}
			lat = append(lat, d)
			hs = append(hs, h)
		}(i)
	}
	wg.Wait()
	seq = base + n
	wall := time.Since(storm0)
	testenv.Report(t, "10-way storm, restore-to-ready per clone", lat)
	t.Logf("10-way storm wall time: %s (%.0f clones/s)", wall.Round(time.Millisecond), float64(n)/wall.Seconds())

	var parks, resumes []time.Duration
	h := hs[0]
	for i := 0; i < 5; i++ {
		start := time.Now()
		ref, err := rt.Park(ctx, h.ID, true)
		if err != nil {
			t.Fatal(err)
		}
		parks = append(parks, time.Since(start))
		seq++
		start = time.Now()
		h, err = rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: "bench", Epoch: 1, Seq: seq}, Deadline: 10 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		resumes = append(resumes, time.Since(start))
	}
	testenv.Report(t, "park (full image)", parks)
	testenv.Report(t, "resume from image", resumes)
	_ = rt.Release(ctx, h.ID, true)
	for _, h := range hs[1:] {
		_ = rt.Release(ctx, h.ID, false)
	}
}

// pushTemplate builds a bare artifact (no CRIU images: a gVisor template
// is restored from the sandbox checkpoint the backend takes) from the
// executable and pushes it to a registry that lives as long as the test.
// It returns the repository the home pulls from and the digest a grant
// names.
func pushTemplate(t *testing.T, executable string, args ...string) (repo, digest string) {
	t.Helper()
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "art")
	// No smoke test: a gVisor-mode template waits on /proc/gvisor/checkpoint,
	// which only a sandbox has, and never speaks fd 3 on the host.
	digest, err := artifact.Build(ctx, artifact.BuildOptions{Zygote: executable, Args: args, Out: out, SkipImages: true, NoSmoke: true})
	if err != nil {
		t.Fatalf("build artifact: %v", err)
	}
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	repo = srv.URL + "/zygotes/ref"
	if _, err := artifact.Push(ctx, out, repo+":v1"); err != nil {
		t.Fatalf("push artifact: %v", err)
	}
	return repo, digest
}
