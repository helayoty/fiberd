//go:build linux && integration

package stormtest

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/tests/internal/testenv"
)

// stormRunc is the proc storm on the runc backend, so the two compare
// like for like: the same zygote, forked inside a container instead of
// on the host, then five park and resume rounds on one fiber.
func stormRunc(t *testing.T) {
	rt := runcRuntime(t)
	ctx := context.Background()
	g := core.Grant{UID: "bench", TemplateDigest: "sha256:ref"}
	t0 := time.Now()
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	t.Logf("warm (runc run + zygote init + self-checkpoint, paid once): %s", time.Since(t0).Round(time.Millisecond))

	var seq uint64
	var single []time.Duration
	var warm []core.FiberHandle
	for i := 0; i < 10; i++ {
		seq++
		start := time.Now()
		h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "bench", Epoch: 1, Seq: seq}, Deadline: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		single = append(single, time.Since(start))
		warm = append(warm, h)
	}
	for _, h := range warm {
		_ = rt.Release(ctx, h.ID, false)
	}
	testenv.Report(t, "single clone, fork-to-ready (n=10)", single)

	const n = 50
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
				Deadline: 5 * time.Second, Payload: []byte(`{"dirty_bytes": 4194304}`)})
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
	testenv.Report(t, "50-way storm, fork-to-ready per clone", lat)
	t.Logf("50-way storm wall time: %s (%.0f clones/s)", wall.Round(time.Millisecond), float64(n)/wall.Seconds())

	// Park and resume, five rounds on one fiber that dirtied 4 MiB.
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
		h, err = rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: "bench", Epoch: 1, Seq: seq}, Deadline: 5 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		resumes = append(resumes, time.Since(start))
	}
	testenv.Report(t, "park (sync, 4 MiB delta)", parks)
	testenv.Report(t, "resume from delta", resumes)
	_ = rt.Release(ctx, h.ID, true)
	for _, h := range hs[1:] {
		_ = rt.Release(ctx, h.ID, false)
	}
}
