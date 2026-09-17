//go:build linux

package gvisortest

import (
	"context"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// TestStormNumbers is the storm measurement on the gVisor backend: a
// clone here is a whole sandbox restored from the template image, so
// the storm is 10-way (each sandbox costs about 90 MiB) and the numbers
// are expected to sit two orders of magnitude above a fork's.
// FIBERD_BENCH=1 enables it.
func TestStormNumbers(t *testing.T) {
	if os.Getenv("FIBERD_BENCH") == "" {
		t.Skip("set FIBERD_BENCH=1 to run the storm measurement")
	}
	rt := newRuntime(t)
	ctx := context.Background()
	g := core.Grant{UID: "bench", TemplateDigest: "sha256:ref"}
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
	report(t, "single clone, restore-to-ready (n=10)", single)

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
	report(t, "10-way storm, restore-to-ready per clone", lat)
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
	report(t, "park (full image)", parks)
	report(t, "resume from image", resumes)
	_ = rt.Release(ctx, h.ID, true)
	for _, h := range hs[1:] {
		_ = rt.Release(ctx, h.ID, false)
	}
}

func report(t *testing.T, label string, ds []time.Duration) {
	t.Helper()
	if len(ds) == 0 {
		return
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	var sum time.Duration
	for _, d := range ds {
		sum += d
	}
	pct := func(p float64) time.Duration { return ds[int(float64(len(ds)-1)*p)] }
	t.Logf("%s: p50=%s p90=%s p99=%s max=%s mean=%s", label,
		pct(0.5).Round(10*time.Microsecond), pct(0.9).Round(10*time.Microsecond), pct(0.99).Round(10*time.Microsecond),
		ds[len(ds)-1].Round(10*time.Microsecond), (sum / time.Duration(len(ds))).Round(10*time.Microsecond))
}
