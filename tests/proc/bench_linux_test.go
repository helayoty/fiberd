//go:build linux

package proctest

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/sys/cgroup"
)

// TestStormNumbers reproduces zygote_bench.c's shapes through the real
// runtime path (agent-side Clone -> control socket -> clone3 -> scrub ->
// endpoint bound -> ready): a 50-way concurrent storm, and sustained
// throughput at W = 1 MiB and W = 4 MiB. It prints numbers rather than
// asserting them; run with -v under make linux-test. Set FIBERD_BENCH=1
// to enable (it takes a few seconds).
func TestStormNumbers(t *testing.T) {
	if os.Getenv("FIBERD_BENCH") == "" {
		t.Skip("set FIBERD_BENCH=1 to run the storm measurement")
	}
	rt := newRuntime(t)
	ctx := context.Background()
	g := core.Grant{UID: "bench", TemplateDigest: "sha256:ref"} // no W budget: measure, do not kill
	t0 := time.Now()
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	t.Logf("zygote init (paid once): %s", time.Since(t0).Round(time.Millisecond))

	var seq uint64
	clone := func(payload string, deadline time.Duration) (core.FiberHandle, time.Duration, error) {
		seq++
		fence := core.Fence{GrantUID: "bench", Epoch: 1, Seq: seq}
		start := time.Now()
		h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: fence, Deadline: deadline, Payload: []byte(payload)})
		return h, time.Since(start), err
	}
	releaseAll := func(hs []core.FiberHandle) {
		for _, h := range hs {
			_ = rt.Release(ctx, h.ID, false)
		}
	}

	// 1. Warm-up single clones (the ~ms claim).
	var single []time.Duration
	var warm []core.FiberHandle
	for i := 0; i < 10; i++ {
		h, d, err := clone("", 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		single = append(single, d)
		warm = append(warm, h)
	}
	releaseAll(warm)
	report(t, "single clone, fork-to-ready (n=10)", single)

	// 2. 50-way storm: all clones issued at once, each dirtying 4 MiB at
	// birth like the C bench's children. Memory: what the grant cgroup
	// charges for zygote + 50 fibers (exact, unlike PSS).
	const n = 50
	var mu sync.Mutex
	var lat []time.Duration
	var hs []core.FiberHandle
	var wg sync.WaitGroup
	seqBase := seq
	storm0 := time.Now()
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			fence := core.Fence{GrantUID: "bench", Epoch: 1, Seq: seqBase + uint64(i) + 1}
			start := time.Now()
			h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: fence, Deadline: 5 * time.Second, Payload: []byte(`{"dirty_bytes": 4194304}`)})
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
	seq = seqBase + n
	stormWall := time.Since(storm0)
	report(t, "50-way storm, fork-to-ready per clone", lat)
	t.Logf("50-way storm wall time: %s (%.0f clones/s)", stormWall.Round(time.Millisecond), float64(n)/stormWall.Seconds())
	time.Sleep(300 * time.Millisecond) // let dirtying settle
	grantCG := cgroup.Root(cgRoot).Child(t.Name()).Child("bench")
	if cur, err := grantMemory(rt, "bench"); err == nil {
		t.Logf("memory: grant cgroup (zygote 32 MiB heap + %d fibers each dirtying 4 MiB) = %d MiB; naive copies would be %d MiB", len(hs), cur>>20, 32*(len(hs)+1))
	}
	_ = grantCG
	releaseAll(hs)

	// 3. Throughput vs W: sustained clone+release cycles with 8 in flight,
	// each fiber dirtying W at birth; the C bench's f(W) claim.
	for _, w := range []uint64{1 << 20, 4 << 20} {
		const cycles = 120
		const inflight = 8
		sem := make(chan struct{}, inflight)
		var cwg sync.WaitGroup
		var cmu sync.Mutex
		var errs int
		start := time.Now()
		base := seq
		for i := 0; i < cycles; i++ {
			sem <- struct{}{}
			cwg.Add(1)
			go func(i int) {
				defer cwg.Done()
				defer func() { <-sem }()
				fence := core.Fence{GrantUID: "bench", Epoch: 1, Seq: base + uint64(i) + 1}
				h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: fence, Deadline: 5 * time.Second,
					Payload: []byte(fmt.Sprintf(`{"dirty_bytes": %d}`, w))})
				if err != nil {
					cmu.Lock()
					errs++
					cmu.Unlock()
					return
				}
				_ = rt.Release(ctx, h.ID, false)
			}(i)
		}
		cwg.Wait()
		seq = base + cycles
		el := time.Since(start)
		t.Logf("throughput W=%dMiB: %d clone+release cycles in %s = %.0f/s (errors %d)", w>>20, cycles, el.Round(time.Millisecond), float64(cycles)/el.Seconds(), errs)
	}
}

func grantMemory(rt core.Runtime, uid string) (uint64, error) {
	type rooted interface{ CgroupRoot() string }
	if r, ok := rt.(rooted); ok {
		return cgroup.Root(r.CgroupRoot()).Child(uid).MemoryCurrent()
	}
	return 0, fmt.Errorf("runtime does not expose its cgroup root")
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
