//go:build linux && integration

package parktest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	procbackend "github.com/helayoty/fiberd/pkg/backend/proc"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/runtime/host"
	"github.com/helayoty/fiberd/tests/internal/testenv"
)

// work holds the zygote and the deltas. It is not a tmpfs, so the images
// cost what they cost on disk.
const work = "/var/lib/fiberd-test/park"

func TestMain(m *testing.M) {
	code := m.Run()
	_ = os.RemoveAll(work)
	os.Exit(code)
}

// TestParkResumeNumbers parks and resumes one fiber cycles times per
// round, rounds times after one discarded warm-up round, and prints the
// median park and resume latency of each round and across rounds. The
// fiber is asked one line after each resume, so a resume counts only
// once the fiber serves again. FIBERD_BENCH_ROUNDS and
// FIBERD_BENCH_CYCLES override the counts.
func TestParkResumeNumbers(t *testing.T) {
	if os.Getenv("FIBERD_BENCH") == "" {
		t.Skip("set FIBERD_BENCH=1 to run the park and resume measurement")
	}
	root, err := testenv.WritableCgroupRoot()
	if err != nil {
		t.Skip(err)
	}
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	zygote, err := testenv.BuildZygote(work)
	if err != nil {
		t.Fatal(err)
	}
	rounds, cycles := envInt("FIBERD_BENCH_ROUNDS", 3), envInt("FIBERD_BENCH_CYCLES", 20)
	name := fmt.Sprintf("bp%d", time.Now().UnixNano()%1_000_000)
	state := filepath.Join(work, name)
	cfg := host.Config{
		Backend:       procbackend.New(procbackend.Options{}),
		Templates:     map[string]string{"default": zygote + " --heap-mb 32"},
		CgroupRoot:    filepath.Join(root, name),
		RunDir:        filepath.Join("/tmp", "fz-"+name),
		DeltaDir:      filepath.Join(state, "deltas"),
		TemplateCache: filepath.Join(work, "templates"),
	}
	rt, err := host.New(cfg)
	if errors.Is(err, host.ErrNoTier) {
		t.Skipf("backend not usable here: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rt.Close)
	if rt.Tier() < core.TierCheckpoint {
		t.Skip("criu not usable here")
	}
	ctx := context.Background()
	g := core.Grant{UID: "bench", TemplateDigest: "sha256:ref"}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	var seq uint64
	var parks, resumes []time.Duration
	for round := 0; round <= rounds; round++ {
		var park, resume []time.Duration
		seq++
		h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: seq}, Deadline: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		say(t, h.Endpoint, "incr")
		for i := 0; i < cycles; i++ {
			t0 := time.Now()
			ref, err := rt.Park(ctx, h.ID, false)
			if err != nil {
				t.Fatalf("park %d: %v", i, err)
			}
			park = append(park, time.Since(t0))
			seq++
			t0 = time.Now()
			if h, err = rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: seq}, Deadline: 5 * time.Second}); err != nil {
				t.Fatalf("resume %d: %v", i, err)
			}
			say(t, h.Endpoint, "get")
			resume = append(resume, time.Since(t0))
			// The delta is resumed, so it goes, or the grant's delta
			// quota ends the round early.
			_ = os.RemoveAll(ref)
		}
		if err := rt.Release(ctx, h.ID, true); err != nil {
			t.Fatal(err)
		}
		if round == 0 {
			t.Logf("warm-up round discarded: park median %s, resume median %s", median(park), median(resume))
			continue
		}
		t.Logf("round %d: park median %s, resume median %s (n=%d)", round, median(park), median(resume), cycles)
		parks = append(parks, median(park))
		resumes = append(resumes, median(resume))
	}
	load, _ := os.ReadFile("/proc/loadavg")
	t.Logf("RESULT park=%s resume=%s rounds=%d cycles=%d loadavg=%s", median(parks), median(resumes), rounds, cycles, string(load))
}

func median(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2].Round(10 * time.Microsecond)
}

func envInt(name string, def int) int {
	var n int
	if _, err := fmt.Sscan(os.Getenv(name), &n); err != nil || n <= 0 {
		return def
	}
	return n
}

// say sends one line to the fiber on its unix endpoint and returns its
// reply, which for a resume is the moment the fiber serves again.
func say(t *testing.T, endpoint, line string) string {
	t.Helper()
	c, err := net.DialTimeout("unix", strings.TrimPrefix(endpoint, "unix://"), 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", endpoint, err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintln(c, line); err != nil {
		t.Fatalf("%s: %v", line, err)
	}
	reply, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("%s: %v", line, err)
	}
	return strings.TrimSpace(reply)
}
