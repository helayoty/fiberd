//go:build linux

package proctest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/runtime/host"
	"github.com/helayoty/fiberd/pkg/sys/cgroup"
)

// TestFibersCannotStarveTheAgent lays out a home as a kubelet or docker
// --memory does: one cgroup with memory.max and pids.max, the agent in
// an `agent` leaf beside the runtime's subtree. The test process plays
// the agent and moves itself into the leaf. Fibers are then cloned
// until one is refused. The subtree must have been capped below the
// home's limits, the refusal must be the home's own pressure (shed), and
// the agent must still fork: the limit a fiber runs into is the
// subtree's, never the home's. Before the cap, the fibers filled the
// home's pids.max and the agent's next fork failed, which in a Go
// runtime is a fatal error that takes every fiber down with the agent.
func TestFibersCannotStarveTheAgent(t *testing.T) {
	cases := []struct {
		name     string
		pidsMax  uint64
		memMax   uint64
		fibers   int
		wantPids string // the subtree's pids.max
		wantMem  string // the subtree's memory.max
	}{
		// 96 tasks: the subtree keeps 32 (an eighth is 12, the floor is 64,
		// half is 48, so 48 are kept). The fibers fill 48, the agent's
		// own threads and its fork fit in the rest.
		{name: "the home's task limit", pidsMax: 96, memMax: 512 << 20, fibers: 128, wantPids: "48", wantMem: strconv.Itoa(448 << 20)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := cgroup.Dir{Path: filepath.Join(cgRoot, fmt.Sprintf("home-%d-%d", os.Getpid(), time.Now().UnixNano()%1_000_000))}
			if err := home.Create(tc.memMax, false); err != nil {
				t.Fatal(err)
			}
			if err := home.Ensure("memory", "pids"); err != nil {
				t.Fatal(err)
			}
			if err := home.SetPidsMax(tc.pidsMax); err != nil {
				t.Fatal(err)
			}
			agent := home.Child("agent")
			if err := os.Mkdir(agent.Path, 0o755); err != nil {
				t.Fatal(err)
			}
			// The agent's seat: this process moves in, and back out at the
			// end so the home can be removed.
			origin := moveSelf(t, agent)
			t.Cleanup(func() {
				_ = os.WriteFile(filepath.Join(origin, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o644)
				for _, d := range []cgroup.Dir{agent, home.Child("fiberd"), home} {
					_ = d.Kill()
					for i := 0; i < 100 && d.Remove() != nil; i++ {
						time.Sleep(10 * time.Millisecond)
					}
				}
			})

			run := filepath.Join("/tmp", fmt.Sprintf("fz-starve-%d", os.Getpid()))
			t.Cleanup(func() { _ = os.RemoveAll(run) })
			rt, err := newHost(host.Config{Templates: map[string]string{"default": zygoteBin + " --heap-mb 1"},
				CgroupRoot: home.Child("fiberd").Path, RunDir: run})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if c, ok := rt.(interface{ Close() }); ok {
					c.Close()
				}
			})
			ctx := context.Background()
			g := core.Grant{UID: "starve", TemplateDigest: "sha256:ref", FiberMax: tc.fibers, WBudgetBytes: 8 << 20}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			var refusal error
			born := 0
			for i := 1; i <= tc.fibers && refusal == nil; i++ {
				_, refusal = rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: uint64(i)}, Deadline: 5 * time.Second})
				if refusal == nil {
					born++
				}
			}
			t.Logf("%d fibers born, then: %v", born, refusal)
			for name, want := range map[string]string{"pids.max": tc.wantPids, "memory.max": tc.wantMem} {
				b, err := os.ReadFile(filepath.Join(home.Path, "fiberd", name))
				if err != nil {
					t.Fatal(err)
				}
				if got := strings.TrimSpace(string(b)); got != want {
					t.Errorf("the subtree's %s = %s, want %s: the fibers share the home's limit with the agent", name, got, want)
				}
			}
			if born == 0 {
				t.Fatal("no fiber was born")
			}
			if out, err := exec.Command("/bin/true").CombinedOutput(); err != nil {
				t.Errorf("the agent cannot fork once %d fibers run: %v %s", born, err, out)
			}
			if refusal == nil {
				t.Errorf("every one of %d fibers was born under a %d-task home", born, tc.pidsMax)
			} else if !errors.Is(refusal, core.ErrPressure) {
				t.Errorf("the refusal is %v, want the home's own pressure (%v)", refusal, core.ErrPressure)
			}
		})
	}
}

// moveSelf puts this process into d and returns the cgroup it came from.
func moveSelf(t *testing.T, d cgroup.Dir) string {
	t.Helper()
	pc, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	origin := filepath.Join("/sys/fs/cgroup", cgroup.ScopeOf(string(pc)))
	if err := os.WriteFile(filepath.Join(d.Path, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		t.Fatalf("move into %s: %v", d.Path, err)
	}
	return origin
}
