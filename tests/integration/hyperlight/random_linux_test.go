//go:build linux && integration

package hyperlighttest

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	hlbackend "github.com/helayoty/fiberd/pkg/backend/hyperlight"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/runtime/host"
	"github.com/helayoty/fiberd/tests/internal/testenv"
)

// helperSpec is one helper the rows run over: the fake, always, and the
// Rust helper where a hypervisor and its build are present.
type helperSpec struct {
	name     string
	helper   string
	guest    string
	template string
}

// helpers is the fake helper, and the Rust helper when it can run here:
// /dev/kvm or /dev/mshv, plus bin/hyperlight-helper and
// bin/hyperlight-guest (make hyperlight-helper), or the paths in
// FIBERD_HL_HELPER and FIBERD_HL_GUEST. CI's conform-hyperlight job has
// KVM and runs this suite with both.
func helpers(t *testing.T) []helperSpec {
	t.Helper()
	hs := []helperSpec{{name: "fake helper", helper: helperBin, guest: guest, template: "guest --init-ms 20"}}
	real := helperSpec{name: "rust helper", template: "guest"}
	real.helper, real.guest = os.Getenv("FIBERD_HL_HELPER"), os.Getenv("FIBERD_HL_GUEST")
	if real.helper == "" {
		real.helper = filepath.Join(testenv.RepoRoot(), "bin", "hyperlight-helper")
	}
	if real.guest == "" {
		real.guest = filepath.Join(testenv.RepoRoot(), "bin", "hyperlight-guest")
	}
	_, kvm := os.Stat("/dev/kvm")
	_, mshv := os.Stat("/dev/mshv")
	_, h := os.Stat(real.helper)
	_, g := os.Stat(real.guest)
	switch {
	case kvm != nil && mshv != nil:
		t.Logf("rust helper rows skipped: no /dev/kvm or /dev/mshv here")
	case h != nil || g != nil:
		t.Logf("rust helper rows skipped: %s or %s missing (make hyperlight-helper)", real.helper, real.guest)
	default:
		hs = append(hs, real)
	}
	return hs
}

// newRuntimeOver is newRuntime over the given helper, with the run
// directory the helper's log lands under.
func newRuntimeOver(t *testing.T, hs helperSpec) (core.Runtime, string) {
	t.Helper()
	name := fmt.Sprintf("hl%d", time.Now().UnixNano()%1_000_000)
	runDir := filepath.Join("/tmp", "fz-"+name)
	rt, err := host.New(host.Config{
		Backend:       hlbackend.New(hlbackend.Options{Helper: hs.helper, Guest: hs.guest}),
		Templates:     map[string]string{"default": hs.template},
		CgroupRoot:    filepath.Join(cgRoot, name),
		RunDir:        runDir,
		DeltaDir:      filepath.Join(t.TempDir(), "deltas"),
		TemplateCache: filepath.Join(t.TempDir(), "templates"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rt.Close)
	return rt, runDir
}

// TestRandomPerIncarnation pins that every Hyperlight fiber draws its
// own randomness and names its generation and kind. Every fiber is a
// sandbox restored from one snapshot, the warm one or a park's, so two
// copies hold the same generator state until Incarnate reseeds each
// from the 32 bytes its CLONE or RESUME carried. Before that call there
// was no generator and no identity in the guest, and the fake answered
// random, generation and kind with "err unknown command". The seed rows
// ask for the seed itself, which a resume's line carries while its park
// holds only the clone's keep_seed flag, so each resume must answer its
// own and never the clone's.
func TestRandomPerIncarnation(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		cmd     string // what each incarnation is asked first
		payload []byte // the clone's payload, which a park carries on
		hex     int    // hex characters each answer must be, 0 for a number
		resumed bool   // two resumes of one park instead of two clones
		chained bool   // the second resumes a park of the first resume
		gens    [2]int
		kind    string
	}{
		{name: "two clones of the warm snapshot", cmd: "random", gens: [2]int{1, 1}, kind: "clone"},
		{name: "two resumes of one park", cmd: "random", resumed: true, gens: [2]int{2, 2}, kind: "resume"},
		{name: "a resume of a resumed park", cmd: "random", resumed: true, chained: true, gens: [2]int{2, 3}, kind: "resume"},
		{name: "two resumes of one park, the seed", cmd: "seed", payload: []byte(`{"keep_seed":1}`), hex: 64, resumed: true, gens: [2]int{2, 2}, kind: "resume"},
		{name: "a resume of a resumed park, the seed", cmd: "seed", payload: []byte(`{"keep_seed":1}`), hex: 64, resumed: true, chained: true, gens: [2]int{2, 3}, kind: "resume"},
	}
	for _, hs := range helpers(t) {
		for _, tc := range cases {
			t.Run(hs.name+"/"+tc.name, func(t *testing.T) {
				rt, _ := newRuntimeOver(t, hs)
				g := core.Grant{UID: "grnd", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20}
				if err := rt.PrepareTemplate(ctx, g); err != nil {
					t.Fatal(err)
				}
				source, ref, born := core.SourceZygote, "", ""
				if tc.resumed {
					h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 5 * time.Second, Payload: tc.payload})
					if err != nil {
						t.Fatalf("clone: %v", err)
					}
					born = talk(t, h.Endpoint, tc.cmd)
					if ref, err = rt.Park(ctx, h.ID, false); err != nil {
						t.Fatalf("park: %v", err)
					}
					source = core.SourceDelta
				}
				var out []string
				for seq := uint64(2); seq <= 3; seq++ {
					h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: source, Ref: ref, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: seq}, Deadline: 10 * time.Second})
					if err != nil {
						t.Fatalf("incarnation %d: %v", seq, err)
					}
					out = append(out, talk(t, h.Endpoint, tc.cmd))
					if tc.resumed && out[len(out)-1] == born {
						t.Fatalf("incarnation %d answers the clone's %s %q, want its own", seq, tc.cmd, born)
					}
					if got := talk(t, h.Endpoint, "fence"); got != h.ID {
						t.Fatalf("incarnation %d: fence = %q, want %q", seq, got, h.ID)
					}
					if got, want := talk(t, h.Endpoint, "generation"), strconv.Itoa(tc.gens[seq-2]); got != want {
						t.Fatalf("incarnation %d: generation = %q, want %s", seq, got, want)
					}
					if got := talk(t, h.Endpoint, "kind"); got != tc.kind {
						t.Fatalf("incarnation %d: kind = %q, want %s", seq, got, tc.kind)
					}
					if tc.chained && seq == 2 {
						if ref, err = rt.Park(ctx, h.ID, false); err != nil {
							t.Fatalf("park %s: %v", h.ID, err)
						}
						continue
					}
					// Released, not discarded, so the park stays for the next
					// resume, which binds the same parked socket name.
					if err := rt.Release(ctx, h.ID, false); err != nil {
						t.Fatalf("release %s: %v", h.ID, err)
					}
				}
				if out[0] == out[1] {
					t.Fatalf("both incarnations answered %s = %q, want different values", tc.cmd, out[0])
				}
				for _, o := range out {
					if b, err := hex.DecodeString(o); tc.hex > 0 && (err != nil || 2*len(b) != tc.hex) {
						t.Fatalf("%s = %q, want %d hex characters", tc.cmd, o, tc.hex)
					}
					if _, err := strconv.ParseUint(o, 10, 64); tc.hex == 0 && err != nil {
						t.Fatalf("%s = %q, want a number", tc.cmd, o)
					}
				}
				t.Logf("%s: %s and %s", tc.cmd, out[0], out[1])
			})
		}
	}
}

// TestSeedNeverLogged pins that a fiber's seed reaches its sandbox
// alone. The helper keeps a clone's seed under the keep_seed payload key
// and answers it, and that value is then looked for in the helper's log
// and in fiberd's, where the CLONE line may not have left it, and the
// helper's log is checked to show the line with the seed by size.
func TestSeedNeverLogged(t *testing.T) {
	ctx := context.Background()
	for _, hs := range helpers(t) {
		t.Run(hs.name, func(t *testing.T) {
			var fiberdLog bytes.Buffer
			log.SetOutput(io.MultiWriter(os.Stderr, &fiberdLog))
			t.Cleanup(func() { log.SetOutput(os.Stderr) })
			rt, runDir := newRuntimeOver(t, hs)
			g := core.Grant{UID: "gseed", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 5 * time.Second, Payload: []byte(`{"keep_seed":1}`)})
			if err != nil {
				t.Fatalf("clone: %v", err)
			}
			seed := talk(t, h.Endpoint, "seed")
			if b, err := hex.DecodeString(seed); err != nil || len(b) != 32 {
				t.Fatalf("seed = %q, want 64 hex characters", seed)
			}
			if err := rt.Release(ctx, h.ID, true); err != nil {
				t.Fatal(err)
			}
			logs, _ := filepath.Glob(filepath.Join(runDir, "*", "zygote.log"))
			if len(logs) == 0 {
				t.Fatal("no zygote.log to check")
			}
			for _, l := range logs {
				b, err := os.ReadFile(l)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(b), seed) {
					t.Fatalf("%s holds the seed %s", l, seed)
				}
				if !strings.Contains(string(b), "helper: < CLONE "+h.ID+" ") || !strings.Contains(string(b), " 1 seed:32B") {
					t.Fatalf("%s lacks the CLONE line with its seed by size:\n%s", l, b)
				}
			}
			if strings.Contains(fiberdLog.String(), seed) {
				t.Fatalf("fiberd's log holds the seed %s:\n%s", seed, fiberdLog.String())
			}
		})
	}
}
