//go:build linux

package hyperlight

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
)

// incarnated is a backend over the fake helper with one warm, g1, and
// the endpoint and park paths its fibers use.
type incarnated struct {
	be   *Backend
	work string
	park string
}

func newIncarnated(t *testing.T) incarnated {
	t.Helper()
	guest := filepath.Join(t.TempDir(), "guest.bin")
	if err := os.WriteFile(guest, []byte("fake guest"), 0o644); err != nil {
		t.Fatal(err)
	}
	be := newFake(t, Options{Helper: "fakehelper", Guest: guest}, &fakeStarter{version: fake})
	work := filepath.Join(t.TempDir(), "run", "g1")
	if _, err := be.Warm(warmCtx(t), backend.WarmSpec{GrantUID: "g1", WorkDir: work, CgroupFD: -1, ProbeCgroupFD: -1,
		Template: backend.Template{Argv: []string{"guest"}}}); err != nil {
		t.Fatal(err)
	}
	return incarnated{be: be, work: work, park: filepath.Join(t.TempDir(), "park")}
}

func (x incarnated) ep(fence string) string { return filepath.Join(x.work, fence+".sock") }

// clone is a fiber of generation 1 from the warm snapshot.
func (x incarnated) clone(t *testing.T, fence string, payload []byte) {
	t.Helper()
	if _, err := x.be.Clone(context.Background(), "g1", backend.FiberSpec{Fence: fence, Endpoint: x.ep(fence), CgroupFD: -1, Deadline: 2 * time.Second, Payload: payload, Generation: 1}); err != nil {
		t.Fatalf("clone %s: %v", fence, err)
	}
}

// parkInto parks fence into dir, with the fiber kept, and is the
// directory a resume takes.
func (x incarnated) parkInto(t *testing.T, fence, dir string) string {
	t.Helper()
	if err := x.be.Park(context.Background(), fence, backend.ParkSpec{Dir: dir, Sync: true}); err != nil {
		t.Fatalf("park %s: %v", fence, err)
	}
	return dir
}

// resume brings dir back as fence, at generation.
func (x incarnated) resume(t *testing.T, dir, fence string, generation int) {
	t.Helper()
	if _, err := x.be.Resume(context.Background(), backend.ResumeSpec{Dir: dir, Fence: fence, Endpoint: x.ep(fence), CgroupFD: -1, Deadline: 2 * time.Second, WarmID: "g1", WorkDir: x.work, Generation: generation}); err != nil {
		t.Fatalf("resume %s: %v", fence, err)
	}
}

// TestIncarnationPerFiber pins what every Hyperlight fiber learns before
// it serves: a seed of its own, which the fake helper's generator and
// the guest's draw from, and the host's generation and kind. Two copies
// of one snapshot answer random differently only because each CLONE and
// RESUME carried a seed. Before the seed, the fake answered random,
// generation and kind with "err unknown command" on every fiber.
func TestIncarnationPerFiber(t *testing.T) {
	cases := []struct {
		name    string
		resumed bool // two resumes of one park instead of two clones
		chained bool // the second resumes a park of the first resume
		gens    [2]int
		kind    string
	}{
		{name: "two clones of the warm snapshot", gens: [2]int{1, 1}, kind: "clone"},
		{name: "two resumes of one park", resumed: true, gens: [2]int{2, 2}, kind: "resume"},
		{name: "a resume of a resumed park", resumed: true, chained: true, gens: [2]int{2, 3}, kind: "resume"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x := newIncarnated(t)
			park := ""
			if tc.resumed {
				x.clone(t, "f1", nil)
				talk(t, x.ep("f1"), "random")
				park = x.parkInto(t, "f1", x.park)
			}
			var out []string
			for i, fence := range []string{"f2", "f3"} {
				if park == "" {
					x.clone(t, fence, nil)
				} else {
					x.resume(t, park, fence, tc.gens[i])
				}
				out = append(out, talk(t, x.ep(fence), "random"))
				if got, want := talk(t, x.ep(fence), "generation"), strconv.Itoa(tc.gens[i]); got != want {
					t.Fatalf("%s: generation = %q, want %s", fence, got, want)
				}
				if got := talk(t, x.ep(fence), "kind"); got != tc.kind {
					t.Fatalf("%s: kind = %q, want %s", fence, got, tc.kind)
				}
				if tc.chained && i == 0 {
					park = x.parkInto(t, fence, filepath.Join(x.park, "again"))
				}
			}
			if out[0] == out[1] {
				t.Fatalf("both fibers answered random = %q, want different values", out[0])
			}
			for _, o := range out {
				if _, err := strconv.ParseUint(o, 10, 64); err != nil {
					t.Fatalf("random = %q, want a number", o)
				}
			}
		})
	}
}

// TestSeedNeverLogged pins that the seed a fiber is born with, and the
// one its resume brings, reach the helper's sandbox alone. The fake
// keeps the latest under the keep_seed payload key and answers it, and
// that value is then looked for in the helper's log, in fiberd's and in
// the park, where neither the CLONE nor the RESUME line may have left
// it. The helper logs every command, so the log is also checked to hold
// the line with the seed shown by size, which is what proves the
// redaction rather than silence.
func TestSeedNeverLogged(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
		resume  bool
	}{
		{name: "a clone", payload: []byte(`{"keep_seed":1}`)},
		{name: "a clone with a payload of its own", payload: []byte(`{"keep_seed":1,"dirty_bytes":4096}`)},
		{name: "a resumed fiber", payload: []byte(`{"keep_seed":1}`), resume: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var fiberdLog bytes.Buffer
			log.SetOutput(io.MultiWriter(os.Stderr, &fiberdLog))
			t.Cleanup(func() { log.SetOutput(os.Stderr) })
			x := newIncarnated(t)
			x.clone(t, "f1", tc.payload)
			seed := talk(t, x.ep("f1"), "seed")
			if b, err := hex.DecodeString(seed); err != nil || len(b) != backend.SeedBytes {
				t.Fatalf("seed = %q, want 64 hex characters", seed)
			}
			wantLogged := "CLONE f1 " + x.ep("f1") + " 2000 payload:" + strconv.Itoa(len(tc.payload)) + "B 1 seed:32B"
			var parked []string
			if tc.resume {
				x.parkInto(t, "f1", x.park)
				x.resume(t, x.park, "f2", 2)
				born := seed
				if seed = talk(t, x.ep("f2"), "seed"); len(seed) != 2*backend.SeedBytes || seed == born {
					t.Fatalf("seed after the resume = %q, want 64 hex characters unlike the birth's %s", seed, born)
				}
				parked, _ = filepath.Glob(filepath.Join(x.park, "*"))
				wantLogged = "RESUME f2 " + x.park + " " + x.ep("f2") + " 2000 2 seed:32B"
			}
			helperLog, err := os.ReadFile(filepath.Join(x.work, "zygote.log"))
			if err != nil {
				t.Fatal(err)
			}
			for name, text := range map[string]string{"the helper's log": string(helperLog), "fiberd's log": fiberdLog.String()} {
				if strings.Contains(text, seed) {
					t.Fatalf("%s holds the seed %s:\n%s", name, seed, text)
				}
			}
			if !strings.Contains(string(helperLog), wantLogged) {
				t.Fatalf("the helper's log lacks %q:\n%s", wantLogged, helperLog)
			}
			for _, f := range parked {
				b, err := os.ReadFile(f)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(b), seed) {
					t.Fatalf("%s holds the seed %s", f, seed)
				}
			}
		})
	}
}
