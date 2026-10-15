//go:build linux && integration

package proctest

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	fiberendpoint "github.com/helayoty/fiberd/pkg/endpoint"
)

// TestRandomPerIncarnation pins that every new incarnation of a fiber
// draws its own randomness. Two forked siblings differ at birth, which
// on_fiber's reseed gives, and the seed each one reseeds from is the
// host's, 32 bytes on its incarnation record and unlike its sibling's.
// Two fibers resumed from one park must differ
// too: CRIU restores the parked RNG state under the same pid, so the
// fence the host publishes beside the endpoint at resume is the one
// signal the template has to reseed before it serves. The getrandom
// rows ask the kernel directly. A glibc of 2.41 or later answers
// getrandom from a per-thread state page the vDSO keeps in user memory,
// which a park dumps like any other page, so the park must drop it or
// every resume replays one keystream, the template's reseed included.
// The kernel wipes that page in a forked child, and a resume must keep
// that too, or a resumed fiber that forks after drawing shares its
// keystream with the child. criu 4.2 restores the page's mapping as the
// kernel made it. An older criu restores plain private memory, and the
// fork row fails under it.
func TestRandomPerIncarnation(t *testing.T) {
	ctx := context.Background()
	// resumeTwice parks one fiber and resumes the delta twice, as a
	// second home or a retry after a failed resume would. The first
	// resume is released, not discarded, so the delta stays. Each
	// incarnation answers cmd as its very first request, and names
	// the fence it serves under.
	resumeTwice := func(t *testing.T, rt core.Runtime, g core.Grant, cmd string) (string, string) {
		h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
		if err != nil {
			t.Fatalf("clone: %v", err)
		}
		talk(t, h.Endpoint, cmd) // the parked image holds a sequence in progress
		ref, err := rt.Park(ctx, h.ID, true)
		if err != nil {
			t.Fatalf("park: %v", err)
		}
		var out []string
		for seq := uint64(2); seq <= 3; seq++ {
			h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: seq}, Deadline: 5 * time.Second})
			if err != nil {
				t.Fatalf("resume %d: %v", seq, err)
			}
			out = append(out, talk(t, h2.Endpoint, cmd))
			if got := talk(t, h2.Endpoint, "fence"); got != h2.ID {
				t.Fatalf("resume %d: fence = %q, want %q", seq, got, h2.ID)
			}
			if err := rt.Release(ctx, h2.ID, false); err != nil {
				t.Fatalf("release %s: %v", h2.ID, err)
			}
		}
		return out[0], out[1]
	}
	// resumedFork parks one fiber that has drawn and resumes it once. The
	// copy answers cmd first, drawing, forking, and drawing once more in
	// itself and in the child, "<parent> <child>".
	resumedFork := func(t *testing.T, rt core.Runtime, g core.Grant, cmd string) (string, string) {
		h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
		if err != nil {
			t.Fatalf("clone: %v", err)
		}
		talk(t, h.Endpoint, "getrandom") // the parked image holds a state page in use
		ref, err := rt.Park(ctx, h.ID, true)
		if err != nil {
			t.Fatalf("park: %v", err)
		}
		h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 2}, Deadline: 5 * time.Second})
		if err != nil {
			t.Fatalf("resume: %v", err)
		}
		t.Cleanup(func() { _ = rt.Release(ctx, h2.ID, true) })
		got := talk(t, h2.Endpoint, cmd)
		parent, child, ok := strings.Cut(got, " ")
		if !ok {
			t.Fatalf("%s answered %q, want two values", cmd, got)
		}
		return parent, child
	}
	// siblings forks two fibers of g, each born with payload, and
	// returns their first answers to cmd.
	siblings := func(payload []byte) func(t *testing.T, rt core.Runtime, g core.Grant, cmd string) (string, string) {
		return func(t *testing.T, rt core.Runtime, g core.Grant, cmd string) (string, string) {
			var out []string
			for seq := uint64(1); seq <= 2; seq++ {
				h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: seq}, Deadline: 2 * time.Second, Payload: payload})
				if err != nil {
					t.Fatalf("clone %d: %v", seq, err)
				}
				t.Cleanup(func() { _ = rt.Release(ctx, h.ID, true) })
				out = append(out, talk(t, h.Endpoint, cmd))
			}
			return out[0], out[1]
		}
	}
	cases := []struct {
		name string
		cmd  string // what each incarnation is asked first
		// runtime opens the home; nil for the unix-endpoint default.
		runtime func(t *testing.T) core.Runtime
		// draw makes two incarnations of g and returns the first
		// answer to cmd from each one.
		draw func(t *testing.T, rt core.Runtime, g core.Grant, cmd string) (a, b string)
		// hex is how many hex characters each answer must be, 0 for
		// any answer.
		hex int
	}{
		{name: "forked siblings, libc random", cmd: "random", draw: siblings(nil)},
		{name: "forked siblings, getrandom", cmd: "getrandom", draw: siblings(nil)},
		// The record's seed, kept by the template under the keep_seed
		// payload key. Before the record, no forked fiber had one.
		{name: "forked siblings, the record's seed", cmd: "seed", draw: siblings([]byte(`{"keep_seed":1}`)), hex: 64},
		{name: "two resumes of one park, libc random", cmd: "random", draw: resumeTwice},
		{name: "two resumes of one park, getrandom", cmd: "getrandom", draw: resumeTwice},
		{name: "a resumed fiber and the child it forks, getrandom", cmd: "getrandom fork", draw: resumedFork},
		// A fiber that binds tcp itself has no socket to find its fence
		// file beside. It reads the file named by its birth fence. The
		// ports sit below the kernel's ephemeral range (32768 and up), which
		// any suite's listener or dial may be holding.
		{name: "two resumes of one park on a tcp endpoint, libc random", cmd: "random", draw: resumeTwice,
			runtime: func(t *testing.T) core.Runtime { return tcpRuntime(t, fiberendpoint.Inet4, "127.0.0.1", 21010, 21013) }},
		{name: "two resumes of one park on a tcp endpoint, getrandom", cmd: "getrandom", draw: resumeTwice,
			runtime: func(t *testing.T) core.Runtime { return tcpRuntime(t, fiberendpoint.Inet4, "127.0.0.1", 21010, 21013) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRuntime(t)
			if tc.runtime != nil {
				rt = tc.runtime(t)
			}
			if rt.Tier() < core.TierCheckpoint {
				t.Skip("criu not usable here")
			}
			g := core.Grant{UID: "grnd", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			a, b := tc.draw(t, rt, g, tc.cmd)
			if a == b {
				t.Fatalf("%s: both answers %q, want different values", tc.cmd, a)
			}
			if tc.hex > 0 && (!isHex(a, tc.hex) || !isHex(b, tc.hex)) {
				t.Fatalf("%s: answers %q and %q, want %d hex characters each", tc.cmd, a, b, tc.hex)
			}
			t.Logf("%s: %s and %s", tc.cmd, a, b)
		})
	}
}

// isHex reports whether s is exactly n hex characters.
func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// TestSeedNeverLogged pins that the seed a fiber is born with reaches
// the fiber alone. The template keeps it under the keep_seed payload key
// and answers it, and that value is then looked for in the zygote's log
// and in fiberd's, where neither the record nor the CLONE line may have
// left it. The seed is 32 random bytes, so a 64-hex run equal to it is
// the seed and nothing else.
func TestSeedNeverLogged(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
	}{
		{name: "a plain fiber", payload: []byte(`{"keep_seed":1}`)},
		{name: "a fiber with a payload of its own", payload: []byte(`{"keep_seed":1,"dirty_bytes":4096}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var fiberdLog bytes.Buffer
			log.SetOutput(io.MultiWriter(os.Stderr, &fiberdLog))
			t.Cleanup(func() { log.SetOutput(os.Stderr) })
			ctx := context.Background()
			rt := newRuntime(t)
			g := core.Grant{UID: "gseed", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second, Payload: tc.payload})
			if err != nil {
				t.Fatalf("clone: %v", err)
			}
			seed := talk(t, h.Endpoint, "seed")
			if !isHex(seed, 64) {
				t.Fatalf("seed = %q, want 64 hex characters", seed)
			}
			if err := rt.Release(ctx, h.ID, true); err != nil {
				t.Fatal(err)
			}
			logs, _ := filepath.Glob(filepath.Join("/tmp", "fz-"+fmt.Sprint(os.Getpid()), "*", "zygote.log"))
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
			}
			if strings.Contains(fiberdLog.String(), seed) {
				t.Fatalf("fiberd's log holds the seed %s:\n%s", seed, fiberdLog.String())
			}
		})
	}
}
