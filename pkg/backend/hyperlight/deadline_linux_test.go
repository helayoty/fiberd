//go:build linux

package hyperlight

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	fakehelper "github.com/Azure/fiberd/hack/hyperlight/fakehelper/helper"
	"github.com/Azure/fiberd/pkg/backend"
)

// probing is a fake helper that says READY, answers the probe clone after
// took with reply ("" for CLONED, "-" for no answer at all, "exit" to
// end), answers its KILL with EXITED after exitAfter, and records every
// line it reads and when its EXITED went.
type probing struct {
	took      time.Duration
	reply     string
	exitAfter time.Duration
	mu        sync.Mutex
	lines     []string
	exitedAt  time.Time
}

func (p *probing) body(r *fakeRun) {
	_, _ = fmt.Fprintf(r.ctl, "READY %s\n", kvmIntel)
	rd := bufio.NewReader(r.ctl)
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return
		}
		p.mu.Lock()
		p.lines = append(p.lines, strings.TrimSpace(line))
		p.mu.Unlock()
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "KILL" {
			time.Sleep(p.exitAfter)
			p.mu.Lock()
			p.exitedAt = time.Now()
			p.mu.Unlock()
			_, _ = fmt.Fprintf(r.ctl, "EXITED %s exit:137\n", f[1])
			continue
		}
		if len(f) < 2 || f[0] != "CLONE" || p.reply == "-" {
			continue
		}
		time.Sleep(p.took)
		switch p.reply {
		case "":
			_, _ = fmt.Fprintf(r.ctl, "CLONED %s\n", f[1])
		case "exit":
			return
		default:
			_, _ = fmt.Fprintf(r.ctl, "%s %s probe refused\n", p.reply, f[1])
		}
	}
}

func (p *probing) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.lines...)
}

// TestDeadlinesFromTheProbe checks that a warm instance's default
// deadlines are sized from one probe clone at warm, as gVisor's are from
// its probe restore: the floors, raised to four times the probe, capped.
func TestDeadlinesFromTheProbe(t *testing.T) {
	cases := []struct {
		name  string
		probe *probing
		ctx   time.Duration // 0 for warmCtx
		// The probe is timed for real, so a created deadline may run up
		// to slack over what the probe's sleep alone gives.
		wantCreate, wantRe time.Duration
		slack              time.Duration // 0 for the usual
		wantErr            string
	}{
		{name: "a quick clone keeps the floors", probe: &probing{},
			wantCreate: createDeadline, wantRe: resumeDeadline},
		{name: "a slow clone raises the create deadline to four times it", probe: &probing{took: 300 * time.Millisecond},
			wantCreate: 1200 * time.Millisecond, wantRe: resumeDeadline},
		{name: "a very slow clone is capped", probe: &probing{took: 1600 * time.Millisecond},
			wantCreate: deadlineCap, wantRe: deadlineCap},
		{name: "a refused probe keeps the floors and the warm", probe: &probing{reply: "ERROR"},
			wantCreate: createDeadline, wantRe: resumeDeadline},
		{name: "a probe that never clones in time takes the cap", probe: &probing{reply: "-"},
			wantCreate: deadlineCap, wantRe: deadlineCap},
		// The caller's second also covers the helper's start, so the probe
		// runs most of it: the warm is kept, sized above the floor and under
		// the cap, neither of which a cut-short probe may fall back to.
		{name: "a caller that gives up during the probe keeps the warm, sized from how long it ran", probe: &probing{reply: "-"}, ctx: time.Second,
			wantCreate: createDeadline + time.Millisecond, wantRe: resumeDeadline, slack: deadlineCap - createDeadline - 2*time.Millisecond},
		{name: "an ERROR as the probe runs out its time takes the cap", probe: &probing{took: deadlineCap - probeLate/2, reply: "ERROR"},
			wantCreate: deadlineCap, wantRe: deadlineCap},
		{name: "a helper that exits during the probe fails the warm", probe: &probing{reply: "exit"},
			wantErr: "exited during its probe clone"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &fakeStarter{version: kvmIntel, body: tc.probe.body}
			be := newFake(t, Options{Helper: "helper"}, s)
			sp := warmSpec(filepath.Join(t.TempDir(), "run", "g1"))
			ctx := warmCtx(t)
			if tc.ctx > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(context.Background(), tc.ctx)
				t.Cleanup(cancel)
			}
			_, err := be.Warm(ctx, sp)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Warm = %v, want an error containing %q", err, tc.wantErr)
				}
				if _, ok := be.warmOf(sp.GrantUID); ok {
					t.Fatal("a failed warm is registered")
				}
				// The host never had the instance, so no end is reported
				// for it: a stale one would end the grant's next warm.
				for _, r := range s.started() {
					awaitRun(t, r)
				}
				select {
				case e := <-be.Exits():
					t.Fatalf("a failed warm reported %+v", e)
				case <-time.After(100 * time.Millisecond):
				}
				return
			}
			if err != nil {
				t.Fatalf("Warm: %v", err)
			}
			slack := 1200 * time.Millisecond
			if tc.slack > 0 {
				slack = tc.slack
			}
			within := func(got, want time.Duration) bool { return got >= want && got <= want+slack }
			if c, r := be.DefaultDeadlines(sp.GrantUID); !within(c, tc.wantCreate) || !within(r, tc.wantRe) {
				t.Fatalf("DefaultDeadlines = %s, %s, want %s, %s (+%s)", c, r, tc.wantCreate, tc.wantRe, slack)
			}
		})
	}
}

// TestProbeClone checks what the probe asks of the helper: one clone of
// the warm snapshot under a fence no real fiber can have, as a first
// incarnation with a seed, then its end, and that it never becomes a
// fiber of the backend's.
func TestProbeClone(t *testing.T) {
	p := &probing{}
	s := &fakeStarter{version: kvmIntel, body: p.body}
	be := newFake(t, Options{Helper: "helper"}, s)
	sp := warmSpec(filepath.Join(t.TempDir(), "run", "g1"))
	if _, err := be.Warm(warmCtx(t), sp); err != nil {
		t.Fatalf("Warm: %v", err)
	}
	var lines []string
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		if lines = p.seen(); len(lines) >= 2 || time.Now().After(deadline) {
			break
		}
	}
	if len(lines) != 2 {
		t.Fatalf("the helper read %q, want the probe's CLONE and KILL", lines)
	}
	f := strings.Fields(lines[0])
	if len(f) != 7 || f[0] != "CLONE" || f[1] != "g1/probe" || f[2] != filepath.Join(sp.WorkDir, "probe.sock") ||
		f[3] != fmt.Sprint(deadlineCap.Milliseconds()) || f[4] != "-" || f[5] != "1" || len(f[6]) != 64 {
		t.Errorf("probe line = %q", lines[0])
	}
	if lines[1] != "KILL g1/probe" {
		t.Errorf("after the probe the helper read %q, want its KILL", lines[1])
	}
	if w, ok := be.FiberW("g1/probe"); ok {
		t.Errorf("the probe is a fiber of the backend's, W %d", w)
	}
}

func TestSizeDeadline(t *testing.T) {
	cases := []struct {
		name            string
		measured, floor time.Duration
		want            time.Duration
	}{
		{name: "nothing measured", floor: createDeadline, want: createDeadline},
		{name: "four times the probe is under the floor", measured: 100 * time.Millisecond, floor: createDeadline, want: createDeadline},
		{name: "four times the probe is over the floor", measured: 290 * time.Millisecond, floor: createDeadline, want: 1160 * time.Millisecond},
		{name: "the resume floor holds a probe the create floor does not", measured: 290 * time.Millisecond, floor: resumeDeadline, want: resumeDeadline},
		{name: "capped", measured: 2 * time.Second, floor: createDeadline, want: deadlineCap},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sizeDeadline(tc.measured, tc.floor); got != tc.want {
				t.Fatalf("sizeDeadline(%s, %s) = %s, want %s", tc.measured, tc.floor, got, tc.want)
			}
		})
	}
}

// TestWarmAwaitsTheProbesEnd checks that Warm returns only once a probe
// that cloned has exited, so the footprint the host reads next is the
// warm instance's alone, and that a probe the helper refused, which left
// no sandbox, is not waited on.
func TestWarmAwaitsTheProbesEnd(t *testing.T) {
	t.Run("a probe that cloned", func(t *testing.T) {
		p := &probing{exitAfter: 300 * time.Millisecond}
		s := &fakeStarter{version: kvmIntel, body: p.body}
		be := newFake(t, Options{Helper: "helper"}, s)
		sp := warmSpec(filepath.Join(t.TempDir(), "run", "g1"))
		if _, err := be.Warm(warmCtx(t), sp); err != nil {
			t.Fatalf("Warm: %v", err)
		}
		returned := time.Now()
		p.mu.Lock()
		exited := p.exitedAt
		p.mu.Unlock()
		if exited.IsZero() || exited.After(returned) {
			t.Fatalf("Warm returned at %s, the probe exited at %s", returned.Format(time.StampMicro), exited.Format(time.StampMicro))
		}
		if lines := p.seen(); len(lines) < 2 || lines[1] != "KILL g1/probe" {
			t.Fatalf("the helper read %q, want the probe's CLONE then its KILL", lines)
		}
	})
	t.Run("a probe the helper refused", func(t *testing.T) {
		p := &probing{reply: "ERROR", exitAfter: time.Hour} // an EXITED would never come
		s := &fakeStarter{version: kvmIntel, body: p.body}
		be := newFake(t, Options{Helper: "helper"}, s)
		sp := warmSpec(filepath.Join(t.TempDir(), "run", "g1"))
		t0 := time.Now()
		if _, err := be.Warm(warmCtx(t), sp); err != nil {
			t.Fatalf("Warm: %v", err)
		}
		if took := time.Since(t0); took > probeEndWait/2 {
			t.Fatalf("Warm took %s, waiting on a probe that left no sandbox", took)
		}
		if lines := p.seen(); len(lines) != 1 {
			t.Fatalf("the helper read %q, want the probe's CLONE alone", lines)
		}
	})
}

// recorded is a control socket that keeps everything the helper writes.
type recorded struct {
	net.Conn
	mu  sync.Mutex
	out strings.Builder
}

func (c *recorded) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.out.Write(b)
	c.mu.Unlock()
	return c.Conn.Write(b)
}

// said is every line the helper wrote.
func (c *recorded) said() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Split(strings.TrimSpace(c.out.String()), "\n")
}

// TestAKillOvertakesABirth checks the fake helper keeps what the protocol
// asks of every helper: a CLONE whose deadline fiberd gave up on is ended
// by the KILL fiberd sends after it, even when the sandbox comes later,
// with an EXITED and no CLONED, and nothing serves on its endpoint.
func TestAKillOvertakesABirth(t *testing.T) {
	guest := filepath.Join(t.TempDir(), "guest.bin")
	if err := os.WriteFile(guest, []byte("fake guest"), 0o644); err != nil {
		t.Fatal(err)
	}
	var ctl *recorded
	s := &fakeStarter{version: fake, body: func(r *fakeRun) {
		ctl = &recorded{Conn: r.ctl}
		_ = fakehelper.Serve(ctl, r.log, "")
	}}
	be := newFake(t, Options{Helper: "fakehelper", Guest: guest}, s)
	work := filepath.Join(t.TempDir(), "run", "g1")
	if _, err := be.Warm(warmCtx(t), backend.WarmSpec{GrantUID: "g1", WorkDir: work, CgroupFD: -1, ProbeCgroupFD: -1,
		Template: backend.Template{Argv: []string{"guest", "--init-ms", "5"}}}); err != nil {
		t.Fatalf("Warm: %v", err)
	}
	ep := filepath.Join(work, "f1.sock")
	_, err := be.Clone(context.Background(), "g1", backend.FiberSpec{Fence: "f1", Endpoint: ep, CgroupFD: -1, Deadline: 50 * time.Millisecond,
		Payload: []byte(`{"ready_delay_ms": 300}`), Generation: 1})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Clone = %v, want its deadline to pass", err)
	}
	var said []string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if said = ctl.said(); slices.Contains(said, "EXITED f1 exit:137") {
			break
		}
	}
	if !slices.Contains(said, "EXITED f1 exit:137") || slices.Contains(said, "CLONED f1") {
		t.Fatalf("the helper said %q, want an EXITED for f1 and no CLONED", said)
	}
	if c, err := net.Dial("unix", ep); err == nil {
		_ = c.Close()
		t.Fatal("the overtaken birth serves its endpoint")
	}
}

// TestAProbeCutShortIsStillAwaited checks that a caller giving up during
// the probe does not cut Warm's wait for the probe's exit, so the
// footprint the host reads next never counts the probe's sandbox.
func TestAProbeCutShortIsStillAwaited(t *testing.T) {
	p := &probing{reply: "-", exitAfter: 300 * time.Millisecond}
	s := &fakeStarter{version: kvmIntel, body: p.body}
	be := newFake(t, Options{Helper: "helper"}, s)
	sp := warmSpec(filepath.Join(t.TempDir(), "run", "g1"))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := be.Warm(ctx, sp); err != nil {
		t.Fatalf("Warm: %v", err)
	}
	returned := time.Now()
	p.mu.Lock()
	exited := p.exitedAt
	p.mu.Unlock()
	if exited.IsZero() || exited.After(returned) {
		t.Fatalf("Warm returned at %s, before the probe exited at %s", returned.Format(time.StampMicro), exited.Format(time.StampMicro))
	}
}

// TestAnOvertakenProbeThatFailsIsNotAwaited checks that a probe whose
// birth fails after fiberd gave up on it, and so answers ERROR rather
// than EXITED, ends Warm's wait at once.
func TestAnOvertakenProbeThatFailsIsNotAwaited(t *testing.T) {
	body := func(r *fakeRun) {
		_, _ = fmt.Fprintf(r.ctl, "READY %s\n", kvmIntel)
		rd := bufio.NewReader(r.ctl)
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				return
			}
			if f := strings.Fields(line); len(f) > 1 && f[0] == "KILL" {
				// The birth fails as the KILL arrives: no EXITED.
				_, _ = fmt.Fprintf(r.ctl, "ERROR %s incarnate: refused\n", f[1])
			}
		}
	}
	be := newFake(t, Options{Helper: "helper"}, &fakeStarter{version: kvmIntel, body: body})
	sp := warmSpec(filepath.Join(t.TempDir(), "run", "g1"))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	if _, err := be.Warm(ctx, sp); err != nil {
		t.Fatalf("Warm: %v", err)
	}
	if took := time.Since(t0); took > probeEndWait/2 {
		t.Fatalf("Warm took %s, waiting on a probe whose birth failed", took)
	}
}

// TestALateCloneIsStillAwaited checks that a probe that clones only after
// its time ran out is ended and awaited like any other, so its sandbox is
// gone before Warm returns, and that the defaults go to the cap.
func TestALateCloneIsStillAwaited(t *testing.T) {
	var exitedAt time.Time
	var mu sync.Mutex
	body := func(r *fakeRun) {
		_, _ = fmt.Fprintf(r.ctl, "READY %s\n", kvmIntel)
		rd := bufio.NewReader(r.ctl)
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				return
			}
			if f := strings.Fields(line); len(f) > 1 && f[0] == "KILL" {
				// The clone lands after the KILL, then the fiber ends.
				_, _ = fmt.Fprintf(r.ctl, "CLONED %s\n", f[1])
				time.Sleep(200 * time.Millisecond)
				mu.Lock()
				exitedAt = time.Now()
				mu.Unlock()
				_, _ = fmt.Fprintf(r.ctl, "EXITED %s exit:137\n", f[1])
			}
		}
	}
	be := newFake(t, Options{Helper: "helper"}, &fakeStarter{version: kvmIntel, body: body})
	sp := warmSpec(filepath.Join(t.TempDir(), "run", "g1"))
	if _, err := be.Warm(warmCtx(t), sp); err != nil {
		t.Fatalf("Warm: %v", err)
	}
	returned := time.Now()
	mu.Lock()
	exited := exitedAt
	mu.Unlock()
	if exited.IsZero() || exited.After(returned) {
		t.Fatalf("Warm returned at %s, before the late probe exited at %s", returned.Format(time.StampMicro), exited.Format(time.StampMicro))
	}
	if c, r := be.DefaultDeadlines(sp.GrantUID); c != deadlineCap || r != deadlineCap {
		t.Fatalf("DefaultDeadlines = %s, %s, want the cap", c, r)
	}
}

// TestAHelperGoneBeforeItsProbeFailsTheWarm checks that a helper that
// dies right after READY, so the probe's CLONE cannot be written, fails
// the warm rather than hand the host an instance already dead.
func TestAHelperGoneBeforeItsProbeFailsTheWarm(t *testing.T) {
	body := func(r *fakeRun) {
		_, _ = fmt.Fprintf(r.ctl, "READY %s\n", kvmIntel)
		_ = r.ctl.(*net.UnixConn).CloseRead()
		_ = r.ctl.Close()
	}
	s := &fakeStarter{version: kvmIntel, body: body}
	be := newFake(t, Options{Helper: "helper"}, s)
	sp := warmSpec(filepath.Join(t.TempDir(), "run", "g1"))
	if _, err := be.Warm(warmCtx(t), sp); err == nil || !strings.Contains(err.Error(), "exited during its probe clone") {
		t.Fatalf("Warm = %v, want the dead helper's warm failed", err)
	}
	if _, ok := be.warmOf(sp.GrantUID); ok {
		t.Fatal("the dead helper's warm is registered")
	}
}
