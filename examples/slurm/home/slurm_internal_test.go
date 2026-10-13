package home

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func jobEnv(k string) string {
	return map[string]string{"SLURM_JOB_ID": "4242", "SLURMD_NODENAME": "localhost"}[k]
}

func fakeCgroup(t *testing.T) string {
	cg := t.TempDir()
	if err := os.WriteFile(filepath.Join(cg, "cgroup.subtree_control"), []byte("memory pids\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return cg
}

// scontrol is a probe command. Only RunProbe sees it, so any argv does.
var scontrol = []string{"scontrol", "show", "job", "-o", "4242"}

// fakeProbe answers the probe in process. The test flips its answer.
type fakeProbe struct {
	mu    sync.Mutex
	out   string
	err   error
	argvs [][]string
}

func (p *fakeProbe) run(_ context.Context, argv []string) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.argvs = append(p.argvs, argv)
	return []byte(p.out), p.err
}

func (p *fakeProbe) set(state string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.out = "JobId=4242 JobName=x JobState=" + state + " NodeList=localhost\n"
}

func (p *fakeProbe) calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.argvs)
}

// TestPoll checks one probe of slurmctld at a time. The issuer starts
// unreachable, so only a poll that counts as liveness makes it reachable.
func TestPoll(t *testing.T) {
	cases := []struct {
		name    string
		probe   []string
		answer  string
		fail    error
		paused  bool
		noHook  bool
		polls   int
		healthy bool
		reasons []string
		ended   int
	}{
		{name: "no probe: the timer is liveness", probe: []string{}, polls: 1, healthy: true},
		{name: "no probe while paused: the issuer stays unreachable", probe: []string{}, paused: true, polls: 1},
		{name: "a failing probe leaves the issuer unreachable", probe: scontrol, answer: "slurmctld down", fail: errors.New("exit status 3"), polls: 1},
		{name: "an answer without JobState leaves the issuer unreachable", probe: scontrol, answer: "JobId=4242", polls: 1},
		{name: "RUNNING is liveness", probe: scontrol, answer: "JobId=4242 JobState=RUNNING", polls: 1, healthy: true},
		{name: "PENDING is liveness", probe: scontrol, answer: "JobState=PENDING", polls: 1, healthy: true},
		{name: "RUNNING while paused: the issuer stays unreachable", probe: scontrol, answer: "JobState=RUNNING", paused: true, polls: 1},
		{name: "a terminal state is scope loss once, however often it is seen", probe: scontrol, answer: "JobState=NODE_FAIL", polls: 3,
			reasons: []string{"job 4242 is NODE_FAIL"}, ended: 1},
		{name: "without a scope-loss hook fiberd still leaves with the job", probe: scontrol, answer: "JobState=COMPLETED", noHook: true, polls: 2,
			ended: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ended := 0
			probe := &fakeProbe{out: tc.answer, err: tc.fail}
			h, err := New(Config{Env: jobEnv, CgroupMount: fakeCgroup(t), StaleTTL: time.Minute, Probe: tc.probe,
				RunProbe: probe.run, OnJobEnd: func() { ended++ }})
			if err != nil {
				t.Fatal(err)
			}
			h.health.MarkSync(time.Now().Add(-time.Hour))
			if tc.paused {
				h.SetIssuerReachable(false)
			}
			var reasons []string
			if !tc.noHook {
				h.OnScopeLost(func(_ context.Context, r string) { reasons = append(reasons, r) })
			}
			for range tc.polls {
				h.poll(context.Background())
			}
			if got := h.Health().Healthy(time.Now()); got != tc.healthy {
				t.Fatalf("healthy = %v, want %v", got, tc.healthy)
			}
			if !slices.Equal(reasons, tc.reasons) {
				t.Fatalf("reasons = %q, want %q", reasons, tc.reasons)
			}
			if ended != tc.ended {
				t.Fatalf("OnJobEnd calls = %d, want %d", ended, tc.ended)
			}
			want := tc.polls
			if len(tc.probe) == 0 {
				want = 0
			}
			if got := probe.calls(); got != want {
				t.Fatalf("the probe ran %d times, want %d", got, want)
			}
		})
	}
}

// TestProbeIsLivenessAndTerminalStateIsScopeLoss checks a job seen RUNNING
// first. Another live state then changes nothing. A terminal state is
// scope loss, reported once, and then fiberd leaves with the job.
func TestProbeIsLivenessAndTerminalStateIsScopeLoss(t *testing.T) {
	cases := []struct {
		name   string
		state  string
		reason string // empty means no scope loss, and fiberd stays
	}{
		{"staying RUNNING is nothing", "RUNNING", ""},
		{"SUSPENDED is still the job's lifetime", "SUSPENDED", ""},
		{"COMPLETING is scope loss", "COMPLETING", "job 4242 is COMPLETING"},
		{"CANCELLED is scope loss", "CANCELLED", "job 4242 is CANCELLED"},
		{"TIMEOUT is scope loss", "TIMEOUT", "job 4242 is TIMEOUT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probe := &fakeProbe{}
			probe.set("RUNNING")
			var reasons []string
			ended := 0
			h, err := New(Config{Env: jobEnv, CgroupMount: fakeCgroup(t), StaleTTL: time.Minute, Probe: scontrol,
				RunProbe: probe.run, OnJobEnd: func() { ended++ }})
			if err != nil {
				t.Fatal(err)
			}
			h.OnScopeLost(func(_ context.Context, r string) { reasons = append(reasons, r) })
			h.health.MarkSync(time.Now().Add(-time.Hour))
			h.poll(context.Background())
			if !h.Health().Healthy(time.Now()) || len(reasons) != 0 {
				t.Fatalf("job RUNNING: healthy = %v, reasons = %v, want reachable and no scope loss", h.Health().Healthy(time.Now()), reasons)
			}
			probe.set(tc.state)
			// Twice, so a terminal state seen again is not a second loss.
			h.poll(context.Background())
			h.poll(context.Background())
			var want []string
			wantEnded := 0
			if tc.reason != "" {
				want, wantEnded = []string{tc.reason}, 1
			}
			if !slices.Equal(reasons, want) {
				t.Fatalf("reasons = %v, want %v for %s", reasons, want, tc.state)
			}
			if ended != wantEnded {
				t.Fatalf("OnJobEnd calls = %d, want %d", ended, wantEnded)
			}
		})
	}
}

// TestRun checks that Run probes at once, then every half stale TTL, and
// returns when its context ends. The probe itself ends the context, so
// the test waits on nothing but Run.
func TestRun(t *testing.T) {
	cases := []struct {
		name  string
		stop  int // the probe call that ends the context
		polls int
	}{
		{"the first probe is immediate", 1, 1},
		{"the next probe comes from the ticker", 2, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			probe := &fakeProbe{}
			probe.set("RUNNING")
			stopping := func(c context.Context, argv []string) ([]byte, error) {
				out, err := probe.run(c, argv)
				if probe.calls() == tc.stop {
					cancel()
				}
				return out, err
			}
			h, err := New(Config{Env: jobEnv, CgroupMount: fakeCgroup(t), StaleTTL: 10 * time.Millisecond, Probe: scontrol,
				RunProbe: stopping, OnJobEnd: func() { t.Error("the job never ended") }})
			if err != nil {
				t.Fatal(err)
			}
			h.health.MarkSync(time.Now().Add(-time.Hour))
			h.Run(ctx)
			if got := probe.calls(); got != tc.polls {
				t.Fatalf("Run probed %d times, want %d", got, tc.polls)
			}
			if !h.Health().Healthy(time.Now()) {
				t.Fatal("a RUNNING job must mark the issuer reachable")
			}
		})
	}
}

// TestDefaults checks what New fills in when the config leaves it open.
// That is the grants dir, the poll period, scontrol as the probe, and
// SIGTERM to fiberd when the job ends.
func TestDefaults(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"the grants dir is the job's and the directory is polled every 2s", func(t *testing.T) {
			h, err := New(Config{Env: jobEnv, CgroupMount: fakeCgroup(t), Probe: []string{}})
			if err != nil {
				t.Fatal(err)
			}
			if h.cfg.GrantsDir != "/run/fiberd/job-4242/grants" || h.cfg.Poll != 2*time.Second {
				t.Fatalf("grants dir %q every %s, want /run/fiberd/job-4242/grants every 2s", h.cfg.GrantsDir, h.cfg.Poll)
			}
		}},
		{"the probe is scontrol show job -o <id>", func(t *testing.T) {
			probe := &fakeProbe{}
			probe.set("RUNNING")
			h, err := New(Config{Env: jobEnv, CgroupMount: fakeCgroup(t), RunProbe: probe.run, OnJobEnd: func() {}})
			if err != nil {
				t.Fatal(err)
			}
			h.health.MarkSync(time.Now().Add(-time.Hour))
			h.poll(context.Background())
			if probe.calls() != 1 || strings.Join(probe.argvs[0], " ") != "scontrol show job -o 4242" {
				t.Fatalf("probe argv = %q, want scontrol show job -o 4242", probe.argvs)
			}
			if !h.Health().Healthy(time.Now()) {
				t.Fatal("scontrol saying RUNNING must mark the issuer reachable")
			}
		}},
		{"the end of the job is the default, SIGTERM to fiberd", func(t *testing.T) {
			old := defaultOnJobEnd
			t.Cleanup(func() { defaultOnJobEnd = old })
			ended := 0
			defaultOnJobEnd = func() { ended++ }
			probe := &fakeProbe{}
			probe.set("CANCELLED")
			h, err := New(Config{Env: jobEnv, CgroupMount: fakeCgroup(t), Probe: scontrol, RunProbe: probe.run})
			if err != nil {
				t.Fatal(err)
			}
			h.poll(context.Background())
			if ended != 1 {
				t.Fatalf("the default OnJobEnd ran %d times, want once", ended)
			}
		}},
		{"the default probe runner execs the command", func(t *testing.T) {
			h, err := New(Config{Env: jobEnv, CgroupMount: fakeCgroup(t), Probe: scontrol, OnJobEnd: func() {}})
			if err != nil {
				t.Fatal(err)
			}
			// Only the choice is checked here. Running it is the integration
			// suite's job (TestSlurmHomeSIGTERMOnJobEnd under tests/).
			if h.cfg.RunProbe == nil {
				t.Fatal("RunProbe left nil")
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, tc.run)
	}
}
