package home

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
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

// sh is a probe that runs script.
func sh(script string) []string { return []string{"/bin/sh", "-c", script} }

// TestPoll checks one probe of slurmctld at a time. The lane starts
// stale, so only a poll that counts as liveness makes it healthy.
func TestPoll(t *testing.T) {
	cases := []struct {
		name    string
		probe   []string
		paused  bool
		noHook  bool
		polls   int
		healthy bool
		reasons []string
		ended   int
	}{
		{name: "no probe: the timer is liveness", probe: []string{}, polls: 1, healthy: true},
		{name: "no probe while the lane is paused: it stays stale", probe: []string{}, paused: true, polls: 1},
		{name: "a failing probe leaves the lane stale", probe: sh("echo slurmctld down; exit 3"), polls: 1},
		{name: "an answer without JobState leaves the lane stale", probe: sh("echo JobId=4242"), polls: 1},
		{name: "RUNNING is liveness", probe: sh("echo JobId=4242 JobState=RUNNING"), polls: 1, healthy: true},
		{name: "PENDING is liveness", probe: sh("echo JobState=PENDING"), polls: 1, healthy: true},
		{name: "RUNNING while the lane is paused: it stays stale", probe: sh("echo JobState=RUNNING"), paused: true, polls: 1},
		{name: "a terminal state is scope loss once, however often it is seen", probe: sh("echo JobState=NODE_FAIL"), polls: 3,
			reasons: []string{"job 4242 is NODE_FAIL"}, ended: 1},
		{name: "without a scope-loss hook the agent still leaves with the job", probe: sh("echo JobState=COMPLETED"), noHook: true, polls: 2,
			ended: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ended := 0
			h, err := New(Config{Env: jobEnv, CgroupMount: fakeCgroup(t), StaleTTL: time.Minute, Probe: tc.probe,
				OnJobEnd: func() { ended++ }})
			if err != nil {
				t.Fatal(err)
			}
			h.health.MarkSync(time.Now().Add(-time.Hour))
			if tc.paused {
				h.SetLane(false)
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
		})
	}
}

// TestDefaults checks what New fills in when the config leaves it open.
// That is the grants dir, the poll period, scontrol as the probe, and
// SIGTERM to the agent when the job ends.
func TestDefaults(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"the grants dir is the job's and the lane polls every 2s", func(t *testing.T) {
			h, err := New(Config{Env: jobEnv, CgroupMount: fakeCgroup(t), Probe: []string{}})
			if err != nil {
				t.Fatal(err)
			}
			if h.cfg.GrantsDir != "/run/fiberd/job-4242/grants" || h.cfg.Poll != 2*time.Second {
				t.Fatalf("grants dir %q every %s, want /run/fiberd/job-4242/grants every 2s", h.cfg.GrantsDir, h.cfg.Poll)
			}
		}},
		{"the probe is scontrol show job -o <id>", func(t *testing.T) {
			bin := t.TempDir()
			args := filepath.Join(bin, "args")
			script := "#!/bin/sh\necho \"$@\" > " + args + "\necho JobId=4242 JobState=RUNNING\n"
			if err := os.WriteFile(filepath.Join(bin, "scontrol"), []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			h, err := New(Config{Env: jobEnv, CgroupMount: fakeCgroup(t), OnJobEnd: func() {}})
			if err != nil {
				t.Fatal(err)
			}
			h.health.MarkSync(time.Now().Add(-time.Hour))
			h.poll(context.Background())
			got, err := os.ReadFile(args)
			if err != nil {
				t.Fatalf("scontrol never ran: %v", err)
			}
			if strings.TrimSpace(string(got)) != "show job -o 4242" {
				t.Fatalf("scontrol args = %q, want show job -o 4242", got)
			}
			if !h.Health().Healthy(time.Now()) {
				t.Fatal("scontrol saying RUNNING must make the lane healthy")
			}
		}},
		{"the end of the job is SIGTERM to the agent", func(t *testing.T) {
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGTERM)
			defer signal.Stop(sig)
			h, err := New(Config{Env: jobEnv, CgroupMount: fakeCgroup(t), Probe: sh("echo JobState=CANCELLED")})
			if err != nil {
				t.Fatal(err)
			}
			h.poll(context.Background())
			select {
			case <-sig:
			case <-time.After(10 * time.Second):
				t.Fatal("the job ended but the agent got no SIGTERM")
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, tc.run)
	}
}
