package home_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/endpoint"

	"github.com/helayoty/fiberd/examples/slurm/home"
)

func env(over map[string]string) func(string) string {
	base := map[string]string{
		"SLURM_JOB_ID": "4242", "SLURM_JOB_NAME": "fiberd-grant", "SLURM_JOB_USER": "heba", "SLURM_JOB_ACCOUNT": "ml",
		"SLURM_JOB_PARTITION": "gpu", "SLURMD_NODENAME": "localhost", "SLURM_JOB_NODELIST": "node[1-2]",
		"SLURM_CPUS_ON_NODE": "4", "SLURM_JOB_GRES": "gpu:2", "CUDA_VISIBLE_DEVICES": "0,1",
	}
	for k, v := range over {
		base[k] = v
	}
	return func(k string) string { return base[k] }
}

// probeScript writes a shell script that reports the state a file names,
// so a test flips the job's state under the home.
func probeScript(t *testing.T, dir string) (probe []string, set func(state string)) {
	stateFile := filepath.Join(dir, "state")
	set = func(s string) { _ = os.WriteFile(stateFile, []byte(s), 0o644) }
	set("RUNNING")
	script := filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho \"JobId=4242 JobName=x JobState=$(cat "+stateFile+") NodeList=localhost\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return []string{"/bin/sh", script}, set
}

func newHome(t *testing.T, over map[string]string, probe []string, onEnd func()) *home.Home {
	dir := t.TempDir()
	cg := filepath.Join(dir, "cgroup")
	_ = os.MkdirAll(cg, 0o755)
	_ = os.WriteFile(filepath.Join(cg, "cgroup.subtree_control"), []byte("memory pids\n"), 0o644)
	_ = os.WriteFile(filepath.Join(cg, "cgroup.procs"), nil, 0o644)
	if onEnd == nil {
		onEnd = func() { t.Error("OnJobEnd called although the job never ended") }
	}
	h, err := home.New(home.Config{
		Env: env(over), GrantsDir: filepath.Join(dir, "grants"), Poll: 20 * time.Millisecond, StaleTTL: 100 * time.Millisecond,
		CgroupMount: cg, Family: endpoint.Inet4, Host: "10.9.8.7", ListenPort: "8484", Probe: probe, OnJobEnd: onEnd,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestScopeFabricEndpointAndCPUBound(t *testing.T) {
	h := newHome(t, nil, []string{}, nil)
	if h.Name() != "slurm" || !strings.HasSuffix(h.CgroupRoot(), "/cgroup/fiberd") {
		t.Fatalf("name %q cgroup root %q", h.Name(), h.CgroupRoot())
	}
	got := map[string]string{}
	for _, c := range h.Scope() {
		got[c.Name] = c.Value
	}
	want := map[string]string{"job_id": "4242", "job_name": "fiberd-grant", "user": "heba", "account": "ml", "partition": "gpu",
		"node": "localhost", "nodelist": "node[1-2]", "gres": "gpu:2", "cpus": "4"}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("scope %s = %q, want %q (all %v)", k, got[k], v, got)
		}
	}
	if h.EndpointHost() != "10.9.8.7" || h.AdvertisedEndpoint() != "10.9.8.7:8484" {
		t.Fatalf("endpoint host %q advertised %q", h.EndpointHost(), h.AdvertisedEndpoint())
	}
	ctx := context.Background()
	fc, release, err := h.Fabric(ctx, core.Grant{UID: "g", FiberMax: 4})
	if err != nil || fc.Kind != "gres" || fc.Detail != "gpu:2" || strings.Join(fc.Devices, ",") != "/dev/nvidia0,/dev/nvidia1" {
		t.Fatalf("fabric = %+v (%v)", fc, err)
	}
	release()
	// The allocation bounds capacity: fibers.max above its CPUs is refused.
	if _, _, err := h.Fabric(ctx, core.Grant{UID: "big", FiberMax: 5}); err == nil || !strings.Contains(err.Error(), "4 CPUs") {
		t.Fatalf("fabric for 5 fibers on 4 CPUs = %v, want a refusal", err)
	}
	// Unlimited fibers (0) and an allocation without a CPU count pass.
	if _, _, err := h.Fabric(ctx, core.Grant{UID: "any"}); err != nil {
		t.Fatal(err)
	}
	h2 := newHome(t, map[string]string{"SLURM_CPUS_ON_NODE": "", "SLURM_JOB_GRES": "", "CUDA_VISIBLE_DEVICES": ""}, []string{}, nil)
	fc, _, err = h2.Fabric(ctx, core.Grant{UID: "g", FiberMax: 64})
	if err != nil || fc.Kind != "" || len(fc.Devices) != 0 {
		t.Fatalf("fabric without GRES = %+v (%v)", fc, err)
	}
}

func TestOutsideAnAllocationIsAnError(t *testing.T) {
	_, err := home.New(home.Config{Env: env(map[string]string{"SLURM_JOB_ID": ""})})
	if err == nil || !strings.Contains(err.Error(), "SLURM_JOB_ID") {
		t.Fatalf("err = %v", err)
	}
}

func TestProbeIsLivenessAndTerminalStateIsScopeLoss(t *testing.T) {
	probe, set := probeScript(t, t.TempDir())
	var mu sync.Mutex
	var reasons []string
	var ended int
	h := newHome(t, nil, probe, func() { mu.Lock(); ended++; mu.Unlock() })
	h.OnScopeLost(func(_ context.Context, r string) {
		mu.Lock()
		reasons = append(reasons, r)
		mu.Unlock()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)
	time.Sleep(120 * time.Millisecond)
	if !h.Health().Healthy(time.Now()) {
		t.Fatal("job RUNNING: lane must be healthy")
	}
	mu.Lock()
	if len(reasons) != 0 {
		t.Fatalf("scope lost while RUNNING: %v", reasons)
	}
	mu.Unlock()
	set("COMPLETING")
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(reasons) != 1 || reasons[0] != "job 4242 is COMPLETING" {
		t.Fatalf("reasons = %v, want exactly one for COMPLETING", reasons)
	}
	// The fences are revoked first, then the agent leaves with the job,
	// once.
	if ended != 1 {
		t.Fatalf("OnJobEnd calls = %d, want 1", ended)
	}
}

func TestProbeSilenceIsUnhealthyAndLaneOverrideWorks(t *testing.T) {
	h := newHome(t, nil, []string{"/bin/sh", "-c", "exit 1"}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)
	time.Sleep(250 * time.Millisecond)
	if h.Health().Healthy(time.Now()) {
		t.Fatal("probe failing past the stale TTL: lane must be stale")
	}
	h.SetLane(true)
	if !h.Health().Healthy(time.Now()) {
		t.Fatal("SetLane(true) must recover the lane")
	}
	h.SetLane(false)
	if h.Health().Healthy(time.Now()) {
		t.Fatal("SetLane(false) must make the lane stale")
	}
}
