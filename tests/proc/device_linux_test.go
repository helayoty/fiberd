//go:build linux

package proctest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/runtime/host"
)

// readPIDs reads a cgroup.procs file.
func readPIDs(t *testing.T, path string) []int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var pids []int
	for _, f := range strings.Fields(string(data)) {
		var p int
		if _, err := fmt.Sscan(f, &p); err == nil {
			pids = append(pids, p)
		}
	}
	return pids
}

// engineRuntime opens the host runtime over the fork backend with the
// reference workload as an engine: a simulated device of deviceMB.
func engineRuntime(t *testing.T, deviceMB int) core.Runtime {
	t.Helper()
	name := fmt.Sprintf("dev%d", time.Now().UnixNano()%1_000_000)
	tpl := zygoteBin + " --heap-mb 16"
	if deviceMB > 0 {
		tpl += fmt.Sprintf(" --device-mb %d", deviceMB)
	}
	rt, err := newHost(host.Config{
		Templates:  map[string]string{"default": tpl},
		CgroupRoot: filepath.Join(cgRoot, name),
		RunDir:     filepath.Join("/tmp", "fz-"+name),
		DeltaDir:   t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rt.(interface{ Close() }).Close() })
	return rt
}

// TestDeviceBudget: the engine reports each fiber's device slice; the
// host prices it, enforces the grant's device budget by killing the
// fiber with reason oom, and a template without a device refuses to
// offer one.
func TestDeviceBudget(t *testing.T) {
	rt := engineRuntime(t, 32)
	ctx := context.Background()
	g := core.Grant{UID: "d1", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 32 << 20,
		DeviceBudget: core.DeviceBudget{Bytes: 4 << 20, Class: "sim"}}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	dc, ok := rt.(core.DeviceCapable)
	if !ok {
		t.Fatal("host runtime does not implement DeviceCapable")
	}
	// The engine reports its capacity shortly after READY.
	deadline := time.Now().Add(2 * time.Second)
	for !dc.OffersDevice(g.UID, "sim") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !dc.OffersDevice(g.UID, "sim") {
		t.Fatal("engine never reported its device")
	}

	h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if got := talk(t, h.Endpoint, "reserve 2097152"); got != "ok" {
		t.Fatalf("reserve 2 MiB = %q", got)
	}
	// The report reaches the host on the zygote channel; sample it.
	var st core.FiberStats
	for i := 0; i < 100; i++ {
		st, _ = rt.Stats(ctx, h.ID)
		if st.DeviceUsedBytes == 2<<20 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st.DeviceUsedBytes != 2<<20 {
		t.Fatalf("device used = %d, want 2 MiB", st.DeviceUsedBytes)
	}
	if got := talk(t, h.Endpoint, "devfree"); got != "ok" {
		t.Fatalf("devfree = %q", got)
	}
	// Over the device budget: the host kills the fiber and says why.
	if got := talk(t, h.Endpoint, "reserve 8388608"); got != "ok" {
		t.Fatalf("reserve 8 MiB = %q", got)
	}
	select {
	case e := <-rt.Exits():
		if e.FiberID != h.ID || e.Reason != "oom" || !strings.Contains(e.Detail, "device") {
			t.Fatalf("exit = %+v, want oom for %s with a device detail", e, h.ID)
		}
		t.Logf("exit: %s %s", e.Reason, e.Detail)
	case <-time.After(5 * time.Second):
		t.Fatal("no exit after reserving past the device budget")
	}
	// The engine's own capacity is also a ceiling: 40 MiB on a 32 MiB device.
	h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 2}, Deadline: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if got := talk(t, h2.Endpoint, "reserve 41943040"); !strings.HasPrefix(got, "err") {
		t.Fatalf("reserve past the engine's capacity = %q, want an error", got)
	}
	_ = rt.Release(ctx, h2.ID, false)

	// A template that is no engine offers no device.
	plain := engineRuntime(t, 0)
	gp := core.Grant{UID: "d0", TemplateDigest: "sha256:ref", FiberMax: 1}
	if err := plain.PrepareTemplate(ctx, gp); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if plain.(core.DeviceCapable).OffersDevice(gp.UID, "sim") {
		t.Fatal("a plain zygote claimed a device")
	}
}

// TestParkEvictsAndResumeRenegotiates: a park drops the fiber's slice at
// the engine (the device is renegotiated, not checkpointed) and the
// resumed fiber reserves again under its new fence.
func TestParkEvictsAndResumeRenegotiates(t *testing.T) {
	rt := engineRuntime(t, 32)
	ctx := context.Background()
	g := core.Grant{UID: "d2", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 32 << 20,
		DeviceBudget: core.DeviceBudget{Bytes: 8 << 20, Class: "sim"}}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	talk(t, h.Endpoint, "reserve 3145728")
	talk(t, h.Endpoint, "incr")
	ref, err := rt.Park(ctx, h.ID, true)
	if err != nil {
		t.Fatalf("park: %v", err)
	}
	// The engine dropped the slice: nothing is used on the device.
	dr := rt.(interface {
		DevicePressure() core.PressureSource
	}).DevicePressure()
	deadline := time.Now().Add(2 * time.Second)
	for {
		p, _ := dr.Pressure(g.UID)
		if p == 0 || time.Now().After(deadline) {
			if p != 0 {
				t.Fatalf("device still %.1f%% used after park", p)
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 2}, Deadline: 5 * time.Second})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if got := talk(t, h2.Endpoint, "get"); got != "1" {
		t.Fatalf("counter after resume = %q", got)
	}
	// Renegotiate: the slice is filed under the new fence, which the fiber
	// read from the fence file beside its endpoint.
	if got := talk(t, h2.Endpoint, "reserve 1048576"); got != "ok" {
		t.Fatalf("reserve after resume = %q", got)
	}
	var st core.FiberStats
	for i := 0; i < 100; i++ {
		st, _ = rt.Stats(ctx, h2.ID)
		if st.DeviceUsedBytes == 1<<20 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st.DeviceUsedBytes != 1<<20 {
		t.Fatalf("device used after resume under %s = %d, want 1 MiB", h2.ID, st.DeviceUsedBytes)
	}
	_ = rt.Release(ctx, h2.ID, true)
}

// TestEngineLossRewarmsOnDemand: killing the zygote ends its running
// fibers (reported as signal exits), parked deltas stay resumable, and
// the next create warms the template again without a re-admission.
func TestEngineLossRewarmsOnDemand(t *testing.T) {
	rt := engineRuntime(t, 0)
	ctx := context.Background()
	g := core.Grant{UID: "d3", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 32 << 20}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	a, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	s, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 2}, Deadline: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	talk(t, s.Endpoint, "incr")
	ref, err := rt.Park(ctx, s.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	// The zygote's pid is in the grant's zygote cgroup: kill it there.
	procs := filepath.Join(cgRoot, filepath.Base(rt.(interface{ CgroupRoot() string }).CgroupRoot()), g.UID, "zygote", "cgroup.procs")
	pids := readPIDs(t, procs)
	if len(pids) == 0 {
		t.Fatalf("no zygote in %s", procs)
	}
	for _, p := range pids {
		_ = syscall.Kill(p, syscall.SIGKILL)
	}
	select {
	case e := <-rt.Exits():
		if e.FiberID != a.ID {
			t.Fatalf("exit for %s, want the running fiber %s", e.FiberID, a.ID)
		}
		t.Logf("running fiber ended with the engine: %s %s", e.Reason, e.Detail)
	case <-time.After(5 * time.Second):
		t.Fatal("running fiber did not end with its engine")
	}
	// The parked session resumes (no engine needed for a restore) and a
	// fresh create warms the template again.
	r, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 3}, Deadline: 5 * time.Second})
	if err != nil {
		t.Fatalf("resume after engine loss: %v", err)
	}
	if got := talk(t, r.Endpoint, "get"); got != "1" {
		t.Fatalf("counter = %q", got)
	}
	fresh, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 4}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatalf("create after engine loss (re-warm on demand): %v", err)
	}
	if got := talk(t, fresh.Endpoint, "ping"); got != "pong" {
		t.Fatalf("ping = %q", got)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("unreachable")
	}
	_ = rt.Release(ctx, r.ID, true)
	_ = rt.Release(ctx, fresh.ID, false)
}
