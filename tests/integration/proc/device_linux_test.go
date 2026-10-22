//go:build linux && integration

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

// waitDeviceIdle waits for the grant's engine to report nothing used.
func waitDeviceIdle(t *testing.T, rt core.Runtime, grantUID, after string) {
	t.Helper()
	ps := rt.(interface{ DevicePressure() core.PressureSource }).DevicePressure()
	deadline := time.Now().Add(2 * time.Second)
	for {
		p, _ := ps.Pressure(grantUID)
		if p == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("device still %.1f%% used after %s", p, after)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestDeviceBudget: the engine reports each fiber's device slice; the
// host prices it, enforces the grant's device budget by killing the
// fiber with reason oom, and a template without a device refuses to
// offer one. A killed or released fiber's slice goes back to the engine,
// which on main kept it.
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
	waitDeviceIdle(t, rt, g.UID, "the over-budget fiber was killed")
	// The engine's own capacity is also a ceiling: 40 MiB on a 32 MiB device.
	h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 2}, Deadline: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if got := talk(t, h2.Endpoint, "reserve 41943040"); !strings.HasPrefix(got, "err") {
		t.Fatalf("reserve past the engine's capacity = %q, want an error", got)
	}
	if got := talk(t, h2.Endpoint, "reserve 1048576"); got != "ok" {
		t.Fatalf("reserve 1 MiB = %q", got)
	}
	if err := rt.Release(ctx, h2.ID, false); err != nil {
		t.Fatalf("release: %v", err)
	}
	waitDeviceIdle(t, rt, g.UID, "the fiber was released")

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

// TestEngineNamesTheCallersFence: the engine takes a caller's fence from
// its socket peer's cgroup leaf, never from the line. A fiber that names a
// sibling's fence, or one nobody holds, gets "err fence" and the
// sibling's slice survives. On main the engine filed a slice under
// whatever fence the line carried, so the sibling's release freed it.
func TestEngineNamesTheCallersFence(t *testing.T) {
	rt := engineRuntime(t, 32)
	ctx := context.Background()
	g := core.Grant{UID: "d4", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 32 << 20,
		DeviceBudget: core.DeviceBudget{Bytes: 8 << 20, Class: "sim"}}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	dc := rt.(core.DeviceCapable)
	deadline := time.Now().Add(2 * time.Second)
	for !dc.OffersDevice(g.UID, "sim") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !dc.OffersDevice(g.UID, "sim") {
		t.Fatal("engine never reported its device")
	}
	a, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	b, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 2}, Deadline: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if got := talk(t, a.Endpoint, "reserve 2097152"); got != "ok" {
		t.Fatalf("a reserves 2 MiB = %q", got)
	}
	// "engine <line>" has b send the line to the engine as it is. The
	// engine's "stat" answers "<used> <capacity>" at once, so a slice
	// freed or replaced by a wrong row shows in the next one.
	capacity := uint64(32 << 20)
	cases := []struct {
		name string
		line string
		want string
		used uint64 // the engine's total after the line
	}{
		{name: "reserve under the sibling's fence", line: "reserve " + a.ID + " 1048576", want: "err fence", used: 2 << 20},
		{name: "release the sibling's slice", line: "release " + a.ID, want: "err fence", used: 2 << 20},
		{name: "reserve under a fence nobody holds", line: "reserve d4/1/99 1048576", want: "err fence", used: 2 << 20},
		{name: "reserve under another grant's fence", line: "reserve other/1/1 1048576", want: "err fence", used: 2 << 20},
		{name: "a fence with junk after it", line: "reserve " + b.ID + "x 1048576", want: "err fence", used: 2 << 20},
		{name: "reserve under its own fence", line: "reserve " + b.ID + " 1048576", want: "ok", used: 3 << 20},
		{name: "release its own slice", line: "release " + b.ID, want: "ok", used: 2 << 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := talk(t, b.Endpoint, "engine "+tc.line); got != tc.want {
				t.Fatalf("%q = %q, want %q", tc.line, got, tc.want)
			}
			if got, want := talk(t, b.Endpoint, "engine stat"), fmt.Sprintf("%d %d", tc.used, capacity); got != want {
				t.Fatalf("engine stat = %q, want %q", got, want)
			}
		})
	}
	var st core.FiberStats
	for i := 0; i < 100; i++ {
		st, _ = rt.Stats(ctx, a.ID)
		if st.DeviceUsedBytes == 2<<20 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st.DeviceUsedBytes != 2<<20 {
		t.Fatalf("the sibling's slice = %d, want 2 MiB", st.DeviceUsedBytes)
	}
	_ = rt.Release(ctx, a.ID, false)
	_ = rt.Release(ctx, b.ID, false)
	waitDeviceIdle(t, rt, g.UID, "both fibers were released")
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
	// Checked, so an engine no fiber can reach fails here, not after the resume.
	if got := talk(t, h.Endpoint, "reserve 3145728"); got != "ok" {
		t.Fatalf("reserve before park = %q", got)
	}
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
	// took from the resume's record on its channel.
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
