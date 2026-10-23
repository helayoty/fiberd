//go:build linux && integration

package runctest

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	runcbackend "github.com/helayoty/fiberd/pkg/backend/runc"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/runtime/host"
	"github.com/helayoty/fiberd/tests/internal/testenv"
)

// refEngine is the reference engine on the host, FIBERD_REFENGINE or the
// checkout's bin/refengine. The test skips without it.
func refEngine(t *testing.T) string {
	t.Helper()
	path := os.Getenv("FIBERD_REFENGINE")
	if path == "" {
		path = filepath.Join(testenv.RepoRoot(), "bin", "refengine")
	}
	if _, err := exec.LookPath(path); err != nil {
		t.Skipf("no reference engine at %s (build it, or set FIBERD_REFENGINE): %v", path, err)
	}
	return path
}

// environOf is the environment of pid, one entry per element.
func environOf(t *testing.T, pid int) [][]byte {
	t.Helper()
	env, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Split(env, []byte{0})
}

// hasEnv reports whether env holds kv exactly.
func hasEnv(env [][]byte, kv string) bool {
	for _, e := range env {
		if string(e) == kv {
			return true
		}
	}
	return false
}

// TestDeviceOnRunc runs the reference engine beside a runc container's
// zygote. fiberd starts the engine on the host, and the zygote learns
// only its socket. The grant's device channel reaches the engine's
// environment and not the zygote's. A fiber reserves under its own fence,
// which the engine names from the fiber's cgroup leaf, and the slice is
// gone once the fiber is released.
func TestDeviceOnRunc(t *testing.T) {
	engine := refEngine(t)
	g := core.Grant{UID: "rdev", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20,
		DeviceBudget: core.DeviceBudget{Bytes: 4 << 20, Class: "sim"}}
	hm := newHome(t, func(_ *runcbackend.Options, hc *host.Config) {
		hc.Templates = map[string]string{"default": "/bin/refzygote --heap-mb 32"}
		hc.Engine = []string{engine, "--sim-mb", "8"}
	})
	hm.rt.(core.DeviceAware).AttachDevices(g.UID, core.DeviceChannel{Kind: "static", Devices: []string{"/dev/sim0", "/dev/sim1"}})
	ctx := context.Background()
	if err := hm.rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	// The grant is warm once the engine said READY, so its offer is in.
	if class, capacity := hm.rt.(core.DeviceCapable).DeviceOffer(g.UID); class != "sim" || capacity == 0 {
		t.Fatalf("DeviceOffer = %q %d, want class sim with some capacity", class, capacity)
	}
	const devices = "FIBERD_DEVICES=/dev/sim0,/dev/sim1"
	cases := []struct {
		name  string
		check func(t *testing.T)
	}{
		{name: "the device channel is in the engine's environment and not the zygote's", check: func(t *testing.T) {
			pids := readPIDs(t, filepath.Join(hm.cgRoot, g.UID, "engine", "cgroup.procs"))
			if len(pids) == 0 {
				t.Fatalf("no engine in %s", g.UID)
			}
			if env := environOf(t, pids[0]); !hasEnv(env, devices) {
				t.Fatalf("the engine's environment %q lacks %s", bytes.Join(env, []byte(" ")), devices)
			}
			if env := environOf(t, hm.zygotePID(t, g.UID)); hasEnv(env, devices) {
				t.Fatalf("the zygote's environment holds %s", devices)
			}
		}},
		{name: "the zygote learns the engine's socket as the container sees it", check: func(t *testing.T) {
			const want = "FIBERD_ENGINE_PATH=/host/engine/engine.sock"
			if env := environOf(t, hm.zygotePID(t, g.UID)); !hasEnv(env, want) {
				t.Fatalf("the zygote's environment %q lacks %s", bytes.Join(env, []byte(" ")), want)
			}
		}},
		{name: "a fiber reserves under its own fence, and its release frees the slice", check: func(t *testing.T) {
			h := clone(t, hm, g, 1)
			if got := talk(t, h.Endpoint, "reserve 1048576"); got != "ok" {
				t.Fatalf("reserve 1 MiB = %q", got)
			}
			var st core.FiberStats
			for i := 0; i < 200; i++ {
				st, _ = hm.rt.Stats(ctx, h.ID)
				if st.DeviceUsedBytes == 1<<20 {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if st.DeviceUsedBytes != 1<<20 {
				t.Fatalf("device used = %d, want 1 MiB", st.DeviceUsedBytes)
			}
			if err := hm.rt.Release(ctx, h.ID, false); err != nil {
				t.Fatalf("release: %v", err)
			}
			ps := hm.rt.(interface{ DevicePressure() core.PressureSource }).DevicePressure()
			deadline := time.Now().Add(2 * time.Second)
			for {
				p, _ := ps.Pressure(g.UID)
				if p == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("device still %.1f%% used after the release", p)
				}
				time.Sleep(10 * time.Millisecond)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, tc.check)
	}
}
