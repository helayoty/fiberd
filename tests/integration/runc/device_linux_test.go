//go:build linux && integration

package runctest

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	runcbackend "github.com/helayoty/fiberd/pkg/backend/runc"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/runtime/host"
)

// TestDeviceOnRunc runs the reference engine as a runc container's init.
// The grant's device channel reaches the zygote's environment, which on
// main it never did. A fiber reserves under its own fence, which the
// engine names from the fiber's cgroup leaf as seen inside the
// container, and the slice is gone once the fiber is released.
func TestDeviceOnRunc(t *testing.T) {
	g := core.Grant{UID: "rdev", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20,
		DeviceBudget: core.DeviceBudget{Bytes: 4 << 20, Class: "sim"}}
	hm := newHome(t, func(_ *runcbackend.Options, hc *host.Config) {
		hc.Templates = map[string]string{"default": "/bin/refzygote --heap-mb 32 --device-mb 8"}
	})
	hm.rt.(core.DeviceAware).AttachDevices(g.UID, core.DeviceChannel{Kind: "static", Devices: []string{"/dev/sim0", "/dev/sim1"}})
	ctx := context.Background()
	if err := hm.rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	dc := hm.rt.(core.DeviceCapable)
	deadline := time.Now().Add(5 * time.Second)
	for !dc.OffersDevice(g.UID, "sim") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !dc.OffersDevice(g.UID, "sim") {
		t.Fatal("the engine never reported its device")
	}
	cases := []struct {
		name  string
		check func(t *testing.T)
	}{
		{name: "the device channel is in the zygote's environment", check: func(t *testing.T) {
			env, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", hm.zygotePID(t, g.UID)))
			if err != nil {
				t.Fatal(err)
			}
			want := []byte("FIBERD_DEVICES=/dev/sim0,/dev/sim1")
			for _, kv := range bytes.Split(env, []byte{0}) {
				if bytes.Equal(kv, want) {
					return
				}
			}
			t.Fatalf("the zygote's environment %q lacks %s", strings.ReplaceAll(string(env), "\x00", " "), want)
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
