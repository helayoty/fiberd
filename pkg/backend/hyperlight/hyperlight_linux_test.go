//go:build linux

package hyperlight

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
)

// homePlatform is what pkg/runtime/host records at open. It is the host's
// own facts, with the backend's non-empty ones in their place.
func homePlatform(be backend.Backend) artifact.Platform {
	host := artifact.Host()
	bp := be.(backend.Platformer).Platform()
	for dst, v := range map[*string]string{&host.Arch: bp.Arch, &host.Kernel: bp.Kernel, &host.Libc: bp.Libc} {
		if v != "" {
			*dst = v
		}
	}
	return host
}

func TestNew(t *testing.T) {
	cases := []struct {
		name     string
		starter  *fakeStarter
		guest    string // "" for none, "present" or "missing"
		wantTier core.Tier
		wantWhy  string
	}{
		{name: "a helper that reports its four facts", starter: says(kvmIntel), wantTier: core.TierSnapshot},
		{name: "the fake helper", starter: says(fake), wantTier: core.TierSnapshot},
		{name: "a helper that cannot say what it is", starter: &fakeStarter{versionErr: errors.New("exit status 1")}, wantWhy: "unusable"},
		{name: "no helper at all", starter: &fakeStarter{versionErr: os.ErrNotExist}, wantWhy: "unusable"},
		{name: "a helper from before the facts", starter: says("hyperlight-helper/0.1.0"), wantWhy: "want 4 facts"},
		{name: "a helper short one fact", starter: says("fiberd-hyperlight-helper/0.1.0 hyperlight_host/0.17.0 kvm"), wantWhy: "want 4 facts"},
		{name: "only the first line of --version counts", starter: &fakeStarter{version: kvmIntel + "\nbuilt yesterday"}, wantTier: core.TierSnapshot},
		{name: "a guest that is there", starter: says(kvmIntel), guest: "present", wantTier: core.TierSnapshot},
		{name: "a guest that is not there", starter: says(kvmIntel), guest: "missing", wantWhy: "guest unusable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opt := Options{Helper: "helper"}
			if c.guest != "" {
				opt.Guest = filepath.Join(t.TempDir(), "guest.bin")
				if c.guest == "present" {
					if err := os.WriteFile(opt.Guest, []byte("guest"), 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}
			be := newFake(t, opt, c.starter)
			if be.Tier() != c.wantTier {
				t.Fatalf("tier = %s, want %s", be.Tier(), c.wantTier)
			}
			// A backend without a tier says why, and only then.
			why := be.ProbeErr()
			if (why == nil) != (c.wantWhy == "") {
				t.Fatalf("ProbeErr = %v with tier %s", why, be.Tier())
			}
			if c.wantWhy != "" && !strings.Contains(why.Error(), c.wantWhy) {
				t.Fatalf("ProbeErr = %v, want it to say %q", why, c.wantWhy)
			}
			// New only asks for the version. Nothing is started until a warm.
			if n := len(c.starter.started()); n != 0 {
				t.Fatalf("New started %d helpers", n)
			}
		})
	}
}

// TestPlatformParity offers a snapshot made through one helper to a home
// running another. Parity must refuse every fact that Hyperlight or the
// helper would refuse at load, and pass the same facts.
func TestPlatformParity(t *testing.T) {
	cases := []struct {
		name   string
		home   string
		made   string
		parity artifact.Parity
		wantOK bool
	}{
		{"same helper, hyperlight, hypervisor and cpu", kvmIntel, kvmIntel, artifact.Strict, true},
		{"another helper version", kvmIntel, "fiberd-hyperlight-helper/0.2.0 hyperlight_host/0.17.0 kvm GenuineIntel", artifact.Strict, false},
		{"another hyperlight version", kvmIntel, "fiberd-hyperlight-helper/0.1.0 hyperlight_host/0.18.0 kvm GenuineIntel", artifact.Strict, false},
		{"another hypervisor", kvmIntel, "fiberd-hyperlight-helper/0.1.0 hyperlight_host/0.17.0 mshv GenuineIntel", artifact.Strict, false},
		{"another cpu vendor", kvmIntel, "fiberd-hyperlight-helper/0.1.0 hyperlight_host/0.17.0 kvm AuthenticAMD", artifact.Strict, false},
		{"the fake helper's parks on a real home", kvmIntel, fake, artifact.Strict, false},
		{"a hyperlight patch release under kernel=series", kvmIntel, "fiberd-hyperlight-helper/0.1.0 hyperlight_host/0.17.1 kvm GenuineIntel",
			artifact.Parity{Kernel: artifact.ParitySeries, Libc: artifact.ParityExact}, true},
		{"another hypervisor under kernel=series", kvmIntel, "fiberd-hyperlight-helper/0.1.0 hyperlight_host/0.17.0 mshv GenuineIntel",
			artifact.Parity{Kernel: artifact.ParitySeries, Libc: artifact.ParityExact}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home := homePlatform(newFake(t, Options{Helper: "home"}, says(c.home)))
			made := homePlatform(newFake(t, Options{Helper: "made"}, says(c.made)))
			err := c.parity.Check(home, made)
			if c.wantOK && err != nil {
				t.Fatalf("Check(%s, %s) = %v, want nil", home, made, err)
			}
			if !c.wantOK && !errors.Is(err, artifact.ErrParity) {
				t.Fatalf("Check(%s, %s) = %v, want %v", home, made, err, artifact.ErrParity)
			}
		})
	}
}

// The facts the host recorded at open are what a warm's parks are filed
// under, so a READY that reports other facts must not warm.
func TestWarmHoldsHelperToItsFacts(t *testing.T) {
	cases := []struct {
		name    string
		ready   string
		wantErr string
	}{
		{"READY agrees with --version", kvmIntel, ""},
		{"READY from another helper version", "fiberd-hyperlight-helper/0.2.0 hyperlight_host/0.17.0 kvm GenuineIntel", "reported"},
		{"READY on another hypervisor", "fiberd-hyperlight-helper/0.1.0 hyperlight_host/0.17.0 mshv GenuineIntel", "reported"},
		{"READY without facts", "", "want 4 facts"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &fakeStarter{version: kvmIntel, body: ready(c.ready)}
			be := newFake(t, Options{Helper: "helper"}, s)
			_, err := be.Warm(warmCtx(t), warmSpec(t.TempDir()))
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("Warm: %v", err)
				}
				return
			}
			if err == nil || !errors.Is(err, ErrHelper) || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("Warm = %v, want ErrHelper containing %q", err, c.wantErr)
			}
			// A helper that is held to its facts is ended, not left talking.
			if r := s.started()[0]; !r.killed.Load() || !r.waited.Load() {
				t.Fatalf("the refused helper was killed %v and reaped %v", r.killed.Load(), r.waited.Load())
			}
		})
	}
}

// TestWarm checks what the helper is started with, and every way it fails
// to come up. What only a real process shows, the cgroup it is born in
// and that it is reaped, is tests/hyperlight TestHelperStartsInCgroup.
func TestWarm(t *testing.T) {
	cases := []struct {
		name    string
		starter *fakeStarter // nil for one that says READY and holds
		opt     func(t *testing.T) Options
		setup   func(t *testing.T, sp *backend.WarmSpec)
		ctx     func(t *testing.T) context.Context
		wantIs  error
		wantErr string
		check   func(t *testing.T, be *Backend, sp backend.WarmSpec, w backend.Warm, r *fakeRun)
	}{
		{name: "the template's arguments follow the guest",
			opt: func(t *testing.T) Options {
				guest := filepath.Join(t.TempDir(), "guest.bin")
				if err := os.WriteFile(guest, []byte("guest"), 0o644); err != nil {
					t.Fatal(err)
				}
				return Options{Helper: "helper", Guest: guest}
			},
			setup: func(_ *testing.T, sp *backend.WarmSpec) {
				sp.Template.Argv = []string{"guest", "--init-ms", "5"}
			},
			check: func(t *testing.T, be *Backend, sp backend.WarmSpec, w backend.Warm, r *fakeRun) {
				if w.ID != sp.GrantUID || w.PID != r.pid {
					t.Errorf("Warm = %+v, want %s with pid %d", w, sp.GrantUID, r.pid)
				}
				if want := []string{"--guest", be.opt.Guest, "--init-ms", "5"}; !reflect.DeepEqual(r.args, want) {
					t.Errorf("helper args = %q, want %q", r.args, want)
				}
			}},
		{name: "a bare template passes nothing",
			setup: func(_ *testing.T, sp *backend.WarmSpec) {
				sp.Template.Argv = []string{"guest"}
			},
			check: func(t *testing.T, _ *Backend, _ backend.WarmSpec, _ backend.Warm, r *fakeRun) {
				if len(r.args) != 0 {
					t.Errorf("helper args = %q, want none", r.args)
				}
			}},
		{name: "the helper runs in the run directory with the grant's cgroup",
			setup: func(_ *testing.T, sp *backend.WarmSpec) { sp.CgroupFD = 7 },
			check: func(t *testing.T, _ *Backend, sp backend.WarmSpec, _ backend.Warm, r *fakeRun) {
				if r.workDir != sp.WorkDir || r.cgroupFD != 7 {
					t.Errorf("helper started in %q with cgroup %d, want %q and 7", r.workDir, r.cgroupFD, sp.WorkDir)
				}
			}},
		{name: "the helper's output goes to the zygote log",
			starter: &fakeStarter{version: kvmIntel, body: func(r *fakeRun) {
				_, _ = fmt.Fprintln(r.log, "hello from the helper")
				ready(kvmIntel)(r)
			}},
			check: func(t *testing.T, _ *Backend, sp backend.WarmSpec, _ backend.Warm, _ *fakeRun) {
				if b, err := os.ReadFile(filepath.Join(sp.WorkDir, "zygote.log")); err != nil || !strings.Contains(string(b), "hello from the helper") {
					t.Errorf("zygote.log = %q, %v", b, err)
				}
			}},
		{name: "no usable helper", wantErr: "helper or guest unavailable",
			starter: &fakeStarter{versionErr: os.ErrNotExist}},
		{name: "the run directory cannot be made", wantErr: "not a directory",
			setup: func(t *testing.T, sp *backend.WarmSpec) {
				if err := os.WriteFile(filepath.Dir(sp.WorkDir), nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "the log cannot be opened", wantErr: "is a directory",
			setup: func(t *testing.T, sp *backend.WarmSpec) {
				if err := os.MkdirAll(filepath.Join(sp.WorkDir, "zygote.log"), 0o755); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "the helper cannot be started", wantErr: "start helper", wantIs: os.ErrPermission,
			starter: &fakeStarter{version: kvmIntel, startErr: os.ErrPermission}},
		{name: "the helper exits before READY", wantIs: io.EOF, wantErr: "did not become ready",
			starter: &fakeStarter{version: kvmIntel, body: func(*fakeRun) {}}},
		{name: "the helper says something else first", wantIs: ErrHelper, wantErr: "expected READY",
			starter: &fakeStarter{version: kvmIntel, body: func(r *fakeRun) {
				_, _ = fmt.Fprintln(r.ctl, "HELLO")
				r.hold()
			}}},
		{name: "the caller gives up", wantIs: context.DeadlineExceeded,
			starter: &fakeStarter{version: kvmIntel, body: (*fakeRun).hold},
			ctx: func(t *testing.T) context.Context {
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				t.Cleanup(cancel)
				return ctx
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.starter
			if s == nil {
				s = says(kvmIntel)
			}
			opt := Options{Helper: "helper"}
			if tc.opt != nil {
				opt = tc.opt(t)
			}
			be := newFake(t, opt, s)
			sp := warmSpec(filepath.Join(t.TempDir(), "run", "g1"))
			if tc.setup != nil {
				tc.setup(t, &sp)
			}
			ctx := warmCtx(t)
			if tc.ctx != nil {
				ctx = tc.ctx(t)
			}
			w, err := be.Warm(ctx, sp)
			if tc.wantErr != "" || tc.wantIs != nil {
				if err == nil {
					t.Fatalf("Warm = %+v, want an error (%s %v)", w, tc.wantErr, tc.wantIs)
				}
				if tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Warm = %v, want an error containing %q", err, tc.wantErr)
				}
				if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
					t.Fatalf("Warm = %v, want %v", err, tc.wantIs)
				}
				if _, ok := be.warmOf(sp.GrantUID); ok {
					t.Fatal("a warm that failed is registered")
				}
				// The helper it started, if any, is killed and reaped.
				for _, r := range s.started() {
					awaitRun(t, r)
					if !r.killed.Load() || !r.waited.Load() {
						t.Fatalf("helper %d: killed %v, reaped %v", r.pid, r.killed.Load(), r.waited.Load())
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("Warm: %v", err)
			}
			r := s.started()[0]
			tc.check(t, be, sp, w, r)
			// Close ends the helper, and the reaper Warm started takes it.
			be.Close()
			awaitRun(t, r)
			if !r.killed.Load() {
				t.Fatal("Close did not kill the helper")
			}
			for deadline := time.Now().Add(5 * time.Second); !r.waited.Load(); time.Sleep(time.Millisecond) {
				if time.Now().After(deadline) {
					t.Fatal("the helper was not reaped after Close")
				}
			}
		})
	}
}
