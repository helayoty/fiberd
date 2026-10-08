//go:build linux

package hyperlight

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
)

const (
	kvmIntel = "fiberd-hyperlight-helper/0.1.0 hyperlight_host/0.17.0 kvm GenuineIntel"
	fake     = "fakehelper/1 none none none"
)

// fakeHelper writes a helper that answers `--version` with the version
// command (an echo, or a failure) and otherwise says READY on fd 3 and
// waits for fiberd to hang up.
func fakeHelper(t *testing.T, versionCmd, ready string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "helper")
	script := "#!/bin/sh\nif [ \"$1\" = --version ]; then " + versionCmd + "; fi\n" +
		"echo \"READY " + ready + "\" >&3\nexec cat <&3 >/dev/null\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func says(facts string) string { return "echo '" + facts + "'; exit 0" }

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
		name       string
		versionCmd string
		guest      string // "" for none, "present" or "missing"
		wantTier   core.Tier
	}{
		{"a helper that reports its four facts", says(kvmIntel), "", core.TierSnapshot},
		{"the fake helper", says(fake), "", core.TierSnapshot},
		{"a helper that cannot say what it is", "exit 1", "", core.TierUnspecified},
		{"a helper from before the facts", says("hyperlight-helper/0.1.0"), "", core.TierUnspecified},
		{"a helper short one fact", says("fiberd-hyperlight-helper/0.1.0 hyperlight_host/0.17.0 kvm"), "", core.TierUnspecified},
		{"a guest that is there", says(kvmIntel), "present", core.TierSnapshot},
		{"a guest that is not there", says(kvmIntel), "missing", core.TierUnspecified},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opt := Options{Helper: fakeHelper(t, c.versionCmd, kvmIntel)}
			if c.guest != "" {
				opt.Guest = filepath.Join(t.TempDir(), "guest.bin")
				if c.guest == "present" {
					if err := os.WriteFile(opt.Guest, []byte("guest"), 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}
			be := New(opt)
			if be.Tier() != c.wantTier {
				t.Fatalf("tier = %s, want %s", be.Tier(), c.wantTier)
			}
			// A backend without a tier says why, and only then.
			if why := be.(backend.Prober).ProbeErr(); (why == nil) != (c.wantTier != core.TierUnspecified) {
				t.Fatalf("ProbeErr = %v with tier %s", why, be.Tier())
			}
		})
	}
	t.Run("no helper at all", func(t *testing.T) {
		be := New(Options{Helper: filepath.Join(t.TempDir(), "missing")})
		if be.Tier() != core.TierUnspecified {
			t.Fatalf("tier = %s, want unspecified", be.Tier())
		}
		if why := be.(backend.Prober).ProbeErr(); why == nil || !strings.Contains(why.Error(), "unusable") {
			t.Fatalf("ProbeErr = %v, want the helper named unusable", why)
		}
	})
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
			home := homePlatform(New(Options{Helper: fakeHelper(t, says(c.home), c.home)}))
			made := homePlatform(New(Options{Helper: fakeHelper(t, says(c.made), c.made)}))
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
			be := New(Options{Helper: fakeHelper(t, says(kvmIntel), c.ready)})
			defer be.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := be.Warm(ctx, backend.WarmSpec{GrantUID: "g", WorkDir: t.TempDir(), CgroupFD: -1, ProbeCgroupFD: -1})
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("Warm: %v", err)
				}
				return
			}
			if err == nil || !errors.Is(err, ErrHelper) || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("Warm = %v, want ErrHelper containing %q", err, c.wantErr)
			}
		})
	}
}
