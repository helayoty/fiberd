//go:build linux

package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/endpoint"
	"github.com/helayoty/fiberd/pkg/handoff"
	"github.com/helayoty/fiberd/pkg/sys/cgroup"
)

const mib = 1 << 20

// handoffRouter is a router that listens nowhere. Tests hand fibers
// connections through Deliver.

// needRoot skips a test that needs root. The launcher chowns into mapped
// id ranges and enters namespaces, so these run in the dev container.
func needRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root (run it with hack/dev/run.sh)")
	}
}
func handoffRouter() *handoff.Router { return &handoff.Router{Advertise: "tcp://10.0.0.1:443"} }

var handoffKey = bytes.Repeat([]byte{9}, 32)

// proberBackend is a backend that says why it offers no tier.
type proberBackend struct {
	*fakeBackend
	why error
}

func (b proberBackend) ProbeErr() error { return b.why }

// TestNewRefusals checks that New refuses a bad configuration before
// touching the cgroup tree or the file system.
func TestNewRefusals(t *testing.T) {
	cases := []struct {
		name string
		cfg  func(t *testing.T) Config
		want string // a fragment of the error
	}{
		{name: "no backend", cfg: func(t *testing.T) Config { return Config{CgroupRoot: "/x"} }, want: "Backend is required"},
		{name: "no cgroup root", cfg: func(t *testing.T) Config { return Config{Backend: newFakeBackend(core.TierWarm)} }, want: "CgroupRoot is required"},
		{name: "a handoff router without a key", cfg: func(t *testing.T) Config {
			return Config{Backend: newFakeBackend(core.TierWarm), CgroupRoot: "/x", Handoff: handoffRouter(), HandoffKey: make([]byte, 16)}
		}, want: "HandoffKey of at least 32 bytes"},
		{name: "a cgroup root that cannot be made", cfg: func(t *testing.T) Config {
			f := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(f, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			return Config{Backend: newFakeBackend(core.TierWarm), CgroupRoot: filepath.Join(f, "cg")}
		}, want: "not a directory"},
		{name: "a run directory that cannot be made", cfg: func(t *testing.T) Config {
			c := testConfig(t, newFakeBackend(core.TierWarm))
			f := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(f, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			c.RunDir = filepath.Join(f, "run")
			return c
		}, want: "not a directory"},
		{name: "an endpoint policy whose host is not an address", cfg: func(t *testing.T) Config {
			c := testConfig(t, newFakeBackend(core.TierWarm))
			c.Endpoints = endpoint.Policy{Family: endpoint.Inet4, Host: "nope"}
			return c
		}, want: "endpoint host"},
		{name: "a delta registry without keys", cfg: func(t *testing.T) Config {
			c := testConfig(t, newFakeBackend(core.TierWarm))
			c.DeltaRegistry = "registry.example/deltas"
			return c
		}, want: "DeltaKeys.Signer"},
		{name: "the run directory inside the delta directory", cfg: func(t *testing.T) Config {
			c := testConfig(t, newFakeBackend(core.TierWarm))
			c.RunDir = filepath.Join(c.DeltaDir, "run")
			return c
		}, want: "inside DeltaDir"},
		{name: "a backend that offers no tier", cfg: func(t *testing.T) Config {
			return Config{Backend: newFakeBackend(core.TierUnspecified), CgroupRoot: filepath.Join(t.TempDir(), "cg")}
		}, want: "host: backend fake offers no tier"},
		{name: "a backend that says why it offers no tier", cfg: func(t *testing.T) Config {
			be := proberBackend{newFakeBackend(core.TierUnspecified), errors.New("runsc missing")}
			return Config{Backend: be, CgroupRoot: filepath.Join(t.TempDir(), "cg")}
		}, want: "host: backend fake offers no tier: runsc missing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := New(tc.cfg(t))
			if err == nil {
				r.Close()
				t.Fatalf("New succeeded, want an error mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New = %v, want an error mentioning %q", err, tc.want)
			}
			if strings.Contains(tc.want, "offers no tier") && !errors.Is(err, ErrNoTier) {
				t.Fatalf("New = %v, want ErrNoTier", err)
			}
		})
	}
}

// TestNewRelay checks which homes relay tcp endpoints: a tcp family over
// a backend that does not bind tcp itself. A backend that does (proc) is
// told the tcp address, and a unix home relays nothing.
func TestNewRelay(t *testing.T) {
	withSchemes := func(schemes ...string) backend.Backend {
		return &struct {
			*fakeBackend
			schemesMixin
		}{newFakeBackend(core.TierWarm), schemesMixin{schemes}}
	}
	cases := []struct {
		name   string
		be     backend.Backend
		policy endpoint.Policy
		relay  bool
	}{
		{name: "inet4 over a backend without an EndpointSchemer", be: newFakeBackend(core.TierWarm),
			policy: endpoint.Policy{Family: endpoint.Inet4, Host: "127.0.0.1"}, relay: true},
		{name: "inet6 over a backend that lists other schemes", be: withSchemes("unix", "vsock"),
			policy: endpoint.Policy{Family: endpoint.Inet6, Host: "::1"}, relay: true},
		{name: "inet4 over a backend that binds tcp itself", be: withSchemes("unix", "tcp"),
			policy: endpoint.Policy{Family: endpoint.Inet4, Host: "127.0.0.1"}},
		{name: "unix over a unix-only backend", be: newFakeBackend(core.TierWarm)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testConfig(t, tc.be)
			c.Endpoints = tc.policy
			r, err := New(c)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer r.Close()
			if r.Relays() != tc.relay {
				t.Fatalf("Relays = %v, want %v", r.Relays(), tc.relay)
			}
		})
	}
}

// TestNewPlatform checks that what the home believes about its host is
// detected, then overridden by the backend's facts, then by the
// configuration. The backend's name always overrides. A proc home
// records its template cache path. Paths are made absolute and
// created.
func TestNewPlatform(t *testing.T) {
	detected := artifact.Host()
	named := func(name string) *fakeBackend {
		b := newFakeBackend(core.TierWarm)
		b.name = name
		return b
	}
	cases := []struct {
		name string
		be   backend.Backend
		mod  func(*Config)
		want artifact.Platform
		hide []string // besides the defaults, DeltaDir, PrivateDir, TemplateCache and the run dir rules
		// templates means want.Templates is the home's template cache.
		templates bool
	}{
		{name: "detected, named after the backend", be: newFakeBackend(core.TierWarm),
			want: artifact.Platform{Arch: detected.Arch, Kernel: detected.Kernel, Libc: detected.Libc, Backend: "fake"}},
		{name: "the backend's facts replace the host's", be: &struct {
			*fakeBackend
			platformMixin
		}{newFakeBackend(core.TierWarm), platformMixin{artifact.Platform{Kernel: "runsc-20260101", Libc: "none"}}},
			want: artifact.Platform{Arch: detected.Arch, Kernel: "runsc-20260101", Libc: "none", Backend: "fake"}},
		{name: "the configuration overrides both", be: &struct {
			*fakeBackend
			platformMixin
		}{newFakeBackend(core.TierWarm), platformMixin{artifact.Platform{Kernel: "runsc-20260101"}}},
			mod:  func(c *Config) { c.Platform = artifact.Platform{Arch: "riscv64", Kernel: "6.1.0-test"} },
			want: artifact.Platform{Arch: "riscv64", Kernel: "6.1.0-test", Libc: detected.Libc, Backend: "fake"}},
		{name: "relative paths become absolute and extra directories are hidden", be: newFakeBackend(core.TierWarm),
			mod: func(c *Config) {
				c.RunDir, c.DeltaDir, c.TemplateCache, c.PrivateDir = "rel/run", "rel/deltas", "rel/cache", "rel/private"
				c.FiberHide = []string{"/srv/secrets", "relative/skipped"}
			},
			want: artifact.Platform{Arch: detected.Arch, Kernel: detected.Kernel, Libc: detected.Libc, Backend: "fake"},
			hide: []string{"/srv/secrets"}},
		{name: "a proc home records its template cache path", be: named("proc"), templates: true,
			want: artifact.Platform{Arch: detected.Arch, Kernel: detected.Kernel, Libc: detected.Libc, Backend: "proc"}},
		{name: "a runc home does not, since it binds a copy of its own", be: named("runc"),
			want: artifact.Platform{Arch: detected.Arch, Kernel: detected.Kernel, Libc: detected.Libc, Backend: "runc"}},
		{name: "a gvisor home does not", be: named("gvisor"),
			want: artifact.Platform{Arch: detected.Arch, Kernel: detected.Kernel, Libc: detected.Libc, Backend: "gvisor"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			cwd, _ := os.Getwd()
			r := newTestRuntime(t, tc.be, tc.mod)
			if tc.templates {
				tc.want.Templates = r.cfg.TemplateCache
			}
			if r.host != tc.want {
				t.Fatalf("host platform = %+v, want %+v", r.host, tc.want)
			}
			for _, p := range []string{r.cfg.RunDir, r.cfg.DeltaDir, r.cfg.TemplateCache, r.cfg.CgroupRoot} {
				if !filepath.IsAbs(p) {
					t.Fatalf("path %q is not absolute", p)
				}
				if st, err := os.Stat(p); err != nil || !st.IsDir() {
					t.Fatalf("%s was not created: %v", p, err)
				}
			}
			if r.cfg.PrivateDir != "" && !strings.HasPrefix(r.cfg.PrivateDir, cwd) {
				t.Fatalf("PrivateDir %q was not made absolute under %s", r.cfg.PrivateDir, cwd)
			}
			// The cache is hidden with the keys and the deltas: a proc
			// fiber could rewrite a cached template otherwise.
			want := []string{DefaultFiberHide[0], r.cfg.DeltaDir}
			if r.cfg.PrivateDir != "" {
				want = append(want, r.cfg.PrivateDir)
			}
			want = append(append(want, r.cfg.TemplateCache), tc.hide...)
			if strings.Join(r.hide, ",") != strings.Join(want, ",") {
				t.Fatalf("hide = %v, want %v", r.hide, want)
			}
			if r.Tier() != core.TierWarm || r.CgroupRoot() != r.cfg.CgroupRoot {
				t.Fatalf("Tier %s root %s", r.Tier(), r.CgroupRoot())
			}
		})
	}
}

// TestBackendFacts checks what the runtime relays from its backend's optional
// interfaces, and the answer without them.
func TestBackendFacts(t *testing.T) {
	sb := newSandboxBackend(core.TierSnapshot)
	sb.deadlineMixin = deadlineMixin{3 * time.Second, 9 * time.Second}
	sb.used, sb.capacity, sb.reported = 25, 100, true
	noDevice := newSandboxBackend(core.TierSnapshot)
	noDevice.capacity, noDevice.reported = 0, true
	cases := []struct {
		name            string
		be              backend.Backend
		isolates        bool
		create, resume  time.Duration
		offersDevice    bool
		devicePressure  float64
		handsOff        bool
		handoffRouterOn bool
	}{
		{name: "a fork backend", be: newFakeBackend(core.TierWarm)},
		{name: "a sandbox backend with a device", be: sb, isolates: true, create: 3 * time.Second, resume: 9 * time.Second,
			offersDevice: true, devicePressure: 25, handsOff: true, handoffRouterOn: true},
		{name: "a sandbox whose engine reports no capacity", be: noDevice, isolates: true, handsOff: true, handoffRouterOn: true},
		{name: "a handoff backend without a router", be: newSandboxBackend(core.TierSnapshot), isolates: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRuntime(t, tc.be, func(c *Config) {
				if tc.handoffRouterOn {
					c.Handoff, c.HandoffKey = handoffRouter(), handoffKey
				}
			})
			if got := r.IsolatesTenants(); got != tc.isolates {
				t.Fatalf("IsolatesTenants = %v, want %v", got, tc.isolates)
			}
			if c, rs := r.DefaultDeadlines(); c != tc.create || rs != tc.resume {
				t.Fatalf("DefaultDeadlines = %s %s, want %s %s", c, rs, tc.create, tc.resume)
			}
			if got := r.OffersDevice("g1", "gpu"); got != tc.offersDevice {
				t.Fatalf("OffersDevice = %v, want %v", got, tc.offersDevice)
			}
			p, err := r.DevicePressure().Pressure("g1")
			if err != nil || p != tc.devicePressure {
				t.Fatalf("DevicePressure = %v %v, want %v", p, err, tc.devicePressure)
			}
			if got := r.HandsOff(); got != tc.handsOff {
				t.Fatalf("HandsOff = %v, want %v", got, tc.handsOff)
			}
			if r.Exits() == nil || r.HasDelta(t.TempDir()) {
				t.Fatal("Exits must be a channel and an empty directory is no delta")
			}
		})
	}
}

// TestPrepareTemplate checks the grant's cgroups, the warm instance, the delta
// parent and the block ceiling.
func TestPrepareTemplate(t *testing.T) {
	sized := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 2, WBudgetBytes: 64 * mib}
	cases := []struct {
		name  string
		be    func() backend.Backend
		mod   func(*Config)
		grant core.Grant
		// before runs before PrepareTemplate.
		before  func(t *testing.T, r *Runtime)
		wantErr error  // errors.Is
		errText string // or a fragment
		// check runs after a successful PrepareTemplate.
		check func(t *testing.T, r *Runtime, be backend.Backend)
	}{
		{name: "a sized grant: cgroups, task limits, ceiling, one warm instance", be: func() backend.Backend { return newFakeBackend(core.TierWarm) }, grant: sized,
			check: func(t *testing.T, r *Runtime, be backend.Backend) {
				fb := be.(*fakeBackend)
				spec, ok := fb.warmSpec("g1")
				if !ok || spec.GrantUID != "g1" || strings.Join(spec.Template.Argv, " ") != "/bin/true --template" ||
					spec.Template.Digest != "sha256:tmpl" || spec.WorkDir != filepath.Join(r.cfg.RunDir, "g1") ||
					spec.CgroupFD < 0 || spec.ProbeCgroupFD < 0 || strings.Join(spec.Hide, ",") != strings.Join(r.hide, ",") || spec.Devices != nil {
					t.Fatalf("warm spec = %+v", spec)
				}
				gcg := r.root.Child("g1")
				if !gcg.Child("zygote").Exists() || gcg.Child("probe").Exists() {
					t.Fatal("want the zygote cgroup kept and the probe removed")
				}
				if got := cgUint(t, gcg, "pids.max"); got != 3*fiberPidsMax {
					t.Fatalf("grant pids.max = %d, want %d", got, 3*fiberPidsMax)
				}
				leaf := r.leafMax(sized)
				ceiling := DefaultCeiling(core.Grant{FiberMax: 2, WBudgetBytes: leaf}, 0)
				if got := cgUint(t, gcg, "memory.high"); got != ceiling {
					t.Fatalf("memory.high = %d, want %d", got, ceiling)
				}
				if got := cgUint(t, gcg, "memory.max"); got != ceiling+leaf {
					t.Fatalf("memory.max = %d, want %d", got, ceiling+leaf)
				}
				if cgFile(t, gcg, "memory.swap.max") != "0" {
					t.Fatal("swap must be closed under the ceiling")
				}
				z := r.warmOf("g1")
				if z == nil || z.parentSHA != "" || z.digest != "sha256:tmpl" || z.bytes != 0 || z.total != 0 || z.pid == 0 {
					t.Fatalf("warm = %+v", z)
				}
				if err := r.PrepareTemplate(context.Background(), sized); err != nil || fb.warmed() != 1 {
					t.Fatalf("second prepare: %v, warmed %d times", err, fb.warmed())
				}
			}},
		{name: "an unlimited grant: no task limit, no ceiling", be: func() backend.Backend { return newFakeBackend(core.TierWarm) },
			grant: core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl"},
			check: func(t *testing.T, r *Runtime, _ backend.Backend) {
				gcg := r.root.Child("g1")
				if cgFile(t, gcg, "pids.max") != "max" || cgFile(t, gcg, "memory.high") != "max" {
					t.Fatalf("pids.max %s memory.high %s, want both unlimited", cgFile(t, gcg, "pids.max"), cgFile(t, gcg, "memory.high"))
				}
			}},
		{name: "a configured ceiling", be: func() backend.Backend { return newFakeBackend(core.TierWarm) }, grant: sized,
			mod: func(c *Config) { c.Ceiling = func(core.Grant, uint64) uint64 { return 100 * mib } },
			check: func(t *testing.T, r *Runtime, _ backend.Backend) {
				gcg := r.root.Child("g1")
				if cgUint(t, gcg, "memory.high") != 100*mib || cgUint(t, gcg, "memory.max") != 164*mib {
					t.Fatalf("memory.high %s memory.max %s", cgFile(t, gcg, "memory.high"), cgFile(t, gcg, "memory.max"))
				}
			}},
		{name: "a ceiling that cannot be set is logged, not fatal", be: func() backend.Backend { return newFakeBackend(core.TierWarm) }, grant: sized,
			mod: func(c *Config) { c.Ceiling = func(core.Grant, uint64) uint64 { return 1 } },
			check: func(t *testing.T, r *Runtime, _ backend.Backend) {
				if r.warmOf("g1") == nil {
					t.Fatal("the template must still be warm")
				}
			}},
		{name: "no template for the digest", be: func() backend.Backend { return newFakeBackend(core.TierWarm) }, grant: sized,
			mod:     func(c *Config) { c.Templates = nil },
			wantErr: ErrNoTemplate,
			check: func(t *testing.T, r *Runtime, _ backend.Backend) {
				if r.root.Child("g1").Exists() {
					t.Fatal("a grant without a template got a cgroup")
				}
			}},
		{name: "the backend cannot warm", be: func() backend.Backend {
			b := newFakeBackend(core.TierWarm)
			b.warmErr = errors.New("fake: no zygote")
			return b
		}, grant: sized, errText: "no zygote",
			check: func(t *testing.T, r *Runtime, _ backend.Backend) {
				if r.warmOf("g1") != nil {
					t.Fatal("a failed warm was recorded")
				}
			}},
		{name: "a handoff grant on a backend without handoff", be: func() backend.Backend { return newFakeBackend(core.TierWarm) },
			grant:   core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", Policy: core.Policy{EndpointMode: core.EndpointHandoff}},
			mod:     func(c *Config) { c.Handoff, c.HandoffKey = handoffRouter(), handoffKey },
			wantErr: ErrNoHandoff},
		{name: "a handoff grant: its identity is derived and the caller pinned", be: func() backend.Backend { return newSandboxBackend(core.TierSnapshot) },
			grant: core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", Policy: core.Policy{EndpointMode: core.EndpointHandoff}, CallerThumbprint: "x5t"},
			mod:   func(c *Config) { c.Handoff, c.HandoffKey = handoffRouter(), handoffKey },
			check: func(t *testing.T, r *Runtime, _ backend.Backend) {
				id, ok := r.identities["g1"]
				if !ok || id.caller != "x5t" || id.id.KeySHA256 == "" {
					t.Fatalf("identity = %+v, %v", id, ok)
				}
			}},
		{name: "an id mapper that refuses the grant stops everything", be: func() backend.Backend {
			return &struct {
				*fakeBackend
				idMapperMixin
			}{newFakeBackend(core.TierWarm), idMapperMixin{err: errors.New("fake: id range held by g0")}}
		}, grant: sized, errText: "id range held",
			check: func(t *testing.T, r *Runtime, be backend.Backend) {
				if r.root.Child("g1").Exists() || be.(interface{ warmed() int }).warmed() != 0 {
					t.Fatal("a refused grant got a cgroup or a warm instance")
				}
			}},
		{name: "an id mapper: the grant's root may write cgroup.procs and nothing else", be: func() backend.Backend {
			return &struct {
				*fakeBackend
				idMapperMixin
			}{newFakeBackend(core.TierWarm), idMapperMixin{uid: 65534}}
		}, grant: sized,
			check: func(t *testing.T, r *Runtime, _ backend.Backend) {
				gcg := r.root.Child("g1")
				if got := fileOwner(t, filepath.Join(gcg.Path, "cgroup.procs")); got != 65534 {
					t.Fatalf("cgroup.procs owner = %d, want 65534", got)
				}
				if got := fileOwner(t, filepath.Join(gcg.Path, "memory.max")); got != 0 {
					t.Fatalf("memory.max owner = %d, want root", got)
				}
			}},
		{name: "a checkpointing backend: the warm instance is self-checkpointed into the parent store", be: func() backend.Backend { return newCodecBackend(core.TierCheckpoint) }, grant: sized,
			check: func(t *testing.T, r *Runtime, be backend.Backend) {
				cb := be.(*codecBackend)
				sha := shaOf("zygote pages of g1")
				if z := r.warmOf("g1"); z.parentSHA != sha || cb.calls.Load() != 1 {
					t.Fatalf("parent %q, %d checkpoints, want %s once", z.parentSHA, cb.calls.Load(), sha)
				}
				if !exists(filepath.Join(r.parentsDir(), sha, fakePagesFile)) || exists(filepath.Join(r.cfg.TemplateCache, "zygote-images", "g1")) {
					t.Fatal("the checkpoint must be moved into the store")
				}
				if _, ok := r.parents[sha]; !ok {
					t.Fatal("the parent must be loaded")
				}
			}},
		{name: "a self-checkpoint that fails: parks will be full images", be: func() backend.Backend {
			cb := newCodecBackend(core.TierCheckpoint)
			cb.err = errors.New("fake: criu missing")
			return cb
		}, grant: sized,
			check: func(t *testing.T, r *Runtime, _ backend.Backend) {
				if z := r.warmOf("g1"); z == nil || z.parentSHA != "" {
					t.Fatalf("warm = %+v, want one without a parent", z)
				}
			}},
		{name: "a self-checkpoint the codec cannot load", be: func() backend.Backend {
			cb := newCodecBackend(core.TierCheckpoint)
			cb.failLoadAt = 1
			return cb
		}, grant: sized,
			check: func(t *testing.T, r *Runtime, _ backend.Backend) {
				if z := r.warmOf("g1"); z == nil || z.parentSHA != "" {
					t.Fatalf("warm = %+v, want one without a parent", z)
				}
			}},
		{name: "a codec below the checkpoint tier takes no parent", be: func() backend.Backend { return newCodecBackend(core.TierWarm) }, grant: sized,
			check: func(t *testing.T, r *Runtime, be backend.Backend) {
				if z := r.warmOf("g1"); z.parentSHA != "" || be.(*codecBackend).calls.Load() != 0 {
					t.Fatal("a warm-tier backend was checkpointed")
				}
			}},
		{name: "a sandbox backend: the measured footprint sizes the leaves, tenants are not task-limited", be: func() backend.Backend {
			sb := newSandboxBackend(core.TierSnapshot)
			sb.warm = backend.Warm{Bytes: 10 * mib, TotalBytes: 20 * mib}
			return sb
		}, grant: sized,
			check: func(t *testing.T, r *Runtime, _ backend.Backend) {
				z := r.warmOf("g1")
				if z.bytes != 10*mib || z.total != 20*mib {
					t.Fatalf("footprint = %d/%d", z.bytes, z.total)
				}
				if got := r.leafMax(sized); got != 64*mib+20*mib+10*mib+32*mib {
					t.Fatalf("leafMax = %d", got)
				}
				if got := r.overhead("g1"); got != 10*mib {
					t.Fatalf("overhead = %d", got)
				}
				gcg := r.root.Child("g1")
				if cgFile(t, gcg, "pids.max") != "max" {
					t.Fatal("a sandbox's tenants got a task limit")
				}
				if got := cgUint(t, gcg, "memory.high"); got != DefaultCeiling(core.Grant{FiberMax: 2, WBudgetBytes: r.leafMax(sized)}, 0) {
					t.Fatalf("memory.high = %d", got)
				}
			}},
		{name: "a sandbox backend that measured nothing falls back to the budget", be: func() backend.Backend { return newSandboxBackend(core.TierSnapshot) }, grant: sized,
			check: func(t *testing.T, r *Runtime, _ backend.Backend) {
				if got := r.leafMax(sized); got != 64*mib {
					t.Fatalf("leafMax = %d, want the bare budget", got)
				}
				if got := r.leafMax(core.Grant{UID: "g1"}); got != 0 {
					t.Fatalf("leafMax without a budget = %d", got)
				}
				if got := r.overhead("g9"); got != 0 {
					t.Fatalf("overhead of an unknown grant = %d", got)
				}
			}},
		{name: "the grant's fabric devices reach the warm instance", be: func() backend.Backend { return newFakeBackend(core.TierWarm) }, grant: sized,
			before: func(t *testing.T, r *Runtime) {
				r.AttachFabric("g1", core.FabricChannel{Kind: "static", Devices: []string{"/dev/sim0"}})
			},
			check: func(t *testing.T, r *Runtime, be backend.Backend) {
				spec, _ := be.(*fakeBackend).warmSpec("g1")
				if strings.Join(spec.Devices, ",") != "/dev/sim0" {
					t.Fatalf("devices = %v", spec.Devices)
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := tc.be()
			r := newTestRuntime(t, be, tc.mod)
			if tc.before != nil {
				tc.before(t, r)
			}
			err := r.PrepareTemplate(context.Background(), tc.grant)
			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("PrepareTemplate = %v, want %v", err, tc.wantErr)
				}
			case tc.errText != "":
				if err == nil || !strings.Contains(err.Error(), tc.errText) {
					t.Fatalf("PrepareTemplate = %v, want an error mentioning %q", err, tc.errText)
				}
			case err != nil:
				t.Fatalf("PrepareTemplate: %v", err)
			}
			if tc.check != nil {
				tc.check(t, r, be)
			}
		})
	}
}

// tcpPolicy serves fibers on 127.0.0.1 with two ports.
var tcpPolicy = endpoint.Policy{Family: endpoint.Inet4, Host: "127.0.0.1", PortMin: 20000, PortMax: 20001}

// TestClone checks that a fiber is born into a leaf of its own with the
// endpoint the policy chooses, and every failure leaves nothing behind.
func TestClone(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 4, WBudgetBytes: 64 * mib}
	handoffG := g
	handoffG.Policy.EndpointMode, handoffG.CallerThumbprint = core.EndpointHandoff, "x5t"
	fence := core.Fence{GrantUID: "g1", Epoch: 1, Seq: 1}
	cases := []struct {
		name    string
		be      func() backend.Backend
		mod     func(*Config)
		grant   core.Grant
		prepare bool
		// before runs after PrepareTemplate, before Clone.
		before  func(t *testing.T, r *Runtime)
		spec    core.CloneSpec
		wantErr error
		errText string
		check   func(t *testing.T, r *Runtime, be backend.Backend, h core.FiberHandle)
	}{
		{name: "a fiber in its own leaf on a unix endpoint", be: func() backend.Backend {
			b := newFakeBackend(core.TierWarm)
			b.endpointFile = true
			return b
		}, grant: g, prepare: true,
			spec: core.CloneSpec{Grant: g, Fence: fence, Deadline: 2 * time.Second, Payload: []byte("hello")},
			check: func(t *testing.T, r *Runtime, be backend.Backend, h core.FiberHandle) {
				sock := filepath.Join(r.cfg.RunDir, "g1", "1-1.sock")
				if h.ID != "g1/1/1" || h.Endpoint != "unix://"+sock {
					t.Fatalf("handle = %+v", h)
				}
				leaf := r.root.Child("g1").Child("f-1-1")
				if cgUint(t, leaf, "memory.max") != 64*mib || cgFile(t, leaf, "memory.oom.group") != "1" ||
					cgUint(t, leaf, "pids.max") != fiberPidsMax || cgFile(t, leaf, "memory.swap.max") != "0" {
					t.Fatalf("leaf %s: memory.max %s oom.group %s pids.max %s", leaf.Path, cgFile(t, leaf, "memory.max"),
						cgFile(t, leaf, "memory.oom.group"), cgFile(t, leaf, "pids.max"))
				}
				ff := be.(*fakeBackend).fiber("g1/1/1")
				if ff == nil || ff.spec.Endpoint != sock || !ff.spec.OwnPIDNS || string(ff.spec.Payload) != "hello" ||
					ff.spec.Deadline != 2*time.Second || ff.spec.CgroupFD < 0 || ff.spec.Handoff != nil {
					t.Fatalf("fiber spec = %+v", ff)
				}
				if !exists(sock) {
					t.Fatal("the fake bound no socket")
				}
				r.mu.Lock()
				f := r.fibers["g1/1/1"]
				r.mu.Unlock()
				if f == nil || !f.ready || f.pid == 0 || f.budget != 64*mib || f.quota != deltaQuota(g) || f.port != 0 {
					t.Fatalf("fiber = %+v", f)
				}
				st, err := r.Stats(context.Background(), h.ID)
				if err != nil || st.WUsedBytes != 0 || st.DeviceUsedBytes != 0 {
					t.Fatalf("Stats = %+v %v, want an empty leaf", st, err)
				}
			}},
		{name: "the warm instance is made on demand", be: func() backend.Backend { return newFakeBackend(core.TierWarm) }, grant: g,
			spec: core.CloneSpec{Grant: g, Fence: fence},
			check: func(t *testing.T, r *Runtime, be backend.Backend, h core.FiberHandle) {
				if be.(*fakeBackend).warmed() != 1 || r.warmOf("g1") == nil {
					t.Fatal("clone did not warm the template")
				}
			}},
		{name: "warming on demand fails", be: func() backend.Backend {
			b := newFakeBackend(core.TierWarm)
			b.warmErr = errors.New("fake: no zygote")
			return b
		}, grant: g, spec: core.CloneSpec{Grant: g, Fence: fence}, wantErr: ErrNotPrepared, errText: "no zygote"},
		{name: "the backend refuses the fork", be: func() backend.Backend {
			b := newFakeBackend(core.TierWarm)
			b.cloneErr = errors.New("fake: fork refused")
			return b
		}, grant: g, prepare: true, spec: core.CloneSpec{Grant: g, Fence: fence}, errText: "fork refused",
			check: func(t *testing.T, r *Runtime, _ backend.Backend, _ core.FiberHandle) {
				if r.root.Child("g1").Child("f-1-1").Exists() || len(r.fibers) != 0 {
					t.Fatal("a refused clone left its leaf or its record")
				}
			}},
		{name: "the backend runs out of time: the leaf is killed, then removed", be: func() backend.Backend {
			b := newFakeBackend(core.TierWarm)
			b.cloneErr = context.DeadlineExceeded
			return b
		}, grant: g, prepare: true, spec: core.CloneSpec{Grant: g, Fence: fence}, wantErr: context.DeadlineExceeded,
			check: func(t *testing.T, r *Runtime, _ backend.Backend, _ core.FiberHandle) {
				leaf := r.root.Child("g1").Child("f-1-1")
				waitFor(t, "the leaf to be removed", func() bool { return !leaf.Exists() })
			}},
		{name: "no budget: the leaf has no memory ceiling", be: func() backend.Backend { return newFakeBackend(core.TierWarm) },
			grant: core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl"}, prepare: true,
			spec: core.CloneSpec{Grant: core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl"}, Fence: fence},
			check: func(t *testing.T, r *Runtime, _ backend.Backend, _ core.FiberHandle) {
				leaf := r.root.Child("g1").Child("f-1-1")
				if cgFile(t, leaf, "memory.max") != "max" {
					t.Fatalf("memory.max = %s", cgFile(t, leaf, "memory.max"))
				}
			}},
		{name: "a handoff fiber: identity queued on its channel, routed through the router", be: func() backend.Backend { return newSandboxBackend(core.TierSnapshot) },
			mod:   func(c *Config) { c.Handoff, c.HandoffKey = handoffRouter(), handoffKey },
			grant: handoffG, prepare: true, spec: core.CloneSpec{Grant: handoffG, Fence: fence},
			check: func(t *testing.T, r *Runtime, be backend.Backend, h core.FiberHandle) {
				sb := be.(*sandboxBackend)
				ff := sb.fiber("g1/1/1")
				if ff.spec.Endpoint != handoffEndpoint || ff.handoff < 0 || sb.pairs.Load() != 1 {
					t.Fatalf("fiber spec = %+v, %d pairs made by the backend", ff.spec, sb.pairs.Load())
				}
				id := r.identities["g1"]
				want, _ := identityMessage(id.id, "x5t")
				if !bytes.Equal(ff.identity, want) {
					t.Fatalf("identity read by the fiber = %q", ff.identity)
				}
				if h.Endpoint != "tcp://10.0.0.1:443" {
					t.Fatalf("handle endpoint = %s, want the router's", h.Endpoint)
				}
				key, pin, ok := r.HandoffRoute(h.ID)
				rkey, _ := r.cfg.Handoff.Key(h.ID)
				if !ok || key == "" || key != rkey || pin != id.id.KeySHA256 {
					t.Fatalf("HandoffRoute = %q %q %v", key, pin, ok)
				}
			}},
		{name: "a handoff fiber whose channel the host makes", be: func() backend.Backend {
			return &struct {
				*fakeBackend
				handoffMixin
			}{newFakeBackend(core.TierWarm), handoffMixin{true}}
		}, mod: func(c *Config) { c.Handoff, c.HandoffKey = handoffRouter(), handoffKey },
			grant: handoffG, prepare: true, spec: core.CloneSpec{Grant: handoffG, Fence: fence},
			check: func(t *testing.T, r *Runtime, be backend.Backend, h core.FiberHandle) {
				ff := be.(interface{ fiber(string) *fakeFiber }).fiber("g1/1/1")
				if ff.handoff < 0 || len(ff.identity) == 0 || ff.identity[0] != identityTag {
					t.Fatalf("fiber = %+v", ff)
				}
			}},
		{name: "a handoff channel the backend cannot make", be: func() backend.Backend {
			sb := newSandboxBackend(core.TierSnapshot)
			sb.err = errors.New("fake: netns gone")
			return sb
		}, mod: func(c *Config) { c.Handoff, c.HandoffKey = handoffRouter(), handoffKey },
			grant: handoffG, prepare: true, spec: core.CloneSpec{Grant: handoffG, Fence: fence}, errText: "handoff channel: fake: netns gone",
			check: func(t *testing.T, r *Runtime, _ backend.Backend, _ core.FiberHandle) {
				if r.root.Child("g1").Child("f-1-1").Exists() {
					t.Fatal("the leaf was left behind")
				}
			}},
		{name: "a handoff grant without a caller has no identity to send", be: func() backend.Backend { return newSandboxBackend(core.TierSnapshot) },
			mod: func(c *Config) { c.Handoff, c.HandoffKey = handoffRouter(), handoffKey },
			grant: func() core.Grant {
				g := handoffG
				g.CallerThumbprint = ""
				return g
			}(), prepare: true,
			spec: func() core.CloneSpec {
				g := handoffG
				g.CallerThumbprint = ""
				return core.CloneSpec{Grant: g, Fence: fence}
			}(), errText: "caller is empty",
			check: func(t *testing.T, r *Runtime, _ backend.Backend, _ core.FiberHandle) {
				if r.root.Child("g1").Child("f-1-1").Exists() || len(r.fibers) != 0 {
					t.Fatal("the leaf or the record was left behind")
				}
			}},
		{name: "tcp endpoints: one port per fiber, none left is an error", be: func() backend.Backend { return newSandboxBackend(core.TierSnapshot) },
			mod:   func(c *Config) { c.Endpoints = tcpPolicy },
			grant: g, prepare: true, spec: core.CloneSpec{Grant: g, Fence: fence},
			check: func(t *testing.T, r *Runtime, be backend.Backend, h core.FiberHandle) {
				if h.Endpoint != "tcp://127.0.0.1:20000" {
					t.Fatalf("first endpoint = %s", h.Endpoint)
				}
				if ff := be.(*sandboxBackend).fiber(h.ID); ff.spec.Endpoint != "tcp://127.0.0.1:20000" {
					t.Fatalf("the backend was told to serve on %s", ff.spec.Endpoint)
				}
				h2, err := r.Clone(context.Background(), core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g1", Epoch: 1, Seq: 2}})
				if err != nil || h2.Endpoint != "tcp://127.0.0.1:20001" {
					t.Fatalf("second clone = %+v %v", h2, err)
				}
				if _, err := r.Clone(context.Background(), core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g1", Epoch: 1, Seq: 3}}); err == nil ||
					!strings.Contains(err.Error(), "no free endpoint port in 20000-20001") {
					t.Fatalf("third clone = %v, want the range exhausted", err)
				}
				if r.root.Child("g1").Child("f-1-3").Exists() {
					t.Fatal("the refused fiber's leaf was left behind")
				}
				r.mu.Lock()
				held := len(r.ports)
				r.mu.Unlock()
				if held != 2 {
					t.Fatalf("%d ports held, want 2", held)
				}
			}},
		{name: "a sandbox fiber's leaf leaves room for its footprint", be: func() backend.Backend {
			sb := newSandboxBackend(core.TierSnapshot)
			sb.warm = backend.Warm{Bytes: 10 * mib, TotalBytes: 20 * mib}
			return sb
		}, grant: g, prepare: true, spec: core.CloneSpec{Grant: g, Fence: fence},
			check: func(t *testing.T, r *Runtime, _ backend.Backend, _ core.FiberHandle) {
				leaf := r.root.Child("g1").Child("f-1-1")
				if got := cgUint(t, leaf, "memory.max"); got != (64+20+10+32)*mib {
					t.Fatalf("memory.max = %d", got)
				}
				if cgFile(t, leaf, "pids.max") != "max" {
					t.Fatal("a sandbox fiber got a task limit")
				}
			}},
		{name: "a run directory that is no longer a directory", be: func() backend.Backend { return newFakeBackend(core.TierWarm) }, grant: g, prepare: true,
			before: func(t *testing.T, r *Runtime) {
				if err := os.RemoveAll(r.cfg.RunDir); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(r.cfg.RunDir, nil, 0o644); err != nil {
					t.Fatal(err)
				}
			},
			spec: core.CloneSpec{Grant: g, Fence: fence}, errText: "not a directory",
			check: func(t *testing.T, r *Runtime, _ backend.Backend, _ core.FiberHandle) {
				if r.root.Child("g1").Child("f-1-1").Exists() {
					t.Fatal("the leaf was left behind")
				}
			}},
		{name: "a handoff fiber the backend refuses: its channel is closed with the rest", be: func() backend.Backend {
			sb := newSandboxBackend(core.TierSnapshot)
			sb.cloneErr = errors.New("fake: restore failed")
			return sb
		}, mod: func(c *Config) { c.Handoff, c.HandoffKey = handoffRouter(), handoffKey },
			grant: handoffG, prepare: true, spec: core.CloneSpec{Grant: handoffG, Fence: fence}, errText: "restore failed",
			check: func(t *testing.T, r *Runtime, _ backend.Backend, _ core.FiberHandle) {
				if r.root.Child("g1").Child("f-1-1").Exists() || len(r.fibers) != 0 {
					t.Fatal("the leaf or the record was left behind")
				}
				if _, ok := r.cfg.Handoff.Key("g1/1/1"); ok {
					t.Fatal("a refused fiber was routed")
				}
			}},
		{name: "a grant cgroup that refuses another leaf", be: func() backend.Backend { return newFakeBackend(core.TierWarm) },
			grant: g, prepare: true, spec: core.CloneSpec{Grant: g, Fence: fence},
			before:  func(t *testing.T, r *Runtime) { refuseLeaves(t, r.root.Child("g1")) },
			errText: "f-1-1",
			check: func(t *testing.T, r *Runtime, _ backend.Backend, _ core.FiberHandle) {
				if r.root.Child("g1").Child("f-1-1").Exists() || len(r.fibers) != 0 {
					t.Fatal("the leaf or the record was left behind")
				}
			}},
		{name: "an id mapper that stops delegating: the leaf is removed again", be: func() backend.Backend {
			return &struct {
				*fakeBackend
				*idMapperMixin
			}{newFakeBackend(core.TierWarm), &idMapperMixin{uid: 65534}}
		}, grant: g, prepare: true,
			before: func(t *testing.T, r *Runtime) {
				r.be.(interface{ mapper() *idMapperMixin }).mapper().err = errors.New("fake: range revoked")
			},
			spec: core.CloneSpec{Grant: g, Fence: fence}, errText: "range revoked",
			check: func(t *testing.T, r *Runtime, _ backend.Backend, _ core.FiberHandle) {
				if r.root.Child("g1").Child("f-1-1").Exists() {
					t.Fatal("the leaf was left behind")
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := tc.be()
			r := newTestRuntime(t, be, tc.mod)
			ctx := context.Background()
			if tc.prepare {
				if err := r.PrepareTemplate(ctx, tc.grant); err != nil {
					t.Fatalf("PrepareTemplate: %v", err)
				}
			}
			if tc.before != nil {
				tc.before(t, r)
			}
			h, err := r.Clone(ctx, tc.spec)
			switch {
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				t.Fatalf("Clone = %v, want %v", err, tc.wantErr)
			case tc.errText != "" && (err == nil || !strings.Contains(err.Error(), tc.errText)):
				t.Fatalf("Clone = %v, want an error mentioning %q", err, tc.errText)
			case tc.wantErr == nil && tc.errText == "" && err != nil:
				t.Fatalf("Clone: %v", err)
			}
			if tc.check != nil {
				tc.check(t, r, be, h)
			}
		})
	}
}

// TestFiberEnds checks how a fiber's end is classified and cleaned up, whether
// the host asked for it, the fiber died, or its template went.
func TestFiberEnds(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", WBudgetBytes: 64 * mib}
	fence := core.Fence{GrantUID: "g1", Epoch: 1, Seq: 1}
	cases := []struct {
		name string
		run  func(t *testing.T, r *Runtime, be *fakeBackend, h core.FiberHandle)
	}{
		{name: "released on purpose: no exit reported, leaf and socket gone", run: func(t *testing.T, r *Runtime, be *fakeBackend, h core.FiberHandle) {
			if err := r.Release(context.Background(), h.ID, false); err != nil {
				t.Fatal(err)
			}
			if strings.Join(be.killedIDs(), ",") != h.ID {
				t.Fatalf("killed %v", be.killedIDs())
			}
			if r.root.Child("g1").Child("f-1-1").Exists() || exists(endpoint.UnixPath(h.Endpoint)) {
				t.Fatal("leaf or socket left behind")
			}
			noExit(t, r)
			if _, err := r.Stats(context.Background(), h.ID); err == nil || !strings.Contains(err.Error(), "unknown fiber") {
				t.Fatalf("Stats after release = %v", err)
			}
		}},
		{name: "exits on its own", run: func(t *testing.T, r *Runtime, be *fakeBackend, h core.FiberHandle) {
			be.die(h.ID, "exit:3")
			if e := waitExit(t, r); e != (core.FiberExit{FiberID: h.ID, Reason: "exit", Detail: "exit:3"}) {
				t.Fatalf("exit = %+v", e)
			}
			waitFor(t, "the leaf to go", func() bool { return !r.root.Child("g1").Child("f-1-1").Exists() })
		}},
		{name: "killed by the kernel for exceeding its budget: reported as oom", run: func(t *testing.T, r *Runtime, be *fakeBackend, h core.FiberHandle) {
			// A task of the test's own in the leaf allocates past the leaf's
			// memory.max, and the kernel's group OOM takes the leaf.
			leaf := r.root.Child("g1").Child("f-1-1")
			startInLeaf(t, leaf, "exec dd if=/dev/zero of=/dev/null bs=256M count=1")
			waitFor(t, "the kernel to kill the leaf", func() bool { n, _ := leaf.OOMKills(); return n > 0 })
			be.die(h.ID, "signal:SIGKILL")
			if e := waitExit(t, r); e.Reason != "oom" || !strings.HasPrefix(e.Detail, "signal:SIGKILL oom_kill=") {
				t.Fatalf("exit = %+v, want oom with the kill count", e)
			}
		}},
		{name: "killed by a signal", run: func(t *testing.T, r *Runtime, be *fakeBackend, h core.FiberHandle) {
			be.die(h.ID, "signal:SIGSEGV")
			if e := waitExit(t, r); e.Reason != "signal" || e.Detail != "signal:SIGSEGV" {
				t.Fatalf("exit = %+v", e)
			}
		}},
		{name: "the warm instance ends: its fibers are reported, the next clone warms again", run: func(t *testing.T, r *Runtime, be *fakeBackend, h core.FiberHandle) {
			be.warmGone("g1")
			if e := waitExit(t, r); e != (core.FiberExit{FiberID: h.ID, Reason: "signal", Detail: "template instance exited"}) {
				t.Fatalf("exit = %+v", e)
			}
			waitFor(t, "the warm instance to be forgotten", func() bool { return r.warmOf("g1") == nil })
			if cgFile(t, r.root, "memory.min") != "0" {
				t.Fatal("the gone template's pages stay protected")
			}
			h2, err := r.Clone(context.Background(), core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g1", Epoch: 1, Seq: 2}})
			if err != nil || be.warmed() != 2 || h2.ID != "g1/1/2" {
				t.Fatalf("clone after the warm instance went: %+v %v, warmed %d", h2, err, be.warmed())
			}
		}},
		{name: "an exit of a fiber nobody knows is ignored", run: func(t *testing.T, r *Runtime, be *fakeBackend, h core.FiberHandle) {
			be.die("g1/9/9", "exit:0")
			noExit(t, r)
			if _, err := r.Stats(context.Background(), h.ID); err != nil {
				t.Fatalf("the known fiber must be unaffected: %v", err)
			}
		}},
		{name: "a release that outlives its context", run: func(t *testing.T, r *Runtime, be *fakeBackend, h core.FiberHandle) {
			be.noExit = true
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			if err := r.Release(ctx, h.ID, false); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Release = %v, want the context's end", err)
			}
		}},
		{name: "releasing an id that is no fence", run: func(t *testing.T, r *Runtime, _ *fakeBackend, _ core.FiberHandle) {
			if err := r.Release(context.Background(), "not-a-fence", true); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "releasing a fiber whose leaf never existed", run: func(t *testing.T, r *Runtime, _ *fakeBackend, _ core.FiberHandle) {
			if err := r.Release(context.Background(), "g1/6/6", false); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "releasing an orphan of a previous agent kills its leaf and removes its files", run: func(t *testing.T, r *Runtime, _ *fakeBackend, _ core.FiberHandle) {
			orphan := core.Fence{GrantUID: "g1", Epoch: 5, Seq: 5}
			leaf := r.root.Child("g1").Child(leafName(orphan))
			if err := leaf.Create(0, false); err != nil {
				t.Fatal(err)
			}
			startSleeper(t, leaf)
			sock := r.unixPath(orphan)
			for _, f := range []string{sock, sock + ".fence"} {
				if err := os.WriteFile(f, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			// The fake fiber has no task in its leaf, but the orphan has one.
			list, err := r.List(context.Background())
			if err != nil || len(list) != 1 || list[0].ID != orphan.String() {
				t.Fatalf("List = %+v %v, want the orphan alone", list, err)
			}
			if err := r.Release(context.Background(), orphan.String(), false); err != nil {
				t.Fatal(err)
			}
			if leaf.Exists() || exists(sock) || exists(sock+".fence") {
				t.Fatal("the orphan's leaf or files remain")
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := newFakeBackend(core.TierWarm)
			be.endpointFile = true
			r := newTestRuntime(t, be, nil)
			ctx := context.Background()
			if err := r.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			h, err := r.Clone(ctx, core.CloneSpec{Grant: g, Fence: fence})
			if err != nil {
				t.Fatal(err)
			}
			tc.run(t, r, be, h)
		})
	}
}

// TestEnforceW checks that a backend that reports W or device use itself has
// its fibers' budgets held by the host, which kills and reports an overrun as
// the kernel would.
func TestEnforceW(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", WBudgetBytes: 1000, DeviceBudget: core.DeviceBudget{Bytes: 50}}
	fence := core.Fence{GrantUID: "g1", Epoch: 1, Seq: 1}
	// deviceOnly reports devices but not W.
	type deviceOnly struct {
		*fakeBackend
		*deviceMixin
	}
	cases := []struct {
		name       string
		be         func() backend.Backend
		grant      core.Grant
		w, device  uint64
		wantDetail string // "" = no exit
	}{
		{name: "W over budget", be: func() backend.Backend { return newSandboxBackend(core.TierSnapshot) }, grant: g, w: 2000, device: 10,
			wantDetail: "signal:SIGKILL W=2000 over budget 1000"},
		{name: "device slice over budget", be: func() backend.Backend { return newSandboxBackend(core.TierSnapshot) }, grant: g, w: 100, device: 80,
			wantDetail: "signal:SIGKILL device 80 over budget 50"},
		{name: "within both budgets", be: func() backend.Backend { return newSandboxBackend(core.TierSnapshot) }, grant: g, w: 999, device: 50},
		{name: "a device-only backend leaves W to the kernel", be: func() backend.Backend {
			return &deviceOnly{newFakeBackend(core.TierWarm), &deviceMixin{}}
		}, grant: g, w: 5000, device: 80, wantDetail: "signal:SIGKILL device 80 over budget 50"},
		{name: "no budgets: never enforced", be: func() backend.Backend { return newSandboxBackend(core.TierSnapshot) },
			grant: core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl"}, w: 1 << 40, device: 1 << 40},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := tc.be()
			r := newTestRuntime(t, be, nil)
			ctx := context.Background()
			if err := r.PrepareTemplate(ctx, tc.grant); err != nil {
				t.Fatal(err)
			}
			h, err := r.Clone(ctx, core.CloneSpec{Grant: tc.grant, Fence: fence})
			if err != nil {
				t.Fatal(err)
			}
			if w, ok := be.(interface{ setW(string, uint64) }); ok {
				w.setW(h.ID, tc.w)
			}
			be.(interface{ setDevice(string, uint64) }).setDevice(h.ID, tc.device)
			if tc.wantDetail == "" {
				noExit(t, r)
				st, err := r.Stats(ctx, h.ID)
				if _, reports := be.(backend.WReporter); err != nil || (reports && st.WUsedBytes != tc.w) || st.DeviceUsedBytes != tc.device {
					t.Fatalf("Stats = %+v %v, want W %d device %d", st, err, tc.w, tc.device)
				}
				return
			}
			e := waitExit(t, r)
			if e.FiberID != h.ID || e.Reason != "oom" || e.Detail != tc.wantDetail {
				t.Fatalf("exit = %+v, want oom %q", e, tc.wantDetail)
			}
			if !strings.Contains(strings.Join(be.(interface{ killedIDs() []string }).killedIDs(), ","), h.ID) {
				t.Fatal("the backend was not asked to kill the fiber")
			}
		})
	}
}

// TestWBytes checks where a fiber's working set is read from, by backend kind.
func TestWBytes(t *testing.T) {
	cases := []struct {
		name string
		be   backend.Backend
		// task puts a process of the test's own in the leaf.
		task bool
		// positive is whether W must be above zero. Otherwise it must be 0.
		positive bool
		wantErr  string
	}{
		{name: "a fork backend reads the leaf's memory.current", be: newFakeBackend(core.TierWarm), task: true, positive: true},
		{name: "an empty leaf charges nothing", be: newFakeBackend(core.TierWarm)},
		{name: "a sandbox's fixed footprint is subtracted from the leaf's count", be: &struct {
			*fakeBackend
			overheadMixin
		}{func() *fakeBackend {
			b := newFakeBackend(core.TierWarm)
			b.warm = backend.Warm{Bytes: 1 << 40}
			return b
		}(), overheadMixin{}}, task: true},
		{name: "a metered backend reads one memory.stat counter", be: &struct {
			*fakeBackend
			wMeterMixin
		}{newFakeBackend(core.TierWarm), wMeterMixin{"anon"}}},
		{name: "a counter the kernel lacks is an error", be: &struct {
			*fakeBackend
			wMeterMixin
		}{newFakeBackend(core.TierWarm), wMeterMixin{"no_such_counter"}}, wantErr: "memory.stat has no"},
		{name: "a reporting backend's unknown fiber counts nothing", be: &struct {
			*fakeBackend
			*wReporterMixin
		}{newFakeBackend(core.TierWarm), &wReporterMixin{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRuntime(t, tc.be, nil)
			g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl"}
			ctx := context.Background()
			if err := r.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			h, err := r.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g1", Epoch: 1, Seq: 1}})
			if err != nil {
				t.Fatal(err)
			}
			if tc.task {
				startSleeper(t, r.root.Child("g1").Child("f-1-1"))
			}
			st, err := r.Stats(ctx, h.ID)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Stats = %v, want an error mentioning %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || (st.WUsedBytes > 0) != tc.positive {
				t.Fatalf("Stats = %+v %v, want W above zero %v", st, err, tc.positive)
			}
		})
	}
}

// TestPressure checks PSI of the grant's cgroup, and an error for a grant with
// none.
func TestPressure(t *testing.T) {
	cases := []struct {
		name    string
		grant   string
		prepare bool
		wantErr bool
	}{
		{name: "a prepared grant reads its cgroup's PSI", grant: "g1", prepare: true},
		{name: "an unknown grant has no cgroup", grant: "g9", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRuntime(t, newFakeBackend(core.TierWarm), nil)
			if tc.prepare {
				if err := r.PrepareTemplate(context.Background(), core.Grant{UID: tc.grant, TemplateDigest: "sha256:tmpl"}); err != nil {
					t.Fatal(err)
				}
			}
			p, err := r.Pressure(tc.grant)
			if (err != nil) != tc.wantErr || (!tc.wantErr && p != 0) {
				t.Fatalf("Pressure = %v %v, want error %v", p, err, tc.wantErr)
			}
		})
	}
}

// TestListAndPrune checks the leaves with live tasks under the root, known or
// not, and the removal of grants no longer admitted.
func TestListAndPrune(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*Config)
		// endpoint is what List reports for a leaf, "" for tcp homes.
		endpoint func(r *Runtime, f core.Fence) string
	}{
		{name: "unix endpoints are reconstructed from the fence", endpoint: func(r *Runtime, f core.Fence) string { return "unix://" + r.unixPath(f) }},
		{name: "tcp endpoints are not recoverable", mod: func(c *Config) { c.Endpoints = tcpPolicy },
			endpoint: func(*Runtime, core.Fence) string { return "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRuntime(t, newSandboxBackend(core.TierSnapshot), tc.mod)
			ctx := context.Background()
			if err := r.PrepareTemplate(ctx, core.Grant{UID: "kept", TemplateDigest: "sha256:tmpl"}); err != nil {
				t.Fatal(err)
			}
			live := core.Fence{GrantUID: "stale", Epoch: 2, Seq: 1}
			stale := r.root.Child("stale")
			if err := stale.Ensure("memory", "pids"); err != nil {
				t.Fatal(err)
			}
			for _, leaf := range []cgroup.Dir{stale.Child(leafName(live)), stale.Child("f-2-2"), stale.Child("f-garbage"), stale.Child("zygote")} {
				if err := leaf.Create(0, false); err != nil {
					t.Fatal(err)
				}
			}
			startSleeper(t, stale.Child(leafName(live)))
			startSleeper(t, stale.Child("f-garbage"))
			list, err := r.List(ctx)
			if err != nil || len(list) != 1 || list[0].ID != live.String() || list[0].Endpoint != tc.endpoint(r, live) {
				t.Fatalf("List = %+v %v, want only %s", list, err, live)
			}
			// A grant with a cgroup nested two deep cannot be pruned. Only
			// leaves are removed, and a leaf with a child is not empty.
			deep := r.root.Child("deep")
			if err := deep.Ensure("memory"); err != nil {
				t.Fatal(err)
			}
			if err := deep.Child("f-1-1").Ensure("memory"); err != nil {
				t.Fatal(err)
			}
			if err := deep.Child("f-1-1").Child("inner").Create(0, false); err != nil {
				t.Fatal(err)
			}
			r.PruneGrants(map[string]bool{"kept": true})
			if stale.Exists() || !r.root.Child("kept").Child("zygote").Exists() || !deep.Child("f-1-1").Child("inner").Exists() {
				t.Fatalf("stale exists %v, kept zygote exists %v, deep inner exists %v", stale.Exists(), r.root.Child("kept").Child("zygote").Exists(), deep.Child("f-1-1").Child("inner").Exists())
			}
			// A root that is gone lists nothing and prunes nothing.
			gone := &Runtime{root: cgroup.Root(filepath.Join(t.TempDir(), "nope")), cfg: r.cfg}
			gone.PruneGrants(nil)
			if _, err := gone.List(ctx); err == nil {
				t.Fatal("List over a missing root must fail")
			}
		})
	}
}

// TestParentStore checks template checkpoints filed by hash, moved or linked,
// shared between warms and found again from disk.
func TestParentStore(t *testing.T) {
	hex64 := strings.Repeat("0123456789abcdef", 4)
	cases := []struct {
		name string
		run  func(t *testing.T, r *Runtime, cb *codecBackend)
	}{
		{name: "a self-checkpoint is moved into the store", run: func(t *testing.T, r *Runtime, cb *codecBackend) {
			src := filepath.Join(t.TempDir(), "zygote-images")
			if err := writeParentDir(src, "a"); err != nil {
				t.Fatal(err)
			}
			sha, err := r.registerParent(src, true)
			if err != nil || sha != shaOf("a") {
				t.Fatalf("registerParent = %s %v", sha, err)
			}
			st, err := os.Lstat(filepath.Join(r.parentsDir(), sha))
			if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || exists(src) {
				t.Fatalf("store entry %v %v, source exists %v", st, err, exists(src))
			}
			if p, ok := r.parents[sha]; !ok || p.SHA256() != sha {
				t.Fatal("the parent is not loaded")
			}
			// With the same pages again, the copy is dropped and the store kept.
			again := filepath.Join(t.TempDir(), "again")
			if err := writeParentDir(again, "a"); err != nil {
				t.Fatal(err)
			}
			if sha2, err := r.registerParent(again, true); err != nil || sha2 != sha || exists(again) || len(r.parents) != 1 {
				t.Fatalf("second register = %s %v, source exists %v, %d parents", sha2, err, exists(again), len(r.parents))
			}
		}},
		{name: "an artifact's images are linked, and linking them again keeps the loaded parent", run: func(t *testing.T, r *Runtime, cb *codecBackend) {
			images := filepath.Join(t.TempDir(), "images")
			if err := writeParentDir(images, "b"); err != nil {
				t.Fatal(err)
			}
			sha, err := r.registerParent(images, false)
			if err != nil || sha != shaOf("b") {
				t.Fatalf("registerParent = %s %v", sha, err)
			}
			st, err := os.Lstat(filepath.Join(r.parentsDir(), sha))
			if err != nil || st.Mode()&os.ModeSymlink == 0 || !exists(filepath.Join(images, fakePagesFile)) {
				t.Fatalf("store entry %v %v", st, err)
			}
			first := r.parents[sha]
			if sha2, err := r.registerParent(images, false); err != nil || sha2 != sha || r.parents[sha] != first {
				t.Fatalf("second register = %s %v, parent replaced %v", sha2, err, r.parents[sha] != first)
			}
			loaded := cb.loadedParents()
			if len(loaded) != 3 || loaded[2].closed.Load() != 1 || loaded[1].closed.Load() != 0 {
				t.Fatalf("%d parents loaded; the duplicate must be closed and the kept one open", len(loaded))
			}
		}},
		{name: "concurrent warms of one artifact all file its images, whichever links first", run: func(t *testing.T, _ *Runtime, _ *codecBackend) {
			// Each round is a fresh store with warms linking at once. The
			// link a warm loses to is the same content, so every warm
			// ends with the parent loaded from the store.
			images := filepath.Join(t.TempDir(), "images")
			if err := writeParentDir(images, "g"); err != nil {
				t.Fatal(err)
			}
			for round := 0; round < 200; round++ {
				cb := newCodecBackend(core.TierCheckpoint)
				r := &Runtime{cfg: Config{TemplateCache: t.TempDir()}, be: cb, parents: map[string]backend.Parent{}}
				const warms = 8
				start := make(chan struct{})
				errs := make([]error, warms)
				var wg sync.WaitGroup
				for i := range warms {
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						sha, err := r.registerParent(images, false)
						if err == nil && sha != shaOf("g") {
							err = fmt.Errorf("sha %s", sha)
						}
						errs[i] = err
					}()
				}
				close(start)
				wg.Wait()
				for i, err := range errs {
					if err != nil {
						t.Fatalf("round %d: warm %d: registerParent: %v", round, i, err)
					}
				}
				if target, err := os.Readlink(filepath.Join(r.parentsDir(), shaOf("g"))); err != nil || target != images {
					t.Fatalf("round %d: store entry -> %s %v", round, target, err)
				}
				kept, open := r.parents[shaOf("g")], 0
				for _, p := range cb.loadedParents() {
					if p.closed.Load() == 0 {
						open++
						if p != kept {
							t.Fatalf("round %d: a parent other than the kept one is open", round)
						}
					}
				}
				if kept == nil || open != 1 {
					t.Fatalf("round %d: kept %v, %d open", round, kept, open)
				}
			}
		}},
		{name: "a checkpoint on another file system cannot be moved into the store", run: func(t *testing.T, r *Runtime, cb *codecBackend) {
			if st, err := os.Stat("/dev/shm"); err != nil || !st.IsDir() {
				t.Skip("no /dev/shm to move from")
			}
			src, err := os.MkdirTemp("/dev/shm", "host-test-")
			if err != nil {
				t.Skipf("cannot write /dev/shm: %v", err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(src) })
			if err := writeParentDir(src, "x"); err != nil {
				t.Fatal(err)
			}
			if _, err := r.registerParent(src, true); !errors.Is(err, syscall.EXDEV) {
				t.Fatalf("registerParent = %v, want a cross-device error", err)
			}
			if loaded := cb.loadedParents(); len(loaded) != 1 || loaded[0].closed.Load() != 1 || len(r.parents) != 0 {
				t.Fatal("the parent loaded from the source must be closed and not kept")
			}
		}},
		{name: "a duplicate self-checkpoint whose stored copy cannot be loaded", run: func(t *testing.T, r *Runtime, cb *codecBackend) {
			for _, n := range []string{"one", "two"} {
				if err := writeParentDir(filepath.Join(t.TempDir(), n), "y"); err != nil {
					t.Fatal(err)
				}
			}
			first := filepath.Join(t.TempDir(), "first")
			if err := writeParentDir(first, "y"); err != nil {
				t.Fatal(err)
			}
			if _, err := r.registerParent(first, true); err != nil {
				t.Fatal(err)
			}
			second := filepath.Join(t.TempDir(), "second")
			if err := writeParentDir(second, "y"); err != nil {
				t.Fatal(err)
			}
			cb.failLoadAt = 4 // the store's copy, after the duplicate is dropped
			if _, err := r.registerParent(second, true); err == nil || !strings.Contains(err.Error(), "load refused") || exists(second) {
				t.Fatalf("registerParent = %v, duplicate kept %v", err, exists(second))
			}
		}},
		{name: "a checkpoint the codec cannot load", run: func(t *testing.T, r *Runtime, _ *codecBackend) {
			if _, err := r.registerParent(filepath.Join(t.TempDir(), "missing"), true); err == nil {
				t.Fatal("want an error")
			}
		}},
		{name: "a checkpoint that cannot be loaded back from the store", run: func(t *testing.T, r *Runtime, cb *codecBackend) {
			src := filepath.Join(t.TempDir(), "zygote-images")
			if err := writeParentDir(src, "c"); err != nil {
				t.Fatal(err)
			}
			cb.failLoadAt = 2
			if _, err := r.registerParent(src, true); err == nil || !strings.Contains(err.Error(), "load refused") {
				t.Fatalf("registerParent = %v", err)
			}
		}},
		{name: "a store that cannot be made", run: func(t *testing.T, r *Runtime, _ *codecBackend) {
			src := filepath.Join(t.TempDir(), "zygote-images")
			if err := writeParentDir(src, "d"); err != nil {
				t.Fatal(err)
			}
			r.cfg.TemplateCache = filepath.Join(src, fakePagesFile)
			if _, err := r.registerParent(src, true); err == nil || !strings.Contains(err.Error(), "not a directory") {
				t.Fatalf("registerParent = %v", err)
			}
		}},
		{name: "parent: found in memory, else loaded from disk and checked", run: func(t *testing.T, r *Runtime, cb *codecBackend) {
			sha := shaOf("e")
			if err := writeParentDir(filepath.Join(r.parentsDir(), sha), "e"); err != nil {
				t.Fatal(err)
			}
			p, err := r.parent(sha)
			if err != nil || p.SHA256() != sha || r.parents[sha] != p {
				t.Fatalf("parent = %v %v", p, err)
			}
			if p2, err := r.parent(sha); err != nil || p2 != p || len(cb.loadedParents()) != 1 {
				t.Fatalf("second lookup loaded again: %v %v", p2, err)
			}
			if _, err := r.parent(hex64); !errors.Is(err, ErrParentMissing) {
				t.Fatalf("missing parent = %v", err)
			}
			if err := writeParentDir(filepath.Join(r.parentsDir(), hex64), "not e"); err != nil {
				t.Fatal(err)
			}
			if _, err := r.parent(hex64); err == nil || !strings.Contains(err.Error(), "hashes to") {
				t.Fatalf("a store entry with other pages = %v", err)
			}
			cb.loadErr = errors.New("fake: corrupt")
			if _, err := r.parent(shaOf("f")); !errors.Is(err, ErrParentMissing) {
				t.Fatalf("missing before loading = %v", err)
			}
			if err := writeParentDir(filepath.Join(r.parentsDir(), shaOf("f")), "f"); err != nil {
				t.Fatal(err)
			}
			if _, err := r.parent(shaOf("f")); err == nil || !strings.Contains(err.Error(), "corrupt") {
				t.Fatalf("unloadable parent = %v", err)
			}
		}},
		{name: "a backend without a codec has no store", run: func(t *testing.T, _ *Runtime, _ *codecBackend) {
			r := &Runtime{cfg: Config{TemplateCache: t.TempDir()}, be: newFakeBackend(core.TierWarm), parents: map[string]backend.Parent{}}
			if _, err := r.registerParent(t.TempDir(), false); err == nil || !strings.Contains(err.Error(), "no delta codec") {
				t.Fatalf("registerParent = %v", err)
			}
			if _, err := r.parent(hex64); err == nil || !strings.Contains(err.Error(), "no delta codec") {
				t.Fatalf("parent = %v", err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cb := newCodecBackend(core.TierCheckpoint)
			r := &Runtime{cfg: Config{TemplateCache: t.TempDir()}, be: cb, parents: map[string]backend.Parent{}}
			tc.run(t, r, cb)
		})
	}
}

// TestPidsPressure checks that a birth refused while the grant's cgroup hit
// pids.max is the grant's own pressure.
func TestPidsPressure(t *testing.T) {
	cause := errors.New("fork: resource temporarily unavailable")
	cases := []struct {
		name   string
		events string // the grant's pids.events content, "" for no pids controller
		root   string // the subtree root's
		before uint64
		want   error
	}{
		{name: "hits rose since before", events: "max 3\n", before: 1, want: core.ErrPressure},
		{name: "no new hits", events: "max 3\n", before: 3, want: cause},
		{name: "no pids controller", before: 0, want: cause},
		{name: "the subtree root refused the fork", events: "max 0\n", root: "max 1\n", before: 0, want: core.ErrPressure},
		{name: "the root's old hits do not count", events: "max 0\n", root: "max 2\n", before: 2, want: cause},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := cgroup.Dir{Path: t.TempDir()}
			r := &Runtime{root: cgroup.Dir{Path: t.TempDir()}}
			for dir, events := range map[cgroup.Dir]string{d: tc.events, r.root: tc.root} {
				if events == "" {
					continue
				}
				if err := os.WriteFile(filepath.Join(dir.Path, "pids.events"), []byte(events), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			err := r.pidsPressure(d, tc.before, "g1", cause)
			if !errors.Is(err, tc.want) || !errors.Is(err, cause) {
				t.Fatalf("pidsPressure = %v, want %v wrapping %v", err, tc.want, cause)
			}
		})
	}
}

// TestNewReservesTheAgent checks that New caps the subtree below the
// limits it finds above its root, keeping an eighth (at least 64 MiB or
// 64 tasks, at most half) for the agent, and leaves a root with nothing
// above it alone. A fake root makes the limits plain files. The root's
// own pids.max is there from the start, as the kernel shows it once the
// parent delegated the controller (without it no task cap is written,
// as on a Slurm step).
func TestNewReservesTheAgent(t *testing.T) {
	cases := []struct {
		name  string
		above map[string]string // files above the root, path relative to the home
		root  string            // the runtime's root, relative to the home
		want  map[string]string // the root's files after New
		none  []string          // files New must not write
	}{
		{name: "an eighth below the home's limits", above: map[string]string{"memory.max": "1073741824", "pids.max": "1000"}, root: "fiberd",
			want: map[string]string{"memory.max": "939524096", "memory.high": "822083584", "pids.max": "875"}},
		{name: "at least 64 MiB and 64 tasks", above: map[string]string{"memory.max": "268435456", "pids.max": "128"}, root: "fiberd",
			want: map[string]string{"memory.max": "201326592", "memory.high": "176160768", "pids.max": "64"}},
		{name: "at most half of a small limit", above: map[string]string{"memory.max": "67108864", "pids.max": "32"}, root: "fiberd",
			want: map[string]string{"memory.max": "33554432", "memory.high": "29360128", "pids.max": "16"}},
		{name: "the smallest limit above wins", above: map[string]string{"memory.max": "536870912", "pids.max": "500", "mid/memory.max": "max", "mid/pids.max": "2000"}, root: "mid/fiberd",
			want: map[string]string{"memory.max": "469762048", "memory.high": "411041792", "pids.max": "436"}},
		{name: "no limit above", above: map[string]string{"memory.max": "max", "pids.max": "max"}, root: "fiberd",
			want: map[string]string{"pids.max": "max"}, none: []string{"memory.max", "memory.high"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			tc.above[filepath.Join(tc.root, "pids.max")] = "max"
			for name, v := range tc.above {
				p := filepath.Join(home, name)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(v+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			dirs := t.TempDir()
			r, err := New(Config{Backend: newFakeBackend(core.TierWarm), CgroupRoot: filepath.Join(home, tc.root),
				RunDir: filepath.Join(dirs, "run"), DeltaDir: filepath.Join(dirs, "deltas"), TemplateCache: filepath.Join(dirs, "cache")})
			if err != nil {
				t.Fatal(err)
			}
			r.Close()
			for name, v := range tc.want {
				b, err := os.ReadFile(filepath.Join(home, tc.root, name))
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if got := strings.TrimSpace(string(b)); got != v {
					t.Fatalf("%s = %q, want %q", name, got, v)
				}
			}
			for _, name := range tc.none {
				if _, err := os.Stat(filepath.Join(home, tc.root, name)); err == nil {
					t.Fatalf("%s written although nothing above limits the root", name)
				}
			}
		})
	}
}

// TestDelegateProcs checks that only an id-mapping backend's grant gets
// cgroup.procs chowned, and only when the mapper and the file allow.
func TestDelegateProcs(t *testing.T) {
	needRoot(t)
	cases := []struct {
		name    string
		be      backend.Backend
		missing bool // the cgroup directory does not exist
		wantUID uint32
		wantErr string
	}{
		{name: "no id mapper: nothing to delegate", be: newFakeBackend(core.TierWarm)},
		{name: "the mapper refuses", be: &struct {
			*fakeBackend
			idMapperMixin
		}{newFakeBackend(core.TierWarm), idMapperMixin{err: errors.New("fake: no range")}}, wantErr: "no range"},
		{name: "cgroup.procs is handed to the mapped root", be: &struct {
			*fakeBackend
			idMapperMixin
		}{newFakeBackend(core.TierWarm), idMapperMixin{uid: 100000}}, wantUID: 100000},
		{name: "a cgroup that does not exist", be: &struct {
			*fakeBackend
			idMapperMixin
		}{newFakeBackend(core.TierWarm), idMapperMixin{uid: 100000}}, missing: true, wantErr: "delegate cgroup.procs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := cgroup.Dir{Path: filepath.Join(t.TempDir(), "cg")}
			if !tc.missing {
				if err := os.MkdirAll(d.Path, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(d.Path, "cgroup.procs"), nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			r := &Runtime{be: tc.be}
			err := r.delegateProcs("g1", d)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("delegateProcs = %v, want an error mentioning %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := fileOwner(t, filepath.Join(d.Path, "cgroup.procs")); got != tc.wantUID {
				t.Fatalf("cgroup.procs owner = %d, want %d", got, tc.wantUID)
			}
		})
	}
}

// TestPorts checks that the port range is handed out once per fiber,
// re-reserved for a resume, and given back.
func TestPorts(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T, r *Runtime)
	}{
		{name: "a wanted port held by another fiber is refused", run: func(t *testing.T, r *Runtime) {
			if _, err := r.allocPort("a", 0); err != nil {
				t.Fatal(err)
			}
			if _, err := r.allocPort("b", 20000); err == nil || !strings.Contains(err.Error(), "held by a") {
				t.Fatalf("allocPort = %v", err)
			}
			if p, err := r.allocPort("a", 20000); err != nil || p != 20000 {
				t.Fatalf("re-reserving one's own port = %d %v", p, err)
			}
		}},
		{name: "a freed port is handed out again, a port freed by the wrong holder is not", run: func(t *testing.T, r *Runtime) {
			if _, err := r.allocPort("a", 0); err != nil {
				t.Fatal(err)
			}
			r.freePort(20000, "b")
			r.freePort(0, "a")
			if p, err := r.allocPort("c", 0); err != nil || p != 20001 {
				t.Fatalf("allocPort = %d %v, want 20001 while a holds 20000", p, err)
			}
			r.freePort(20000, "a")
			if _, err := r.allocPort("d", 0); err != nil {
				t.Fatalf("allocPort after a free = %v", err)
			}
			if _, err := r.allocPort("e", 0); err == nil {
				t.Fatal("the range is exhausted")
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Runtime{cfg: Config{Endpoints: tcpPolicy}, ports: map[int]string{}}
			tc.run(t, r)
		})
	}
}

// TestFileHelpers checks the JSON, size and fsync helpers around delta
// directories.
func TestFileHelpers(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T, dir string)
	}{
		{name: "writeJSON and readJSON round trip, and refuse what is not JSON", run: func(t *testing.T, dir string) {
			p := filepath.Join(dir, "m.json")
			if err := writeJSON(p, manifest{Fence: "g/1/1"}); err != nil {
				t.Fatal(err)
			}
			st, _ := os.Stat(p)
			if st.Mode().Perm() != 0o600 {
				t.Fatalf("manifest mode %v, want 0600", st.Mode().Perm())
			}
			var m manifest
			if err := readJSON(p, &m); err != nil || m.Fence != "g/1/1" {
				t.Fatalf("readJSON = %+v %v", m, err)
			}
			if err := writeJSON(p, make(chan int)); err == nil {
				t.Fatal("a channel marshalled")
			}
			if err := readJSON(filepath.Join(dir, "none.json"), &m); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("readJSON of a missing file = %v", err)
			}
			if err := os.WriteFile(p, []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := readJSON(p, &m); err == nil {
				t.Fatal("truncated JSON read")
			}
		}},
		{name: "dirBytes counts regular files in the directory only", run: func(t *testing.T, dir string) {
			write(t, dir, map[string]string{"a": "123", "b": "45"})
			write(t, filepath.Join(dir, "sub"), map[string]string{"c": "6789"})
			if err := os.Symlink("a", filepath.Join(dir, "link")); err != nil {
				t.Fatal(err)
			}
			if got := dirBytes(dir); got != 5 {
				t.Fatalf("dirBytes = %d, want 5", got)
			}
			if got := dirBytes(filepath.Join(dir, "none")); got != 0 {
				t.Fatalf("dirBytes of a missing dir = %d", got)
			}
		}},
		{name: "treeBytes counts regular files at any depth", run: func(t *testing.T, dir string) {
			write(t, dir, map[string]string{"a": "123"})
			write(t, filepath.Join(dir, "1-1"), map[string]string{"pages": "45"})
			write(t, filepath.Join(dir, "1-2", "nested"), map[string]string{"pages": "6789"})
			if err := os.Symlink("a", filepath.Join(dir, "link")); err != nil {
				t.Fatal(err)
			}
			if got := treeBytes(dir); got != 9 {
				t.Fatalf("treeBytes = %d, want 9", got)
			}
			if got := treeBytes(filepath.Join(dir, "none")); got != 0 {
				t.Fatalf("treeBytes of a missing dir = %d", got)
			}
		}},
		{name: "syncDir fsyncs nested files, then directories children first, fails on what it cannot open", run: func(t *testing.T, dir string) {
			write(t, dir, map[string]string{"a": "123"})
			write(t, filepath.Join(dir, "sub"), map[string]string{"c": "6789"})
			var order []string
			orig := fsync
			fsync = func(f *os.File) error {
				rel, _ := filepath.Rel(dir, f.Name())
				order = append(order, rel)
				return f.Sync()
			}
			t.Cleanup(func() { fsync = orig })
			if err := syncDir(dir); err != nil {
				t.Fatal(err)
			}
			if want := []string{"a", "sub/c", "sub", "."}; strings.Join(order, " ") != strings.Join(want, " ") {
				t.Fatalf("fsync order = %q, want %q", order, want)
			}
			if err := syncDir(filepath.Join(dir, "none")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("syncDir of a missing dir = %v", err)
			}
			if err := os.Symlink("/nonexistent/ghost", filepath.Join(dir, "ghost")); err != nil {
				t.Fatal(err)
			}
			if err := syncDir(dir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("syncDir with a dangling link = %v", err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, t.TempDir()) })
	}
}

// TestDropTemplate checks what the host does when the agent drops a
// yielded grant's template. The warm instance is unwarmed and forgotten,
// its pages lose their memory.min on the grant's cgroups and in the
// root's sum, the backend's later report of its exit changes nothing,
// and the next clone warms the grant again. A grant that was never
// warmed is nothing to drop.
func TestDropTemplate(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", WBudgetBytes: 64 * mib}
	cases := []struct {
		name string
		warm bool // the grant was warmed before the drop
	}{
		{name: "a warm grant's instance ends and its pages are unprotected", warm: true},
		{name: "a grant never warmed is nothing to drop", warm: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := newFakeBackend(core.TierWarm)
			r := newTestRuntime(t, be, nil)
			ctx := context.Background()
			gcg := r.root.Child("g1")
			cgroups := []cgroup.Dir{gcg.Child("zygote"), gcg}
			if tc.warm {
				if err := r.PrepareTemplate(ctx, g); err != nil {
					t.Fatal(err)
				}
				// The fake instance has no pages. Protect some, as a real
				// one's are.
				r.mu.Lock()
				r.warms["g1"].minBytes = mib
				r.mu.Unlock()
				for _, d := range cgroups {
					if err := d.SetMemoryMin(mib); err != nil {
						t.Fatal(err)
					}
				}
				r.protectTemplates()
				if got := cgFile(t, r.root, "memory.min"); got != fmt.Sprint(mib) {
					t.Fatalf("root memory.min before the drop = %s, want %d", got, mib)
				}
			}
			r.DropTemplate("g1")
			wantUnwarmed := 0
			if tc.warm {
				wantUnwarmed = 1
			}
			if ids := be.unwarmedIDs(); len(ids) != wantUnwarmed {
				t.Fatalf("unwarmed %v, want %d", ids, wantUnwarmed)
			}
			if r.warmOf("g1") != nil {
				t.Fatal("the dropped warm instance is still known")
			}
			if got := cgFile(t, r.root, "memory.min"); got != "0" {
				t.Fatalf("root memory.min after the drop = %s, want 0", got)
			}
			if tc.warm {
				for _, d := range cgroups {
					if got := cgFile(t, d, "memory.min"); got != "0" {
						t.Fatalf("%s memory.min after the drop = %s, want 0", d.Path, got)
					}
				}
				// The backend reports the instance's end after the drop.
				be.warmGone("g1")
				noExit(t, r)
			}
			h, err := r.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g1", Epoch: 1, Seq: 2}})
			if err != nil || h.ID != "g1/1/2" || be.warmed() != wantUnwarmed+1 {
				t.Fatalf("clone after the drop = %+v %v, warmed %d times, want a fiber under a fresh warm", h, err, be.warmed())
			}
		})
	}
}
