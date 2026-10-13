package standalone_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/home"
	"github.com/helayoty/fiberd/pkg/home/standalone"
	"github.com/helayoty/fiberd/pkg/runtime/stub"
)

// TestStandaloneGrantsDirDrivesAdmission checks that the grants directory
// is the home's source of truth. In order, a file that verifies is
// admitted, one that does not is logged and ignored, and removing a file
// revokes.
func TestStandaloneGrantsDirDrivesAdmission(t *testing.T) {
	key, _ := grant.GenerateKey(jose.EdDSA)
	is := &grant.Issuer{Key: key, URL: "https://issuer.test"}
	dir := t.TempDir()
	h := standalone.New(standalone.Config{GrantsDir: dir, Poll: 20 * time.Millisecond, StaleTTL: time.Second})

	// A verifier that trusts this issuer's key directly (no network).
	pub := key.Public()
	ver := verifierFunc(func(_ context.Context, tok []byte) (core.Grant, error) {
		return grant.Verify(string(tok), &pub, grant.VerifyOptions{Audience: "node-a"})
	})
	a := &core.Core{NodeID: "node-a", Ledger: core.NewLedger(1), RateLimit: core.NewRateLimit(100, 1<<20),
		Runtime: stub.New(), Verify: ver, Health: h.Health()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go home.Drive(ctx, h, a)

	steps := []struct {
		name     string
		write    *core.Grant // minted into <UID>.jwt
		remove   string      // file removed instead
		uid      string
		admitted bool
		// settle > 0 checks once after that long, for a grant that must
		// never appear. Otherwise the state is awaited.
		settle time.Duration
	}{
		{name: "a grant file that verifies is admitted",
			write: &core.Grant{UID: "pre-1", Audience: "node-a", FiberMax: 1, LeaseExpiry: time.Now().Add(time.Hour)},
			uid:   "pre-1", admitted: true},
		{name: "a token that does not verify (wrong audience) is logged, not admitted",
			write: &core.Grant{UID: "bad-1", Audience: "node-z", LeaseExpiry: time.Now().Add(time.Hour)},
			uid:   "bad-1", settle: 60 * time.Millisecond},
		{name: "removing the file revokes the grant", remove: "pre-1.jwt", uid: "pre-1"},
	}
	for _, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			if st.write != nil {
				tok, err := is.Mint(*st.write)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, st.write.UID+".jwt"), []byte(tok), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if st.remove != "" {
				if err := os.Remove(filepath.Join(dir, st.remove)); err != nil {
					t.Fatal(err)
				}
			}
			admitted := func() bool { _, ok := a.Ledger.Grant(st.uid); return ok }
			if st.settle > 0 {
				time.Sleep(st.settle)
				if admitted() != st.admitted {
					t.Fatalf("grant %s admitted = %v, want %v", st.uid, !st.admitted, st.admitted)
				}
				return
			}
			waitFor(t, func() bool { return admitted() == st.admitted }, st.name)
		})
	}
}

// TestStandaloneReachabilityOverrideAndTimer checks that SetIssuerReachable overrides the
// staleness timer in both directions, and a paused home ignores the timer.
func TestStandaloneReachabilityOverrideAndTimer(t *testing.T) {
	h := standalone.New(standalone.Config{StaleTTL: 200 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)
	steps := []struct {
		name    string
		act     func()
		sleep   time.Duration
		healthy bool
	}{
		{name: "a fresh home is healthy", healthy: true},
		{name: "SetIssuerReachable(false) marks the issuer unreachable at once", act: func() { h.SetIssuerReachable(false) }},
		// The timer keeps ticking but is ignored while paused.
		{name: "a paused home stays unreachable despite the timer", sleep: 300 * time.Millisecond},
		{name: "SetIssuerReachable(true) marks the issuer reachable again", act: func() { h.SetIssuerReachable(true) }, healthy: true},
	}
	for _, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			if st.act != nil {
				st.act()
			}
			time.Sleep(st.sleep)
			if got := h.Health().Healthy(time.Now()); got != st.healthy {
				t.Fatalf("Healthy = %v, want %v", got, st.healthy)
			}
		})
	}
}

type verifierFunc func(context.Context, []byte) (core.Grant, error)

func (f verifierFunc) Verify(ctx context.Context, tok []byte) (core.Grant, error) { return f(ctx, tok) }

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

// TestStandaloneAccessors checks what a standalone home reports about
// itself. The cgroup root defaults to the delegated fiberd subtree, a
// standalone host asserts no scope, and readiness is never published.
func TestStandaloneAccessors(t *testing.T) {
	cases := []struct {
		name       string
		cfg        standalone.Config
		wantCgroup string
	}{
		{name: "defaults", wantCgroup: "/sys/fs/cgroup/fiberd"},
		{name: "configured", cfg: standalone.Config{CgroupRoot: "/sys/fs/cgroup/custom"}, wantCgroup: "/sys/fs/cgroup/custom"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := standalone.New(tc.cfg)
			if h.Name() != "standalone" {
				t.Fatalf("Name = %q, want standalone", h.Name())
			}
			if h.CgroupRoot() != tc.wantCgroup {
				t.Fatalf("CgroupRoot = %q, want %q", h.CgroupRoot(), tc.wantCgroup)
			}
			if sc := h.Scope(); sc != nil {
				t.Fatalf("Scope = %+v, want none", sc)
			}
			if err := h.PublishReady(context.Background(), "g1", true); err != nil {
				t.Fatalf("PublishReady = %v", err)
			}
			if !h.Health().Healthy(time.Now()) {
				t.Fatal("a fresh home is unhealthy")
			}
		})
	}
}

// TestStandaloneDevices checks the standalone device channel. It is the
// static device set every grant shares, or nothing without devices, and
// there is nothing to release. Each grant gets its own copy of the list.
func TestStandaloneDevices(t *testing.T) {
	cases := []struct {
		name     string
		devices  []string
		wantKind string
	}{
		{name: "no devices is no channel"},
		{name: "a static device set", devices: []string{"/dev/sim0", "/dev/sim1"}, wantKind: "static"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := standalone.New(standalone.Config{Devices: tc.devices})
			fc, release, err := h.Devices(context.Background(), core.Grant{UID: "g1"})
			if err != nil || release == nil {
				t.Fatalf("Devices = %+v, release %v, %v; want a channel and a release", fc, release != nil, err)
			}
			release()
			if fc.Kind != tc.wantKind || !slices.Equal(fc.Devices, tc.devices) {
				t.Fatalf("Devices = %+v, want kind %q devices %v", fc, tc.wantKind, tc.devices)
			}
			if len(fc.Devices) > 0 {
				fc.Devices[0] = "/dev/changed"
				again, _, _ := h.Devices(context.Background(), core.Grant{UID: "g2"})
				if !slices.Equal(again.Devices, tc.devices) {
					t.Fatalf("a grant's change to its list reached the next grant: %v", again.Devices)
				}
			}
		})
	}
}

// TestStandaloneGrantsDir checks that a home without a grants directory
// delivers nothing, and one with a directory polls it.
func TestStandaloneGrantsDir(t *testing.T) {
	cases := []struct {
		name         string
		dir          bool
		wantDelivery bool
	}{
		{name: "no grants directory delivers nothing"},
		{name: "a grants directory is polled", dir: true, wantDelivery: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := standalone.Config{}
			if tc.dir {
				cfg.GrantsDir = t.TempDir()
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ch, err := standalone.New(cfg).Grants(ctx)
			if err != nil {
				t.Fatalf("Grants = %v", err)
			}
			if (ch != nil) != tc.wantDelivery {
				t.Fatalf("delivery = %v, want %v", ch != nil, tc.wantDelivery)
			}
		})
	}
}

// TestStandaloneIssuerLiveness checks that with an issuer, each key set
// refresh is the liveness signal, which a paused home ignores. Run
// drives the refreshes until its context ends.
func TestStandaloneIssuerLiveness(t *testing.T) {
	cases := []struct {
		name        string
		paused      bool
		run         bool // refresh through Run instead of directly
		wantHealthy bool
	}{
		{name: "a refresh marks the issuer reachable", wantHealthy: true},
		{name: "a paused home ignores a refresh", paused: true},
		{name: "Run refreshes the key set", run: true, wantHealthy: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := grant.GenerateKey(jose.EdDSA)
			if err != nil {
				t.Fatal(err)
			}
			is := &grant.Issuer{Key: key}
			var handler http.Handler
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
			t.Cleanup(srv.Close)
			is.URL = srv.URL + "/"
			handler = is.Handler()

			const ttl = time.Minute
			cache := &grant.Cache{IssuerURL: is.URL}
			h := standalone.New(standalone.Config{Cache: cache, StaleTTL: ttl})
			if tc.paused {
				h.SetIssuerReachable(false)
			} else {
				h.Health().MarkSync(time.Now().Add(-ttl))
			}
			if h.Health().Healthy(time.Now()) {
				t.Fatal("the issuer counts as reachable before any refresh")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.run {
				done := make(chan struct{})
				go func() {
					h.Run(ctx)
					close(done)
				}()
				waitFor(t, func() bool { return !cache.LastRefresh().IsZero() && h.Health().Healthy(time.Now()) }, "a refresh through Run")
				cancel()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Fatal("Run did not return after its context ended")
				}
				return
			}
			if err := cache.Refresh(ctx); err != nil {
				t.Fatalf("Refresh = %v", err)
			}
			if got := h.Health().Healthy(time.Now()); got != tc.wantHealthy {
				t.Fatalf("Healthy after a refresh = %v, want %v", got, tc.wantHealthy)
			}
		})
	}
}
