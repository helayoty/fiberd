package home

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	fhome "github.com/helayoty/fiberd/pkg/home"

	"github.com/helayoty/fiberd/examples/substrate/herder"
)

func newHome(t *testing.T, cfg Config) (*Home, string) {
	t.Helper()
	// The issuer URL is only known once the handler is served; bootstrap
	// through a placeholder the test rewrites.
	var h *Home
	srv := httptest.NewServer(nil)
	t.Cleanup(srv.Close)
	cfg.Audience = "worker-1"
	cfg.IssuerURL = srv.URL
	cfg.CgroupRoot = t.TempDir()
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = h.Handler()
	return h, srv.URL
}

// TestGrantsAreMintedPerTemplateAndVerifiable checks that each run of a
// template asks for its grant. The first run mints one sized by the actor's
// memory limit and announces it on the lane. The same template again gets
// the same grant, and another template gets another. Every token verifies
// against the home's own key set.
func TestGrantsAreMintedPerTemplateAndVerifiable(t *testing.T) {
	ctx := context.Background()
	h, issuer := newHome(t, Config{Isolation: core.Trusted})
	v := &grant.Verifier{Cache: &grant.Cache{IssuerURL: issuer}, Audience: "worker-1", MaxStale: time.Hour}
	lane, _ := h.Grants(ctx)
	minted := map[string]core.Grant{} // by digest
	tokens := map[string]string{}     // by digest
	cases := []struct {
		name   string
		tmpl   herder.Template
		memory uint64
		digest string
		budget uint64
		reused bool // the template's earlier grant and token, nothing new on the lane
	}{
		{name: "a template's first run mints a grant sized by its memory limit",
			tmpl: herder.Template{Atespace: "team-a", Name: "counter"}, memory: 128 << 20, digest: "team-a/counter", budget: 128 << 20},
		{name: "the same template again is the same grant, not a second one",
			tmpl: herder.Template{Atespace: "team-a", Name: "counter"}, digest: "team-a/counter", budget: 128 << 20, reused: true},
		{name: "another template mints another grant with the default budget",
			tmpl: herder.Template{Atespace: "team-a", Name: "other"}, digest: "team-a/other", budget: 64 << 20},
	}
	for _, tc := range cases {
		if !t.Run(tc.name, func(t *testing.T) {
			tok, g, err := h.Grant(ctx, tc.tmpl, tc.memory)
			if err != nil {
				t.Fatal(err)
			}
			if g.UID != GrantUID(tc.tmpl) || g.TemplateDigest != tc.digest || g.WBudgetBytes != tc.budget || g.Audience != "worker-1" || g.MinTier != core.TierCheckpoint || g.Policy.Isolation != core.Trusted {
				t.Fatalf("grant %+v", g)
			}
			// The agent's verifier accepts it against the home's own key set.
			got, err := v.Verify(ctx, []byte(tok))
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if got.UID != g.UID || got.TemplateDigest != g.TemplateDigest || got.WBudgetBytes != g.WBudgetBytes {
				t.Fatalf("verified %+v, minted %+v", got, g)
			}
			if tc.reused {
				if prev := minted[tc.digest]; tok != tokens[tc.digest] || g.UID != prev.UID {
					t.Fatal("a template must map to one grant")
				}
				select {
				case ev := <-lane:
					t.Fatalf("a reused grant announced again: %+v", ev.Kind)
				default:
				}
				return
			}
			for d, prev := range minted {
				if g.UID == prev.UID {
					t.Fatalf("grant %s reuses the uid of template %s", g.UID, d)
				}
			}
			minted[tc.digest], tokens[tc.digest] = g, tok
			// Announced on the lane, in order.
			select {
			case ev := <-lane:
				if ev.Kind != fhome.GrantAdded || string(ev.Token) != tok {
					t.Fatalf("lane event: %+v", ev.Kind)
				}
			case <-time.After(time.Second):
				t.Fatal("lane event missing")
			}
		}) {
			t.FailNow()
		}
	}
}

// TestReadyOnceEveryMintedTemplateIsWarm checks that the home is ready only
// once every minted template is warm. With nothing minted yet it is ready,
// because the worker can take work.
func TestReadyOnceEveryMintedTemplateIsWarm(t *testing.T) {
	ctx := context.Background()
	h, _ := newHome(t, Config{})
	cases := []struct {
		name string
		mint string // template minted at this step
		warm string // template published warm at this step
		want bool
	}{
		{name: "nothing minted yet: ready", want: true},
		{name: "a template minted, not warm: not ready", mint: "counter"},
		{name: "two templates minted, neither warm: not ready", mint: "other"},
		{name: "one of two templates warm: not ready", warm: "counter"},
		{name: "every template warm: ready", warm: "other", want: true},
	}
	for _, tc := range cases {
		if !t.Run(tc.name, func(t *testing.T) {
			if tc.mint != "" {
				if _, _, err := h.Grant(ctx, herder.Template{Atespace: "team-a", Name: tc.mint}, 0); err != nil {
					t.Fatal(err)
				}
			}
			if tc.warm != "" {
				_ = h.PublishReady(ctx, GrantUID(herder.Template{Atespace: "team-a", Name: tc.warm}), true)
			}
			if got := h.Ready(); got != tc.want {
				t.Fatalf("Ready = %v, want %v", got, tc.want)
			}
		}) {
			t.FailNow()
		}
	}
}

// TestLivenessFollowsTheProbe checks that liveness follows the probe within
// StaleTTL, and that the admin override on the lane wins over the probe.
// Steps run in order on one home and one clock.
func TestLivenessFollowsTheProbe(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	alive := true
	h, _ := newHome(t, Config{StaleTTL: 10 * time.Second, Now: clock, Probe: func(context.Context) error {
		if alive {
			return nil
		}
		return errors.New("no socket")
	}})
	ctx := context.Background()
	cases := []struct {
		name    string
		lane    string // the admin override, "up" or "down", set before the probe
		probe   bool
		down    bool // the probe fails
		advance time.Duration
		healthy bool
	}{
		{name: "a fresh home is healthy", healthy: true},
		{name: "probed 9s ago with a 10s TTL: healthy", probe: true, advance: 9 * time.Second, healthy: true},
		{name: "11s of failed probes: unhealthy", probe: true, down: true, advance: 2 * time.Second},
		{name: "the supervisor is back: healthy", probe: true, healthy: true},
		{name: "lane forced down stays down though the probe answers", lane: "down", probe: true},
		{name: "lane forced up", lane: "up", healthy: true},
	}
	for _, tc := range cases {
		if !t.Run(tc.name, func(t *testing.T) {
			alive = !tc.down
			if tc.lane != "" {
				h.SetLane(tc.lane == "up")
			}
			if tc.probe {
				h.probe(ctx)
			}
			now = now.Add(tc.advance)
			if got := h.Health().Healthy(now); got != tc.healthy {
				t.Fatalf("Healthy = %v, want %v", got, tc.healthy)
			}
		}) {
			t.FailNow()
		}
	}
}

func TestNewNeedsAudienceAndIssuer(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{name: "neither audience nor issuer", wantErr: true},
		{name: "audience without an issuer", cfg: Config{Audience: "worker-1"}, wantErr: true},
		{name: "issuer without an audience", cfg: Config{IssuerURL: "http://127.0.0.1:1"}, wantErr: true},
		{name: "both given", cfg: Config{Audience: "worker-1", IssuerURL: "http://127.0.0.1:1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.CgroupRoot = t.TempDir()
			if _, err := New(tc.cfg); (err != nil) != tc.wantErr {
				t.Fatalf("New err = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}
