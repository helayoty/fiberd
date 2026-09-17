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

func TestGrantsAreMintedPerTemplateAndVerifiable(t *testing.T) {
	ctx := context.Background()
	h, issuer := newHome(t, Config{})
	tmpl := herder.Template{Atespace: "team-a", Name: "counter"}

	tok, g, err := h.Grant(ctx, tmpl, 128<<20)
	if err != nil {
		t.Fatal(err)
	}
	if g.UID != GrantUID(tmpl) || g.TemplateDigest != "team-a/counter" || g.WBudgetBytes != 128<<20 || g.Audience != "worker-1" || g.MinTier != core.TierCheckpoint {
		t.Fatalf("grant %+v", g)
	}
	// The agent's verifier accepts it against the home's own key set.
	v := &grant.Verifier{Cache: &grant.Cache{IssuerURL: issuer}, Audience: "worker-1", MaxStale: time.Hour}
	got, err := v.Verify(ctx, []byte(tok))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.UID != g.UID || got.TemplateDigest != g.TemplateDigest || got.WBudgetBytes != g.WBudgetBytes {
		t.Fatalf("verified %+v, minted %+v", got, g)
	}
	// Same template again: the same grant, not a second one; another
	// template: another grant with the default budget.
	tok2, g2, _ := h.Grant(ctx, tmpl, 0)
	if tok2 != tok || g2.UID != g.UID {
		t.Fatal("a template must map to one grant")
	}
	_, g3, _ := h.Grant(ctx, herder.Template{Atespace: "team-a", Name: "other"}, 0)
	if g3.UID == g.UID || g3.WBudgetBytes != 64<<20 {
		t.Fatalf("second template's grant %+v", g3)
	}

	// Both were announced on the lane, in order.
	lane, _ := h.Grants(ctx)
	for i, want := range []string{tok, "?"} {
		select {
		case ev := <-lane:
			if ev.Kind != fhome.GrantAdded || (want != "?" && string(ev.Token) != want) {
				t.Fatalf("lane event %d: %+v", i, ev.Kind)
			}
		case <-time.After(time.Second):
			t.Fatalf("lane event %d missing", i)
		}
	}

	// Ready only once every minted template is warm.
	if h.Ready() {
		t.Fatal("ready before any template warmed")
	}
	_ = h.PublishReady(ctx, g.UID, true)
	if h.Ready() {
		t.Fatal("ready with one of two templates warm")
	}
	_ = h.PublishReady(ctx, g3.UID, true)
	if !h.Ready() {
		t.Fatal("not ready with every template warm")
	}
}

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
	if !h.Health().Healthy(now) {
		t.Fatal("fresh home must be healthy")
	}
	h.probe(ctx)
	now = now.Add(9 * time.Second)
	if !h.Health().Healthy(now) {
		t.Fatal("probed 9s ago with a 10s TTL: healthy")
	}
	alive = false
	h.probe(ctx)
	now = now.Add(2 * time.Second)
	if h.Health().Healthy(now) {
		t.Fatal("11s of failed probes: unhealthy")
	}
	alive = true
	h.probe(ctx)
	if !h.Health().Healthy(now) {
		t.Fatal("the supervisor is back: healthy")
	}
	// The admin override wins over the probe.
	h.SetLane(false)
	h.probe(ctx)
	if h.Health().Healthy(now) {
		t.Fatal("lane forced down must stay down")
	}
	h.SetLane(true)
	if !h.Health().Healthy(now) {
		t.Fatal("lane forced up")
	}
}

func TestNeedsAudienceAndIssuer(t *testing.T) {
	if _, err := New(Config{CgroupRoot: t.TempDir()}); err == nil {
		t.Fatal("want an error")
	}
}
