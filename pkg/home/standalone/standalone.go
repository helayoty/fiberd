// Package standalone is the home for a plain host: no scheduler, no
// kubelet. The issuer is the control plane. Liveness is "the issuer's key
// set refreshed recently"; grants arrive inside Clone requests or as
// *.jwt files dropped into a directory for pre-warming; readiness is the
// Watch stream. The agent owns a delegated cgroup subtree it was pointed
// at.
package standalone

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/home"
)

type Config struct {
	// Cache is the verifier's JWKS cache; its refreshes are the liveness
	// signal. Nil means no issuer (development verifier): the lane then
	// stays healthy on a timer until told otherwise.
	Cache *grant.Cache
	// StaleTTL: silence from the issuer longer than this is unhealthy.
	StaleTTL time.Duration
	// GrantsDir, when set, is polled for *.jwt files to pre-admit.
	GrantsDir string
	Poll      time.Duration
	// CgroupRoot is the delegated cgroup v2 subtree (default
	// /sys/fs/cgroup/fiberd).
	CgroupRoot string
	Endpoint   string
	// DieAfter simulates the issuer disappearing after this long (demos).
	DieAfter time.Duration
}

type Home struct {
	cfg    Config
	health *core.SourceHealth

	mu     sync.Mutex
	paused bool // admin override: ignore liveness signals, stay stale
}

func New(cfg Config) *Home {
	if cfg.StaleTTL <= 0 {
		cfg.StaleTTL = 30 * time.Second
	}
	if cfg.Poll <= 0 {
		cfg.Poll = 2 * time.Second
	}
	if cfg.CgroupRoot == "" {
		cfg.CgroupRoot = "/sys/fs/cgroup/fiberd"
	}
	h := &Home{cfg: cfg, health: core.NewSourceHealth(cfg.StaleTTL, time.Now())}
	if cfg.Cache != nil {
		cfg.Cache.OnRefresh = h.mark
	}
	return h
}

func (h *Home) Name() string               { return "standalone" }
func (h *Home) Health() *core.SourceHealth { return h.health }
func (h *Home) CgroupRoot() string         { return h.cfg.CgroupRoot }
func (h *Home) AdvertisedEndpoint() string { return h.cfg.Endpoint }
func (h *Home) PublishReady(context.Context, string, bool) error {
	return nil // readiness rides the Watch stream; nothing to publish
}

// mark is the liveness signal, ignored while paused.
func (h *Home) mark(at time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.paused {
		h.health.MarkSync(at)
	}
}

// SetLane is the test-only override behind fiberd's admin socket: false
// makes the lane stale now and keeps it so; true resumes and marks it
// healthy.
func (h *Home) SetLane(healthy bool) {
	h.mu.Lock()
	h.paused = !healthy
	h.mu.Unlock()
	if healthy {
		h.health.MarkSync(time.Now())
	} else {
		h.health.MarkSync(time.Now().Add(-h.cfg.StaleTTL))
	}
	log.Printf("standalone: grant lane set healthy=%v", healthy)
}

// Run keeps the liveness signal flowing: issuer key refreshes when there
// is an issuer, a plain timer otherwise. DieAfter stops the signal for
// demos of the SHED path.
func (h *Home) Run(ctx context.Context) {
	if h.cfg.DieAfter > 0 {
		go func() {
			select {
			case <-ctx.Done():
			case <-time.After(h.cfg.DieAfter):
				log.Printf("standalone: simulated issuer death (-lane-dies-after=%s)", h.cfg.DieAfter)
				h.SetLane(false)
			}
		}()
	}
	every := h.cfg.StaleTTL / 2
	if h.cfg.Cache != nil {
		h.cfg.Cache.Run(ctx, every)
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			h.mark(now)
		}
	}
}

// Grants polls GrantsDir. A new or changed *.jwt file is GrantAdded with
// its contents; a removed file is GrantRemoved with the UID read
// (unverified: it is only used to stop admissions) from the last copy.
func (h *Home) Grants(ctx context.Context) (<-chan home.GrantEvent, error) {
	if h.cfg.GrantsDir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(h.cfg.GrantsDir, 0o700); err != nil {
		return nil, err
	}
	ch := make(chan home.GrantEvent, 16)
	go func() {
		defer close(ch)
		seen := map[string]fileState{}
		t := time.NewTicker(h.cfg.Poll)
		defer t.Stop()
		for {
			h.scan(ctx, seen, ch)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	return ch, nil
}

type fileState struct {
	mod time.Time
	uid string
}

func (h *Home) scan(ctx context.Context, seen map[string]fileState, ch chan<- home.GrantEvent) {
	entries, err := os.ReadDir(h.cfg.GrantsDir)
	if err != nil {
		return
	}
	present := map[string]bool{}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".jwt" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(h.cfg.GrantsDir, name)
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		present[name] = true
		if st, ok := seen[name]; ok && st.mod.Equal(info.ModTime()) {
			continue
		}
		tok, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		uid, _ := grant.PeekUID(string(tok))
		seen[name] = fileState{mod: info.ModTime(), uid: uid}
		select {
		case ch <- home.GrantEvent{Kind: home.GrantAdded, Token: tok}:
		case <-ctx.Done():
			return
		}
	}
	for name, st := range seen {
		if present[name] {
			continue
		}
		delete(seen, name)
		if st.uid == "" {
			continue
		}
		select {
		case ch <- home.GrantEvent{Kind: home.GrantRemoved, UID: st.uid}:
		case <-ctx.Done():
			return
		}
	}
}
