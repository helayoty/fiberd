// Package home is fiberd's home inside a Substrate worker Pod. There is
// no grant controller in a Substrate cluster and the worker Pod's spec is
// Substrate's, so the home is its own issuer: it holds a key, serves
// discovery and the key set on the loopback for the agent's verifier,
// and mints one grant per ActorTemplate the herder is asked to run,
// sized by the actor's memory limit. Liveness is Substrate's node
// supervisor answering on its socket (atelet, which is what would send
// work); readiness is every minted grant's template warm. The cgroup
// subtree is the Pod's own, as in the Kubernetes example.
package home

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	fhome "github.com/helayoty/fiberd/pkg/home"
	"github.com/helayoty/fiberd/pkg/sys/cgroup"

	"github.com/helayoty/fiberd/examples/substrate/herder"
)

type Config struct {
	// Audience is the agent's node id; grants are addressed to it.
	Audience string
	// IssuerURL is where Handler is served (http://127.0.0.1:<port>).
	IssuerURL string
	// Key signs grants; generated (EdDSA) when nil.
	Key *jose.JSONWebKey
	// StaleTTL: silence from the probe longer than this is unhealthy.
	StaleTTL time.Duration
	// Probe is the liveness check (nil: always alive); ProbeSocket makes
	// the default one, a connect to atelet's socket.
	Probe       func(ctx context.Context) error
	ProbeSocket string
	// CgroupRoot, when set, is used as the delegated subtree as it is;
	// empty means the Pod's own cgroup, delegated.
	CgroupRoot string
	// Grant sizing.
	Lease         time.Duration // default 24h
	FiberMax      int           // default 4
	DefaultBudget uint64        // W budget when the actor names no memory limit (default 64 MiB)
	MinTier       core.Tier     // default FIBER_CHECKPOINT
	// Scope claims this home asserts (worker pod uid, node, ...).
	Scope []core.ScopeClaim
	Now   func() time.Time
}

type minted struct {
	jwt string
	g   core.Grant
}

type Home struct {
	cfg    Config
	issuer *grant.Issuer
	health *core.SourceHealth
	root   string
	lane   chan fhome.GrantEvent

	mu     sync.Mutex
	grants map[string]minted // by template digest
	ready  map[string]bool   // by grant uid
	paused bool
}

func New(cfg Config) (*Home, error) {
	if cfg.Audience == "" || cfg.IssuerURL == "" {
		return nil, fmt.Errorf("substrate home: audience and issuer URL are required")
	}
	if cfg.Key == nil {
		k, err := grant.GenerateKey(jose.EdDSA)
		if err != nil {
			return nil, err
		}
		cfg.Key = k
	}
	if cfg.StaleTTL <= 0 {
		cfg.StaleTTL = 30 * time.Second
	}
	if cfg.Lease <= 0 {
		cfg.Lease = 24 * time.Hour
	}
	if cfg.FiberMax <= 0 {
		cfg.FiberMax = 4
	}
	if cfg.DefaultBudget == 0 {
		cfg.DefaultBudget = 64 << 20
	}
	if cfg.MinTier == 0 {
		cfg.MinTier = core.TierCheckpoint
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Probe == nil && cfg.ProbeSocket != "" {
		sock := cfg.ProbeSocket
		cfg.Probe = func(ctx context.Context) error {
			var d net.Dialer
			c, err := d.DialContext(ctx, "unix", sock)
			if err != nil {
				return err
			}
			return c.Close()
		}
	}
	root := cfg.CgroupRoot
	if root == "" {
		own, err := cgroup.Delegate(cgroup.Own("/sys/fs/cgroup"))
		if err != nil {
			return nil, fmt.Errorf("substrate home: delegate the pod's cgroup: %w", err)
		}
		root = own.Child("fiberd").Path
	}
	return &Home{
		cfg:    cfg,
		issuer: &grant.Issuer{Key: cfg.Key, URL: cfg.IssuerURL, Now: cfg.Now},
		health: core.NewSourceHealth(cfg.StaleTTL, cfg.Now()),
		root:   root,
		lane:   make(chan fhome.GrantEvent, 64),
		grants: map[string]minted{},
		ready:  map[string]bool{},
	}, nil
}

// Handler serves discovery and the JWKS; mount it at IssuerURL.
func (h *Home) Handler() http.Handler { return h.issuer.Handler() }

// GrantUID is the grant a template runs under on this worker.
func GrantUID(tmpl herder.Template) string {
	sum := sha256.Sum256([]byte(tmpl.Digest()))
	return "at-" + hex.EncodeToString(sum[:8])
}

// Grant implements herder.Grants: one grant per template, minted on
// first use and re-minted past half its lease, announced on the grant
// lane so the agent warms the template before the first Clone.
func (h *Home) Grant(_ context.Context, tmpl herder.Template, memoryBytes uint64) (string, core.Grant, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.cfg.Now()
	if m, ok := h.grants[tmpl.Digest()]; ok && m.g.LeaseExpiry.Sub(now) > h.cfg.Lease/2 {
		return m.jwt, m.g, nil
	}
	budget := memoryBytes
	if budget == 0 {
		budget = h.cfg.DefaultBudget
	}
	g := core.Grant{
		UID: GrantUID(tmpl), Audience: h.cfg.Audience, TemplateDigest: tmpl.Digest(),
		FiberMax: h.cfg.FiberMax, FiberWarm: 1, WBudgetBytes: budget, MinTier: h.cfg.MinTier,
		LeaseExpiry: now.Add(h.cfg.Lease),
	}
	tok, err := h.issuer.Mint(g)
	if err != nil {
		return "", core.Grant{}, err
	}
	g.Issuer = h.cfg.IssuerURL
	h.grants[tmpl.Digest()] = minted{jwt: tok, g: g}
	select {
	case h.lane <- fhome.GrantEvent{Kind: fhome.GrantAdded, Token: []byte(tok)}:
	default:
		log.Printf("substrate home: grant lane full; %s admits on its first Clone", g.UID)
	}
	log.Printf("substrate home: minted grant %s for template %s (W budget %d)", g.UID, tmpl.Digest(), budget)
	return tok, g, nil
}

// Ready reports whether every minted template is warm (nothing minted
// yet counts as ready: the worker can take work).
func (h *Home) Ready() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, m := range h.grants {
		if !h.ready[m.g.UID] {
			return false
		}
	}
	return true
}

func (h *Home) Name() string               { return "substrate" }
func (h *Home) Health() *core.SourceHealth { return h.health }
func (h *Home) CgroupRoot() string         { return h.root }
func (h *Home) AdvertisedEndpoint() string { return "" }
func (h *Home) Scope() []core.ScopeClaim   { return append([]core.ScopeClaim(nil), h.cfg.Scope...) }

// Fabric: a worker Pod offers no devices.
func (h *Home) Fabric(context.Context, core.Grant) (core.FabricChannel, func(), error) {
	return core.FabricChannel{}, func() {}, nil
}

// Grants is the lane the herder's minted grants arrive on.
func (h *Home) Grants(context.Context) (<-chan fhome.GrantEvent, error) { return h.lane, nil }

// PublishReady records the template's warmth; the Pod's readiness reads it.
func (h *Home) PublishReady(_ context.Context, grantUID string, ready bool) error {
	h.mu.Lock()
	h.ready[grantUID] = ready
	h.mu.Unlock()
	return nil
}

// SetLane is the test-only override (fiberd's admin socket).
func (h *Home) SetLane(healthy bool) {
	h.mu.Lock()
	h.paused = !healthy
	h.mu.Unlock()
	if healthy {
		h.health.MarkSync(h.cfg.Now())
	} else {
		h.health.MarkSync(h.cfg.Now().Add(-h.cfg.StaleTTL))
	}
}

func (h *Home) mark() {
	h.mu.Lock()
	paused := h.paused
	h.mu.Unlock()
	if !paused {
		h.health.MarkSync(h.cfg.Now())
	}
}

// Run probes liveness every StaleTTL/2: the node supervisor answering
// keeps the lane healthy; silence turns capacity misses into SHED.
func (h *Home) Run(ctx context.Context) {
	every := h.cfg.StaleTTL / 2
	t := time.NewTicker(every)
	defer t.Stop()
	h.probe(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.probe(ctx)
		}
	}
}

func (h *Home) probe(ctx context.Context) {
	if h.cfg.Probe == nil {
		h.mark()
		return
	}
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := h.cfg.Probe(pctx); err != nil {
		log.Printf("substrate home: node supervisor unreachable: %v", err)
		return
	}
	h.mark()
}
