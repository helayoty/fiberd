// Package agent is the grant agent as a library: the flags, the wiring
// of verifier, runtime, ledger, pressure ladder, admin socket and RPC
// server, and the fixed startup order (epoch++ -> reconcile -> open
// RPC). cmd/fiberd is this package plus the standalone home; an
// integration builds its own binary from this package plus its home
// (examples/kubernetes/cmd/fiberd-k8s is one). Nothing here knows which
// home it runs under beyond the home.Home interface and the optional
// interfaces below.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/backend"
	gvisorbackend "github.com/helayoty/fiberd/pkg/backend/gvisor"
	hlbackend "github.com/helayoty/fiberd/pkg/backend/hyperlight"
	procbackend "github.com/helayoty/fiberd/pkg/backend/proc"
	runcbackend "github.com/helayoty/fiberd/pkg/backend/runc"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/endpoint"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/home"
	"github.com/helayoty/fiberd/pkg/home/standalone"
	"github.com/helayoty/fiberd/pkg/rpc"
	"github.com/helayoty/fiberd/pkg/runtime/host"
	"github.com/helayoty/fiberd/pkg/runtime/stub"
)

// Optional interfaces a home may implement; Run looks for them.
type (
	// LaneSetter is the test-only lane override behind POST /lane.
	LaneSetter interface{ SetLane(healthy bool) }
	// ScopeLoser can lose its scope while running and wants to say so;
	// Run wires the callback to the agent's epoch bump.
	ScopeLoser interface {
		OnScopeLost(func(ctx context.Context, reason string))
	}
	// EndpointHoster knows the one address its fibers share (a Pod IP, a
	// node address); it fills -endpoint-host when that is empty.
	EndpointHoster interface{ EndpointHost() string }
)

// HomeFactory builds the home once the verifier exists (the standalone
// home polls the issuer's key cache for liveness).
type HomeFactory func(c *Config, ver core.Verifier, jwks *grant.Cache) (home.Home, error)

// Standalone is the factory cmd/fiberd uses.
func Standalone(c *Config, _ core.Verifier, jwks *grant.Cache) (home.Home, error) {
	return standalone.New(standalone.Config{
		Cache: jwks, StaleTTL: c.StaleTTL, GrantsDir: c.GrantsDir,
		CgroupRoot: c.CgroupRoot, Endpoint: c.Advertise, DieAfter: c.LaneDies, Devices: c.Devices,
	}), nil
}

// Config is every flag the agent takes. Bind registers them; Finish
// applies defaults after parsing.
type Config struct {
	Listen, HTTPAddr, StateDir, NodeID, Issuer    string
	RuntimeName, RuntimeTier, Verifier, AdminPath string
	GrantsDir, CgroupRoot, Advertise, RunDir      string
	DeltaDir, CRIUBin, Registry, TemplateCache    string
	DeltaRegistry, Parity                         string
	GvisorRootfs, Runsc, RuncRootfs, Runc         string
	HLHelper, HLGuest                             string
	EndpointFamily, EndpointHost, EndpointPorts   string
	GvisorOverhead                                uint64
	RegistryPlain, GvisorDebug                    bool
	GrantCeiling                                  uint64
	Templates                                     map[string]string
	AdminUnsafe                                   bool
	StaleTTL, LaneDies, StatusEvery, JWKSMaxStale time.Duration
	PressureEvery                                 time.Duration
	BaseRate, RefW                                float64
	// Devices is the parsed -devices list.
	Devices []string

	devices string
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func envFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			return f
		}
	}
	return def
}

// Bind registers the agent's flags on fs. A binary adds its own (a home's)
// beside them.
func (c *Config) Bind(fs *flag.FlagSet) {
	hostname, _ := os.Hostname()
	fs.StringVar(&c.Listen, "listen", ":8484", "gRPC listen address for the Fibers service")
	fs.StringVar(&c.Advertise, "advertise", "", "address callers reach this home at (default the listen address, or what the home knows)")
	fs.StringVar(&c.HTTPAddr, "http", "", "optional JSON gateway listen address (off when empty)")
	fs.StringVar(&c.StateDir, "state", envOr("FIBERD_STATE", "/var/lib/fiberd"), "state directory: epoch, audit spool, deltas")
	fs.StringVar(&c.NodeID, "node-id", envOr("FIBERD_NODE_ID", hostname), "this home's identity; a grant's audience must match it")
	fs.StringVar(&c.Issuer, "issuer", "", "issuer URL: OIDC discovery root for -verifier=jwks, and what Miss details report")
	fs.StringVar(&c.Verifier, "verifier", "", "grant verifier: jwks (signed JWTs, keys from -issuer) or insecure-json (development only); required")
	fs.DurationVar(&c.JWKSMaxStale, "jwks-max-stale", time.Hour, "refuse to verify when the key set is older than this (set to the lease TTL)")
	fs.StringVar(&c.GrantsDir, "grants-dir", "", "directory polled for *.jwt files to pre-admit (warm before the first Clone)")
	fs.StringVar(&c.CgroupRoot, "cgroup-root", "/sys/fs/cgroup/fiberd", "delegated cgroup v2 subtree the runtime may carve (homes that own their cgroup ignore it)")
	fs.StringVar(&c.RuntimeName, "runtime", "stub", "runtime: stub (in-memory), or a sandbox backend on the host runtime: proc (fork zygote + criu), runc (the zygote as an OCI container's init), gvisor (runsc sandbox per fiber), hyperlight (micro-VM snapshots through a helper process)")
	fs.StringVar(&c.RuntimeTier, "runtime-tier", "FIBER_CHECKPOINT", "tier the stub runtime advertises (stub only)")
	c.Templates = map[string]string{}
	fs.Func("template", "proc: digest=path [args] mapping a template digest to a zygote command (repeatable; key `default` catches the rest)",
		func(v string) error { return host.ParseTemplateFlag(c.Templates, v) })
	fs.StringVar(&c.RunDir, "run-dir", "/run/fiberd", "proc: directory for fiber endpoints (unix sockets; keep short)")
	fs.StringVar(&c.EndpointFamily, "endpoint-family", "unix", "address family fibers are served on: unix (sockets under -run-dir), inet4 or inet6 (tcp on -endpoint-host, a port per fiber); declared, never discovered")
	fs.StringVar(&c.EndpointHost, "endpoint-host", "", "inet4/inet6: the one address the grant's fibers share and callers dial (default: what the home knows, else the loopback of the family)")
	fs.StringVar(&c.EndpointPorts, "endpoint-ports", "30000-32767", "inet4/inet6: port range handed out one per live fiber")
	fs.StringVar(&c.DeltaDir, "delta-dir", "", "proc: directory for parked deltas (default <state>/deltas)")
	fs.StringVar(&c.CRIUBin, "criu", "criu", "proc: criu binary; park/resume (FIBER_CHECKPOINT) is offered when `criu check` passes")
	fs.Uint64Var(&c.GrantCeiling, "grant-ceiling", 0, "proc: fixed block ceiling per grant in bytes (memory.high); 0 = fibers.max * w_budget + zygote + 25%")
	fs.StringVar(&c.Registry, "registry", "", "proc: OCI repository (host/repo) to pull zygote artifacts from by template digest")
	fs.BoolVar(&c.RegistryPlain, "registry-plain-http", false, "proc: the registry speaks http, not https")
	fs.StringVar(&c.TemplateCache, "template-cache", "", "proc: directory for pulled artifacts (default <state>/templates)")
	fs.StringVar(&c.DeltaRegistry, "delta-registry", "", "proc: OCI repository prefix (host/prefix) where parked sessions are published and claimed by other homes")
	fs.StringVar(&c.GvisorRootfs, "gvisor-rootfs", "", "gvisor: rootfs directory every sandbox runs in; -template commands are paths inside it")
	fs.StringVar(&c.Runsc, "runsc", "runsc", "gvisor: runsc binary")
	fs.StringVar(&c.RuncRootfs, "runc-rootfs", "", "runc: rootfs directory the zygote container runs in; -template commands are paths inside it")
	fs.StringVar(&c.Runc, "runc", "runc", "runc: runc binary")
	fs.StringVar(&c.HLHelper, "hyperlight-helper", "", "hyperlight: helper executable speaking hack/hyperlight/PROTOCOL.md (the Rust helper, or fakehelper)")
	fs.StringVar(&c.HLGuest, "hyperlight-guest", "", "hyperlight: guest binary the helper loads")
	fs.Uint64Var(&c.GvisorOverhead, "gvisor-overhead", 0, "gvisor: fixed bytes one sandbox costs besides its working set (sentry + template pages); added to memory.max, subtracted from W; 0 = the warm template's measured size")
	fs.BoolVar(&c.GvisorDebug, "gvisor-debug", false, "gvisor: keep runsc debug logs under <state>/gvisor/log")
	fs.StringVar(&c.Parity, "parity", "strict", "proc: how closely artifact images and other homes' deltas must match this host: strict, off, or kernel=exact|series|off,libc=exact|off (arch always)")
	fs.StringVar(&c.devices, "devices", "", "comma-separated devices every grant's engine may drive (the home's fabric channel; empty = none)")
	fs.StringVar(&c.AdminPath, "admin", "", "admin unix socket (default <state>/admin.sock): GET /healthz")
	fs.BoolVar(&c.AdminUnsafe, "admin-unsafe", false, "enable test-only admin controls (POST /lane, POST /scope-lost)")
	fs.DurationVar(&c.StaleTTL, "stale-ttl", envDuration("FIBERD_STALE_TTL", 30*time.Second), "grant lane is unhealthy past this silence from the control plane")
	fs.DurationVar(&c.LaneDies, "lane-dies-after", envDuration("FIBERD_LANE_DIES_AFTER", 0), "standalone: simulate the issuer disappearing after this long (0 = never)")
	fs.Float64Var(&c.BaseRate, "base-rate", envFloat("FIBERD_BASE_RATE", 200), "thrash budget: clones/sec at W -> 0")
	fs.Float64Var(&c.RefW, "ref-w", 256<<20, "thrash budget: working-set bytes at which the rate halves")
	fs.DurationVar(&c.StatusEvery, "status-interval", time.Second, "W sampling and Watch cadence")
	fs.DurationVar(&c.PressureEvery, "pressure-interval", time.Second, "pressure ladder evaluation cadence (0 disables the ladder)")
}

// Finish applies what follows from the parsed flags.
func (c *Config) Finish() {
	if c.Advertise == "" {
		c.Advertise = c.Listen
	}
	c.Devices = c.Devices[:0]
	for _, d := range strings.Split(c.devices, ",") {
		if d = strings.TrimSpace(d); d != "" {
			c.Devices = append(c.Devices, d)
		}
	}
}

// ListenPort is the port of -listen, for homes that advertise their own
// address with it.
func (c *Config) ListenPort() (string, error) {
	_, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return "", fmt.Errorf("-listen %q: %w", c.Listen, err)
	}
	return port, nil
}

// Family is the parsed -endpoint-family.
func (c *Config) Family() (endpoint.Family, error) { return endpoint.ParseFamily(c.EndpointFamily) }

// endpointPolicy reads the -endpoint-* flags: the family a deployment
// declares, the address its fibers share, and the port range.
func (c *Config) endpointPolicy() (endpoint.Policy, error) {
	fam, err := c.Family()
	if err != nil {
		return endpoint.Policy{}, err
	}
	p := endpoint.Policy{Family: fam, Host: c.EndpointHost}
	if fam != endpoint.Unix {
		if p.Host == "" {
			p.Host = map[endpoint.Family]string{endpoint.Inet4: "127.0.0.1", endpoint.Inet6: "::1"}[fam]
		}
		lo, hi, ok := strings.Cut(c.EndpointPorts, "-")
		if !ok {
			return endpoint.Policy{}, fmt.Errorf("-endpoint-ports %q: want lo-hi", c.EndpointPorts)
		}
		if p.PortMin, err = strconv.Atoi(strings.TrimSpace(lo)); err != nil {
			return endpoint.Policy{}, fmt.Errorf("-endpoint-ports: %w", err)
		}
		if p.PortMax, err = strconv.Atoi(strings.TrimSpace(hi)); err != nil {
			return endpoint.Policy{}, fmt.Errorf("-endpoint-ports: %w", err)
		}
	}
	return p, p.Validate()
}

// Run is the agent: it returns when the RPC server stops.
func Run(c *Config, newHome HomeFactory) error {
	// Verifier first: it decides whether there is an issuer to poll.
	var ver core.Verifier
	var jwks *grant.Cache
	switch c.Verifier {
	case "jwks":
		if c.Issuer == "" {
			return errors.New("-verifier=jwks needs -issuer (the OIDC discovery root)")
		}
		jwks = &grant.Cache{IssuerURL: c.Issuer}
		ver = &grant.Verifier{Cache: jwks, Audience: c.NodeID, MaxStale: c.JWKSMaxStale}
	case "insecure-json":
		log.Printf("WARNING: -verifier=insecure-json performs no signature check; development only")
		ver = grant.InsecureJSONVerifier{}
	case "":
		return errors.New("-verifier is required: jwks (signed grants) or insecure-json (development only)")
	default:
		return fmt.Errorf("unknown verifier %q", c.Verifier)
	}

	h, err := newHome(c, ver, jwks)
	if err != nil {
		return err
	}
	// What the home knows about addresses fills what the flags left open.
	if fam, err := c.Family(); err == nil && fam != endpoint.Unix && c.EndpointHost == "" {
		if eh, ok := h.(EndpointHoster); ok {
			if c.EndpointHost = eh.EndpointHost(); c.EndpointHost == "" {
				return fmt.Errorf("-endpoint-family %s: home %s has no address of that family", fam, h.Name())
			}
		}
	}
	if c.Advertise == c.Listen && h.AdvertisedEndpoint() != "" {
		c.Advertise = h.AdvertisedEndpoint()
	}

	var rt core.Runtime
	switch c.RuntimeName {
	case "stub":
		tier, err := core.ParseTier(c.RuntimeTier)
		if err != nil {
			return fmt.Errorf("runtime-tier: %w", err)
		}
		rt = stub.NewWithTier(tier)
	case "proc", "gvisor", "runc", "hyperlight":
		if len(c.Templates) == 0 && c.Registry == "" {
			return fmt.Errorf("-runtime=%s needs a -template digest=path or a -registry to pull artifacts from", c.RuntimeName)
		}
		// One host runtime, one backend per -runtime name.
		var be backend.Backend
		switch c.RuntimeName {
		case "proc":
			be = procbackend.New(procbackend.Options{CRIU: c.CRIUBin})
		case "hyperlight":
			if c.HLHelper == "" {
				return errors.New("-runtime=hyperlight needs -hyperlight-helper (hack/hyperlight/helper, or fakehelper without a hypervisor)")
			}
			be = hlbackend.New(hlbackend.Options{Helper: c.HLHelper, Guest: c.HLGuest})
		case "runc":
			if c.RuncRootfs == "" {
				return errors.New("-runtime=runc needs -runc-rootfs (hack/gvisor/rootfs.sh builds one)")
			}
			be = runcbackend.New(runcbackend.Options{Runc: c.Runc, Rootfs: c.RuncRootfs, CRIU: c.CRIUBin,
				StateDir: filepath.Join(c.StateDir, "runc")})
		case "gvisor":
			if c.GvisorRootfs == "" {
				return errors.New("-runtime=gvisor needs -gvisor-rootfs (hack/gvisor/rootfs.sh builds one)")
			}
			be = gvisorbackend.New(gvisorbackend.Options{Runsc: c.Runsc, Rootfs: c.GvisorRootfs,
				StateDir: filepath.Join(c.StateDir, "gvisor"), OverheadBytes: c.GvisorOverhead, Debug: c.GvisorDebug})
		}
		if c.DeltaDir == "" {
			c.DeltaDir = filepath.Join(c.StateDir, "deltas")
		}
		if c.TemplateCache == "" {
			c.TemplateCache = filepath.Join(c.StateDir, "templates")
		}
		parity, err := artifact.ParseParity(c.Parity)
		if err != nil {
			return err
		}
		eps, err := c.endpointPolicy()
		if err != nil {
			return err
		}
		pc := host.Config{Backend: be, Templates: c.Templates, CgroupRoot: h.CgroupRoot(), RunDir: c.RunDir,
			DeltaDir: c.DeltaDir, Endpoints: eps,
			Registry: c.Registry, RegistryPlainHTTP: c.RegistryPlain, TemplateCache: c.TemplateCache,
			DeltaRegistry: c.DeltaRegistry, HomeID: c.NodeID, Parity: parity}
		if c.GrantCeiling > 0 {
			fixed := c.GrantCeiling
			pc.Ceiling = func(core.Grant, uint64) uint64 { return fixed }
		}
		rt, err = host.New(pc)
		if err != nil {
			return fmt.Errorf("%s runtime: %w", c.RuntimeName, err)
		}
		if closer, ok := rt.(interface{ Close() }); ok {
			defer closer.Close()
		}
	default:
		return fmt.Errorf("runtime %q is not available yet", c.RuntimeName)
	}
	if err := os.MkdirAll(c.StateDir, 0o700); err != nil {
		return fmt.Errorf("state dir: %w", err)
	}
	if c.AdminPath == "" {
		c.AdminPath = filepath.Join(c.StateDir, "admin.sock")
	}

	// 1. Epoch: every prior fence is invalid from here on.
	ep, err := core.OpenEpochStore(c.StateDir)
	if err != nil {
		return fmt.Errorf("epoch: %w", err)
	}
	log.Printf("fiberd epoch=%d node=%s home=%s (all prior fences invalid)", ep.Current(), c.NodeID, h.Name())

	// 2. Ledger, audit spool, agent.
	led := core.NewLedger(ep.Current())
	spool, err := core.OpenSpool(c.StateDir, nil)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	defer func() { _ = spool.Close() }()

	store := &core.SnapshotStore{Path: filepath.Join(c.StateDir, "ledger.json")}
	ag := &core.Agent{
		NodeID:         c.NodeID,
		Ledger:         led,
		Budget:         core.NewBudget(c.BaseRate, c.RefW),
		Runtime:        rt,
		Audit:          spool,
		Verify:         ver,
		Health:         h.Health(),
		Scope:          h.Scope,
		Fabric:         h.Fabric,
		Epoch:          ep,
		Store:          store,
		StatusInterval: c.StatusEvery,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 3. Reconcile: the snapshot says what to re-admit and which parked
	// sessions to remember; the runtime says what is actually running,
	// and everything running is from a prior epoch and is killed.
	snap, err := store.Load()
	if err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	rep, err := ag.Reconcile(ctx, snap)
	if err != nil {
		return err
	}
	if pruner, ok := rt.(interface{ PruneGrants(map[string]bool) }); ok {
		keep := map[string]bool{}
		for _, st := range led.Statuses() {
			keep[st.GrantUID] = true
		}
		pruner.PruneGrants(keep)
	}
	log.Printf("reconcile: grants re-admitted=%d expired=%d parked restored=%d dropped=%d orphans killed=%d",
		rep.GrantsReadmitted, rep.GrantsExpired, rep.ParkedRestored, rep.ParkedDropped, rep.OrphansKilled)
	go ag.Run(ctx)
	if sl, ok := h.(ScopeLoser); ok {
		sl.OnScopeLost(func(ctx context.Context, reason string) {
			if _, err := ag.BumpEpoch(ctx, reason); err != nil {
				log.Printf("scope lost (%s) but the epoch could not be bumped: %v", reason, err)
			}
		})
	}

	// The pressure ladder, when the runtime can report PSI: two inputs,
	// one ladder, when the runtime's template is an engine reporting
	// device occupancy as well.
	if src, ok := rt.(core.PressureSource); ok && c.PressureEvery > 0 {
		if dp, ok := rt.(interface{ DevicePressure() core.PressureSource }); ok {
			src = core.MaxPressure{src, dp.DevicePressure()}
		}
		ctl := &core.PressureController{
			Ledger: led, Source: src, Interval: c.PressureEvery,
			Park:    func(ctx context.Context, id string) error { _, _, err := ag.Park(ctx, id, false); return err },
			Release: func(ctx context.Context, id string) error { _, err := ag.Release(ctx, id, false); return err },
			Yield:   func(ctx context.Context, uid string) { ag.Yield(ctx, uid, "pressure") },
		}
		ag.Pressure = ctl
		go ctl.Run(ctx)
	}

	// 4. The home: liveness signal and the async grant lane.
	go h.Run(ctx)
	go home.Drive(ctx, h, ag)

	// 5. Admin socket.
	healthz := rpc.HealthFunc(ep.Current, h.Health(), rt.Tier())
	admin := http.NewServeMux()
	admin.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(healthz())
	})
	admin.HandleFunc("POST /lane", func(w http.ResponseWriter, r *http.Request) {
		if !c.AdminUnsafe {
			http.Error(w, "admin controls disabled; start with -admin-unsafe", http.StatusForbidden)
			return
		}
		var body struct {
			Healthy bool `json:"healthy"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		lane, ok := h.(LaneSetter)
		if !ok {
			http.Error(w, "home "+h.Name()+" has no lane override", http.StatusNotImplemented)
			return
		}
		lane.SetLane(body.Healthy)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(healthz())
	})
	admin.HandleFunc("POST /scope-lost", func(w http.ResponseWriter, r *http.Request) {
		// A stand-in for a scope the home can lose while running: what a
		// Kubernetes home does on its own when its namespace, issuer or
		// claim goes away under it.
		if !c.AdminUnsafe {
			http.Error(w, "admin controls disabled; start with -admin-unsafe", http.StatusForbidden)
			return
		}
		epoch, err := ag.BumpEpoch(r.Context(), "scope lost (admin)")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]uint64{"epoch": epoch})
	})
	_ = os.Remove(c.AdminPath)
	al, err := net.Listen("unix", c.AdminPath)
	if err != nil {
		return fmt.Errorf("admin socket: %w", err)
	}
	defer func() { _ = os.Remove(c.AdminPath) }()
	adminSrv := &http.Server{Handler: admin, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = adminSrv.Serve(al) }()

	// 6. Open the warm path.
	srv := &rpc.Server{Agent: ag, Issuer: c.Issuer}
	gs := rpc.NewGRPCServer(srv)
	gl, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", c.Listen, err)
	}
	if c.HTTPAddr != "" {
		gw := &rpc.Gateway{Server: srv, Health: healthz}
		hs := &http.Server{Addr: c.HTTPAddr, Handler: gw.Handler(), ReadHeaderTimeout: 5 * time.Second}
		go func() {
			log.Printf("fiberd json gateway on %s", c.HTTPAddr)
			if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("gateway: %v", err)
			}
		}()
		go func() { <-ctx.Done(); _ = hs.Close() }()
	}
	go func() {
		<-ctx.Done()
		gs.GracefulStop()
		_ = adminSrv.Close()
	}()
	log.Printf("fiberd warm path on %s tier=%s admin=%s (no control plane needed beyond this point)", gl.Addr(), rt.Tier(), c.AdminPath)
	if err := gs.Serve(gl); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
