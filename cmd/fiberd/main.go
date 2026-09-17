// Command fiberd is the grant agent: one process per home instance. It
// verifies signed grants offline, mints fibers under them through a
// runtime, and serves the grant protocol (api/grant/v1) over gRPC.
//
// Startup order is fixed: epoch++ -> reconcile -> open RPC. The agent
// serves nothing until its view of the home is real.
package main

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
	"syscall"
	"time"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/backend"
	gvisorbackend "github.com/helayoty/fiberd/pkg/backend/gvisor"
	hlbackend "github.com/helayoty/fiberd/pkg/backend/hyperlight"
	procbackend "github.com/helayoty/fiberd/pkg/backend/proc"
	runcbackend "github.com/helayoty/fiberd/pkg/backend/runc"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/home"
	"github.com/helayoty/fiberd/pkg/home/standalone"
	"github.com/helayoty/fiberd/pkg/rpc"
	"github.com/helayoty/fiberd/pkg/runtime/host"
	"github.com/helayoty/fiberd/pkg/runtime/stub"
)

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

type config struct {
	home, listen, httpAddr, stateDir, nodeID, issuer string
	runtimeName, runtimeTier, verifier, adminPath    string
	grantsDir, cgroupRoot, advertise, runDir         string
	deltaDir, criuBin, registry, templateCache       string
	deltaRegistry, parity                            string
	gvisorRootfs, runsc, runcRootfs, runc            string
	hlHelper, hlGuest                                string
	gvisorOverhead                                   uint64
	registryPlain, gvisorDebug                       bool
	grantCeiling                                     uint64
	templates                                        map[string]string
	adminUnsafe                                      bool
	staleTTL, laneDies, statusEvery, jwksMaxStale    time.Duration
	pressureEvery                                    time.Duration
	baseRate, refW                                   float64
}

func parseFlags() config {
	hostname, _ := os.Hostname()
	var c config
	flag.StringVar(&c.home, "home", "standalone", "home adapter: standalone (k8s and slurm arrive with their phases)")
	flag.StringVar(&c.listen, "listen", ":8484", "gRPC listen address for the Fibers service")
	flag.StringVar(&c.advertise, "advertise", "", "address callers reach this home at (default the listen address)")
	flag.StringVar(&c.httpAddr, "http", "", "optional JSON gateway listen address (off when empty)")
	flag.StringVar(&c.stateDir, "state", envOr("FIBERD_STATE", "/var/lib/fiberd"), "state directory: epoch, audit spool, deltas")
	flag.StringVar(&c.nodeID, "node-id", envOr("FIBERD_NODE_ID", hostname), "this home's identity; a grant's audience must match it")
	flag.StringVar(&c.issuer, "issuer", "", "issuer URL: OIDC discovery root for -verifier=jwks, and what Miss details report")
	flag.StringVar(&c.verifier, "verifier", "", "grant verifier: jwks (signed JWTs, keys from -issuer) or insecure-json (development only); required")
	flag.DurationVar(&c.jwksMaxStale, "jwks-max-stale", time.Hour, "refuse to verify when the key set is older than this (set to the lease TTL)")
	flag.StringVar(&c.grantsDir, "grants-dir", "", "directory polled for *.jwt files to pre-admit (warm before the first Clone)")
	flag.StringVar(&c.cgroupRoot, "cgroup-root", "/sys/fs/cgroup/fiberd", "delegated cgroup v2 subtree the runtime may carve (phase 3)")
	flag.StringVar(&c.runtimeName, "runtime", "stub", "runtime: stub (in-memory), or a sandbox backend on the host runtime: proc (fork zygote + criu), runc (the zygote as an OCI container's init), gvisor (runsc sandbox per fiber), hyperlight (micro-VM snapshots through a helper process)")
	flag.StringVar(&c.runtimeTier, "runtime-tier", "FIBER_CHECKPOINT", "tier the stub runtime advertises (stub only)")
	c.templates = map[string]string{}
	flag.Func("template", "proc: digest=path [args] mapping a template digest to a zygote command (repeatable; key `default` catches the rest)",
		func(v string) error { return host.ParseTemplateFlag(c.templates, v) })
	flag.StringVar(&c.runDir, "run-dir", "/run/fiberd", "proc: directory for fiber endpoints (unix sockets; keep short)")
	flag.StringVar(&c.deltaDir, "delta-dir", "", "proc: directory for parked deltas (default <state>/deltas)")
	flag.StringVar(&c.criuBin, "criu", "criu", "proc: criu binary; park/resume (FIBER_CHECKPOINT) is offered when `criu check` passes")
	flag.Uint64Var(&c.grantCeiling, "grant-ceiling", 0, "proc: fixed block ceiling per grant in bytes (memory.high); 0 = fibers.max * w_budget + zygote + 25%")
	flag.StringVar(&c.registry, "registry", "", "proc: OCI repository (host/repo) to pull zygote artifacts from by template digest")
	flag.BoolVar(&c.registryPlain, "registry-plain-http", false, "proc: the registry speaks http, not https")
	flag.StringVar(&c.templateCache, "template-cache", "", "proc: directory for pulled artifacts (default <state>/templates)")
	flag.StringVar(&c.deltaRegistry, "delta-registry", "", "proc: OCI repository prefix (host/prefix) where parked sessions are published and claimed by other homes")
	flag.StringVar(&c.gvisorRootfs, "gvisor-rootfs", "", "gvisor: rootfs directory every sandbox runs in; -template commands are paths inside it")
	flag.StringVar(&c.runsc, "runsc", "runsc", "gvisor: runsc binary")
	flag.StringVar(&c.runcRootfs, "runc-rootfs", "", "runc: rootfs directory the zygote container runs in; -template commands are paths inside it")
	flag.StringVar(&c.runc, "runc", "runc", "runc: runc binary")
	flag.StringVar(&c.hlHelper, "hyperlight-helper", "", "hyperlight: helper executable speaking hack/hyperlight/PROTOCOL.md (the Rust helper, or fakehelper)")
	flag.StringVar(&c.hlGuest, "hyperlight-guest", "", "hyperlight: guest binary the helper loads")
	flag.Uint64Var(&c.gvisorOverhead, "gvisor-overhead", 0, "gvisor: fixed bytes one sandbox costs besides its working set (sentry + template pages); added to memory.max, subtracted from W; 0 = the warm template's measured size")
	flag.BoolVar(&c.gvisorDebug, "gvisor-debug", false, "gvisor: keep runsc debug logs under <state>/gvisor/log")
	flag.StringVar(&c.parity, "parity", "strict", "proc: how closely artifact images and other homes' deltas must match this host: strict, off, or kernel=exact|series|off,libc=exact|off (arch always)")
	flag.StringVar(&c.adminPath, "admin", "", "admin unix socket (default <state>/admin.sock): GET /healthz")
	flag.BoolVar(&c.adminUnsafe, "admin-unsafe", false, "enable test-only admin controls (POST /lane)")
	flag.DurationVar(&c.staleTTL, "stale-ttl", envDuration("FIBERD_STALE_TTL", 30*time.Second), "grant lane is unhealthy past this silence from the issuer")
	flag.DurationVar(&c.laneDies, "lane-dies-after", envDuration("FIBERD_LANE_DIES_AFTER", 0), "simulate the issuer disappearing after this long (0 = never)")
	flag.Float64Var(&c.baseRate, "base-rate", envFloat("FIBERD_BASE_RATE", 200), "thrash budget: clones/sec at W -> 0")
	flag.Float64Var(&c.refW, "ref-w", 256<<20, "thrash budget: working-set bytes at which the rate halves")
	flag.DurationVar(&c.statusEvery, "status-interval", time.Second, "W sampling and Watch cadence")
	flag.DurationVar(&c.pressureEvery, "pressure-interval", time.Second, "pressure ladder evaluation cadence (0 disables the ladder)")
	flag.Parse()
	if c.advertise == "" {
		c.advertise = c.listen
	}
	return c
}

func main() {
	if err := run(parseFlags()); err != nil {
		log.Fatal(err)
	}
}

func run(c config) error {
	// Verifier first: it decides whether there is an issuer to poll.
	var ver core.Verifier
	var jwks *grant.Cache
	switch c.verifier {
	case "jwks":
		if c.issuer == "" {
			return errors.New("-verifier=jwks needs -issuer (the OIDC discovery root)")
		}
		jwks = &grant.Cache{IssuerURL: c.issuer}
		ver = &grant.Verifier{Cache: jwks, Audience: c.nodeID, MaxStale: c.jwksMaxStale}
	case "insecure-json":
		log.Printf("WARNING: -verifier=insecure-json performs no signature check; development only")
		ver = grant.InsecureJSONVerifier{}
	case "":
		return errors.New("-verifier is required: jwks (signed grants) or insecure-json (development only)")
	default:
		return fmt.Errorf("unknown verifier %q", c.verifier)
	}

	var h *standalone.Home
	switch c.home {
	case "standalone":
		h = standalone.New(standalone.Config{
			Cache: jwks, StaleTTL: c.staleTTL, GrantsDir: c.grantsDir,
			CgroupRoot: c.cgroupRoot, Endpoint: c.advertise, DieAfter: c.laneDies,
		})
	default:
		return fmt.Errorf("home %q is not available yet; only standalone is wired in this phase", c.home)
	}

	var rt core.Runtime
	switch c.runtimeName {
	case "stub":
		tier, err := core.ParseTier(c.runtimeTier)
		if err != nil {
			return fmt.Errorf("runtime-tier: %w", err)
		}
		rt = stub.NewWithTier(tier)
	case "proc", "gvisor", "runc", "hyperlight":
		if len(c.templates) == 0 && c.registry == "" {
			return fmt.Errorf("-runtime=%s needs a -template digest=path or a -registry to pull artifacts from", c.runtimeName)
		}
		// One host runtime, one backend per -runtime name.
		var be backend.Backend
		switch c.runtimeName {
		case "proc":
			be = procbackend.New(procbackend.Options{CRIU: c.criuBin})
		case "hyperlight":
			if c.hlHelper == "" {
				return errors.New("-runtime=hyperlight needs -hyperlight-helper (hack/hyperlight/helper, or fakehelper without a hypervisor)")
			}
			be = hlbackend.New(hlbackend.Options{Helper: c.hlHelper, Guest: c.hlGuest})
		case "runc":
			if c.runcRootfs == "" {
				return errors.New("-runtime=runc needs -runc-rootfs (hack/gvisor/rootfs.sh builds one)")
			}
			be = runcbackend.New(runcbackend.Options{Runc: c.runc, Rootfs: c.runcRootfs, CRIU: c.criuBin,
				StateDir: filepath.Join(c.stateDir, "runc")})
		case "gvisor":
			if c.gvisorRootfs == "" {
				return errors.New("-runtime=gvisor needs -gvisor-rootfs (hack/gvisor/rootfs.sh builds one)")
			}
			be = gvisorbackend.New(gvisorbackend.Options{Runsc: c.runsc, Rootfs: c.gvisorRootfs,
				StateDir: filepath.Join(c.stateDir, "gvisor"), OverheadBytes: c.gvisorOverhead, Debug: c.gvisorDebug})
		}
		if c.deltaDir == "" {
			c.deltaDir = filepath.Join(c.stateDir, "deltas")
		}
		if c.templateCache == "" {
			c.templateCache = filepath.Join(c.stateDir, "templates")
		}
		parity, err := artifact.ParseParity(c.parity)
		if err != nil {
			return err
		}
		pc := host.Config{Backend: be, Templates: c.templates, CgroupRoot: h.CgroupRoot(), RunDir: c.runDir,
			DeltaDir: c.deltaDir,
			Registry: c.registry, RegistryPlainHTTP: c.registryPlain, TemplateCache: c.templateCache,
			DeltaRegistry: c.deltaRegistry, HomeID: c.nodeID, Parity: parity}
		if c.grantCeiling > 0 {
			fixed := c.grantCeiling
			pc.Ceiling = func(core.Grant, uint64) uint64 { return fixed }
		}
		rt, err = host.New(pc)
		if err != nil {
			return fmt.Errorf("%s runtime: %w", c.runtimeName, err)
		}
		if closer, ok := rt.(interface{ Close() }); ok {
			defer closer.Close()
		}
	default:
		return fmt.Errorf("runtime %q is not available yet", c.runtimeName)
	}
	if err := os.MkdirAll(c.stateDir, 0o700); err != nil {
		return fmt.Errorf("state dir: %w", err)
	}
	if c.adminPath == "" {
		c.adminPath = filepath.Join(c.stateDir, "admin.sock")
	}

	// 1. Epoch: every prior fence is invalid from here on.
	ep, err := core.OpenEpochStore(c.stateDir)
	if err != nil {
		return fmt.Errorf("epoch: %w", err)
	}
	log.Printf("fiberd epoch=%d node=%s home=%s (all prior fences invalid)", ep.Current(), c.nodeID, h.Name())

	// 2. Ledger, audit spool, agent.
	led := core.NewLedger(ep.Current())
	spool, err := core.OpenSpool(c.stateDir, nil)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	defer func() { _ = spool.Close() }()

	store := &core.SnapshotStore{Path: filepath.Join(c.stateDir, "ledger.json")}
	ag := &core.Agent{
		NodeID:         c.nodeID,
		Ledger:         led,
		Budget:         core.NewBudget(c.baseRate, c.refW),
		Runtime:        rt,
		Audit:          spool,
		Verify:         ver,
		Health:         h.Health(),
		Store:          store,
		StatusInterval: c.statusEvery,
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

	// The pressure ladder, when the runtime can report PSI.
	if src, ok := rt.(core.PressureSource); ok && c.pressureEvery > 0 {
		ctl := &core.PressureController{
			Ledger: led, Source: src, Interval: c.pressureEvery,
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
		if !c.adminUnsafe {
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
		h.SetLane(body.Healthy)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(healthz())
	})
	_ = os.Remove(c.adminPath)
	al, err := net.Listen("unix", c.adminPath)
	if err != nil {
		return fmt.Errorf("admin socket: %w", err)
	}
	defer func() { _ = os.Remove(c.adminPath) }()
	adminSrv := &http.Server{Handler: admin, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = adminSrv.Serve(al) }()

	// 6. Open the warm path.
	srv := &rpc.Server{Agent: ag, Issuer: c.issuer}
	gs := rpc.NewGRPCServer(srv)
	gl, err := net.Listen("tcp", c.listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", c.listen, err)
	}
	if c.httpAddr != "" {
		gw := &rpc.Gateway{Server: srv, Health: healthz}
		hs := &http.Server{Addr: c.httpAddr, Handler: gw.Handler(), ReadHeaderTimeout: 5 * time.Second}
		go func() {
			log.Printf("fiberd json gateway on %s", c.httpAddr)
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
	log.Printf("fiberd warm path on %s tier=%s admin=%s (no control plane needed beyond this point)", gl.Addr(), rt.Tier(), c.adminPath)
	if err := gs.Serve(gl); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
