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
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/go-jose/go-jose/v4"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/backend"
	gvisorbackend "github.com/helayoty/fiberd/pkg/backend/gvisor"
	hlbackend "github.com/helayoty/fiberd/pkg/backend/hyperlight"
	procbackend "github.com/helayoty/fiberd/pkg/backend/proc"
	runcbackend "github.com/helayoty/fiberd/pkg/backend/runc"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/endpoint"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/handoff"
	"github.com/helayoty/fiberd/pkg/home"
	"github.com/helayoty/fiberd/pkg/home/standalone"
	"github.com/helayoty/fiberd/pkg/rpc"
	"github.com/helayoty/fiberd/pkg/runtime/host"
	"github.com/helayoty/fiberd/pkg/runtime/stub"
	"github.com/helayoty/fiberd/pkg/sys/caps"
	"github.com/helayoty/fiberd/pkg/tlsconf"
)

// Optional interfaces a home may implement; Run looks for them.
type (
	// ScopeLoser can lose its scope while running and wants to say so;
	// Run wires the callback to the agent's epoch bump.
	ScopeLoser interface {
		OnScopeLost(func(ctx context.Context, reason string))
	}
	// EndpointHoster knows the one address its fibers share (a Pod IP, a
	// node address); it fills -endpoint-host when that is empty.
	EndpointHoster interface{ EndpointHost() string }
)

// HomeFactory builds the home once the key cache exists. jwks is nil
// unless -verifier=jwks. The standalone home polls it for liveness.
type HomeFactory func(c *Config, jwks *grant.Cache) (home.Home, error)

// Standalone is the factory cmd/fiberd uses.
func Standalone(c *Config, jwks *grant.Cache) (home.Home, error) {
	return standalone.New(standalone.Config{
		Cache: jwks, StaleTTL: c.StaleTTL, GrantsDir: c.GrantsDir,
		CgroupRoot: c.CgroupRoot, Endpoint: c.Advertise, Devices: c.Devices,
	}), nil
}

// Config is every flag the agent takes. Bind registers them; Finish
// applies defaults after parsing.
type Config struct {
	Listen, HTTPAddr, StateDir, NodeID, Issuer  string
	RuntimeName, RuntimeTier, Verifier          string
	GrantsDir, CgroupRoot, Advertise, RunDir    string
	CRIUBin, Registry                           string
	DeltaRegistry, Parity                       string
	DeltaKey, DeltaTrust, DeltaSealKey          string
	AuditKey                                    string
	HandoffListen, HandoffAdvertise, HandoffKey string
	GvisorRootfs, Runsc, RuncRootfs, Runc       string
	HLHelper, HLGuest                           string
	EndpointFamily, EndpointHost                string
	TLSCert, TLSKey, ClientCA                   string
	InsecurePlaintext                           bool
	RegistryPlain                               bool
	GrantCeiling                                uint64
	Templates                                   map[string]string
	AllCaps                                     bool
	UsernsPool                                  string
	// FiberHide is the parsed -fiber-hide list.
	FiberHide              []string
	StaleTTL, StatusEvery  time.Duration
	JWKSMaxStale, MaxLease time.Duration
	PressureEvery          time.Duration
	// Devices is the parsed -devices list.
	Devices []string

	devices string
	// hooks holds the test-only admin controls. It is empty unless the
	// binary is built with the fiberd_testhooks tag.
	hooks testHooks
	// ready, when set, is told the bound addresses once every listener is
	// open. Tests use it to find ":0" ports. http and handoff are nil when
	// off.
	ready func(grpc, http, handoff net.Addr)
	// auditHealth, when set, replaces the spool's Poisoned on /healthz.
	// Tests use it, since a real fsync cannot be made to fail.
	auditHealth func() error
}

// The port range inet4 and inet6 endpoints are handed out from, one port
// per live fiber.
const (
	endpointPortMin = 30000
	endpointPortMax = 32767
)

// Bind registers the agent's flags on fs. A binary adds its own (a home's)
// beside them.
func (c *Config) Bind(fs *flag.FlagSet) {
	hostname, _ := os.Hostname()
	fs.StringVar(&c.Listen, "listen", ":8484", "gRPC listen address for the Fibers service")
	fs.StringVar(&c.Advertise, "advertise", "", "address callers reach this home at (default the listen address, or what the home knows)")
	fs.StringVar(&c.HTTPAddr, "http", "", "optional JSON gateway listen address (off when empty)")
	fs.StringVar(&c.TLSCert, "tls-cert", "", "PEM server certificate for the gRPC API and the JSON gateway")
	fs.StringVar(&c.TLSKey, "tls-key", "", "PEM private key of -tls-cert")
	fs.StringVar(&c.ClientCA, "client-ca", "", "PEM CA bundle every caller's client certificate must chain to")
	fs.BoolVar(&c.InsecurePlaintext, "insecure-plaintext", false, "serve the API without TLS and without caller identity (development and tests only)")
	fs.StringVar(&c.StateDir, "state", "/var/lib/fiberd", "state directory: templates and deltas, and under private/ (mode 0700, hidden from fibers) the keys, epoch, ledger, deny-list, audit spool and admin socket")
	fs.StringVar(&c.NodeID, "node-id", hostname, "this home's identity; a grant's audience must match it")
	fs.StringVar(&c.Issuer, "issuer", "", "issuer URL: OIDC discovery root for -verifier=jwks, and what Miss details report")
	fs.StringVar(&c.Verifier, "verifier", "", "grant verifier: jwks (signed JWTs, keys from -issuer) or insecure-json (development only); required")
	fs.DurationVar(&c.JWKSMaxStale, "jwks-max-stale", time.Hour, "refuse to verify when the key set is older than this (set to the lease TTL)")
	fs.DurationVar(&c.MaxLease, "max-lease", 0, "-verifier=jwks: refuse grants signed for longer than this (exp - iat), or without a lease; 0 accepts any")
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
	fs.StringVar(&c.CRIUBin, "criu", "criu", "proc: criu binary; park/resume (FIBER_CHECKPOINT) is offered when `criu check` passes")
	fs.Uint64Var(&c.GrantCeiling, "grant-ceiling", 0, "proc: fixed block ceiling per grant in bytes (memory.high); 0 = fibers.max * w_budget + zygote + 25%")
	fs.BoolVar(&c.AllCaps, "all-caps", false, "proc and runc: keep every capability the agent started with; by default it re-executes with only what the runtime was measured to need in its bounding set (proc: SYS_ADMIN, SYS_PTRACE, SYS_RESOURCE, SYS_TIME, SYS_CHROOT, NET_ADMIN, SETPCAP; runc adds CHOWN, DAC_OVERRIDE, SETGID, SETUID), which criu and the zygote inherit, and refuses to start when it cannot drop the rest")
	fs.StringVar(&c.UsernsPool, "userns-pool", runcbackend.DefaultPool, "runc: START:SLOTS, the host ids grants' user namespaces are carved from in 65536-id slots; a grant's slot is a hash of its uid, so homes with the same pool give it the same ids; the default sits above every /etc/subuid convention, and a pool overlapping an /etc/subuid or /etc/subgid entry is refused at start")
	fs.Func("fiber-hide", "proc: directory fibers must not see, besides the service-account token, <state>/private, <state>/deltas and -grants-dir (repeatable)",
		func(v string) error { c.FiberHide = append(c.FiberHide, v); return nil })
	fs.StringVar(&c.Registry, "registry", "", "proc: OCI repository (host/repo) to pull zygote artifacts from by template digest")
	fs.BoolVar(&c.RegistryPlain, "registry-plain-http", false, "proc: the registry speaks http, not https")
	fs.StringVar(&c.DeltaRegistry, "delta-registry", "", "proc: OCI repository prefix (host/prefix) where parked sessions are published and claimed by other homes")
	fs.StringVar(&c.DeltaKey, "delta-key", "", "proc: private Ed25519 JWK every published delta is signed with (grant-issuer keygen -alg EdDSA); default <state>/private/delta-key.json, generated when missing")
	fs.StringVar(&c.DeltaTrust, "delta-trust", "", "proc: JWKS of further public keys whose deltas this home claims and imports; -delta-key's own is always trusted")
	fs.StringVar(&c.DeltaSealKey, "delta-seal-key", "", "proc: 32-byte symmetric JWK every delta is encrypted with before it leaves the home (grant-issuer keygen -alg A256GCM); homes that move sessions between them share it; default <state>/private/delta-seal-key.json, generated when missing")
	fs.StringVar(&c.AuditKey, "audit-key", "", "private Ed25519 JWK the audit spool's checkpoints are signed with (grant-issuer keygen -alg EdDSA); default <state>/private/audit-key.json, generated when missing")
	fs.StringVar(&c.HandoffListen, "handoff-listen", "", "proc, runc: TCP address the home accepts callers' TLS connections on for grants whose endpoint mode is HANDOFF, routed to fibers by server name (off when empty; such grants are then refused)")
	fs.StringVar(&c.HandoffAdvertise, "handoff-advertise", "", "host:port callers dial for -handoff-listen (default the listen address, its host filled from -endpoint-host or the home when it is a wildcard)")
	fs.StringVar(&c.HandoffKey, "handoff-key", "", "32-byte symmetric JWK each handoff grant's TLS key is derived from (grant-issuer keygen -alg A256GCM); homes that move sessions between them share it; default <state>/private/handoff-key.json, generated when missing")
	fs.StringVar(&c.GvisorRootfs, "gvisor-rootfs", "", "gvisor: rootfs directory every sandbox runs in; -template commands are paths inside it")
	fs.StringVar(&c.Runsc, "runsc", "runsc", "gvisor: runsc binary")
	fs.StringVar(&c.RuncRootfs, "runc-rootfs", "", "runc: rootfs directory the zygote container runs in; -template commands are paths inside it")
	fs.StringVar(&c.Runc, "runc", "runc", "runc: runc binary")
	fs.StringVar(&c.HLHelper, "hyperlight-helper", "", "hyperlight: helper executable speaking hack/hyperlight/PROTOCOL.md (the Rust helper, or fakehelper)")
	fs.StringVar(&c.HLGuest, "hyperlight-guest", "", "hyperlight: guest binary the helper loads")
	fs.StringVar(&c.Parity, "parity", "strict", "proc: how closely artifact images and other homes' deltas must match this host: strict, off, or kernel=exact|series|off,libc=exact|off (arch always)")
	fs.StringVar(&c.devices, "devices", "", "comma-separated devices every grant's engine may drive (the home's fabric channel; empty = none)")
	fs.DurationVar(&c.StaleTTL, "stale-ttl", 30*time.Second, "grant lane is unhealthy past this silence from the control plane")
	fs.DurationVar(&c.StatusEvery, "status-interval", time.Second, "W sampling and Watch cadence")
	fs.DurationVar(&c.PressureEvery, "pressure-interval", time.Second, "pressure ladder evaluation cadence (0 disables the ladder)")
	c.hooks.bind(fs)
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

// NarrowCaps re-executes the agent with only what its runtime needs in
// its capability bounding set, unless -all-caps. Call it in main right
// after Finish, since the process starts over. The proc and runc sets
// are measured (hack/test/caps.sh, tests/runc). The other runtimes keep
// what they have. It fails closed. An agent that holds more than its
// runtime needs but cannot drop it returns an error instead of running
// with everything, and the caller should exit.
func (c *Config) NarrowCaps() error {
	keep, measured := caps.ForRuntime(c.RuntimeName)
	if c.AllCaps || !measured || len(capsExtra(keep)) == 0 {
		return nil
	}
	names := make([]string, 0, len(keep))
	for _, n := range keep {
		names = append(names, caps.Names[n])
	}
	log.Printf("agent: re-executing with only %s in the capability bounding set (-all-caps keeps them all)", strings.Join(names, ", "))
	if err := capsNarrow(keep); err != nil {
		return fmt.Errorf("agent: narrow capabilities for -runtime=%s: %w (grant CAP_SETPCAP, or pass -all-caps to keep every capability)", c.RuntimeName, err)
	}
	return nil
}

// capsExtra and capsNarrow are the caps calls NarrowCaps makes. Tests
// replace them.
var (
	capsExtra  = caps.Extra
	capsNarrow = caps.Narrow
)

// LoadDeltaKeys reads -delta-key, -delta-trust and -delta-seal-key;
// without a delta registry there is nothing to sign or seal. Without
// -delta-key or -delta-seal-key the home uses a key of its own under
// -state, generated on first use, which no other home trusts or can open
// with until it is shared.
func (c *Config) LoadDeltaKeys() (artifact.Keys, error) {
	if c.DeltaRegistry == "" {
		return artifact.Keys{}, nil
	}
	path, err := c.stateKey(c.DeltaKey, "delta-key.json", func() (*jose.JSONWebKey, error) { return grant.GenerateKey(jose.EdDSA) },
		"delta signing key", "share one with -delta-key or trust each other's with -delta-trust")
	if err != nil {
		return artifact.Keys{}, fmt.Errorf("-delta-key: %w", err)
	}
	k, err := artifact.LoadKeys(path, c.DeltaTrust)
	if err != nil {
		return artifact.Keys{}, fmt.Errorf("-delta-key/-delta-trust: %w", err)
	}
	if path, err = c.stateKey(c.DeltaSealKey, "delta-seal-key.json", artifact.GenerateSealKey,
		"delta seal key", "share one with -delta-seal-key"); err != nil {
		return artifact.Keys{}, fmt.Errorf("-delta-seal-key: %w", err)
	}
	if k.Seal, err = artifact.LoadSealKey(path); err != nil {
		return artifact.Keys{}, fmt.Errorf("-delta-seal-key: %w", err)
	}
	return k, nil
}

// loadAuditKey reads -audit-key; without it the home signs checkpoints
// with a key of its own under -state, generated on first use, whose public
// half audit-verify needs.
func (c *Config) loadAuditKey() (*core.Checkpoints, error) {
	path, err := c.stateKey(c.AuditKey, "audit-key.json", func() (*jose.JSONWebKey, error) { return grant.GenerateKey(jose.EdDSA) },
		"audit checkpoint key", "keep its public half for audit-verify")
	if err != nil {
		return nil, fmt.Errorf("-audit-key: %w", err)
	}
	k, err := artifact.LoadKeys(path, "")
	if err != nil {
		return nil, fmt.Errorf("-audit-key: %w", err)
	}
	return &core.Checkpoints{KeyID: k.Signer.KeyID, Key: k.Signer.Key.(ed25519.PrivateKey)}, nil
}

// loadHandoffKey reads -handoff-key; without it the home derives handoff
// identities from a key of its own under -state, generated on first use,
// so a session resumed on a home without the same key fails its caller's
// pin.
func (c *Config) loadHandoffKey() ([]byte, error) {
	path, err := c.stateKey(c.HandoffKey, "handoff-key.json", artifact.GenerateSealKey,
		"handoff key", "share one with -handoff-key")
	if err != nil {
		return nil, fmt.Errorf("-handoff-key: %w", err)
	}
	k, err := artifact.LoadSealKey(path)
	if err != nil {
		return nil, fmt.Errorf("-handoff-key: %w", err)
	}
	return k.Key, nil
}

// handoffAdvertise is the tcp:// address callers dial for the handoff
// listener at addr: -handoff-advertise, or addr with a wildcard host
// replaced by -endpoint-host (else the loopback).
func (c *Config) handoffAdvertise(addr net.Addr) (string, error) {
	if c.HandoffAdvertise != "" {
		if _, _, err := net.SplitHostPort(c.HandoffAdvertise); err != nil {
			return "", fmt.Errorf("-handoff-advertise %q: %w", c.HandoffAdvertise, err)
		}
		return "tcp://" + c.HandoffAdvertise, nil
	}
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", err
	}
	if ip := net.ParseIP(host); ip == nil || ip.IsUnspecified() {
		host = c.EndpointHost
		if host == "" {
			host = "127.0.0.1"
			log.Printf("WARNING: -handoff-listen %s is a wildcard and no -handoff-advertise or -endpoint-host is set; advertising %s", addr, host)
		}
	}
	return "tcp://" + net.JoinHostPort(host, port), nil
}

// stateKey is the key file a flag names, or name under the private state
// directory, generated with gen when missing.
func (c *Config) stateKey(flagPath, name string, gen func() (*jose.JSONWebKey, error), what, share string) (string, error) {
	if flagPath != "" {
		return flagPath, nil
	}
	if err := c.ensurePrivate(); err != nil {
		return "", err
	}
	path := filepath.Join(c.PrivateDir(), name)
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		return path, nil
	}
	k, err := gen()
	if err != nil {
		return "", err
	}
	if err := grant.SaveKey(path, k); err != nil {
		return "", err
	}
	log.Printf("WARNING: generated %s %s (kid %s); homes that move sessions between them must %s", what, path, k.KeyID, share)
	return path, nil
}

// Family is the parsed -endpoint-family.
func (c *Config) Family() (endpoint.Family, error) { return endpoint.ParseFamily(c.EndpointFamily) }

// endpointPolicy reads the -endpoint-* flags: the family a deployment
// declares and the address its fibers share. The port range is fixed.
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
		p.PortMin, p.PortMax = endpointPortMin, endpointPortMax
	}
	return p, p.Validate()
}

// AdminSocket is the admin unix socket, <state>/private/admin.sock.
func (c *Config) AdminSocket() string { return filepath.Join(c.PrivateDir(), "admin.sock") }

// Run is the agent: it returns when the RPC server stops, on SIGINT or
// SIGTERM.
func Run(c *Config, newHome HomeFactory) error { return RunContext(context.Background(), c, newHome) }

// RunContext is Run that also stops when ctx ends. A binary that owns its
// process's lifetime, and a test, stop the agent through ctx.
func RunContext(ctx context.Context, c *Config, newHome HomeFactory) error {
	// Transport before anything starts: a misconfigured TLS setup must not
	// leave a half-started agent behind.
	serverTLS, err := tlsconf.Server(c.TLSCert, c.TLSKey, c.ClientCA, c.InsecurePlaintext)
	if err != nil {
		return err
	}
	if serverTLS == nil {
		log.Printf("WARNING: -insecure-plaintext serves the API without TLS or caller identity; development only")
	}
	// The private state directory, before any key is read or generated.
	// Fibers are given its absolute path to hide, whatever -state was.
	if abs, err := filepath.Abs(c.StateDir); err == nil {
		c.StateDir = abs
	}
	if err := c.ensurePrivate(); err != nil {
		return err
	}

	// Verifier first: it decides whether there is an issuer to poll.
	var ver core.Verifier
	var jwks *grant.Cache
	switch c.Verifier {
	case "jwks":
		if c.Issuer == "" {
			return errors.New("-verifier=jwks needs -issuer (the OIDC discovery root)")
		}
		jwks = &grant.Cache{IssuerURL: c.Issuer}
		ver = &grant.Verifier{Cache: jwks, Audience: c.NodeID, MaxStale: c.JWKSMaxStale, MaxLease: c.MaxLease}
	case "insecure-json":
		log.Printf("WARNING: -verifier=insecure-json performs no signature check; development only")
		ver = grant.InsecureJSONVerifier{}
	case "":
		return errors.New("-verifier is required: jwks (signed grants) or insecure-json (development only)")
	default:
		return fmt.Errorf("unknown verifier %q", c.Verifier)
	}

	h, err := newHome(c, jwks)
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
	var hrt *host.Runtime // the host runtime; nil for the stub
	var router *handoff.Router
	var handoffLn net.Listener
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
			be = procbackend.New(c.procOptions())
		case "hyperlight":
			if c.HLHelper == "" {
				return errors.New("-runtime=hyperlight needs -hyperlight-helper (hack/hyperlight/helper, or fakehelper without a hypervisor)")
			}
			be = hlbackend.New(hlbackend.Options{Helper: c.HLHelper, Guest: c.HLGuest})
		case "runc":
			if c.RuncRootfs == "" {
				return errors.New("-runtime=runc needs -runc-rootfs (hack/gvisor/rootfs.sh builds one)")
			}
			pool, err := runcbackend.ParsePool(c.UsernsPool)
			if err != nil {
				return fmt.Errorf("-userns-pool: %w", err)
			}
			be, err = runcbackend.New(runcbackend.Options{Runc: c.Runc, Rootfs: c.RuncRootfs, CRIU: c.CRIUBin,
				StateDir: filepath.Join(c.StateDir, "runc"), Pool: pool})
			if err != nil {
				return err
			}
		case "gvisor":
			if c.GvisorRootfs == "" {
				return errors.New("-runtime=gvisor needs -gvisor-rootfs (hack/gvisor/rootfs.sh builds one)")
			}
			be = gvisorbackend.New(gvisorbackend.Options{Runsc: c.Runsc, Rootfs: c.GvisorRootfs,
				StateDir: filepath.Join(c.StateDir, "gvisor")})
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
			DeltaDir: filepath.Join(c.StateDir, "deltas"), Endpoints: eps,
			Registry: c.Registry, RegistryPlainHTTP: c.RegistryPlain, TemplateCache: filepath.Join(c.StateDir, "templates"),
			DeltaRegistry: c.DeltaRegistry, HomeID: c.NodeID, Parity: parity,
			FiberHide: c.FiberHide, PrivateDir: c.PrivateDir()}
		if pc.DeltaKeys, err = c.LoadDeltaKeys(); err != nil {
			return err
		}
		if c.HandoffListen != "" {
			if pc.HandoffKey, err = c.loadHandoffKey(); err != nil {
				return err
			}
			if handoffLn, err = net.Listen("tcp", c.HandoffListen); err != nil {
				return fmt.Errorf("-handoff-listen %s: %w", c.HandoffListen, err)
			}
			defer func() { _ = handoffLn.Close() }()
			adv, err := c.handoffAdvertise(handoffLn.Addr())
			if err != nil {
				return err
			}
			router = &handoff.Router{Advertise: adv}
			pc.Handoff = router
		}
		if c.GrantsDir != "" {
			abs, err := filepath.Abs(c.GrantsDir)
			if err != nil {
				return err
			}
			pc.FiberHide = append(pc.FiberHide, abs)
		}
		if c.GrantCeiling > 0 {
			fixed := c.GrantCeiling
			pc.Ceiling = func(core.Grant, uint64) uint64 { return fixed }
		}
		if hrt, err = host.New(pc); err != nil {
			return fmt.Errorf("%s runtime: %w", c.RuntimeName, err)
		}
		rt = hrt
		if router != nil {
			router.Deliver = hrt.Deliver
		}
		defer hrt.Close()
	default:
		return fmt.Errorf("runtime %q is not available yet", c.RuntimeName)
	}
	private := c.PrivateDir()

	// 1. Epoch: every prior fence is invalid from here on.
	ep, err := core.OpenEpochStore(private)
	if err != nil {
		return fmt.Errorf("epoch: %w", err)
	}
	log.Printf("fiberd epoch=%d node=%s home=%s (all prior fences invalid)", ep.Current(), c.NodeID, h.Name())

	// 2. Ledger, audit spool, agent.
	led := core.NewLedger(ep.Current())
	cp, err := c.loadAuditKey()
	if err != nil {
		return err
	}
	spool, err := core.OpenSpool(private, cp)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	defer func() { _ = spool.Close() }()

	store := &core.SnapshotStore{Path: filepath.Join(private, "ledger.json")}
	// A removed grant stays refused for -max-lease past its lease, or
	// core.DefaultRevokeTTL without one.
	revoked, err := core.OpenRevoked(filepath.Join(private, "revoked.json"), c.MaxLease, time.Now())
	if err != nil {
		return fmt.Errorf("deny-list: %w", err)
	}
	ag := &core.Agent{
		NodeID:             c.NodeID,
		RequireBoundGrants: serverTLS != nil,
		Ledger:             led,
		Budget:             core.NewBudget(core.DefaultBaseRate, core.DefaultRefW),
		Runtime:            rt,
		Audit:              spool,
		Verify:             ver,
		Health:             h.Health(),
		Scope:              h.Scope,
		Fabric:             h.Fabric,
		Epoch:              ep,
		Store:              store,
		Revoked:            revoked,
		StatusInterval:     c.StatusEvery,
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
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
	if hrt != nil {
		keep := map[string]bool{}
		for _, st := range led.Statuses() {
			keep[st.GrantUID] = true
		}
		hrt.PruneGrants(keep)
	}
	log.Printf("reconcile: grants re-admitted=%d expired=%d unverified=%d parked restored=%d dropped=%d orphans killed=%d",
		rep.GrantsReadmitted, rep.GrantsExpired, rep.GrantsUnverified, rep.ParkedRestored, rep.ParkedDropped, rep.OrphansKilled)
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
		if hrt != nil {
			src = core.MaxPressure{src, hrt.DevicePressure()}
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
	auditHealth := spool.Poisoned
	if c.auditHealth != nil {
		auditHealth = c.auditHealth
	}
	healthz := rpc.HealthFunc(ep.Current, h.Health(), rt.Tier(), auditHealth)
	admin := http.NewServeMux()
	admin.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { rpc.WriteHealth(w, healthz()) })
	c.hooks.register(admin, h, ag, healthz)
	adminSock := c.AdminSocket()
	_ = os.Remove(adminSock)
	al, err := net.Listen("unix", adminSock)
	if err != nil {
		return fmt.Errorf("admin socket: %w", err)
	}
	defer func() { _ = os.Remove(adminSock) }()
	adminSrv := &http.Server{Handler: admin, ReadHeaderTimeout: 5 * time.Second}
	// Closed on every return, so a start that fails below leaves no admin
	// server behind.
	defer func() { _ = adminSrv.Close() }()
	go func() { _ = adminSrv.Serve(al) }()

	// 6. Open the warm path.
	srv := &rpc.Server{Agent: ag, Issuer: c.Issuer}
	var gopts []grpc.ServerOption
	if serverTLS != nil {
		gopts = append(gopts, grpc.Creds(credentials.NewTLS(serverTLS)))
	}
	gs := rpc.NewGRPCServer(srv, gopts...)
	gl, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", c.Listen, err)
	}
	// The gateway listens here, not in its goroutine, so an address it
	// cannot bind fails the start instead of leaving an agent without it.
	var hl net.Listener
	if c.HTTPAddr != "" {
		if hl, err = net.Listen("tcp", c.HTTPAddr); err != nil {
			_ = gl.Close()
			return fmt.Errorf("-http %s: %w", c.HTTPAddr, err)
		}
		gw := &rpc.Gateway{Server: srv, Health: healthz}
		hs := &http.Server{Handler: gw.Handler(), TLSConfig: serverTLS, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			log.Printf("fiberd json gateway on %s", hl.Addr())
			serve := func() error { return hs.Serve(hl) }
			if serverTLS != nil {
				serve = func() error { return hs.ServeTLS(hl, "", "") }
			}
			if err := serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("gateway: %v", err)
			}
		}()
		go func() { <-ctx.Done(); _ = hs.Close() }()
	}
	if router != nil {
		go func() {
			log.Printf("fiberd handoff on %s (callers dial %s)", handoffLn.Addr(), router.Advertise)
			if err := router.Serve(handoffLn); err != nil {
				log.Printf("handoff: %v", err)
			}
		}()
	}
	go func() {
		<-ctx.Done()
		gs.GracefulStop()
		_ = adminSrv.Close()
		if handoffLn != nil {
			_ = handoffLn.Close()
		}
	}()
	log.Printf("fiberd warm path on %s tier=%s admin=%s (no control plane needed beyond this point)", gl.Addr(), rt.Tier(), adminSock)
	if c.ready != nil {
		var ha, ho net.Addr
		if hl != nil {
			ha = hl.Addr()
		}
		if handoffLn != nil {
			ho = handoffLn.Addr()
		}
		c.ready(gl.Addr(), ha, ho)
	}
	// A stop that lands before Serve starts makes it return
	// ErrServerStopped. That is a clean stop too.
	if err := gs.Serve(gl); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
