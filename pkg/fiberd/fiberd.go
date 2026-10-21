// Package fiberd is fiberd as a library: the flags, the wiring
// of verifier, runtime, ledger, pressure ladder, admin socket and RPC
// server, and the fixed startup order (epoch++ -> reconcile -> open
// RPC). cmd/fiberd is this package plus the standalone home; an
// integration builds its own binary from this package plus its home
// (examples/kubernetes/cmd/fiberd-k8s is one). Nothing here knows which
// home it runs under beyond the home.Home interface and the optional
// interfaces below.
package fiberd

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
	"sync"
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
	// Run wires the callback to fiberd's epoch bump.
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
		Cache: jwks, StaleTTL: c.Node.StaleTTL, GrantsDir: c.Node.GrantsDir,
		CgroupRoot: c.Node.CgroupRoot, Devices: c.Node.Devices,
	}), nil
}

// Config is every flag fiberd takes, grouped by concern. Bind registers
// them.
type Config struct {
	Node     Node
	API      API
	Trust    Trust
	Runtime  Runtime
	Endpoint Endpoint
	Handoff  Handoff
	Registry Registry
	Audit    Audit
	// Timing paces the loops. It is not a flag in a release build. Tests
	// and embedding binaries set it, and the testhooks build binds flags
	// on it.
	Timing Timing
	// Ready, when set, is told the bound addresses once every listener
	// is open. A binary or a test that listens on ":0" learns its ports
	// from it. http and handoff are nil when off.
	Ready func(grpc, http, handoff net.Addr)

	// hooks holds the test-only admin controls. It is empty unless the
	// binary is built with the fiberd_testhooks tag.
	hooks testHooks
	// auditHealth, when set, replaces the spool's Poisoned on /healthz.
	// Tests use it, since a real fsync cannot be made to fail.
	auditHealth func() error
}

// Node is this home's identity and what it owns on the host.
type Node struct {
	ID         string        // -node-id
	StateDir   string        // -state
	CgroupRoot string        // -cgroup-root
	GrantsDir  string        // -grants-dir
	StaleTTL   time.Duration // -stale-ttl
	Devices    []string      // -devices
	AllCaps    bool          // -all-caps
}

// API is where fiberd serves and how callers prove who they are.
type API struct {
	Listen string // -listen
	HTTP   string // -http
	TLS    TLS
}

// TLS is the API's transport.
type TLS struct {
	Cert, Key, ClientCA string // -tls-cert, -tls-key, -client-ca
	InsecurePlaintext   bool   // -insecure-plaintext
}

// Trust is how grants are verified.
type Trust struct {
	Verifier     string        // -verifier
	Issuer       string        // -issuer
	JWKSMaxStale time.Duration // -jwks-max-stale
	MaxLease     time.Duration // -max-lease
}

// Runtime picks the backend and what every backend shares.
type Runtime struct {
	Name         string            // -runtime
	StubTier     string            // -runtime-tier
	Templates    map[string]string // -template
	Parity       string            // -parity
	GrantCeiling uint64            // -grant-ceiling
	FiberHide    []string          // -fiber-hide
	Gvisor       Gvisor
	Runc         Runc
	Hyperlight   Hyperlight
}

// Gvisor, Runc and Hyperlight are what only that backend needs. The
// backends find their criu, runsc and runc binaries on PATH.
type (
	Gvisor struct {
		Rootfs          string // -gvisor-rootfs
		TemplatesOnDisk bool   // -gvisor-templates-on-disk
	}
	Runc       struct{ Rootfs, UsernsPool string } // -runc-rootfs, -userns-pool
	Hyperlight struct{ Helper, Guest string }      // -hyperlight-helper, -hyperlight-guest
)

// gvisorOptions configures the gVisor backend. Its state lives under the
// home's own state directory.
func (c *Config) gvisorOptions() gvisorbackend.Options {
	return gvisorbackend.Options{Rootfs: c.Runtime.Gvisor.Rootfs, StateDir: filepath.Join(c.Node.StateDir, "gvisor"),
		TemplatesOnDisk: c.Runtime.Gvisor.TemplatesOnDisk}
}

// Endpoint is the address family fibers are served on.
type Endpoint struct{ Family, Host string } // -endpoint-family, -endpoint-host

// Handoff is the TLS listener for HANDOFF-mode grants.
type Handoff struct{ Listen, Key string } // -handoff-listen, -handoff-key

// Registry is where templates come from and where deltas go. A
// repository starting with http:// is reached over plain HTTP.
type Registry struct {
	Templates string // -registry
	Deltas    string // -delta-registry
	Keys      DeltaKeys
}

// DeltaKeys sign, trust and seal published deltas.
type DeltaKeys struct{ Sign, Trust, Seal string } // -delta-key, -delta-trust, -delta-seal-key

// Audit is the audit spool's signing key.
type Audit struct{ Key string } // -audit-key

// Timing paces the W sampler, the Watch stream and the pressure ladder.
// Zero means one second. A negative PressureEvery turns the ladder off.
type Timing struct{ StatusEvery, PressureEvery time.Duration }

// The port range inet4 and inet6 endpoints are handed out from, one port
// per live fiber.
const (
	endpointPortMin = 30000
	endpointPortMax = 32767
)

// Bind registers fiberd's flags on fs. A binary adds its own (a home's)
// beside them.
func (c *Config) Bind(fs *flag.FlagSet) {
	hostname, _ := os.Hostname()
	fs.StringVar(&c.Node.ID, "node-id", hostname, "this home's identity, which a grant's audience must match")
	fs.StringVar(&c.Node.StateDir, "state", "/var/lib/fiberd", "state directory for templates, deltas and fiber endpoints (unix sockets under run/, so keep the path short). Keys, epoch, ledger, deny-list, audit spool and admin socket live under private/ (mode 0700, hidden from fibers)")
	fs.StringVar(&c.Node.CgroupRoot, "cgroup-root", "/sys/fs/cgroup/fiberd", "delegated cgroup v2 subtree the runtime may carve (homes that own their cgroup ignore it)")
	fs.StringVar(&c.Node.GrantsDir, "grants-dir", "", "directory polled for *.jwt files to pre-admit (warm before the first Clone)")
	fs.DurationVar(&c.Node.StaleTTL, "stale-ttl", 30*time.Second, "the issuer counts as unreachable past this silence from the control plane")
	fs.Func("devices", "comma-separated devices every grant's engine may drive (the home's device channel; empty = none)", c.parseDevices)
	fs.BoolVar(&c.Node.AllCaps, "all-caps", false, "proc and runc: keep every capability. By default fiberd re-executes with only the measured set its runtime needs, and refuses to start if it cannot drop the rest")

	fs.StringVar(&c.API.Listen, "listen", ":8484", "gRPC listen address for the Fibers service")
	fs.StringVar(&c.API.HTTP, "http", "", "optional JSON gateway listen address (off when empty)")
	fs.StringVar(&c.API.TLS.Cert, "tls-cert", "", "PEM server certificate for the gRPC API and the JSON gateway")
	fs.StringVar(&c.API.TLS.Key, "tls-key", "", "PEM private key of -tls-cert")
	fs.StringVar(&c.API.TLS.ClientCA, "client-ca", "", "PEM CA bundle every caller's client certificate must chain to")
	fs.BoolVar(&c.API.TLS.InsecurePlaintext, "insecure-plaintext", false, "serve the API without TLS and without caller identity (development and tests only)")

	fs.StringVar(&c.Trust.Verifier, "verifier", "", "grant verifier: jwks (signed JWTs, keys from -issuer) or insecure-json (development only); required")
	fs.StringVar(&c.Trust.Issuer, "issuer", "", "issuer URL: OIDC discovery root for -verifier=jwks, and what Miss details report")
	fs.DurationVar(&c.Trust.JWKSMaxStale, "jwks-max-stale", time.Hour, "refuse to verify when the key set is older than this (set to the lease TTL)")
	fs.DurationVar(&c.Trust.MaxLease, "max-lease", 0, "-verifier=jwks: refuse grants signed for longer than this (exp - iat) or without a lease (0 accepts any)")

	fs.StringVar(&c.Runtime.Name, "runtime", "stub", "runtime: stub (in-memory), or a sandbox backend on the host runtime: proc (fork zygote + criu from PATH; park/resume is offered with criu 4.2 or later whose `criu check` passes), runc (the zygote as an OCI container's init), gvisor (runsc sandbox per fiber), hyperlight (micro-VM snapshots through a helper process)")
	fs.StringVar(&c.Runtime.StubTier, "runtime-tier", "FIBER_CHECKPOINT", "tier the stub runtime advertises (stub only)")
	c.Runtime.Templates = map[string]string{}
	fs.Func("template", "proc: digest=path [args] mapping a template digest to a zygote command (repeatable; key `default` catches the rest)",
		func(v string) error { return host.ParseTemplateFlag(c.Runtime.Templates, v) })
	fs.StringVar(&c.Runtime.Parity, "parity", "strict", "proc: how closely artifact images and other homes' deltas must match this host: strict, off, or kernel=exact|series|off,libc=exact|off (arch always)")
	fs.Uint64Var(&c.Runtime.GrantCeiling, "grant-ceiling", 0, "proc: fixed block ceiling per grant in bytes (memory.high); 0 = fibers.max * w_budget + zygote + 25%")
	fs.Func("fiber-hide", "proc: directory fibers must not see, besides the service-account token, <state>/private, <state>/deltas and -grants-dir (repeatable)",
		func(v string) error { c.Runtime.FiberHide = append(c.Runtime.FiberHide, v); return nil })
	fs.StringVar(&c.Runtime.Gvisor.Rootfs, "gvisor-rootfs", "", "gvisor: rootfs directory every sandbox runs in; -template commands are paths inside it")
	fs.BoolVar(&c.Runtime.Gvisor.TemplatesOnDisk, "gvisor-templates-on-disk", false, "gvisor: keep template images under <state>/gvisor/templates on disk. By default fiberd mounts a tmpfs there, so a warm template's memory never reaches a disk, at the cost of about one template image of RAM per warm grant")
	fs.StringVar(&c.Runtime.Runc.Rootfs, "runc-rootfs", "", "runc: rootfs directory the zygote container runs in; -template commands are paths inside it")
	fs.StringVar(&c.Runtime.Runc.UsernsPool, "userns-pool", runcbackend.DefaultPool, "runc: START:SLOTS host id pool that grants' user namespaces take 65536-id slots from, picked by a hash of the grant uid. A pool overlapping /etc/subuid or /etc/subgid is refused")
	fs.StringVar(&c.Runtime.Hyperlight.Helper, "hyperlight-helper", "", "hyperlight: helper executable speaking hack/hyperlight/PROTOCOL.md (the Rust helper, or fakehelper)")
	fs.StringVar(&c.Runtime.Hyperlight.Guest, "hyperlight-guest", "", "hyperlight: guest binary the helper loads")

	fs.StringVar(&c.Endpoint.Family, "endpoint-family", "unix", "address family fibers are served on: unix (sockets under <state>/run), inet4 or inet6 (tcp on -endpoint-host, a port per fiber); declared, never discovered")
	fs.StringVar(&c.Endpoint.Host, "endpoint-host", "", "inet4/inet6: the one address the grant's fibers share and callers dial (default: what the home knows, else the loopback of the family)")

	fs.StringVar(&c.Handoff.Listen, "handoff-listen", "", "proc, runc: TCP address for callers' TLS connections to HANDOFF-mode grants, routed to fibers by server name. Empty turns it off and refuses such grants")
	fs.StringVar(&c.Handoff.Key, "handoff-key", "", "32-byte symmetric JWK that handoff grants' TLS keys are derived from (grant-issuer keygen -alg A256GCM). Homes that move sessions between them share it. Default <state>/private/handoff-key.json, generated when missing")

	fs.StringVar(&c.Registry.Templates, "registry", "", "proc, gvisor: OCI repository (host/repo, or http://host/repo for plain HTTP) to pull zygote artifacts from by template digest. A gvisor home binds the pulled executable read-only at /fiberd/template in every sandbox, so it must be static")
	fs.StringVar(&c.Registry.Deltas, "delta-registry", "", "proc: OCI repository prefix (host/prefix, or http://host/prefix for plain HTTP) where parked sessions are published and claimed by other homes")
	fs.StringVar(&c.Registry.Keys.Sign, "delta-key", "", "proc: private Ed25519 JWK that signs every published delta (grant-issuer keygen -alg EdDSA). Default <state>/private/delta-key.json, generated when missing")
	fs.StringVar(&c.Registry.Keys.Trust, "delta-trust", "", "proc: JWKS of further public keys whose deltas this home claims and imports (-delta-key's own is always trusted)")
	fs.StringVar(&c.Registry.Keys.Seal, "delta-seal-key", "", "proc: the fleet's 32-byte symmetric master seal key (grant-issuer keygen -alg A256GCM). It encrypts every delta and parent checkpoint before it leaves the home, and opens the author images of -registry templates, which zygotectl build -seal-to sealed to its public half. Homes that move sessions between them share it. With -delta-registry the default is <state>/private/delta-seal-key.json, generated when missing")

	fs.StringVar(&c.Audit.Key, "audit-key", "", "private Ed25519 JWK that signs the audit spool's checkpoints (grant-issuer keygen -alg EdDSA). Default <state>/private/audit-key.json, generated when missing")

	c.hooks.bind(fs, &c.Timing)
}

// parseDevices reads -devices. A later flag replaces an earlier one.
func (c *Config) parseDevices(v string) error {
	c.Node.Devices = nil
	for _, d := range strings.Split(v, ",") {
		if d = strings.TrimSpace(d); d != "" {
			c.Node.Devices = append(c.Node.Devices, d)
		}
	}
	return nil
}

// NarrowCaps re-executes fiberd with only what its runtime needs in
// its capability bounding set, unless -all-caps. Call it in main right
// after parsing the flags, since the process starts over. Only proc and runc have
// measured sets. It fails closed. If it cannot drop the extra, it returns
// an error and the caller should exit.
func (c *Config) NarrowCaps() error {
	keep, measured := caps.ForRuntime(c.Runtime.Name)
	if c.Node.AllCaps || !measured || len(capsExtra(keep)) == 0 {
		return nil
	}
	names := make([]string, 0, len(keep))
	for _, n := range keep {
		names = append(names, caps.Names[n])
	}
	log.Printf("fiberd: re-executing with only %s in the capability bounding set (-all-caps keeps them all)", strings.Join(names, ", "))
	if err := capsNarrow(keep); err != nil {
		return fmt.Errorf("fiberd: narrow capabilities for -runtime=%s: %w (grant CAP_SETPCAP, or pass -all-caps to keep every capability)", c.Runtime.Name, err)
	}
	return nil
}

// capsExtra and capsNarrow are the caps calls NarrowCaps makes. Tests
// replace them.
var (
	capsExtra  = caps.Extra
	capsNarrow = caps.Narrow
)

// LoadDeltaKeys reads -delta-key, -delta-trust and -delta-seal-key. A
// missing key is generated under -state on first use, and no other home
// trusts or opens with it until it is shared. Without a delta registry
// nothing is signed, and the seal key is read only when -delta-seal-key
// names one, since it also opens the author images of templates a home
// pulls with -registry.
func (c *Config) LoadDeltaKeys() (artifact.Keys, error) {
	if c.Registry.Deltas == "" {
		if c.Registry.Keys.Seal == "" {
			return artifact.Keys{}, nil
		}
		seal, err := artifact.LoadSealKey(c.Registry.Keys.Seal)
		if err != nil {
			return artifact.Keys{}, fmt.Errorf("-delta-seal-key: %w", err)
		}
		return artifact.Keys{Seal: seal}, nil
	}
	path, err := c.stateKey(c.Registry.Keys.Sign, "delta-key.json", func() (*jose.JSONWebKey, error) { return grant.GenerateKey(jose.EdDSA) },
		"delta signing key", "share one with -delta-key or trust each other's with -delta-trust")
	if err != nil {
		return artifact.Keys{}, fmt.Errorf("-delta-key: %w", err)
	}
	k, err := artifact.LoadKeys(path, c.Registry.Keys.Trust)
	if err != nil {
		return artifact.Keys{}, fmt.Errorf("-delta-key/-delta-trust: %w", err)
	}
	if path, err = c.stateKey(c.Registry.Keys.Seal, "delta-seal-key.json", artifact.GenerateSealKey,
		"delta seal key", "share one with -delta-seal-key"); err != nil {
		return artifact.Keys{}, fmt.Errorf("-delta-seal-key: %w", err)
	}
	if k.Seal, err = artifact.LoadSealKey(path); err != nil {
		return artifact.Keys{}, fmt.Errorf("-delta-seal-key: %w", err)
	}
	return k, nil
}

// loadAuditKey reads -audit-key. Without it the home signs checkpoints
// with a key of its own under -state, generated on first use, whose
// public half audit-verify needs.
func (c *Config) loadAuditKey() (*core.Checkpoints, error) {
	path, err := c.stateKey(c.Audit.Key, "audit-key.json", func() (*jose.JSONWebKey, error) { return grant.GenerateKey(jose.EdDSA) },
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

// loadHandoffKey reads -handoff-key. Without it the home derives handoff
// identities from a key of its own under -state, generated on first use.
// A session resumed on a home without the same key fails its caller's pin.
func (c *Config) loadHandoffKey() ([]byte, error) {
	path, err := c.stateKey(c.Handoff.Key, "handoff-key.json", artifact.GenerateSealKey,
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
// listener at addr. It is addr with a wildcard host replaced by
// -endpoint-host (else the loopback).
func (c *Config) handoffAdvertise(addr net.Addr) (string, error) {
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", err
	}
	if ip := net.ParseIP(host); ip == nil || ip.IsUnspecified() {
		host = c.Endpoint.Host
		if host == "" {
			host = "127.0.0.1"
			log.Printf("WARNING: -handoff-listen %s is a wildcard and no -endpoint-host is set; advertising %s", addr, host)
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
func (c *Config) Family() (endpoint.Family, error) { return endpoint.ParseFamily(c.Endpoint.Family) }

// endpointPolicy reads the -endpoint-* flags: the family a deployment
// declares and the address its fibers share. The port range is fixed.
func (c *Config) endpointPolicy() (endpoint.Policy, error) {
	fam, err := c.Family()
	if err != nil {
		return endpoint.Policy{}, err
	}
	p := endpoint.Policy{Family: fam, Host: c.Endpoint.Host}
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

// Run is fiberd. It returns when the RPC server stops, on SIGINT or
// SIGTERM.
func Run(c *Config, newHome HomeFactory) error { return RunContext(context.Background(), c, newHome) }

// RunContext is Run that also stops when ctx ends. A binary that owns its
// process's lifetime, and a test, stop fiberd through ctx.
func RunContext(ctx context.Context, c *Config, newHome HomeFactory) error {
	// Transport comes before anything starts, so a misconfigured TLS setup
	// never leaves a half-started fiberd behind.
	serverTLS, err := tlsconf.Server(c.API.TLS.Cert, c.API.TLS.Key, c.API.TLS.ClientCA, c.API.TLS.InsecurePlaintext)
	if err != nil {
		return err
	}
	if serverTLS == nil {
		log.Printf("WARNING: -insecure-plaintext serves the API without TLS or caller identity; development only")
	}
	// The private state directory, before any key is read or generated.
	// Fibers are given its absolute path to hide, whatever -state was.
	if abs, err := filepath.Abs(c.Node.StateDir); err == nil {
		c.Node.StateDir = abs
	}
	if err := c.ensurePrivate(); err != nil {
		return err
	}

	// Verifier first: it decides whether there is an issuer to poll.
	var ver core.Verifier
	var jwks *grant.Cache
	switch c.Trust.Verifier {
	case "jwks":
		if c.Trust.Issuer == "" {
			return errors.New("-verifier=jwks needs -issuer (the OIDC discovery root)")
		}
		jwks = &grant.Cache{IssuerURL: c.Trust.Issuer}
		ver = &grant.Verifier{Cache: jwks, Audience: c.Node.ID, MaxStale: c.Trust.JWKSMaxStale, MaxLease: c.Trust.MaxLease}
	case "insecure-json":
		log.Printf("WARNING: -verifier=insecure-json performs no signature check; development only")
		ver = grant.InsecureJSONVerifier{}
	case "":
		return errors.New("-verifier is required: jwks (signed grants) or insecure-json (development only)")
	default:
		return fmt.Errorf("unknown verifier %q", c.Trust.Verifier)
	}

	h, err := newHome(c, jwks)
	if err != nil {
		return err
	}
	// What the home knows about addresses fills what the flags left open.
	if fam, err := c.Family(); err == nil && fam != endpoint.Unix && c.Endpoint.Host == "" {
		if eh, ok := h.(EndpointHoster); ok {
			if c.Endpoint.Host = eh.EndpointHost(); c.Endpoint.Host == "" {
				return fmt.Errorf("-endpoint-family %s: home %s has no address of that family", fam, h.Name())
			}
		}
	}

	// serving counts the goroutines that accept on a listener Run bound.
	// Run returns only when they have, so the addresses are free again by
	// then. A listener's Close returns early when another Close of it is
	// under way, and the socket is gone only once its Accept has returned.
	var serving sync.WaitGroup
	defer serving.Wait()

	var rt core.Runtime
	var hrt *host.Runtime // the host runtime, nil for the stub
	var router *handoff.Router
	var handoffLn net.Listener
	switch c.Runtime.Name {
	case "stub":
		tier, err := core.ParseTier(c.Runtime.StubTier)
		if err != nil {
			return fmt.Errorf("runtime-tier: %w", err)
		}
		rt = stub.NewWithTier(tier)
	case "proc", "gvisor", "runc", "hyperlight":
		if len(c.Runtime.Templates) == 0 && c.Registry.Templates == "" {
			return fmt.Errorf("-runtime=%s needs a -template digest=path or a -registry to pull artifacts from", c.Runtime.Name)
		}
		// One host runtime, one backend per -runtime name.
		var be backend.Backend
		switch c.Runtime.Name {
		case "proc":
			be = procbackend.New(c.procOptions())
		case "hyperlight":
			if c.Runtime.Hyperlight.Helper == "" {
				return errors.New("-runtime=hyperlight needs -hyperlight-helper (hack/hyperlight/helper, or fakehelper without a hypervisor)")
			}
			be = hlbackend.New(hlbackend.Options{Helper: c.Runtime.Hyperlight.Helper, Guest: c.Runtime.Hyperlight.Guest})
		case "runc":
			if c.Runtime.Runc.Rootfs == "" {
				return errors.New("-runtime=runc needs -runc-rootfs (hack/gvisor/rootfs.sh builds one)")
			}
			pool, err := runcbackend.ParsePool(c.Runtime.Runc.UsernsPool)
			if err != nil {
				return fmt.Errorf("-userns-pool: %w", err)
			}
			be, err = runcbackend.New(runcbackend.Options{Rootfs: c.Runtime.Runc.Rootfs, StateDir: filepath.Join(c.Node.StateDir, "runc"), Pool: pool})
			if err != nil {
				return err
			}
		case "gvisor":
			if c.Runtime.Gvisor.Rootfs == "" {
				return errors.New("-runtime=gvisor needs -gvisor-rootfs (hack/gvisor/rootfs.sh builds one)")
			}
			be = gvisorbackend.New(c.gvisorOptions())
		}
		parity, err := artifact.ParseParity(c.Runtime.Parity)
		if err != nil {
			return err
		}
		eps, err := c.endpointPolicy()
		if err != nil {
			return err
		}
		pc := host.Config{Backend: be, Templates: c.Runtime.Templates, CgroupRoot: h.CgroupRoot(), RunDir: filepath.Join(c.Node.StateDir, "run"),
			DeltaDir: filepath.Join(c.Node.StateDir, "deltas"), Endpoints: eps,
			Registry: c.Registry.Templates, TemplateCache: filepath.Join(c.Node.StateDir, "templates"),
			DeltaRegistry: c.Registry.Deltas, HomeID: c.Node.ID, Parity: parity,
			FiberHide: c.Runtime.FiberHide, PrivateDir: c.PrivateDir()}
		if pc.DeltaKeys, err = c.LoadDeltaKeys(); err != nil {
			return err
		}
		if c.Handoff.Listen != "" {
			if pc.HandoffKey, err = c.loadHandoffKey(); err != nil {
				return err
			}
			if handoffLn, err = net.Listen("tcp", c.Handoff.Listen); err != nil {
				return fmt.Errorf("-handoff-listen %s: %w", c.Handoff.Listen, err)
			}
			defer func() { _ = handoffLn.Close() }()
			adv, err := c.handoffAdvertise(handoffLn.Addr())
			if err != nil {
				return err
			}
			router = &handoff.Router{Advertise: adv}
			pc.Handoff = router
		}
		if c.Node.GrantsDir != "" {
			abs, err := filepath.Abs(c.Node.GrantsDir)
			if err != nil {
				return err
			}
			pc.FiberHide = append(pc.FiberHide, abs)
		}
		if c.Runtime.GrantCeiling > 0 {
			fixed := c.Runtime.GrantCeiling
			pc.Ceiling = func(core.Grant, uint64) uint64 { return fixed }
		}
		if hrt, err = host.New(pc); err != nil {
			return fmt.Errorf("%s runtime: %w", c.Runtime.Name, err)
		}
		rt = hrt
		if router != nil {
			router.Deliver = hrt.Deliver
		}
		defer hrt.Close()
	default:
		return fmt.Errorf("runtime %q is not available yet", c.Runtime.Name)
	}
	private := c.PrivateDir()

	// 1. Epoch: every prior fence is invalid from here on.
	ep, err := core.OpenEpochStore(private)
	if err != nil {
		return fmt.Errorf("epoch: %w", err)
	}
	log.Printf("fiberd epoch=%d node=%s home=%s (all prior fences invalid)", ep.Current(), c.Node.ID, h.Name())

	// 2. Ledger, audit spool, core.
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
	revoked, err := core.OpenRevoked(filepath.Join(private, "revoked.json"), c.Trust.MaxLease, time.Now())
	if err != nil {
		return fmt.Errorf("deny-list: %w", err)
	}
	ag := &core.Core{
		NodeID:             c.Node.ID,
		RequireBoundGrants: serverTLS != nil,
		Ledger:             led,
		RateLimit:          core.NewRateLimit(core.DefaultBaseRate, core.DefaultRefW),
		Runtime:            rt,
		Audit:              spool,
		Verify:             ver,
		Health:             h.Health(),
		Scope:              h.Scope,
		Devices:            h.Devices,
		Epoch:              ep,
		Store:              store,
		Revoked:            revoked,
		StatusInterval:     c.Timing.StatusEvery,
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
	if src, ok := rt.(core.PressureSource); ok && c.Timing.PressureEvery >= 0 {
		if hrt != nil {
			src = core.MaxPressure{src, hrt.DevicePressure()}
		}
		ctl := &core.PressureController{
			Ledger: led, Source: src, Interval: c.Timing.PressureEvery,
			Drain:   ag.DrainPool,
			Park:    func(ctx context.Context, id string) error { _, _, err := ag.Park(ctx, id, false); return err },
			Release: func(ctx context.Context, id string) error { _, err := ag.Release(ctx, id, false); return err },
			Yield:   func(ctx context.Context, uid string) { ag.Yield(ctx, uid, "pressure") },
		}
		ag.Pressure = ctl
		go ctl.Run(ctx)
	}

	// 4. The home: issuer reachability and grant delivery.
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
	serving.Go(func() { _ = adminSrv.Serve(al) })

	// 6. Open the warm path.
	srv := &rpc.Server{Core: ag, Issuer: c.Trust.Issuer}
	var gopts []grpc.ServerOption
	if serverTLS != nil {
		gopts = append(gopts, grpc.Creds(credentials.NewTLS(serverTLS)))
	}
	gs := rpc.NewGRPCServer(srv, gopts...)
	gl, err := net.Listen("tcp", c.API.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", c.API.Listen, err)
	}
	// The gateway listens here, not in its goroutine, so an address it
	// cannot bind fails the start instead of leaving fiberd without it.
	var hl net.Listener
	var hs *http.Server
	if c.API.HTTP != "" {
		if hl, err = net.Listen("tcp", c.API.HTTP); err != nil {
			_ = gl.Close()
			return fmt.Errorf("-http %s: %w", c.API.HTTP, err)
		}
		gw := &rpc.Gateway{Server: srv, Health: healthz}
		hs = &http.Server{Handler: gw.Handler(), TLSConfig: serverTLS, ReadHeaderTimeout: 5 * time.Second}
		defer func() { _ = hs.Close() }()
		serving.Go(func() {
			log.Printf("fiberd json gateway on %s", hl.Addr())
			serve := func() error { return hs.Serve(hl) }
			if serverTLS != nil {
				serve = func() error { return hs.ServeTLS(hl, "", "") }
			}
			if err := serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("gateway: %v", err)
			}
		})
		go func() { <-ctx.Done(); _ = hs.Close() }()
	}
	if router != nil {
		serving.Go(func() {
			log.Printf("fiberd handoff on %s (callers dial %s)", handoffLn.Addr(), router.Advertise)
			if err := router.Serve(handoffLn); err != nil {
				log.Printf("handoff: %v", err)
			}
		})
	}
	go func() {
		<-ctx.Done()
		gs.GracefulStop()
	}()
	log.Printf("fiberd warm path on %s tier=%s admin=%s (no control plane needed beyond this point)", gl.Addr(), rt.Tier(), adminSock)
	if c.Ready != nil {
		var ha, ho net.Addr
		if hl != nil {
			ha = hl.Addr()
		}
		if handoffLn != nil {
			ho = handoffLn.Addr()
		}
		c.Ready(gl.Addr(), ha, ho)
	}
	// A stop that lands before Serve starts makes it return
	// ErrServerStopped. That is a clean stop too. Serve returns once
	// GracefulStop is through. The handoff listener closes here, before
	// the deferred runtime close takes the fibers it routes to, and the
	// other listeners close in the defers above.
	err = gs.Serve(gl)
	if handoffLn != nil {
		_ = handoffLn.Close()
	}
	if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
