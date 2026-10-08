// Package host is the runtime every sandbox mechanism plugs into. It
// implements core.Runtime once, over a backend.Backend: templates are
// resolved from artifacts and gated on platform parity, every fiber is
// born in its own cgroup v2 leaf with memory.max = w_budget_bytes and
// memory.oom.group = 1 (the kernel is the executioner, the leaf's
// memory.current is W), grants get a block ceiling, PSI feeds the
// pressure ladder, parks become W-sized deltas over the template's
// checkpoint and travel to other homes through the delta registry. The
// backend only forks, checkpoints and restores.
package host

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/endpoint"
	"github.com/helayoty/fiberd/pkg/handoff"
)

// Config selects the backend, the templates and where the runtime may write.
type Config struct {
	// Backend is the sandbox mechanism (pkg/backend/proc, ...). Required.
	Backend backend.Backend
	// Templates maps a template digest to the template command line
	// ("path [args...]"). The key "default" serves digests not listed.
	Templates map[string]string
	// Registry, when set, resolves digests not in Templates by pulling
	// the template artifact "<Registry>@<digest>" into TemplateCache.
	Registry string
	// RegistryPlainHTTP selects http:// for Registry.
	RegistryPlainHTTP bool
	// TemplateCache holds pulled artifacts, one directory per digest
	// (default /var/lib/fiberd/templates), and the parent-checkpoint store.
	// It is hidden from fibers like PrivateDir and DeltaDir: a proc fiber
	// runs as the agent's uid and could otherwise rewrite a cached
	// template between the host's check and the exec, or read another
	// grant's. A proc fiber still sees its own template's executable,
	// bound back read-only at its path inside the cover, because CRIU
	// names a mapped file by its path (zygote/libfiberzygote.c).
	TemplateCache string
	// CgroupRoot is the delegated cgroup v2 subtree (from the home).
	CgroupRoot string
	// RunDir holds fiber endpoints (unix sockets); keep it short, the path
	// limit is 108 bytes.
	RunDir string
	// Endpoints is the address family fibers are served on: unix sockets
	// under RunDir (the zero value), or tcp on one declared address with
	// a port per fiber. A backend that lists "tcp" in EndpointSchemes
	// (proc) binds the port itself. Any other serves the unix socket and
	// the agent relays the port to it (relay.go).
	Endpoints endpoint.Policy
	// DeltaDir holds parked images: <DeltaDir>/<grant>/<epoch>-<seq>/.
	DeltaDir string
	// DeltaRegistry, when set, is the OCI repository prefix (host/prefix)
	// under which parked deltas are published (one repository per session
	// domain, one tag per session) and looked up by other homes. Uses
	// RegistryPlainHTTP.
	DeltaRegistry string
	// DeltaKeys signs every delta and parent checkpoint this home pushes to
	// DeltaRegistry. The home pulls or imports only those a trusted key
	// signed. Its Seal key encrypts each delta before it leaves the home, so
	// homes that move sessions between them share it. Signer and Seal are
	// required with DeltaRegistry.
	DeltaKeys artifact.Keys
	// Handoff routes callers' connections to the fibers of handoff-mode
	// grants, whose handles name its address. Nil refuses such grants
	// (ErrNoHandoff).
	Handoff *handoff.Router
	// HandoffKey derives each handoff grant's TLS identity. Homes that
	// move sessions between them share it. Required, at least 32 bytes,
	// when Handoff is set.
	HandoffKey []byte
	// HomeID names this home in published deltas, so a home that will not
	// pull a session can tell the caller where it is (Miss.preferred_home).
	HomeID string
	// Parity is how strictly an artifact's images or another home's delta
	// must match this host (architecture and backend always; kernel and
	// libc per level). The zero value is strict.
	Parity artifact.Parity
	// Platform overrides what this home believes about its own host, for
	// tests and for hosts whose uname is not what the checkpoints will
	// run under. Zero fields are detected; Backend is always the
	// backend's name.
	Platform artifact.Platform
	// Ceiling computes the grant's block ceiling in bytes from the grant
	// and the warm template's resident size; 0 means no ceiling. The
	// default is fibers.max * w_budget + template + 25%, and nothing when
	// either factor is unlimited. It is applied as memory.high (throttle,
	// which PSI reports and the ladder reacts to) with memory.max one W
	// budget above it as the hard stop.
	Ceiling func(g core.Grant, templateBytes uint64) uint64
	// FiberHide lists directories fibers must not see, besides
	// DefaultFiberHide, DeltaDir and PrivateDir, in backends that give a
	// fiber a mount namespace of its own. A directory holding RunDir is
	// never hidden, because fiber endpoints live there.
	FiberHide []string
	// PrivateDir is the agent's private state (its keys, the ledger
	// snapshot, the epoch, the audit spool). Fibers run as the agent's uid
	// and would pass the owner checks on its files, so it is always
	// hidden from them, like DeltaDir. Empty when the agent has none.
	PrivateDir string
}

// checkDeltaRegistry is what every use of the delta registry needs.
func (c Config) checkDeltaRegistry() error {
	if c.DeltaRegistry == "" {
		return errors.New("host: no delta registry configured")
	}
	if c.DeltaKeys.Signer == nil {
		return errors.New("host: the delta registry needs DeltaKeys.Signer: deltas are signed")
	}
	if c.DeltaKeys.Seal == nil {
		return errors.New("host: the delta registry needs DeltaKeys.Seal: deltas are sealed")
	}
	return nil
}

const (
	// fiberPidsMax is each fiber leaf's pids.max. The grant's cgroup gets
	// (fibers.max + 1) times it, the extra share for its warm template.
	// Backends that isolate tenants in a sandbox get no task limit.
	fiberPidsMax = 256
	// defaultDeltaQuota caps the bytes a grant's parked deltas take under
	// DeltaDir when fibers.max or w_budget_bytes is unlimited. Otherwise
	// the cap is 4 x fibers.max x w_budget_bytes.
	defaultDeltaQuota = 1 << 30
	// deltaTTL is how long a published or exported delta may be claimed
	// or imported.
	deltaTTL = 24 * time.Hour
)

// DefaultFiberHide is hidden from every fiber. It holds the Kubernetes
// service-account token of the home's Pod.
var DefaultFiberHide = []string{"/var/run/secrets/kubernetes.io/serviceaccount"}

// fiberHide lists what fibers must not see. That is the defaults,
// DeltaDir, PrivateDir, TemplateCache and FiberHide, cleaned and without
// duplicates. Relative paths and extra directories holding RunDir are
// returned as skipped. DeltaDir, PrivateDir or TemplateCache holding
// RunDir is an error, because fiber endpoints live in RunDir and the
// deltas, keys or templates would be visible.
func (c Config) fiberHide() (hide, skipped []string, err error) {
	for _, d := range []struct{ name, path string }{{"DeltaDir", c.DeltaDir}, {"PrivateDir", c.PrivateDir}, {"TemplateCache", c.TemplateCache}} {
		if filepath.IsAbs(d.path) && holds(filepath.Clean(d.path), c.RunDir) {
			return nil, nil, fmt.Errorf("host: RunDir %s is inside %s %s, which fibers must not see; move it out", c.RunDir, d.name, d.path)
		}
	}
	seen := map[string]bool{}
	for _, p := range append(append(append([]string{}, DefaultFiberHide...), c.DeltaDir, c.PrivateDir, c.TemplateCache), c.FiberHide...) {
		if p == "" {
			continue
		}
		if !filepath.IsAbs(p) {
			skipped = append(skipped, p)
			continue
		}
		p = filepath.Clean(p)
		if seen[p] {
			continue
		}
		seen[p] = true
		if holds(p, c.RunDir) {
			skipped = append(skipped, p)
			continue
		}
		hide = append(hide, p)
	}
	return hide, skipped, nil
}

// holds reports whether dir is run or one of its ancestors.
func holds(dir, run string) bool {
	rel, err := filepath.Rel(dir, run)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

// grantPids is the pids.max of a grant's cgroup. It is 0 (none) for a
// grant without a fibers.max.
func grantPids(g core.Grant) uint64 {
	if g.FiberMax <= 0 {
		return 0
	}
	return uint64(g.FiberMax+1) * fiberPidsMax
}

// deltaQuota is the grant's parked-delta budget on this home.
func deltaQuota(g core.Grant) uint64 {
	if g.FiberMax <= 0 || g.WBudgetBytes == 0 {
		return defaultDeltaQuota
	}
	return 4 * uint64(g.FiberMax) * g.WBudgetBytes
}

// DefaultCeiling is Config.Ceiling when unset.
func DefaultCeiling(g core.Grant, templateBytes uint64) uint64 {
	if g.FiberMax <= 0 || g.WBudgetBytes == 0 {
		return 0
	}
	block := uint64(g.FiberMax)*g.WBudgetBytes + templateBytes
	return block + block/4
}

var ErrUnsupported = errors.New("host: not supported on this platform")

// ErrNoTier is New's refusal of a backend that offers no tier, because
// its tools or files are missing. Confinement fails closed, so the agent
// does not start over such a backend.
var ErrNoTier = errors.New("offers no tier")

// ParseTemplateFlag parses "digest=path [args]" for -template.
func ParseTemplateFlag(m map[string]string, v string) error {
	k, cmd, ok := strings.Cut(v, "=")
	if !ok || k == "" || strings.TrimSpace(cmd) == "" {
		return errors.New("template: want digest=path [args]")
	}
	m[strings.TrimSpace(k)] = strings.TrimSpace(cmd)
	return nil
}

// Command resolves the template command line for a digest from the
// Templates map, falling back to the "default" entry. Registry pulls are
// handled by the runtime (they need a context and a cache).
func (c Config) Command(digest string) ([]string, bool) {
	cmd, ok := c.Templates[digest]
	if !ok {
		cmd, ok = c.Templates["default"]
	}
	if !ok {
		return nil, false
	}
	return strings.Fields(cmd), true
}
