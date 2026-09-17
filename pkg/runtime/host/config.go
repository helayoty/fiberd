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
	"strings"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
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
	TemplateCache string
	// CgroupRoot is the delegated cgroup v2 subtree (from the home).
	CgroupRoot string
	// RunDir holds fiber endpoints (unix sockets); keep it short, the path
	// limit is 108 bytes.
	RunDir string
	// DeltaDir holds parked images: <DeltaDir>/<grant>/<epoch>-<seq>/.
	DeltaDir string
	// Tier advertised. Unspecified means the backend's best; a lower
	// explicit value caps what is offered.
	Tier core.Tier
	// NoFiberPIDNS keeps fibers in the home's pid namespace. By default
	// every fiber is the init of its own, so its checkpoint restores on
	// any host without colliding with a live pid (needs CAP_SYS_ADMIN;
	// the proc backend falls back silently without it).
	NoFiberPIDNS bool
	// NoDeltas parks full checkpoints instead of deltas over the
	// template's pages.
	NoDeltas bool
	// DeltaRegistry, when set, is the OCI repository prefix (host/prefix)
	// under which parked deltas are published (one repository per session
	// domain, one tag per session) and looked up by other homes. Uses
	// RegistryPlainHTTP.
	DeltaRegistry string
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
