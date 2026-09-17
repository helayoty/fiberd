package artifact

import (
	"errors"
	"fmt"
	"strings"
)

// Platform parity.
//
// A CRIU image is a picture of a process on one particular host: its
// pages assume the instruction set, the file-backed mappings assume the
// exact libc the loader mapped (offsets and sizes are recorded, not the
// bytes), and what the kernel let the process have (syscalls, vdso
// layout, cgroup and namespace features) assumes that kernel. The zygote
// artifact records all three at build time; every parked delta records
// them at park time. A home compares them with its own before it warms a
// template from an artifact's images or pulls a session from another
// home. A mismatch is refused, not attempted: a restore that fails late
// or, worse, succeeds with a subtly wrong libc is not a miss the caller
// can reason about.

// Platform is what a checkpoint's pages assume about the host that made
// them.
type Platform struct {
	Arch   string `json:"arch"`
	Kernel string `json:"kernel"` // uname -r
	Libc   string `json:"libc"`   // "(gnu libc) 2.36"
	// Backend is the sandbox mechanism that made the checkpoint ("proc",
	// "gvisor", ...). Empty for a template artifact (any backend that
	// reads the format may warm it) and for facts recorded before it.
	Backend string `json:"backend,omitempty"`
}

// Host is the platform this process runs on.
func Host() Platform {
	arch, kernel, libc := HostInfo()
	return Platform{Arch: arch, Kernel: kernel, Libc: libc}
}

// Platform returns the build host recorded in an artifact config.
func (c Config) Platform() Platform {
	return Platform{Arch: c.Arch, Kernel: c.Kernel, Libc: c.Libc}
}

// Annotations for platform facts on delta and parent manifests.
const (
	AnnotationArch    = "io.fiberd.arch"
	AnnotationKernel  = "io.fiberd.kernel"
	AnnotationLibc    = "io.fiberd.libc"
	AnnotationBackend = "io.fiberd.backend"
)

// Annotate adds the platform to a manifest annotation map.
func (p Platform) Annotate(m map[string]string) {
	m[AnnotationArch] = p.Arch
	m[AnnotationKernel] = p.Kernel
	m[AnnotationLibc] = p.Libc
	if p.Backend != "" {
		m[AnnotationBackend] = p.Backend
	}
}

// PlatformFromAnnotations reads a platform back; ok is false when the
// manifest carries none (a publisher from before the parity gate).
func PlatformFromAnnotations(m map[string]string) (Platform, bool) {
	p := Platform{Arch: m[AnnotationArch], Kernel: m[AnnotationKernel], Libc: m[AnnotationLibc], Backend: m[AnnotationBackend]}
	return p, p.Arch != "" || p.Kernel != "" || p.Libc != "" || p.Backend != ""
}

func (p Platform) String() string {
	s := fmt.Sprintf("%s/%s/%s", p.Arch, p.Kernel, p.Libc)
	if p.Backend != "" {
		s += "/" + p.Backend
	}
	return s
}

// KernelSeries is the "major.minor" of a release string ("6.10.14-linuxkit"
// -> "6.10"): the level at which the syscall and image ABI usually holds.
func KernelSeries(release string) string {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return release
	}
	minor := parts[1]
	if i := strings.IndexAny(minor, "-+_"); i >= 0 {
		minor = minor[:i]
	}
	return parts[0] + "." + minor
}

// Parity levels for one fact.
const (
	ParityExact  = "exact"  // must be identical
	ParitySeries = "series" // kernel only: same major.minor
	ParityOff    = "off"    // not compared
)

// Parity says how strictly a home requires a checkpoint's platform to
// match its own. The architecture and the backend are always required to
// match; there is no level at which a foreign instruction set or another
// mechanism's image format can restore. The zero value is strict: exact
// kernel release and exact libc.
type Parity struct {
	Kernel string // ParityExact (default), ParitySeries or ParityOff
	Libc   string // ParityExact (default) or ParityOff
}

// Strict requires everything to match exactly.
var Strict = Parity{Kernel: ParityExact, Libc: ParityExact}

// ParseParity reads the -parity flag: "strict", "off", or a comma list
// of kernel=exact|series|off and libc=exact|off.
func ParseParity(s string) (Parity, error) {
	p := Strict
	switch strings.TrimSpace(s) {
	case "", "strict":
		return p, nil
	case "off":
		return Parity{Kernel: ParityOff, Libc: ParityOff}, nil
	}
	for _, kv := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok {
			return p, fmt.Errorf("parity: %q is not key=level", kv)
		}
		switch k {
		case "kernel":
			if v != ParityExact && v != ParitySeries && v != ParityOff {
				return p, fmt.Errorf("parity: kernel=%q; want exact, series or off", v)
			}
			p.Kernel = v
		case "libc":
			if v != ParityExact && v != ParityOff {
				return p, fmt.Errorf("parity: libc=%q; want exact or off", v)
			}
			p.Libc = v
		case "arch":
			return p, errors.New("parity: the architecture is always required to match")
		default:
			return p, fmt.Errorf("parity: unknown fact %q", k)
		}
	}
	return p, nil
}

func (p Parity) String() string {
	k, l := p.Kernel, p.Libc
	if k == "" {
		k = ParityExact
	}
	if l == "" {
		l = ParityExact
	}
	return "kernel=" + k + ",libc=" + l
}

// ErrParity is wrapped by every mismatch.
var ErrParity = errors.New("platform parity")

// Check compares the platform a checkpoint was made on with the host it
// would restore on, at this parity level.
func (p Parity) Check(host, want Platform) error {
	if want.Arch != "" && want.Arch != host.Arch {
		return fmt.Errorf("%w: arch %s, host is %s", ErrParity, want.Arch, host.Arch)
	}
	if want.Backend != "" && host.Backend != "" && want.Backend != host.Backend {
		return fmt.Errorf("%w: made by backend %s, this home runs %s", ErrParity, want.Backend, host.Backend)
	}
	switch p.Kernel {
	case ParityOff:
	case ParitySeries:
		if want.Kernel != "" && KernelSeries(want.Kernel) != KernelSeries(host.Kernel) {
			return fmt.Errorf("%w: kernel %s (series %s), host is %s", ErrParity, want.Kernel, KernelSeries(want.Kernel), host.Kernel)
		}
	default:
		if want.Kernel != "" && want.Kernel != host.Kernel {
			return fmt.Errorf("%w: kernel %s, host is %s (relax with kernel=series)", ErrParity, want.Kernel, host.Kernel)
		}
	}
	if p.Libc != ParityOff && want.Libc != "" && want.Libc != host.Libc {
		return fmt.Errorf("%w: libc %q, host is %q", ErrParity, want.Libc, host.Libc)
	}
	return nil
}
