package core

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// The patterns a grant's fields must match. They are exported because an
// issuer outside this module repeats them as schema literals, such as the
// Kubernetes controller's CRD markers, and tests that its copies stay
// equal to these.
const (
	// UIDPattern is the Kubernetes DNS-1123 label rule. The UID becomes a
	// cgroup and run-directory name beside kernel files like memory.max,
	// so it must be one plain path segment ("." and ".." never match).
	// Lowercase keeps names distinct on case-insensitive filesystems. The
	// length bound keeps paths under the unix socket limit.
	UIDPattern = `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`

	// TenantPattern bounds a tenant name to one path segment of letters,
	// digits, ".", "_" and "-", at most 253 characters. The tenant is the
	// first half of the session domain "<tenant>/<class or digest>", so
	// "/" and whitespace are out and the domain splits at its first "/"
	// without ambiguity. A Kubernetes namespace and a Slurm account both
	// fit.
	TenantPattern = `^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`

	// TemplateDigestPattern is a full lowercase sha256 OCI digest. It is
	// what host.FormatTemplateFlag and the Kubernetes controller's CRD
	// marker require of an OCI digest. Validate itself asks only that a
	// template digest be a usable key into fiberd's template map.
	TemplateDigestPattern = `^sha256:[a-f0-9]{64}$`

	// CallerThumbprintPattern is the form of an RFC 7638 JWK thumbprint.
	// That is a SHA-256 hash in unpadded base64url, which is always 43
	// characters.
	CallerThumbprintPattern = `^[A-Za-z0-9_-]{43}$`
)

var (
	uidRE              = regexp.MustCompile(UIDPattern)
	tenantRE           = regexp.MustCompile(TenantPattern)
	callerThumbprintRE = regexp.MustCompile(CallerThumbprintPattern)
)

// Validate is the single check a grant passes before an issuer signs it.
// It reports every fault at once, each as a sentence that names the
// field in lowerCamelCase, the way a Kubernetes field path does.
//
// Some fields may be left unset.
//   - An empty Tenant is allowed. Such a grant runs anonymous fibers only.
//   - An empty TemplateDigest or CallerThumbprint is allowed. The home
//     then serves its default template, and the grant is not bound to a
//     caller key.
//   - A zero LeaseExpiry is allowed and means the lease never expires.
//   - A zero FiberMax is allowed, since Grant documents it as unlimited.
//     Only a negative one or one above math.MaxUint32 is refused.
//
// A set TemplateDigest need not be a real sha256 digest. fiberd treats it
// as an opaque key into its -template digest=command map, so keys like
// "default", "sha256:conform" or "team-a/counter" work. It must be one
// token usable as that key, with no whitespace and no "=".
//
// Validate does not check Issuer or Audience. The issuer sets the first
// and Sign refuses a grant without the second.
func (g Grant) Validate() error {
	var errs []error
	switch {
	case g.UID == "":
		errs = append(errs, errors.New("uid is required"))
	case !uidRE.MatchString(g.UID):
		errs = append(errs, fmt.Errorf("uid %q must be a DNS-1123 label matching %s", g.UID, UIDPattern))
	}
	if g.Tenant != "" && !tenantRE.MatchString(g.Tenant) {
		errs = append(errs, fmt.Errorf("tenant %q must be one path segment matching %s", g.Tenant, TenantPattern))
	}
	// The signed proto carries both fiber counts as uint32. A larger value
	// would be cut short in the token and differ from the one verified.
	switch {
	case g.FiberMax < 0:
		errs = append(errs, fmt.Errorf("fiberMax %d must not be negative", g.FiberMax))
	case uint64(g.FiberMax) > math.MaxUint32:
		errs = append(errs, fmt.Errorf("fiberMax %d must not exceed %d", g.FiberMax, uint64(math.MaxUint32)))
	}
	switch {
	case g.FiberWarm < 0:
		errs = append(errs, fmt.Errorf("fiberWarm %d must not be negative", g.FiberWarm))
	case uint64(g.FiberWarm) > math.MaxUint32:
		errs = append(errs, fmt.Errorf("fiberWarm %d must not exceed %d", g.FiberWarm, uint64(math.MaxUint32)))
	case g.FiberMax > 0 && g.FiberWarm > g.FiberMax:
		errs = append(errs, fmt.Errorf("fiberWarm %d must not exceed fiberMax %d", g.FiberWarm, g.FiberMax))
	}
	// A home sizes the grant's parked-delta quota as 4 * FiberMax *
	// WBudgetBytes in uint64. The product must fit, or the quota wraps to
	// a tiny value and every park is refused.
	if g.FiberMax > 0 && g.WBudgetBytes > 0 {
		hi, lo := bits.Mul64(uint64(g.FiberMax), g.WBudgetBytes)
		if hi != 0 || lo > math.MaxUint64/4 {
			errs = append(errs, fmt.Errorf("fiberMax %d times wBudgetBytes %d is too large, four times that product must fit in 64 bits",
				g.FiberMax, g.WBudgetBytes))
		}
	}
	// The token's exp claim holds whole seconds, and a verifier measures
	// the lease from whole-second claims. A fraction would be cut off in
	// the token and the lease the home sees would differ from this one.
	if !g.LeaseExpiry.IsZero() && !g.LeaseExpiry.Equal(g.LeaseExpiry.Truncate(time.Second)) {
		errs = append(errs, fmt.Errorf("leaseExpiry %s must be a whole number of seconds", g.LeaseExpiry.Format(time.RFC3339Nano)))
	}
	if g.TemplateDigest != "" && strings.ContainsFunc(g.TemplateDigest, func(r rune) bool { return unicode.IsSpace(r) || r == '=' }) {
		errs = append(errs, fmt.Errorf("templateDigest %q must be one template key without whitespace or \"=\"", g.TemplateDigest))
	}
	if g.CallerThumbprint != "" && !callerThumbprintRE.MatchString(g.CallerThumbprint) {
		errs = append(errs, fmt.Errorf("callerThumbprint %q must match %s", g.CallerThumbprint, CallerThumbprintPattern))
	}
	return errors.Join(errs...)
}
