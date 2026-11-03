package core_test

import (
	"math"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// validGrant passes Validate with every optional field set.
func validGrant() core.Grant {
	return core.Grant{
		UID:              "g-1",
		Issuer:           "https://issuer.test",
		Audience:         "node-a",
		TemplateDigest:   "sha256:" + strings.Repeat("ab", 32),
		Tenant:           "team-a",
		FiberMax:         8,
		FiberWarm:        2,
		WBudgetBytes:     64 << 20,
		MinTier:          core.TierBasic,
		LeaseExpiry:      time.Unix(1_700_000_600, 0).UTC(),
		CallerThumbprint: strings.Repeat("Q", 43),
	}
}

// TestGrantValidate checks each rule an issuer applies before it signs,
// one refused row per rule, and the unset fields Validate allows.
func TestGrantValidate(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(g *core.Grant)
		// wantErrs are substrings the error must hold, none for a valid
		// grant.
		wantErrs []string
	}{
		{name: "every field set is valid"},
		{name: "only a uid is valid", mutate: func(g *core.Grant) { *g = core.Grant{UID: "g-1"} }},
		{name: "an empty tenant runs anonymous fibers", mutate: func(g *core.Grant) { g.Tenant = "" }},
		{name: "a zero fiberMax is unlimited", mutate: func(g *core.Grant) { g.FiberMax, g.FiberWarm = 0, 5 }},
		{name: "fiberWarm equal to fiberMax", mutate: func(g *core.Grant) { g.FiberWarm = g.FiberMax }},
		{name: "a zero lease never expires", mutate: func(g *core.Grant) { g.LeaseExpiry = time.Time{} }},
		{name: "a lease in the past is still valid", mutate: func(g *core.Grant) { g.LeaseExpiry = time.Unix(1, 0) }},
		{name: "no digest and no thumbprint", mutate: func(g *core.Grant) { g.TemplateDigest, g.CallerThumbprint = "", "" }},
		{name: "a conformance template key", mutate: func(g *core.Grant) { g.TemplateDigest = "sha256:conform" }},
		{name: "a tenant and name template key", mutate: func(g *core.Grant) { g.TemplateDigest = "team-a/counter" }},
		{name: "the largest budget that fits", mutate: func(g *core.Grant) {
			g.FiberMax, g.FiberWarm, g.WBudgetBytes = 1, 1, math.MaxUint64/4
		}},
		{name: "the largest fiber counts the token carries", mutate: func(g *core.Grant) {
			g.FiberMax, g.FiberWarm, g.WBudgetBytes = math.MaxUint32, math.MaxUint32, 0
		}},

		{name: "an empty uid", mutate: func(g *core.Grant) { g.UID = "" }, wantErrs: []string{"uid is required"}},
		{name: "an uppercase uid", mutate: func(g *core.Grant) { g.UID = "G-1" }, wantErrs: []string{`uid "G-1" must be a DNS-1123 label`}},
		{name: "a uid that is a path", mutate: func(g *core.Grant) { g.UID = "../x" }, wantErrs: []string{`uid "../x"`}},
		{name: "a uid of 64 characters", mutate: func(g *core.Grant) { g.UID = strings.Repeat("a", 64) }, wantErrs: []string{"uid"}},
		{name: "a tenant with a slash", mutate: func(g *core.Grant) { g.Tenant = "team/a" }, wantErrs: []string{`tenant "team/a" must be one path segment`}},
		{name: "a tenant of 254 characters", mutate: func(g *core.Grant) { g.Tenant = strings.Repeat("t", 254) }, wantErrs: []string{"tenant"}},
		{name: "a negative fiberMax", mutate: func(g *core.Grant) { g.FiberMax = -1 }, wantErrs: []string{"fiberMax -1 must not be negative"}},
		{name: "a negative fiberWarm", mutate: func(g *core.Grant) { g.FiberWarm = -1 }, wantErrs: []string{"fiberWarm -1 must not be negative"}},
		{name: "fiberWarm above fiberMax", mutate: func(g *core.Grant) { g.FiberWarm = 9 }, wantErrs: []string{"fiberWarm 9 must not exceed fiberMax 8"}},
		// Regression: the signed proto carries the fiber counts as uint32,
		// so a larger value was cut short and verified as another grant.
		{name: "a huge fiberMax without a budget", mutate: func(g *core.Grant) { g.FiberMax, g.WBudgetBytes = math.MaxInt, 0 },
			wantErrs: []string{"fiberMax", "must not exceed 4294967295"}},
		{name: "fiberWarm above the uint32 bound", mutate: func(g *core.Grant) { g.FiberMax, g.FiberWarm = 0, math.MaxUint32+1 },
			wantErrs: []string{"fiberWarm 4294967296 must not exceed 4294967295"}},
		// Regression: 4 * 2^31 * 2^31 is 2^64, which wraps to zero in
		// uint64 although the product of the two fields fits.
		{name: "a budget that wraps once multiplied by four", mutate: func(g *core.Grant) { g.FiberMax, g.WBudgetBytes = 1<<31, 1<<31 },
			wantErrs: []string{"fiberMax 2147483648 times wBudgetBytes 2147483648"}},
		{name: "a budget whose product alone overflows", mutate: func(g *core.Grant) { g.FiberMax, g.WBudgetBytes = math.MaxInt, math.MaxUint64 },
			wantErrs: []string{"too large"}},
		{name: "one byte over the largest budget that fits", mutate: func(g *core.Grant) {
			g.FiberMax, g.FiberWarm, g.WBudgetBytes = 1, 1, math.MaxUint64/4+1
		}, wantErrs: []string{"too large"}},
		// Regression: exp holds whole seconds, so a fractional lease is
		// not the lease a home sees.
		{name: "a fractional lease expiry", mutate: func(g *core.Grant) { g.LeaseExpiry = g.LeaseExpiry.Add(500 * time.Millisecond) },
			wantErrs: []string{"leaseExpiry", "whole number of seconds"}},
		{name: "a digest with a space", mutate: func(g *core.Grant) { g.TemplateDigest = "sha256:abc def" }, wantErrs: []string{`templateDigest "sha256:abc def"`}},
		{name: "a digest with an equals sign", mutate: func(g *core.Grant) { g.TemplateDigest = "sha256:abc=def" }, wantErrs: []string{"templateDigest"}},
		{name: "a digest with a tab", mutate: func(g *core.Grant) { g.TemplateDigest = "sha256:abc\tdef" }, wantErrs: []string{"templateDigest"}},
		// Regression: an x5t#S256 is always 43 characters.
		{name: "a thumbprint of the wrong length", mutate: func(g *core.Grant) { g.CallerThumbprint = strings.Repeat("Q", 42) }, wantErrs: []string{"callerThumbprint"}},
		{name: "a padded thumbprint", mutate: func(g *core.Grant) { g.CallerThumbprint = strings.Repeat("Q", 42) + "=" }, wantErrs: []string{"callerThumbprint"}},
		{name: "every fault is reported at once",
			mutate: func(g *core.Grant) {
				g.UID, g.Tenant, g.FiberMax, g.TemplateDigest = "", "a b", -2, "sha256:abc def"
			},
			wantErrs: []string{"uid is required", `tenant "a b"`, "fiberMax -2", "templateDigest"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := validGrant()
			if tc.mutate != nil {
				tc.mutate(&g)
			}
			err := g.Validate()
			if len(tc.wantErrs) == 0 {
				if err != nil {
					t.Fatalf("Validate = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate = nil, want an error holding %q", tc.wantErrs)
			}
			for _, want := range tc.wantErrs {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Validate = %q, want it to hold %q", err, want)
				}
			}
		})
	}
}

// TestGrantPatterns pins the exported patterns, which an issuer outside
// this module repeats as schema literals.
func TestGrantPatterns(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		match   []string
		refuse  []string
	}{
		{name: "uid", pattern: core.UIDPattern,
			match:  []string{"a", "g-1", strings.Repeat("a", 63)},
			refuse: []string{"", "-a", "a-", "A", ".", "..", strings.Repeat("a", 64)}},
		{name: "tenant", pattern: core.TenantPattern,
			match:  []string{"a", "Team_A.1-x", strings.Repeat("t", 253)},
			refuse: []string{"", ".a", "a/b", "a b", strings.Repeat("t", 254)}},
		{name: "template digest", pattern: core.TemplateDigestPattern,
			match:  []string{"sha256:" + strings.Repeat("0f", 32)},
			refuse: []string{"sha256:", "sha256:" + strings.Repeat("0f", 31), "sha256:" + strings.Repeat("0F", 32), "default"}},
		{name: "caller thumbprint", pattern: core.CallerThumbprintPattern,
			match:  []string{strings.Repeat("a", 40) + "_-Z"},
			refuse: []string{"", strings.Repeat("a", 44), strings.Repeat("a", 42) + "+"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			re := regexp.MustCompile(tc.pattern)
			for _, s := range tc.match {
				if !re.MatchString(s) {
					t.Errorf("%s refuses %q, want a match", tc.pattern, s)
				}
			}
			for _, s := range tc.refuse {
				if re.MatchString(s) {
					t.Errorf("%s matches %q, want a refusal", tc.pattern, s)
				}
			}
		})
	}
}
