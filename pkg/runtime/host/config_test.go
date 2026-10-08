package host

import (
	"slices"
	"strings"
	"testing"

	"github.com/helayoty/fiberd/pkg/core"
)

func TestConfigDerivations(t *testing.T) {
	sized := core.Grant{FiberMax: 4, WBudgetBytes: 32 << 20}
	token := DefaultFiberHide[0]
	cases := []struct {
		name      string
		cfg       Config
		grant     core.Grant
		grantPids uint64
		quota     uint64
		// tmplBytes is the warm template's resident size the default
		// ceiling adds to the block. ceiling is the result, 0 for none.
		tmplBytes uint64
		ceiling   uint64
		hide      []string
		skipped   []string
		// wantErr is a fragment of fiberHide's error, "" for none.
		wantErr string
	}{
		{name: "defaults on a sized grant", grant: sized, grantPids: 5 * fiberPidsMax, quota: 4 * 4 * 32 << 20,
			tmplBytes: 8 << 20, ceiling: (4*32<<20 + 8<<20) * 5 / 4, hide: []string{token}},
		{name: "unlimited fibers: no grant pids limit, default quota, no ceiling", grant: core.Grant{WBudgetBytes: 32 << 20},
			quota: defaultDeltaQuota, tmplBytes: 8 << 20, hide: []string{token}},
		{name: "unlimited W: default quota, no ceiling", grant: core.Grant{FiberMax: 4},
			grantPids: 5 * fiberPidsMax, quota: defaultDeltaQuota, tmplBytes: 8 << 20, hide: []string{token}},
		{name: "hidden: delta dir and extras, cleaned and deduplicated; never relative or above the run dir",
			cfg: Config{DeltaDir: "/var/lib/fiberd/deltas", RunDir: "/run/fiberd",
				FiberHide: []string{"/srv/grants/", "/var/lib/fiberd/deltas", "grants", "/run", "/run/fiberd"}},
			grant: sized, grantPids: 5 * fiberPidsMax, quota: 4 * 4 * 32 << 20, ceiling: 160 << 20,
			hide: []string{token, "/var/lib/fiberd/deltas", "/srv/grants"}, skipped: []string{"grants", "/run", "/run/fiberd"}},
		{name: "the private state dir is always hidden, once, before the extras",
			cfg: Config{DeltaDir: "/var/lib/fiberd/deltas", PrivateDir: "/var/lib/fiberd/private/", RunDir: "/run/fiberd",
				FiberHide: []string{"/var/lib/fiberd/private", "/srv/grants"}},
			grant: sized, grantPids: 5 * fiberPidsMax, quota: 4 * 4 * 32 << 20, ceiling: 160 << 20,
			hide: []string{token, "/var/lib/fiberd/deltas", "/var/lib/fiberd/private", "/srv/grants"}},
		{name: "a private state dir holding the run dir is an error",
			cfg:   Config{PrivateDir: "/var/lib/fiberd/private", RunDir: "/var/lib/fiberd/private/run"},
			grant: sized, grantPids: 5 * fiberPidsMax, quota: 4 * 4 * 32 << 20, ceiling: 160 << 20,
			wantErr: "inside PrivateDir /var/lib/fiberd/private"},
		{name: "a private state dir that is the run dir is an error",
			cfg:   Config{PrivateDir: "/var/lib/fiberd/private/", RunDir: "/var/lib/fiberd/private"},
			grant: sized, grantPids: 5 * fiberPidsMax, quota: 4 * 4 * 32 << 20, ceiling: 160 << 20,
			wantErr: "inside PrivateDir"},
		{name: "a delta dir holding the run dir is an error",
			cfg:   Config{DeltaDir: "/var/lib/fiberd", RunDir: "/var/lib/fiberd/run"},
			grant: sized, grantPids: 5 * fiberPidsMax, quota: 4 * 4 * 32 << 20, ceiling: 160 << 20,
			wantErr: "inside DeltaDir /var/lib/fiberd"},
		{name: "a run dir beside the private and delta dirs is fine",
			cfg:   Config{DeltaDir: "/var/lib/fiberd/deltas", PrivateDir: "/var/lib/fiberd/private", RunDir: "/var/lib/fiberd/private-run"},
			grant: sized, grantPids: 5 * fiberPidsMax, quota: 4 * 4 * 32 << 20, ceiling: 160 << 20,
			hide: []string{token, "/var/lib/fiberd/deltas", "/var/lib/fiberd/private"}},
		{name: "a relative private state dir is skipped",
			cfg:   Config{PrivateDir: "state/private", RunDir: "/run/fiberd"},
			grant: sized, grantPids: 5 * fiberPidsMax, quota: 4 * 4 * 32 << 20, ceiling: 160 << 20,
			hide: []string{token}, skipped: []string{"state/private"}},
		// A proc fiber runs as the agent's uid and could rewrite a cached
		// template, so the cache is hidden like the keys and the deltas.
		{name: "the template cache is hidden without being listed, once, after the private dir",
			cfg: Config{DeltaDir: "/var/lib/fiberd/deltas", PrivateDir: "/var/lib/fiberd/private", TemplateCache: "/var/lib/fiberd/templates/", RunDir: "/run/fiberd",
				FiberHide: []string{"/srv/grants", "/var/lib/fiberd/templates"}},
			grant: sized, grantPids: 5 * fiberPidsMax, quota: 4 * 4 * 32 << 20, ceiling: 160 << 20,
			hide: []string{token, "/var/lib/fiberd/deltas", "/var/lib/fiberd/private", "/var/lib/fiberd/templates", "/srv/grants"}},
		{name: "a template cache holding the run dir is an error",
			cfg:   Config{TemplateCache: "/var/lib/fiberd/templates", RunDir: "/var/lib/fiberd/templates/run"},
			grant: sized, grantPids: 5 * fiberPidsMax, quota: 4 * 4 * 32 << 20, ceiling: 160 << 20,
			wantErr: "inside TemplateCache /var/lib/fiberd/templates"},
		{name: "a template cache that is the run dir is an error",
			cfg:   Config{TemplateCache: "/var/lib/fiberd/templates/", RunDir: "/var/lib/fiberd/templates"},
			grant: sized, grantPids: 5 * fiberPidsMax, quota: 4 * 4 * 32 << 20, ceiling: 160 << 20,
			wantErr: "inside TemplateCache"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := grantPids(tc.grant); got != tc.grantPids {
				t.Fatalf("grantPids = %d, want %d", got, tc.grantPids)
			}
			if got := deltaQuota(tc.grant); got != tc.quota {
				t.Fatalf("deltaQuota = %d, want %d", got, tc.quota)
			}
			if got := DefaultCeiling(tc.grant, tc.tmplBytes); got != tc.ceiling {
				t.Fatalf("DefaultCeiling = %d, want %d", got, tc.ceiling)
			}
			hide, skipped, err := tc.cfg.fiberHide()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("fiberHide err = %v, want one mentioning %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("fiberHide: %v", err)
			}
			if !slices.Equal(hide, tc.hide) || !slices.Equal(skipped, tc.skipped) {
				t.Fatalf("fiberHide = %v skipped %v, want %v skipped %v", hide, skipped, tc.hide, tc.skipped)
			}
		})
	}
}

// TestTemplateFlag checks that -template entries are "digest=path [args]",
// and a digest resolves to its own entry, else to "default", else to nothing.
func TestTemplateFlag(t *testing.T) {
	cases := []struct {
		name string
		// flags are parsed in order into one map.
		flags   []string
		wantErr bool
		// lookups map a digest to the argv expected, nil for none.
		lookups map[string][]string
	}{
		{name: "an entry per digest and a default", flags: []string{"sha256:a= /zyg/a --heap 8 ", " default =/zyg/default"},
			lookups: map[string][]string{"sha256:a": {"/zyg/a", "--heap", "8"}, "sha256:b": {"/zyg/default"}}},
		{name: "no default: unknown digests resolve to nothing", flags: []string{"sha256:a=/zyg/a"},
			lookups: map[string][]string{"sha256:a": {"/zyg/a"}, "sha256:b": nil}},
		{name: "no equals sign", flags: []string{"sha256:a /zyg/a"}, wantErr: true},
		{name: "an empty digest", flags: []string{"=/zyg/a"}, wantErr: true},
		{name: "an empty command", flags: []string{"sha256:a=  "}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := map[string]string{}
			var err error
			for _, f := range tc.flags {
				if err = ParseTemplateFlag(m, f); err != nil {
					break
				}
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseTemplateFlag = %v, want error %v", err, tc.wantErr)
			}
			cfg := Config{Templates: m}
			for digest, want := range tc.lookups {
				argv, ok := cfg.Command(digest)
				if ok != (want != nil) || !slices.Equal(argv, want) {
					t.Fatalf("Command(%s) = %v %v, want %v", digest, argv, ok, want)
				}
			}
		})
	}
}
