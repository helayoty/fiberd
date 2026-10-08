package runc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParsePool checks the flag's spelling, and the bounds that keep every
// slot inside the 32-bit id space and off the host's own ids.
func TestParsePool(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    IDPool
		wantErr bool
	}{
		{name: "default", in: DefaultPool, want: IDPool{Start: 1 << 30, Slots: 49151}},
		{name: "one slot", in: "65536:1", want: IDPool{Start: 65536, Slots: 1}},
		{name: "spaces around", in: " 200000:10 ", want: IDPool{Start: 200000, Slots: 10}},
		{name: "no colon", in: "100000", wantErr: true},
		{name: "start not a number", in: "x:10", wantErr: true},
		{name: "slots not a number", in: "100000:y", wantErr: true},
		{name: "zero slots", in: "100000:0", wantErr: true},
		{name: "start inside the host's ids", in: "1000:10", wantErr: true},
		{name: "past the id space", in: "100000:65535", wantErr: true},
		{name: "default plus one slot is past the id space", in: "1073741824:49152", wantErr: true},
		{name: "negative", in: "-1:1", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePool(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParsePool(%q) = %v, want error %v", tc.in, err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Fatalf("ParsePool(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

// TestDefaultPoolClearsConventions checks that the default sits above every
// id a host hands out by convention and below 2^31, and reaches the top of
// the id space minus the overflow ids.
func TestDefaultPoolClearsConventions(t *testing.T) {
	def, err := ParsePool(DefaultPool)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		start uint64
		count uint64
	}{
		{name: "useradd's first subuid range", start: 100000, count: 65536},
		{name: "useradd's last range below SUB_UID_MAX", start: 600100000 - 65536, count: 65536},
		{name: "LXC's conventional range", start: 1000000, count: 65536},
		{name: "kubelet pods, 65536 ids each up to 1024 pods", start: 65536, count: 65536 * 1024},
		{name: "everything below 2^30", start: 0, count: 1 << 30},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.start+tc.count > uint64(def.Start) {
				t.Fatalf("convention %d-%d reaches into the default pool from %d", tc.start, tc.start+tc.count-1, def.Start)
			}
		})
	}
	if def.Start >= 1<<31 {
		t.Fatalf("default start %d is not below 2^31", def.Start)
	}
	if last := def.end() - 1; last < 1<<32-2-SlotIDs {
		t.Fatalf("default pool ends at %d and wastes a slot below the overflow id", last)
	}
}

// TestCheckSubIDs checks that a pool that overlaps a subordinate id range of
// the host is refused with the entry named, a missing file is no check, and a
// line that does not parse is refused too.
func TestCheckSubIDs(t *testing.T) {
	pool := IDPool{Start: 1 << 20, Slots: 16} // host ids 1048576-2097151
	cases := []struct {
		name    string
		subuid  string // "" for no file
		subgid  string
		wantErr string // substring, "" for none
	}{
		{name: "no files", wantErr: ""},
		{name: "empty files", subuid: "\n", subgid: "", wantErr: ""},
		{name: "ranges below the pool", subuid: "alice:100000:65536\nbob:165536:65536\n", subgid: "alice:100000:65536\n"},
		{name: "range right below the pool", subuid: fmt.Sprintf("alice:%d:65536\n", 1<<20-65536)},
		{name: "range right above the pool", subuid: fmt.Sprintf("alice:%d:65536\n", 1<<20+16*65536)},
		{name: "range inside the pool", subuid: "alice:100000:65536\nbob:1048576:65536\n", wantErr: `/etc/subuid entry "bob:1048576:65536"`},
		{name: "range straddling the pool start", subuid: fmt.Sprintf("bob:%d:65536\n", 1<<20-100), wantErr: "overlaps"},
		{name: "range covering the whole pool", subuid: "bob:65536:4000000000\n", wantErr: "overlaps"},
		{name: "overlap in subgid alone", subuid: "alice:100000:65536\n", subgid: "alice:1100000:65536\n", wantErr: "/etc/subgid"},
		{name: "comment and blank lines", subuid: "# managed\n\nalice:100000:65536\n"},
		{name: "malformed line", subuid: "alice:100000\n", wantErr: "want name:start:count"},
		{name: "malformed count", subuid: "alice:100000:lots\n", wantErr: "want name:start:count"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			var files []string
			for name, body := range map[string]string{"subuid": tc.subuid, "subgid": tc.subgid} {
				p := filepath.Join(dir, "etc", name)
				files = append(files, p)
				if (name == "subuid" && tc.subuid == "" && !strings.Contains(tc.name, "empty")) ||
					(name == "subgid" && tc.subgid == "" && !strings.Contains(tc.name, "empty")) {
					continue // no file
				}
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			err := pool.CheckSubIDs(files...)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("CheckSubIDs = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("CheckSubIDs = %v, want an error mentioning %q", err, tc.wantErr)
			}
		})
	}
}

// TestRange checks that a grant's range is a function of its uid and the pool,
// aligned to a slot, inside the pool, and the same on every call.
func TestRange(t *testing.T) {
	def, _ := ParsePool(DefaultPool)
	cases := []struct {
		name  string
		pool  IDPool
		grant string
		other string // a grant that must get a different range, "" to skip
	}{
		{name: "default pool", pool: def, grant: "g1", other: "g2"},
		{name: "one slot maps everything to the start", pool: IDPool{Start: 100000, Slots: 1}, grant: "anything"},
		{name: "kubernetes uid", pool: def, grant: "b1a2c3d4-0000-4000-8000-000000000001", other: "b1a2c3d4-0000-4000-8000-000000000002"},
		{name: "empty uid still maps", pool: IDPool{Start: 65536, Slots: 3}, grant: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.pool.Range(tc.grant)
			if r != tc.pool.Range(tc.grant) {
				t.Fatalf("Range(%q) is not stable", tc.grant)
			}
			if r.Count != SlotIDs {
				t.Fatalf("Count = %d, want %d", r.Count, SlotIDs)
			}
			if r.Start < tc.pool.Start || (r.Start-tc.pool.Start)%SlotIDs != 0 {
				t.Fatalf("Start %d is not slot-aligned in pool %+v", r.Start, tc.pool)
			}
			if end := uint64(r.Start) + uint64(r.Count); end > uint64(tc.pool.Start)+uint64(tc.pool.Slots)*SlotIDs {
				t.Fatalf("range ends at %d, past the pool", end)
			}
			if tc.pool.Slots == 1 && r.Start != tc.pool.Start {
				t.Fatalf("one slot: Start = %d, want %d", r.Start, tc.pool.Start)
			}
			if tc.other != "" && tc.pool.Range(tc.other) == r {
				t.Fatalf("%q and %q share range %+v", tc.grant, tc.other, r)
			}
		})
	}
}

// TestRangeSameAcrossHomes treats two pools configured alike as two homes.
// They agree on every grant, and a home with another pool does not.
func TestRangeSameAcrossHomes(t *testing.T) {
	a, _ := ParsePool(DefaultPool)
	b, _ := ParsePool(DefaultPool)
	c, _ := ParsePool("200000:49151")
	cases := []struct {
		name  string
		grant string
	}{
		{name: "short", grant: "g1"},
		{name: "uuid", grant: "0f3c9d2e-7a1b-4c5d-9e8f-123456789abc"},
		{name: "path-like", grant: "team/alpha:7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if a.Range(tc.grant) != b.Range(tc.grant) {
				t.Fatalf("homes with the same pool disagree on %q", tc.grant)
			}
			if a.Range(tc.grant) == c.Range(tc.grant) {
				t.Fatalf("homes with different pools agree on %q", tc.grant)
			}
		})
	}
}

// colliding finds a grant uid that hashes to the same slot as grant.
func colliding(p IDPool, grant string) string {
	for i := 0; ; i++ {
		o := fmt.Sprintf("other-%d", i)
		if o != grant && p.slot(o) == p.slot(grant) {
			return o
		}
	}
}

// TestClaims checks that a slot is held by one grant at a time and for as
// long as any user of the grant has it, the warm zygote or a restored fiber.
// The zygote's hold counts once however often it is taken, each fiber's
// counts, the slot is free once the last user lets go, and a release by a
// grant that does not hold the slot changes nothing.
func TestClaims(t *testing.T) {
	pool := IDPool{Start: 100000, Slots: 4}
	const warm, fiber = true, false
	cases := []struct {
		name string
		run  func(t *testing.T, c *claims)
	}{
		{name: "two grants in one slot", run: func(t *testing.T, c *claims) {
			g2 := colliding(pool, "g1")
			if err := c.acquire("g1", warm); err != nil {
				t.Fatal(err)
			}
			if err := c.check(g2); !errors.Is(err, ErrRangeCollision) {
				t.Fatalf("check(%s) = %v, want ErrRangeCollision", g2, err)
			}
			if err := c.acquire(g2, warm); !errors.Is(err, ErrRangeCollision) {
				t.Fatalf("acquire(%s) = %v, want ErrRangeCollision", g2, err)
			}
			if err := c.acquire(g2, fiber); !errors.Is(err, ErrRangeCollision) {
				t.Fatalf("acquire(%s, fiber) = %v, want ErrRangeCollision", g2, err)
			}
		}},
		{name: "warm twice counts once", run: func(t *testing.T, c *claims) {
			for i := 0; i < 2; i++ {
				if err := c.acquire("g1", warm); err != nil {
					t.Fatalf("acquire %d: %v", i, err)
				}
			}
			if !c.release("g1", warm) {
				t.Fatal("one release of the zygote did not free the slot")
			}
		}},
		{name: "different slots do not collide", run: func(t *testing.T, c *claims) {
			g := "g1"
			other := ""
			for i := 0; other == ""; i++ {
				o := fmt.Sprintf("x%d", i)
				if pool.slot(o) != pool.slot(g) {
					other = o
				}
			}
			if err := c.acquire(g, warm); err != nil {
				t.Fatal(err)
			}
			if err := c.acquire(other, warm); err != nil {
				t.Fatalf("acquire(%s) = %v, want nil", other, err)
			}
		}},
		{name: "release frees the slot", run: func(t *testing.T, c *claims) {
			g2 := colliding(pool, "g1")
			if err := c.acquire("g1", warm); err != nil {
				t.Fatal(err)
			}
			if !c.release("g1", warm) {
				t.Fatal("release did not report the slot free")
			}
			if err := c.acquire(g2, warm); err != nil {
				t.Fatalf("acquire after release = %v, want nil", err)
			}
		}},
		{name: "a restored fiber holds the slot after the zygote is gone", run: func(t *testing.T, c *claims) {
			g2 := colliding(pool, "g1")
			if err := c.acquire("g1", warm); err != nil {
				t.Fatal(err)
			}
			if err := c.acquire("g1", fiber); err != nil {
				t.Fatal(err)
			}
			if c.release("g1", warm) {
				t.Fatal("the zygote's release freed a slot a fiber still uses")
			}
			if err := c.check(g2); !errors.Is(err, ErrRangeCollision) {
				t.Fatalf("check(%s) with a fiber of g1 live = %v, want ErrRangeCollision", g2, err)
			}
			if !c.release("g1", fiber) {
				t.Fatal("the last fiber's release did not free the slot")
			}
			if err := c.acquire(g2, warm); err != nil {
				t.Fatalf("acquire after the last user = %v, want nil", err)
			}
		}},
		{name: "every restored fiber counts", run: func(t *testing.T, c *claims) {
			for i := 0; i < 3; i++ {
				if err := c.acquire("g1", fiber); err != nil {
					t.Fatal(err)
				}
			}
			if c.release("g1", fiber) {
				t.Fatal("the first release, with two fibers left, freed the slot")
			}
			if c.release("g1", fiber) {
				t.Fatal("the second release, with one fiber left, freed the slot")
			}
			if !c.release("g1", fiber) {
				t.Fatal("the third release did not free the slot")
			}
		}},
		{name: "re-warming with fibers live is not a collision", run: func(t *testing.T, c *claims) {
			if err := c.acquire("g1", fiber); err != nil {
				t.Fatal(err)
			}
			if err := c.acquire("g1", warm); err != nil {
				t.Fatalf("warm with a fiber live = %v, want nil", err)
			}
			if c.release("g1", fiber) {
				t.Fatal("the fiber's release freed a slot the zygote holds")
			}
			if !c.release("g1", warm) {
				t.Fatal("the zygote's release did not free the slot")
			}
		}},
		{name: "release by a non-holder keeps the slot", run: func(t *testing.T, c *claims) {
			g2 := colliding(pool, "g1")
			if err := c.acquire("g1", warm); err != nil {
				t.Fatal(err)
			}
			if c.release(g2, warm) || c.release(g2, fiber) {
				t.Fatal("a stranger's release reported the slot free")
			}
			if err := c.check(g2); !errors.Is(err, ErrRangeCollision) {
				t.Fatalf("check after a stranger's release = %v, want ErrRangeCollision", err)
			}
		}},
		{name: "release of a user the grant does not have changes nothing", run: func(t *testing.T, c *claims) {
			if err := c.acquire("g1", warm); err != nil {
				t.Fatal(err)
			}
			if c.release("g1", fiber) {
				t.Fatal("releasing a fiber the grant never restored freed the slot")
			}
			if c.release("g1", fiber) {
				t.Fatal("a second such release freed the slot")
			}
			if !c.release("g1", warm) {
				t.Fatal("the zygote's release did not free the slot")
			}
			if c.release("g1", warm) {
				t.Fatal("a release of a free slot reported it freed")
			}
		}},
		{name: "collision names the slot, the ids and the remedy", run: func(t *testing.T, c *claims) {
			g2 := colliding(pool, "g1")
			_ = c.acquire("g1", warm)
			err := c.acquire(g2, warm)
			for _, want := range []string{"g1", fmt.Sprintf("slot %d of %d", pool.slot("g1"), pool.Slots), fmt.Sprintf("from %d", pool.Range("g1").Start), "larger -userns-pool"} {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("err = %v, want it to mention %q", err, want)
				}
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, newClaims(pool)) })
	}
}

// TestCheckSubIDsUnreadable checks that a subordinate id file that exists but
// cannot be read hides ranges, so it is an error rather than no check.
func TestCheckSubIDsUnreadable(t *testing.T) {
	pool := IDPool{Start: 1 << 20, Slots: 16}
	cases := []struct {
		name    string
		path    func(t *testing.T) string
		wantErr string
	}{
		{name: "a path under a file", wantErr: "not a directory", path: func(t *testing.T) string {
			f := filepath.Join(t.TempDir(), "subuid")
			if err := os.WriteFile(f, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(f, "subuid")
		}},
		{name: "a directory", wantErr: "read", path: func(t *testing.T) string { return t.TempDir() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := pool.CheckSubIDs(tc.path(t))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !strings.Contains(err.Error(), "userns pool") {
				t.Fatalf("CheckSubIDs = %v, want a userns pool error containing %q", err, tc.wantErr)
			}
		})
	}
}
