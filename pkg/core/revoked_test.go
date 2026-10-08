package core_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// TestRemoveDenialLapse checks how long Remove denies a grant. A grant the
// ledger holds is denied until its lease and the ttl have both run out,
// and for good when it has no lease. A grant the ledger does not hold
// (swept on lease expiry already, or never admitted) has no lease to go
// by, so its denial runs for the ttl from now rather than for good.
func TestRemoveDenialLapse(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name  string
		held  bool          // the grant is admitted when removed
		lease time.Duration // the admitted grant's lease past now, 0 is none
		token time.Duration // the presented token's lease past now, 0 is none
		at    time.Duration // when the token is presented, past now
		// unwritable removes the deny-list's directory first, so the
		// denial cannot be persisted.
		unwritable bool
		want       bool
	}{
		{name: "a held grant with no lease: denied for good", held: true, at: 48 * time.Hour, want: true},
		{name: "a held leased grant: denied while lease and ttl run", held: true, lease: 30 * time.Minute, token: 30 * time.Minute, at: 59 * time.Minute, want: true},
		{name: "a held leased grant: dropped once lease and ttl are out", held: true, lease: 30 * time.Minute, token: 30 * time.Minute, at: time.Hour},
		{name: "an unknown grant: denied for the ttl", token: 30 * time.Minute, at: 59 * time.Minute, want: true},
		{name: "an unknown grant: lapses after the ttl, not for good", token: 30 * time.Minute, at: time.Hour},
		{name: "a denial that cannot be persisted holds in memory", held: true, unwritable: true, at: 48 * time.Hour, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newAgent(t, "up", core.TierCheckpoint)
			a.Ledger.Now = func() time.Time { return now }
			dir := filepath.Join(t.TempDir(), "state")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			r, err := core.OpenRevoked(filepath.Join(dir, "revoked.json"), time.Hour, now)
			if err != nil {
				t.Fatal(err)
			}
			a.Revoked = r
			if tc.unwritable {
				if err := os.RemoveAll(dir); err != nil {
					t.Fatal(err)
				}
			}
			var lease, token time.Time
			if tc.lease != 0 {
				lease = now.Add(tc.lease)
			}
			if tc.token != 0 {
				token = now.Add(tc.token)
			}
			if tc.held {
				a.Ledger.AdmitGrant(core.Grant{UID: "g1", Tenant: "acme", Audience: "node-a", LeaseExpiry: lease})
			}
			a.Remove(context.Background(), "g1")
			if got := r.Denied("g1", token, now.Add(tc.at)); got != tc.want {
				t.Fatalf("denied at +%s = %v, want %v", tc.at, got, tc.want)
			}
		})
	}
}

// A removed grant is denied until its lease and the ttl have both run
// out. One with no lease has tokens that never expire, so it is denied
// for good, across a reopen too.
func TestRevokedLapse(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		lease  time.Duration // past now, 0 is no lease
		at     time.Duration // when the token is presented, past now
		reopen bool          // read the list back from disk first
		want   bool
	}{
		{name: "no lease: still denied past the ttl", at: 25 * time.Hour, want: true},
		{name: "no lease: still denied after a reopen past the ttl", at: 25 * time.Hour, reopen: true, want: true},
		{name: "a lease past the ttl: denied until it ends", lease: 48 * time.Hour, at: 47 * time.Hour, want: true},
		{name: "a lease past the ttl: dropped once it ends", lease: 48 * time.Hour, at: 48 * time.Hour},
		{name: "a lease past the ttl: dropped on a reopen once it ends", lease: 48 * time.Hour, at: 48 * time.Hour, reopen: true},
		{name: "a short lease: denied for the ttl", lease: time.Hour, at: 23 * time.Hour, want: true},
		{name: "a short lease: dropped after the ttl", lease: time.Hour, at: 25 * time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "revoked.json")
			r, err := core.OpenRevoked(path, 0, now) // the 24h default
			if err != nil {
				t.Fatal(err)
			}
			var lease time.Time
			if tc.lease != 0 {
				lease = now.Add(tc.lease)
			}
			if err := r.Add("g1", lease, now); err != nil {
				t.Fatal(err)
			}
			at := now.Add(tc.at)
			if tc.reopen {
				if r, err = core.OpenRevoked(path, 0, at); err != nil {
					t.Fatal(err)
				}
			}
			if got := r.Denied("g1", lease, at); got != tc.want {
				t.Fatalf("denied at +%s = %v, want %v", tc.at, got, tc.want)
			}
		})
	}
}

// TestRevokedPersistence checks the deny-list's file. A path that does not
// read does not open. Clearing an entry that is not there reports false.
// A change that cannot be persisted, an extension or a lapse found by
// Denied or an entry that does not encode, still holds in memory.
func TestRevokedPersistence(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name       string
		dirAtPath  bool // the deny-list's path is a directory
		add        time.Time
		addErr     bool
		unwritable bool // the directory is gone after the add
		clear      bool // clear the entry instead of asking Denied
		lease      time.Time
		at         time.Time
		wantOpen   bool
		want       bool // Denied, or what Clear reports
		// wantAgain is Denied at again after the first answer.
		again     time.Time
		wantAgain bool
	}{
		{name: "a path that is a directory does not open", dirAtPath: true},
		{name: "clearing an entry that is not there reports false", wantOpen: true, clear: true},
		{name: "clearing an entry reports true", wantOpen: true, add: now.Add(time.Hour), clear: true, want: true},
		{name: "an extension that cannot be persisted holds in memory", wantOpen: true, add: now.Add(time.Hour), unwritable: true,
			lease: now.Add(3 * time.Hour), at: now, want: true, again: now.Add(150 * time.Minute), wantAgain: true},
		{name: "a lapse that cannot be persisted lifts in memory", wantOpen: true, add: now.Add(time.Hour), unwritable: true,
			at: now.Add(2 * time.Hour), again: now.Add(2 * time.Hour)},
		// A time past year 9999 has no JSON form.
		{name: "an entry that does not encode is an error from Add and holds in memory", wantOpen: true,
			add: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), addErr: true, at: now, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "revoked.json")
			if tc.dirAtPath {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			r, err := core.OpenRevoked(path, time.Minute, now)
			if (err == nil) != tc.wantOpen {
				t.Fatalf("OpenRevoked = %v, want opened %v", err, tc.wantOpen)
			}
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					t.Fatalf("OpenRevoked = %v, want an error other than not-exist", err)
				}
				return
			}
			if !tc.add.IsZero() {
				if err := r.Add("g1", tc.add, now); (err != nil) != tc.addErr {
					t.Fatalf("Add = %v, want error %v", err, tc.addErr)
				}
			}
			if tc.unwritable {
				if err := os.RemoveAll(dir); err != nil {
					t.Fatal(err)
				}
			}
			if tc.clear {
				lifted, err := r.Clear("g1")
				if err != nil || lifted != tc.want {
					t.Fatalf("Clear = %v %v, want %v", lifted, err, tc.want)
				}
				if r.Denied("g1", time.Time{}, now) {
					t.Fatal("denied after Clear")
				}
				return
			}
			if got := r.Denied("g1", tc.lease, tc.at); got != tc.want {
				t.Fatalf("Denied at %s = %v, want %v", tc.at, got, tc.want)
			}
			if !tc.again.IsZero() {
				if got := r.Denied("g1", time.Time{}, tc.again); got != tc.wantAgain {
					t.Fatalf("Denied again at %s = %v, want %v", tc.again, got, tc.wantAgain)
				}
			}
		})
	}
}
