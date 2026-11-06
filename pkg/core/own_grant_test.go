package core_test

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/fiberd/pkg/core"
	"github.com/Azure/fiberd/pkg/core/coretest"
)

// The UIDs of a home that holds its own grant and of another Pod.
const (
	ownUID   = "g-own"
	otherUID = "g-other"
)

// ownTokens are the tokens the test verifier knows on a home that holds
// its own grant. The home's file and the caller's token name the same UID
// with different digests, so the ledger shows which one was admitted. The
// bound ones carry a caller key.
func ownTokens() map[string]core.Grant {
	past, future := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	return map[string]core.Grant{
		"caller":         {UID: ownUID, Tenant: "acme", Audience: "node-a", TemplateDigest: "sha256:new", LeaseExpiry: future},
		"caller-lapsed":  {UID: ownUID, Tenant: "acme", Audience: "node-a", TemplateDigest: "sha256:new", LeaseExpiry: past},
		"caller-bound":   {UID: ownUID, Tenant: "acme", Audience: "node-a", TemplateDigest: "sha256:new", LeaseExpiry: future, CallerThumbprint: "home-jkt"},
		"caller-rekeyed": {UID: ownUID, Tenant: "acme", Audience: "node-a", TemplateDigest: "sha256:new", LeaseExpiry: future, CallerThumbprint: "other-jkt"},
		"same":           {UID: ownUID, Tenant: "acme", Audience: "node-a", TemplateDigest: "sha256:old", LeaseExpiry: future},
		"file":           {UID: ownUID, Tenant: "acme", Audience: "node-a", TemplateDigest: "sha256:old", LeaseExpiry: future},
		"file-bound":     {UID: ownUID, Tenant: "acme", Audience: "node-a", TemplateDigest: "sha256:old", LeaseExpiry: future, CallerThumbprint: "home-jkt"},
		"file-sync":      {UID: ownUID, Tenant: "acme", Audience: "node-a", TemplateDigest: "sha256:old", LeaseExpiry: future, Policy: core.Policy{Durability: core.Sync}},
		"file-lapsed":    {UID: ownUID, Tenant: "acme", Audience: "node-a", TemplateDigest: "sha256:old", LeaseExpiry: past},
		"file-other":     {UID: otherUID, Tenant: "acme", Audience: "node-a", TemplateDigest: "sha256:old", LeaseExpiry: future},
		"delivered":      {UID: ownUID, Tenant: "acme", Audience: "node-a", TemplateDigest: "sha256:old", LeaseExpiry: future},
		"foreign":        {UID: otherUID, Tenant: "acme", Audience: "node-a", TemplateDigest: "sha256:new", LeaseExpiry: future},
	}
}

// delivered is the grant a token names, with the token kept, as a
// delivery hands it to Admit.
func delivered(tokens map[string]core.Grant, tok string) core.Grant {
	g := tokens[tok]
	g.Token = tok
	return g
}

// ownGrantHook is the hook of a home whose own grant is the token file,
// or none when file is empty. calls counts how often it was asked.
func ownGrantHook(file string, calls *int) func() ([]byte, bool) {
	return func() ([]byte, bool) {
		*calls++
		if file == "" {
			return nil, false
		}
		return []byte(file), true
	}
}

// TestCloneOwnGrant checks Clone on a home that holds a grant of its own.
// The home's UID, unadmitted, is admitted from the home's token and never
// from the one presented. A foreign UID, an admitted UID and a home
// without the hook run as before.
func TestCloneOwnGrant(t *testing.T) {
	ctx := context.Background()
	tokens := ownTokens()
	cases := []struct {
		name    string
		health  string
		noHook  bool   // the home has no own grant hook
		file    string // the token the hook answers, none when empty
		token   string // the token the caller presents
		caller  string // the thumbprint of the caller's key
		session string
		setup   func(t *testing.T, a *core.Core)
		want    core.StatusCode
		wantErr error
		calls   int    // how often the hook was asked
		running int    // the own grant's running fibers afterwards
		held    string // the token the ledger holds for own, nothing when empty
		digest  string // the digest the ledger holds for own
	}{
		{name: "a lapse after a refused renewal is a miss, the live caller token notwithstanding",
			file: "file-lapsed", token: "caller", want: core.DeferredFallback, wantErr: core.ErrGrantExpired, calls: 1},
		{name: "the same lapse is shed while the home reports the issuer unreachable", health: "down",
			file: "file-lapsed", token: "caller", want: core.Shed, wantErr: core.ErrGrantExpired, calls: 1},
		{name: "an expired caller token with a live file is a miss before the hook",
			file: "file", token: "caller-lapsed", want: core.DeferredFallback, wantErr: core.ErrGrantExpired},
		{name: "an expired caller token with a live file is shed during an outage", health: "down",
			file: "file", token: "caller-lapsed", want: core.Shed, wantErr: core.ErrGrantExpired},
		{name: "a newer spec's token on an older Pod admits the home's grant",
			file: "file", token: "caller", want: core.OK, calls: 1, running: 1, held: "file", digest: "sha256:old"},
		{name: "a missed delivery recovers on the next Clone from the home's token",
			file: "file", token: "same", want: core.OK, calls: 1, running: 1, held: "file", digest: "sha256:old"},
		{name: "a named session through the own branch clones under the home's grant",
			file: "file", token: "caller", session: "S", want: core.OK, calls: 1, running: 1, held: "file", digest: "sha256:old"},
		{name: "a caller token under another key than the home's grant is refused, the home's grant held",
			file: "file-bound", token: "caller-rekeyed", caller: "other-jkt",
			want: core.Unauthenticated, wantErr: core.ErrCallerMismatch, calls: 1, held: "file-bound", digest: "sha256:old"},
		{name: "a caller token under the home's grant's key clones",
			file: "file-bound", token: "caller-bound", caller: "home-jkt",
			want: core.OK, calls: 1, running: 1, held: "file-bound", digest: "sha256:old"},
		{name: "a token before the first delivery is a miss",
			token: "caller", want: core.DeferredFallback, wantErr: core.ErrGrantUnknown, calls: 1},
		{name: "a home grant that does not verify is a miss",
			file: "garbage", token: "caller", want: core.DeferredFallback, wantErr: core.ErrGrantUnknown, calls: 1},
		{name: "a home grant for another UID is a miss",
			file: "file-other", token: "caller", want: core.DeferredFallback, wantErr: core.ErrGrantUnknown, calls: 1},
		{name: "a foreign UID is refused before the hook",
			file: "file", token: "foreign", want: core.Unauthenticated, wantErr: core.ErrWrongAudience},
		{name: "an admitted UID clones under the admitted grant without the hook",
			file: "file", token: "caller", setup: func(t *testing.T, a *core.Core) { a.Ledger.AdmitGrant(delivered(tokens, "delivered")) },
			want: core.OK, running: 1, held: "delivered", digest: "sha256:old"},
		{name: "a delivery after a lapse admits again",
			file: "file", token: "caller", setup: func(t *testing.T, a *core.Core) {
				a.Ledger.AdmitGrant(delivered(tokens, "file-lapsed"))
				if n := a.Sweep(ctx); n != 1 {
					t.Fatalf("swept %d grants, want the lapsed one", n)
				}
				if _, err := a.Admit(ctx, delivered(tokens, "delivered")); err != nil {
					t.Fatalf("Admit after the lapse: %v", err)
				}
			},
			want: core.OK, running: 1, held: "delivered", digest: "sha256:old"},
		{name: "a denied UID stays refused with a live file",
			file: "file", token: "caller", setup: func(t *testing.T, a *core.Core) {
				r, err := core.OpenRevoked(filepath.Join(t.TempDir(), "revoked.json"), time.Hour, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				a.Revoked = r
				a.Remove(ctx, ownUID)
			},
			want: core.DeferredFallback, wantErr: core.ErrGrantRevoked, calls: 1},
		{name: "without the hook the presented token self-admits", noHook: true,
			token: "caller", want: core.OK, running: 1, held: "caller", digest: "sha256:new"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newCore(t, tc.health, core.TierCheckpoint)
			a.Verify = acceptVerifier{grants: tokens}
			a.SelfAdmitUID = ownUID
			calls := 0
			if !tc.noHook {
				a.OwnGrant = ownGrantHook(tc.file, &calls)
			}
			if tc.setup != nil {
				tc.setup(t, a)
			}
			req := core.CloneRequest{GrantJWT: []byte(tc.token), Session: tc.session, CallerThumbprint: tc.caller, Deadline: time.Second}
			_, code, err := a.Clone(ctx, req)
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("Clone err = %v, want %v", err, tc.wantErr)
			}
			if code != tc.want {
				t.Fatalf("Clone code = %d, want %d (err %v)", code, tc.want, err)
			}
			if calls != tc.calls {
				t.Fatalf("the hook was asked %d times, want %d", calls, tc.calls)
			}
			if st, _ := coretest.GrantStatus(a.Ledger, ownUID); st.Running != tc.running {
				t.Fatalf("running = %d after clone, want %d", st.Running, tc.running)
			}
			held, ok := a.Ledger.Grant(ownUID)
			if ok != (tc.held != "") {
				t.Fatalf("the ledger holds %s = %v, want %v", ownUID, ok, tc.held != "")
			}
			if held.Token != tc.held || held.TemplateDigest != tc.digest {
				t.Fatalf("the ledger holds token %q digest %q, want %q %q", held.Token, held.TemplateDigest, tc.held, tc.digest)
			}
			// The snapshot carries the admitted token, so a restart
			// re-admits what the home held and never what a caller sent.
			var snap []string
			for _, g := range a.Ledger.Snapshot().Grants {
				snap = append(snap, g.Token)
			}
			if len(snap) > 1 || (len(snap) == 1) != (tc.held != "") || (tc.held != "" && snap[0] != tc.held) {
				t.Fatalf("the snapshot holds tokens %q, want %q", snap, tc.held)
			}
		})
	}
}

// TestDiscardOwnGrant checks Discard on a home that holds a grant of its
// own. On the home's UID with no grant admitted, the home's grant answers
// for the token, and nothing is admitted. That covers a session parked
// here before the grant was yielded, and one in the store only. A foreign
// UID and an admitted UID run as before, the foreign one to the store's
// copy.
func TestDiscardOwnGrant(t *testing.T) {
	const (
		oldS = "acme/sha256:old/S" // S in the store under the home's grant
		newS = "acme/sha256:new/S" // S in the store under a caller's token
	)
	ctx := context.Background()
	tokens := ownTokens()
	cases := []struct {
		name      string
		file      string // the token the hook answers, none when empty
		token     string // the token the caller presents
		caller    string // the thumbprint of the caller's key
		stored    string // the key S is published under in the store, none when empty
		parked    string // the home's token S was parked under before the grant was yielded, none when empty
		failAudit bool   // sync audit records fail
		setup     func(t *testing.T, a *core.Core)
		want      core.StatusCode
		wantErr   error
		calls     int    // how often the hook was asked
		deleted   int    // store copies deleted
		dropped   bool   // the local delta was dropped
		state     string // S under own afterwards, gone when empty
		held      string // the token the ledger holds for own, nothing when empty
	}{
		{name: "a live file with the caller's key discards the parked session",
			parked: "file-bound", file: "file-bound", token: "caller-bound", caller: "home-jkt", want: core.OK, calls: 1, dropped: true},
		{name: "a live file under another key leaves the parked session",
			parked: "file-bound", file: "file-bound", token: "caller-rekeyed", caller: "other-jkt",
			want: core.Unauthenticated, wantErr: core.ErrCallerMismatch, calls: 1, state: "parked"},
		{name: "an expired file leaves the parked session",
			parked: "file", file: "file-lapsed", token: "caller", want: core.DeferredFallback, wantErr: core.ErrGrantExpired, calls: 1, state: "parked"},
		{name: "the home's grant's durability governs the discard record",
			parked: "file-sync", file: "file-sync", token: "caller", failAudit: true,
			want: core.Internal, wantErr: core.ErrAudit, calls: 1, dropped: true},
		{name: "a live file lets the discard run under the home's grant",
			file: "file", token: "caller", stored: oldS, want: core.OK, calls: 1, deleted: 1},
		{name: "a live file under another key than the caller's is refused",
			file: "file-bound", token: "caller-rekeyed", caller: "other-jkt", stored: oldS,
			want: core.Unauthenticated, wantErr: core.ErrCallerMismatch, calls: 1},
		{name: "a live file under the caller's key discards",
			file: "file-bound", token: "caller-bound", caller: "home-jkt", stored: oldS, want: core.OK, calls: 1, deleted: 1},
		{name: "an expired file is a miss",
			file: "file-lapsed", token: "caller", stored: oldS, want: core.DeferredFallback, wantErr: core.ErrGrantExpired, calls: 1},
		{name: "no file is a miss",
			token: "caller", stored: oldS, want: core.DeferredFallback, wantErr: core.ErrGrantUnknown, calls: 1},
		{name: "an expired caller token with a live file is a miss before the hook",
			file: "file", token: "caller-lapsed", stored: oldS, want: core.DeferredFallback, wantErr: core.ErrGrantExpired},
		{name: "a foreign UID does not ask the hook and reaches the store's copy as before",
			file: "file", token: "foreign", stored: newS, want: core.OK, deleted: 1},
		{name: "an admitted UID discards under the admitted grant without the hook",
			file: "file", token: "caller", stored: oldS,
			setup: func(t *testing.T, a *core.Core) { a.Ledger.AdmitGrant(delivered(tokens, "delivered")) },
			want:  core.OK, deleted: 1, held: "delivered"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := &store{deltas: map[string]published{}}
			if tc.stored != "" {
				st.deltas[tc.stored] = published{ref: "r1", home: "node-b"}
			}
			a, rt, _ := newDiscardHome(t, "node-a", st)
			a.Verify = acceptVerifier{grants: tokens}
			a.SelfAdmitUID = ownUID
			calls := 0
			a.OwnGrant = ownGrantHook(tc.file, &calls)
			if tc.failAudit {
				a.Audit = failingAuditor{}
			}
			if tc.parked != "" {
				// S parks under the home's grant, which then lapses. The
				// delta stays, and the grant is gone from the ledger.
				a.Ledger.AdmitGrant(delivered(tokens, tc.parked))
				createFiber(t, a.Ledger, ownUID, "S", "f1")
				a.Ledger.OnPark("f1", "delta-f1")
				a.Yield(ctx, ownUID, "lease expired")
			}
			if tc.setup != nil {
				tc.setup(t, a)
			}
			req := core.DiscardRequest{GrantJWT: []byte(tc.token), Session: "S", CallerThumbprint: tc.caller}
			code, err := a.Discard(ctx, req)
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("Discard err = %v, want %v", err, tc.wantErr)
			}
			if code != tc.want {
				t.Fatalf("Discard code = %d, want %d (err %v)", code, tc.want, err)
			}
			if calls != tc.calls {
				t.Fatalf("the hook was asked %d times, want %d", calls, tc.calls)
			}
			if len(rt.deleted) != tc.deleted {
				t.Fatalf("deleted %v from the store, want %d", rt.deleted, tc.deleted)
			}
			if got := len(rt.discarded) > 0; got != tc.dropped {
				t.Fatalf("dropped %v, want a local delta dropped %v", rt.discarded, tc.dropped)
			}
			if want := cmp.Or(tc.state, "gone"); ledgerState(a.Ledger, ownUID, "S") != want {
				t.Fatalf("S = %s, want %s", ledgerState(a.Ledger, ownUID, "S"), want)
			}
			held, ok := a.Ledger.Grant(ownUID)
			if ok != (tc.held != "") || held.Token != tc.held {
				t.Fatalf("the ledger holds %s = %v %q, want %q", ownUID, ok, held.Token, tc.held)
			}
			// Nothing the hook answered enters the snapshot.
			var snap []string
			for _, g := range a.Ledger.Snapshot().Grants {
				snap = append(snap, g.Token)
			}
			if len(snap) > 1 || (len(snap) == 1) != (tc.held != "") || (tc.held != "" && snap[0] != tc.held) {
				t.Fatalf("the snapshot holds tokens %q, want %q", snap, tc.held)
			}
		})
	}
}

// TestCloneOwnGrantConcurrent runs many Clones at once on the home's UID
// while it is unadmitted, each under a caller token with a digest of its
// own, with the first warm held open so they overlap in the admission.
// Whatever runs beside them, only the home's token reaches the ledger and
// the snapshot, and no clone is refused as unauthenticated.
func TestCloneOwnGrantConcurrent(t *testing.T) {
	const clones = 8
	ctx := context.Background()
	tokens := ownTokens()
	renewal := tokens["file"]
	renewal.LeaseExpiry = renewal.LeaseExpiry.Add(time.Hour)
	tokens["renewal"] = renewal
	for i := range clones {
		g := tokens["caller"]
		g.TemplateDigest = fmt.Sprintf("sha256:caller-%d", i)
		tokens[fmt.Sprintf("caller-%d", i)] = g
	}
	type result struct {
		code core.StatusCode
		err  error
	}
	cases := []struct {
		name string
		// beside, when set, runs once every clone is in the admission and
		// the warm is still held open.
		beside    func(a *core.Core)
		allOK     bool          // every clone creates, else each creates or misses
		wantHeld  []string      // the tokens the ledger may hold for own afterwards, "" for none
		wantLease time.Duration // how far past the file's lease the held one ends
		wantWarms int           // template warms, unchecked when zero
	}{
		{name: "clones on an unadmitted UID share one warm and hold the home's token",
			allOK: true, wantHeld: []string{"file"}, wantWarms: 1},
		{name: "clones racing a renewal's delivery end on the longer lease",
			beside: func(a *core.Core) { _, _ = a.Admit(ctx, delivered(tokens, "renewal")) },
			allOK:  true, wantHeld: []string{"renewal"}, wantLease: time.Hour},
		{name: "clones racing a yield create or miss, and never hold a caller token",
			beside:   func(a *core.Core) { a.Yield(ctx, ownUID, "removed by the home") },
			wantHeld: []string{"", "file"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newCore(t, "up", core.TierCheckpoint)
			a.Verify = acceptVerifier{grants: tokens}
			a.SelfAdmitUID = ownUID
			rt := prepRuntime{fakeRuntime: fakeRuntime{tier: core.TierCheckpoint}, started: make(chan struct{}, clones+1), proceed: make(chan struct{})}
			a.Runtime = rt
			var calls atomic.Int32
			a.OwnGrant = func() ([]byte, bool) {
				calls.Add(1)
				return []byte("file"), true
			}
			stop := make(chan struct{})
			defer close(stop)
			inWait := make(chan struct{}, clones)
			results := make(chan result, clones)
			for i := range clones {
				wc := &waitCtx{Context: ctx, waiting: make(chan struct{})}
				go func() {
					select {
					case <-wc.waiting:
						inWait <- struct{}{}
					case <-stop:
					}
				}()
				go func() {
					_, code, err := a.Clone(wc, core.CloneRequest{GrantJWT: []byte(fmt.Sprintf("caller-%d", i)), Deadline: time.Second})
					results <- result{code, err}
				}()
			}
			timeout := time.After(10 * time.Second)
			// One clone warms. The others reach the admission's wait while
			// the warm is held, so they share it.
			select {
			case <-rt.started:
			case <-timeout:
				t.Fatal("no clone reached the template warm")
			}
			for range clones - 1 {
				select {
				case <-inWait:
				case <-timeout:
					t.Fatal("the clones did not all reach the admission's wait")
				}
			}
			beside := make(chan struct{})
			if tc.beside != nil {
				go func() {
					defer close(beside)
					tc.beside(a)
				}()
			} else {
				close(beside)
			}
			close(rt.proceed)
			for range clones {
				select {
				case r := <-results:
					switch {
					case r.code == core.OK:
					case tc.allOK:
						t.Fatalf("Clone = %d %v, want OK", r.code, r.err)
					case r.code != core.DeferredFallback && r.code != core.Shed:
						t.Fatalf("Clone = %d %v, want OK or a capacity miss", r.code, r.err)
					}
				case <-timeout:
					t.Fatal("a clone did not return")
				}
			}
			select {
			case <-beside:
			case <-timeout:
				t.Fatal("what ran beside the clones did not return")
			}
			if n := calls.Load(); n != clones {
				t.Fatalf("the hook was asked %d times, want %d", n, clones)
			}
			if warms := 1 + len(rt.started); tc.wantWarms != 0 && warms != tc.wantWarms {
				t.Fatalf("the template warmed %d times, want %d", warms, tc.wantWarms)
			}
			if st, _ := coretest.GrantStatus(a.Ledger, ownUID); tc.allOK && st.Running != clones {
				t.Fatalf("running = %d, want %d", st.Running, clones)
			}
			held, ok := a.Ledger.Grant(ownUID)
			if !slices.Contains(tc.wantHeld, held.Token) || ok != (held.Token != "") {
				t.Fatalf("the ledger holds %q (%v), want one of %q", held.Token, ok, tc.wantHeld)
			}
			if want := tokens["file"].LeaseExpiry.Add(tc.wantLease); ok && tc.wantLease != 0 && !held.LeaseExpiry.Equal(want) {
				t.Fatalf("the held lease ends %s, want %s", held.LeaseExpiry, want)
			}
			var snap []string
			for _, g := range a.Ledger.Snapshot().Grants {
				snap = append(snap, g.Token)
			}
			if len(snap) > 1 || (len(snap) == 1) != ok || (ok && snap[0] != held.Token) {
				t.Fatalf("the snapshot holds tokens %q, want %q", snap, held.Token)
			}
		})
	}
}
