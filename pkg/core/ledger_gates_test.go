package core_test

import (
	"sync"
	"testing"

	"github.com/helayoty/fiberd/pkg/core"
)

// TestSessionGatesBounded pins that the per-session gate map is bounded
// by in-flight resolves, not by names ever seen. After every Resolve has
// unlocked, no gate remains, however many distinct or repeated names and
// however many concurrent callers.
func TestSessionGatesBounded(t *testing.T) {
	cases := []struct {
		name     string
		sessions int  // distinct session names
		callers  int  // concurrent Resolve callers per name
		errPath  bool // resolve against a grant that is revoked, so every call errors
	}{
		{name: "one name, one caller", sessions: 1, callers: 1},
		{name: "many names, one caller each", sessions: 64, callers: 1},
		{name: "one name, many concurrent callers", sessions: 1, callers: 32},
		{name: "error paths release the gate too", sessions: 8, callers: 4, errPath: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := core.NewLedger(1)
			l.AdmitGrant(core.Grant{UID: "g1", TemplateDigest: "sha256:t", FiberMax: 0})
			var wg sync.WaitGroup
			var mu sync.Mutex
			peak := 0
			for i := 0; i < tc.sessions; i++ {
				for c := 0; c < tc.callers; c++ {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						name := "S" + string(rune('a'+i%26)) + string(rune('a'+i/26))
						_, _, _, _, unlock, err := l.Resolve("g1", name, core.TierCheckpoint)
						if tc.errPath {
							// Revoke under the gate, so the next caller on this
							// name fails inside resolveHeld and must still release.
							l.RevokeGrant("g1")
						}
						mu.Lock()
						if n := core.SessionGates(l); n > peak {
							peak = n
						}
						mu.Unlock()
						if err == nil {
							unlock()
						} else if unlock != nil {
							unlock()
						}
					}(i)
				}
			}
			wg.Wait()
			if got := core.SessionGates(l); got != 0 {
				t.Fatalf("gates after every resolve unlocked = %d, want 0", got)
			}
			if peak > tc.sessions {
				t.Fatalf("peak gates = %d, want <= %d distinct names in flight", peak, tc.sessions)
			}
		})
	}
}
