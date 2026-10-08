// Package coretest holds helpers for tests of code built on pkg/core.
package coretest

import "github.com/helayoty/fiberd/pkg/core"

// GrantStatus returns the ledger's status for one grant, and false when
// the grant is not admitted.
func GrantStatus(l *core.Ledger, uid string) (core.Status, bool) {
	for _, st := range l.Statuses() {
		if st.GrantUID == uid {
			return st, true
		}
	}
	return core.Status{}, false
}
