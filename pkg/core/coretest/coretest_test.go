package coretest_test

import (
	"testing"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/core/coretest"
)

func TestGrantStatus(t *testing.T) {
	l := core.NewLedger(7)
	l.AdmitGrant(core.Grant{UID: "a"})
	l.AdmitGrant(core.Grant{UID: "b"})
	cases := []struct {
		name string
		uid  string
		ok   bool
	}{
		{name: "an admitted grant has a status", uid: "b", ok: true},
		{name: "another admitted grant has its own", uid: "a", ok: true},
		{name: "a grant never admitted has none", uid: "c"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st, ok := coretest.GrantStatus(l, c.uid)
			if ok != c.ok {
				t.Fatalf("GrantStatus(%q) ok = %v, want %v", c.uid, ok, c.ok)
			}
			want := core.Status{}
			if c.ok {
				want.GrantUID = c.uid
			}
			if st.GrantUID != want.GrantUID || st.Running != 0 || st.Parked != 0 || st.WUsedBytes != 0 {
				t.Fatalf("GrantStatus(%q) = %+v, want an idle status for %q", c.uid, st, want.GrantUID)
			}
		})
	}
}
