//go:build linux && integration

package proctest

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// TestSessionAtBirth pins that a fiber learns the session the caller
// named, in its record and in its environment, and that an anonymous
// fiber learns none. The birth payload rides the same line and is
// delivered whole.
func TestSessionAtBirth(t *testing.T) {
	cases := []struct {
		name    string
		session string
		payload []byte
		want    string // the session the fiber answers
	}{
		{name: "anonymous", want: "-"},
		{name: "named, with a space", session: "conv 42", payload: []byte(`{"task":1}`), want: "conv 42"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			rt := newRuntime(t)
			g := core.Grant{UID: "gsess", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1},
				Deadline: 2 * time.Second, Session: tc.session, Payload: tc.payload})
			if err != nil {
				t.Fatalf("clone: %v", err)
			}
			t.Cleanup(func() { _ = rt.Release(ctx, h.ID, true) })
			if got := talk(t, h.Endpoint, "session"); got != tc.want {
				t.Fatalf("session = %q, want %q", got, tc.want)
			}
			if got := talk(t, h.Endpoint, "getenv FIBERD_SESSION"); got != tc.want {
				t.Fatalf("FIBERD_SESSION = %q, want %q", got, tc.want)
			}
			wantPayload := "-"
			if len(tc.payload) > 0 {
				wantPayload = hex.EncodeToString(tc.payload)
			}
			if got := talk(t, h.Endpoint, "payload"); got != wantPayload {
				t.Fatalf("payload = %q, want %q", got, wantPayload)
			}
		})
	}
}
