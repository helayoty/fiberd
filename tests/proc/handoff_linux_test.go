//go:build linux

package proctest

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// TestHandoffKeyNeverOnDisk pins that a grant's TLS key reaches its fibers
// over their handoff channel, never through a file. Every fiber runs as
// the agent's user without capabilities, so any file under the run
// directory is readable by every grant's fibers, whatever its mode.
func TestHandoffKeyNeverOnDisk(t *testing.T) {
	rt := newRuntime(t)
	ctx := context.Background()
	callerA, x5tA := callerCert(t)
	callerB, x5tB := callerCert(t)
	run := filepath.Join("/tmp", "fz-"+fmt.Sprint(os.Getpid()))
	ga := core.Grant{UID: "gka", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20, CallerThumbprint: x5tA, Policy: core.Policy{EndpointMode: core.EndpointHandoff}}
	gb := core.Grant{UID: "gkb", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20, CallerThumbprint: x5tB, Policy: core.Policy{EndpointMode: core.EndpointHandoff}}
	for _, g := range []core.Grant{ga, gb} {
		if err := rt.PrepareTemplate(ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	fa, err := rt.Clone(ctx, core.CloneSpec{Grant: ga, Fence: core.Fence{GrantUID: ga.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	fb, err := rt.Clone(ctx, core.CloneSpec{Grant: gb, Fence: core.Fence{GrantUID: gb.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		// reader is the fiber asked, as its caller over TLS with the key
		// the host pins for it. Each reply proves the fiber holds the
		// grant's identity.
		reader core.FiberHandle
		caller tls.Certificate
		// cmd is the refzygote command and want its reply. "read" answers
		// the first line of a file, or "-" when it cannot be read.
		cmd, want string
	}{
		{name: "A serves its caller", reader: fa, caller: callerA, cmd: "ping", want: "pong"},
		{name: "B serves its caller", reader: fb, caller: callerB, cmd: "ping", want: "pong"},
		{name: "A cannot read B's key", reader: fa, caller: callerA, cmd: "read " + filepath.Join(run, gb.UID, "handoff.key"), want: "-"},
		{name: "B cannot read A's key", reader: fb, caller: callerB, cmd: "read " + filepath.Join(run, ga.UID, "handoff.key"), want: "-"},
		{name: "A's own key is not a file", reader: fa, caller: callerA, cmd: "read " + filepath.Join(run, ga.UID, "handoff.key"), want: "-"},
		{name: "no key path in the environment", reader: fa, caller: callerA, cmd: "getenv FIBERD_TLS_KEY", want: "-"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := talkOver(t, handOff(t, rt, tc.reader.ID, tc.caller), tc.cmd); got != tc.want {
				t.Fatalf("%s: %s = %q, want %q", tc.reader.ID, tc.cmd, got, tc.want)
			}
		})
	}
	// The host wrote no key file either. Such a file, however it is
	// protected, is what this guards against.
	for _, g := range []core.Grant{ga, gb} {
		if _, err := os.Stat(filepath.Join(run, g.UID, "handoff.key")); err == nil {
			t.Fatalf("%s/handoff.key exists on the host", g.UID)
		}
	}
}
