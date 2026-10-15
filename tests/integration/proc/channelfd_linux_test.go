//go:build linux && integration

package proctest

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/tlsconf"
	"github.com/helayoty/fiberd/pkg/tlsconf/tlsconftest"
)

// TestChannelClosedUnlessHandoff pins that a fiber holds its channel to
// fiberd only while it serves handoff. Every fiber reads its record off
// fd 4, and a fiber that serves an endpoint of its own then closes it
// before on_fiber, so it holds no SOCK_SEQPACKET socket at all, a park
// has no channel to carry and a runc resume lands in a fresh network
// namespace as before. A handoff fiber keeps the channel, named in its
// environment, and serves over it.
func TestChannelClosedUnlessHandoff(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		handoff bool
		wantEnv string // FIBERD_CHANNEL_FD as the fiber sees it
	}{
		{name: "a fiber serving its own endpoint holds no channel", wantEnv: "-"},
		{name: "a handoff fiber keeps its channel at fd 4", handoff: true, wantEnv: "4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRuntime(t)
			g := core.Grant{UID: "gch", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20}
			spec := core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second}
			caller := tlsconftest.NewCA(t, "ca").Client(t, "caller")
			if tc.handoff {
				g.CallerThumbprint, g.Policy.EndpointMode = tlsconf.Thumbprint(caller.Cert), core.EndpointHandoff
				spec.Grant, spec.CallerCert = g, caller.Cert.Raw
			}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			h, err := rt.Clone(ctx, spec)
			if err != nil {
				t.Fatalf("clone: %v", err)
			}
			t.Cleanup(func() { _ = rt.Release(ctx, h.ID, true) })
			if tc.handoff {
				// Served over the channel, which is what keeping it is for.
				if got := talkOver(t, handOff(t, rt, h.ID, caller.TLS()), "getenv FIBERD_CHANNEL_FD"); got != tc.wantEnv {
					t.Fatalf("FIBERD_CHANNEL_FD = %q, want %q", got, tc.wantEnv)
				}
				return
			}
			if got := talk(t, h.Endpoint, "getenv FIBERD_CHANNEL_FD"); got != tc.wantEnv {
				t.Fatalf("FIBERD_CHANNEL_FD = %q, want %q", got, tc.wantEnv)
			}
			if socks := seqpacketSockets(t, peerPID(t, h.Endpoint)); len(socks) != 0 {
				t.Fatalf("the fiber holds SOCK_SEQPACKET sockets %v, want none once its record is read", socks)
			}
		})
	}
}

// seqpacketSockets lists the descriptors of pid that are SOCK_SEQPACKET
// unix sockets, by their inodes in /proc/net/unix (type 0005). The proc
// backend's fibers share the host's network namespace, so the table is
// this process's.
func seqpacketSockets(t *testing.T, pid int) []string {
	t.Helper()
	seqpacket := map[string]bool{}
	f, err := os.Open("/proc/net/unix")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 7 && fields[4] == "0005" {
			seqpacket["socket:["+fields[6]+"]"] = true
		}
	}
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join(fmt.Sprintf("/proc/%d/fd", pid), e.Name()))
		if err == nil && seqpacket[target] {
			out = append(out, e.Name()+" "+target)
		}
	}
	return out
}
