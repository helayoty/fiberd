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

// TestChannelDescriptors pins where a fiber's channel lives. Every fiber
// reads its birth record off fd 4 and finds the number in its
// environment. A fiber that serves an endpoint of its own then holds a
// pair of its own there, both ends, fd 4 to read and fd 5 as the peer,
// so a park carries the pair whole and a resume's record can be written
// on the peer. A handoff fiber keeps fiberd's channel at fd 4 alone,
// and serves over it.
func TestChannelDescriptors(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name      string
		handoff   bool
		wantEnv   string   // FIBERD_CHANNEL_FD as the fiber sees it
		wantSocks []string // the SOCK_SEQPACKET descriptors the fiber holds
	}{
		{name: "a fiber serving its own endpoint holds its own pair at fd 4 and 5", wantEnv: "4", wantSocks: []string{"4", "5"}},
		{name: "a handoff fiber keeps fiberd's channel at fd 4", handoff: true, wantEnv: "4"},
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
			socks := seqpacketSockets(t, peerPID(t, h.Endpoint))
			var fds []string
			for _, s := range socks {
				fds = append(fds, strings.Fields(s)[0])
			}
			if strings.Join(fds, ",") != strings.Join(tc.wantSocks, ",") {
				t.Fatalf("the fiber holds SOCK_SEQPACKET sockets %v, want descriptors %v", socks, tc.wantSocks)
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
