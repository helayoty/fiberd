//go:build linux && integration

package proctest

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/tlsconf"
	"github.com/helayoty/fiberd/pkg/tlsconf/tlsconftest"
)

// TestHandoffRefusesInHandshake pins that the reference template fails
// the handshake itself for any certificate but the bound caller's,
// whether or not the home's CA stands behind it. A caller it turns away
// sees a TLS alert, never a connection closed after a handshake that
// succeeded, so no other certificate ever completes a handshake with the
// fiber. The fiber goes on serving its caller after each refusal.
func TestHandoffRefusesInHandshake(t *testing.T) {
	rt := newRuntime(t)
	ctx := context.Background()
	ca := tlsconftest.NewCA(t, "ca")
	caller := ca.Client(t, "caller")
	other := ca.Client(t, "other")
	stranger := tlsconftest.NewCA(t, "stranger").Client(t, "stranger")
	g := core.Grant{UID: "ghr", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20,
		CallerThumbprint: tlsconf.Thumbprint(caller.Cert), Policy: core.Policy{EndpointMode: core.EndpointHandoff}}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second, CallerCert: caller.Cert.Raw})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Release(ctx, h.ID, true) })
	cases := []struct {
		name string
		cert tls.Certificate
		// served says the caller gets a reply to ping. Otherwise the
		// caller must get the fiber's handshake alert.
		served bool
	}{
		{name: "the bound caller is served", cert: caller.TLS(), served: true},
		{name: "another certificate under the CA fails the handshake itself", cert: other.TLS()},
		{name: "a certificate outside the CA fails the handshake itself", cert: stranger.TLS()},
		{name: "the bound caller is served after the refusals", cert: caller.TLS(), served: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.served {
				if got := talkOver(t, handOff(t, rt, h.ID, tc.cert), "ping"); got != "pong" {
					t.Fatalf("ping = %q, want pong", got)
				}
				return
			}
			if err := refusal(handOff(t, rt, h.ID, tc.cert)); !isAlert(err) {
				t.Fatalf("got %v, want the fiber's handshake alert", err)
			}
		})
	}
}

// refusal is what a caller the fiber turns away sees. In TLS 1.3 the
// caller's side of the handshake ends with its Finished, before the fiber
// has looked at its certificate, so the verdict arrives on the first
// read. A handshake the fiber failed is a TLS alert, and a connection
// closed after a handshake that succeeded is a bare EOF.
func refusal(c net.Conn) error {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := c.(*tls.Conn).Handshake(); err != nil {
		return err
	}
	_, err := c.Read(make([]byte, 1))
	return err
}

// isAlert reports whether err is a TLS alert the peer sent, as crypto/tls
// surfaces it.
func isAlert(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "remote error"
}

// TestHandoffKeyNeverOnDisk pins that a grant's TLS key reaches its fibers
// over their handoff channel, never through a file. Every fiber runs as
// fiberd's user without capabilities, so any file under the run
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
	fa, err := rt.Clone(ctx, core.CloneSpec{Grant: ga, Fence: core.Fence{GrantUID: ga.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second, CallerCert: callerA.Certificate[0]})
	if err != nil {
		t.Fatal(err)
	}
	fb, err := rt.Clone(ctx, core.CloneSpec{Grant: gb, Fence: core.Fence{GrantUID: gb.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second, CallerCert: callerB.Certificate[0]})
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
