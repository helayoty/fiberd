//go:build linux

package host

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
)

// callerDER stands in for the DER certificate a clone arrives under in
// the tests of this package, whose fake backends never open TLS.
var callerDER = []byte("caller der")

// callerPEM is callerDER as the record carries it.
var callerPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: callerDER})

// TestIdentityFor checks that a handoff fiber's record takes the grant's
// key, certificate and caller, and the caller's certificate as PEM, as
// libfiberzygote parses it. A clone without the caller's certificate, as
// one without mutual TLS, gets no identity, and neither does a grant
// whose identity was never prepared or names no caller.
func TestIdentityFor(t *testing.T) {
	cases := []struct {
		name       string
		prepared   bool
		caller     string
		callerCert []byte
		wantErr    string
	}{
		{name: "key, certificate, caller, caller certificate", prepared: true, caller: "x5t", callerCert: callerDER},
		{name: "no caller certificate", prepared: true, caller: "x5t", wantErr: "no caller certificate"},
		{name: "no caller", prepared: true, callerCert: callerDER, wantErr: "names no caller"},
		{name: "no identity prepared", caller: "x5t", callerCert: callerDER, wantErr: "no handoff identity prepared"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Runtime{cfg: Config{HandoffKey: handoffKey}}
			if tc.prepared {
				if err := r.prepareIdentity("g1", tc.caller); err != nil {
					t.Fatal(err)
				}
			}
			id, err := r.identityFor("g1", tc.callerCert)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("identityFor = %+v, %v, want an error mentioning %q", id, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			had := r.identities["g1"].id
			if id.KeyPEM != string(had.KeyPEM) || id.CertPEM != string(had.CertPEM) || id.Caller != "x5t" || id.CallerPEM != string(callerPEM) {
				t.Fatalf("identity = %+v, want the grant's and the caller's certificate", id)
			}
		})
	}
}

// TestIdentityLifecycle checks that a grant's identity is held from
// PrepareTemplate until its warm instance ends, then dropped so the home does
// not keep every admitted grant's key for its lifetime. It is derived from
// the home's key, so a grant prepared again gets the same one.
func TestIdentityLifecycle(t *testing.T) {
	cases := []struct {
		name string
		// steps run in order, each "prepare" or "forget" for grant ga.
		steps []string
		// held is whether ga's identity must be in memory afterwards.
		held bool
	}{
		{name: "prepared identity is held", steps: []string{"prepare"}, held: true},
		{name: "dropped when the warm instance ends", steps: []string{"prepare", "forget"}},
		{name: "forgetting an unknown grant is harmless", steps: []string{"forget"}},
		{name: "prepared again after the drop", steps: []string{"prepare", "forget", "prepare"}, held: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Runtime{cfg: Config{HandoffKey: bytes.Repeat([]byte{7}, 32)}}
			var first handoffIdentity
			for i, s := range tc.steps {
				switch s {
				case "prepare":
					if err := r.prepareIdentity("ga", "x5t"); err != nil {
						t.Fatal(err)
					}
					if i == 0 {
						first = r.identities["ga"]
					}
				case "forget":
					r.forgetIdentity("ga")
				}
			}
			got, ok := r.identities["ga"]
			if ok != tc.held {
				t.Fatalf("identity held = %v, want %v", ok, tc.held)
			}
			if ok && first.id.KeySHA256 != "" && got.id.KeySHA256 != first.id.KeySHA256 {
				t.Fatalf("identity changed across a drop: %s then %s", first.id.KeySHA256, got.id.KeySHA256)
			}
		})
	}
}

// TestCanHandoff checks that a home gives its fibers a channel when its
// backend takes one, and hands connections to them only when a router
// gives them out as well.
func TestCanHandoff(t *testing.T) {
	cases := []struct {
		name     string
		be       backend.Backend
		router   bool
		channels bool
		want     bool
	}{
		{name: "a backend without channels", be: newFakeBackend(core.TierWarm), router: true},
		{name: "a backend that says no", be: &struct {
			*fakeBackend
			handoffMixin
		}{newFakeBackend(core.TierWarm), handoffMixin{false}}, router: true},
		{name: "a channel backend without a router", be: newSandboxBackend(core.TierSnapshot), channels: true},
		{name: "a channel backend with a router", be: newSandboxBackend(core.TierSnapshot), router: true, channels: true, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Runtime{be: tc.be}
			if tc.router {
				r.cfg.Handoff = handoffRouter()
			}
			if got := r.canHandoff(); got != tc.want || r.HandsOff() != tc.want {
				t.Fatalf("canHandoff = %v, HandsOff = %v, want %v", got, r.HandsOff(), tc.want)
			}
			if r.channels() != tc.channels {
				t.Fatalf("channels = %v, want %v", r.channels(), tc.channels)
			}
			if tc.want {
				return
			}
			if _, _, _, ok := r.HandoffRoute("g1/1/1"); ok {
				t.Fatal("a home without handoff routes a fiber")
			}
		})
	}
}

// recvHandoff reads one message from a handoff channel's fiber end, the
// bytes and the file descriptors passed with them.
func recvHandoff(t *testing.T, fd int) ([]byte, []int) {
	t.Helper()
	buf, oob := make([]byte, 64<<10), make([]byte, 256)
	n, oobn, _, _, err := syscall.Recvmsg(fd, buf, oob, syscall.MSG_DONTWAIT)
	if err != nil {
		t.Fatalf("recvmsg: %v", err)
	}
	var fds []int
	if oobn > 0 {
		msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range msgs {
			got, err := syscall.ParseUnixRights(&m)
			if err != nil {
				t.Fatal(err)
			}
			fds = append(fds, got...)
		}
	}
	return buf[:n], fds
}

// TestDeliver checks that a connection reaches a ready handoff fiber as one
// zero byte with the socket attached, and every other fiber or state is
// refused without blocking.
func TestDeliver(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", WBudgetBytes: 64 << 20, Policy: core.Policy{EndpointMode: core.EndpointHandoff}, CallerThumbprint: "x5t"}
	direct := core.Grant{UID: "g2", TemplateDigest: "sha256:tmpl", WBudgetBytes: 64 << 20}
	cases := []struct {
		name string
		// target picks the fiber to deliver to and may change its state.
		target  func(t *testing.T, r *Runtime, be *sandboxBackend, handoff, direct string) string
		wantErr error
		// delivered is whether the fiber's end must hold the connection.
		delivered bool
	}{
		{name: "a ready handoff fiber takes the connection", target: func(_ *testing.T, _ *Runtime, _ *sandboxBackend, h, _ string) string { return h }, delivered: true},
		{name: "a fiber nobody knows", target: func(*testing.T, *Runtime, *sandboxBackend, string, string) string { return "g1/9/9" }, wantErr: ErrNotHandoff},
		{name: "a fiber reached directly", target: func(_ *testing.T, _ *Runtime, _ *sandboxBackend, _, d string) string { return d }, wantErr: ErrNotHandoff},
		{name: "a fiber not yet ready", target: func(_ *testing.T, r *Runtime, _ *sandboxBackend, h, _ string) string {
			r.mu.Lock()
			r.fibers[h].ready = false
			r.mu.Unlock()
			return h
		}, wantErr: ErrNotHandoff},
		{name: "a fiber whose end of the channel is gone", target: func(_ *testing.T, _ *Runtime, be *sandboxBackend, h, _ string) string {
			be.closeHandoff(h)
			return h
		}, wantErr: ErrNotHandoff},
		{name: "a fiber whose host end is closed", target: func(_ *testing.T, r *Runtime, _ *sandboxBackend, h, _ string) string {
			r.mu.Lock()
			_ = r.fibers[h].channel.Close()
			r.mu.Unlock()
			return h
		}, wantErr: ErrNotHandoff},
		{name: "a fiber that is not accepting", target: func(t *testing.T, r *Runtime, _ *sandboxBackend, h, _ string) string {
			// Fill its queue, since the kernel bounds unread SEQPACKET messages.
			conn := pipeEnd(t)
			for i := 0; i < 10000; i++ {
				if err := r.Deliver(h, conn); errors.Is(err, ErrHandoffBusy) {
					return h
				} else if err != nil {
					t.Fatalf("Deliver %d = %v", i, err)
				}
			}
			t.Fatal("the fiber's queue never filled")
			return h
		}, wantErr: ErrHandoffBusy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := newSandboxBackend(core.TierSnapshot)
			r := newTestRuntime(t, be, func(c *Config) { c.Handoff, c.HandoffKey = handoffRouter(), handoffKey })
			ctx := context.Background()
			for _, gr := range []core.Grant{g, direct} {
				if err := r.PrepareTemplate(ctx, gr); err != nil {
					t.Fatal(err)
				}
			}
			h, err := r.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g1", Epoch: 1, Seq: 1}, CallerCert: callerDER})
			if err != nil {
				t.Fatal(err)
			}
			d, err := r.Clone(ctx, core.CloneSpec{Grant: direct, Fence: core.Fence{GrantUID: "g2", Epoch: 1, Seq: 1}})
			if err != nil {
				t.Fatal(err)
			}
			if _, _, _, ok := r.HandoffRoute(d.ID); ok {
				t.Fatal("a direct fiber has a handoff route")
			}
			target := tc.target(t, r, be, h.ID, d.ID)
			conn := pipeEnd(t)
			err = r.Deliver(target, conn)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Deliver = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			// The record went first, then the connection.
			ff := be.fiber(h.ID)
			msg, fds := recvHandoff(t, ff.handoff)
			if !bytes.Equal(msg, []byte{0}) || len(fds) != 1 {
				t.Fatalf("the fiber read %q with %d fds, want one zero byte with the socket", msg, len(fds))
			}
			// What arrived is the very socket, so a byte written to it is
			// read from the other end.
			if _, err := syscall.Write(fds[0], []byte("hi")); err != nil {
				t.Fatal(err)
			}
			_ = syscall.Close(fds[0])
			other := connPeer(t, conn)
			buf := make([]byte, 2)
			if n, err := other.Read(buf); err != nil || string(buf[:n]) != "hi" {
				t.Fatalf("read from the handed connection = %q %v", buf[:n], err)
			}
			// The fiber's end and its route are gone with its finish.
			if err := r.Release(ctx, h.ID, false); err != nil {
				t.Fatal(err)
			}
			if _, _, _, ok := r.HandoffRoute(h.ID); ok {
				t.Fatal("a released fiber keeps its route")
			}
			if _, ok := r.cfg.Handoff.Key(h.ID); ok {
				t.Fatal("the router keeps the released fiber's key")
			}
		})
	}
}

// pipeEnd is one end of a stream socket pair, as a caller's accepted
// connection. connPeer returns the other end of the pair made last.
var pipePeers = map[*os.File]*os.File{}

func pipeEnd(t *testing.T) *os.File {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	a, b := os.NewFile(uintptr(fds[0]), "conn"), os.NewFile(uintptr(fds[1]), "peer")
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	pipePeers[a] = b
	return a
}

func connPeer(t *testing.T, conn *os.File) *os.File {
	t.Helper()
	p, ok := pipePeers[conn]
	if !ok {
		t.Fatal("not a pipeEnd")
	}
	return p
}
