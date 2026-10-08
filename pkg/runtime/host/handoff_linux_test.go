//go:build linux

package host

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/handoff"
)

// TestIdentityMessage checks that the one message a fresh handoff fiber reads
// before any connection is the tag, then the key, the certificate and
// the caller, each ended by a NUL, as libfiberzygote parses it. A field
// that is empty or holds a NUL cannot be framed.
func TestIdentityMessage(t *testing.T) {
	id := handoff.Identity{KeyPEM: []byte("-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----\n"), CertPEM: []byte("-----BEGIN CERTIFICATE-----\nc\n-----END CERTIFICATE-----\n")}
	cases := []struct {
		name   string
		id     handoff.Identity
		caller string
		// fields, when set, are what the message must carry in order.
		// Otherwise framing must fail.
		fields [][]byte
	}{
		{name: "key, certificate, caller", id: id, caller: "x5t", fields: [][]byte{id.KeyPEM, id.CertPEM, []byte("x5t")}},
		{name: "no caller", id: id},
		{name: "no key", id: handoff.Identity{CertPEM: id.CertPEM}, caller: "x5t"},
		{name: "no certificate", id: handoff.Identity{KeyPEM: id.KeyPEM}, caller: "x5t"},
		{name: "NUL in a field", id: id, caller: "x\x00t"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := identityMessage(tc.id, tc.caller)
			if tc.fields == nil {
				if err == nil {
					t.Fatalf("framed %q, want an error", msg)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if msg[0] != identityTag || msg[len(msg)-1] != 0 {
				t.Fatalf("message %q: want tag %q first and a NUL last", msg, identityTag)
			}
			got := bytes.Split(msg[1:len(msg)-1], []byte{0})
			if len(got) != len(tc.fields) {
				t.Fatalf("%d fields %q, want %d", len(got), got, len(tc.fields))
			}
			for i := range got {
				if !bytes.Equal(got[i], tc.fields[i]) {
					t.Fatalf("field %d = %q, want %q", i, got[i], tc.fields[i])
				}
			}
			// A connection message is a zero byte, and the two must never
			// be confused.
			if msg[0] == 0 {
				t.Fatal("identity message starts like a connection message")
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

// TestCanHandoff checks that a home hands connections to fibers only when its
// backend can take them and a router gives them out.
func TestCanHandoff(t *testing.T) {
	cases := []struct {
		name   string
		be     backend.Backend
		router bool
		want   bool
	}{
		{name: "a backend without handoff", be: newFakeBackend(core.TierWarm), router: true},
		{name: "a backend that says no", be: &struct {
			*fakeBackend
			handoffMixin
		}{newFakeBackend(core.TierWarm), handoffMixin{false}}, router: true},
		{name: "a handoff backend without a router", be: newSandboxBackend(core.TierSnapshot)},
		{name: "a handoff backend with a router", be: newSandboxBackend(core.TierSnapshot), router: true, want: true},
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
			if tc.want {
				return
			}
			if _, _, err := r.handoffPair("g1"); !errors.Is(err, ErrNoHandoff) {
				t.Fatalf("handoffPair = %v, want ErrNoHandoff", err)
			}
			if _, _, ok := r.HandoffRoute("g1/1/1"); ok {
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

// TestSendIdentity checks that the identity is one message queued on the
// host's end of a fresh channel, and nothing is sent when there is none to
// send or nowhere to send it.
func TestSendIdentity(t *testing.T) {
	cases := []struct {
		name string
		// prepare sets the runtime up. closeHost and closePeer close a
		// channel end before the send.
		caller               string
		prepared             bool
		closeHost, closePeer bool
		wantErr              string
	}{
		{name: "queued for the fiber", caller: "x5t", prepared: true},
		{name: "no identity prepared", wantErr: "no handoff identity prepared"},
		{name: "an identity without a caller cannot be framed", prepared: true, wantErr: "caller is empty"},
		{name: "a host end already closed", caller: "x5t", prepared: true, closeHost: true, wantErr: "use of closed file"},
		{name: "a fiber end already gone", caller: "x5t", prepared: true, closePeer: true, wantErr: "broken pipe"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Runtime{cfg: Config{HandoffKey: handoffKey}}
			if tc.prepared {
				if err := r.prepareIdentity("g1", tc.caller); err != nil {
					t.Fatal(err)
				}
			}
			fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			host := os.NewFile(uintptr(fds[0]), "host")
			defer func() { _ = host.Close() }()
			if tc.closeHost {
				_ = host.Close()
			}
			if tc.closePeer {
				_ = syscall.Close(fds[1])
			} else {
				defer func() { _ = syscall.Close(fds[1]) }()
			}
			err = r.sendIdentity(host, "g1")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("sendIdentity = %v, want an error mentioning %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			msg, passed := recvHandoff(t, fds[1])
			want, _ := identityMessage(r.identities["g1"].id, "x5t")
			if !bytes.Equal(msg, want) || len(passed) != 0 {
				t.Fatalf("the fiber read %q with %d fds, want the identity message alone", msg, len(passed))
			}
		})
	}
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
			_ = r.fibers[h].handoff.Close()
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
			h, err := r.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g1", Epoch: 1, Seq: 1}})
			if err != nil {
				t.Fatal(err)
			}
			d, err := r.Clone(ctx, core.CloneSpec{Grant: direct, Fence: core.Fence{GrantUID: "g2", Epoch: 1, Seq: 1}})
			if err != nil {
				t.Fatal(err)
			}
			if _, _, ok := r.HandoffRoute(d.ID); ok {
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
			// The identity went first, then the connection.
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
			if _, _, ok := r.HandoffRoute(h.ID); ok {
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
