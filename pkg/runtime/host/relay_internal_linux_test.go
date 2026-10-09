//go:build linux

package host

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/endpoint"
)

// relayBackend is a unix-only sandbox backend whose fibers answer on
// their socket, so bytes through a relay can be checked end to end.
func relayBackend(tier core.Tier) *sandboxBackend {
	sb := newSandboxBackend(tier)
	sb.schemesMixin = schemesMixin{[]string{"unix"}}
	sb.serve = true
	return sb
}

// say sends one line to a tcp endpoint and returns the reply.
func say(t *testing.T, ep, line string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := endpoint.Dial(ctx, ep)
	if err != nil {
		return "", err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := fmt.Fprintln(c, line); err != nil {
		return "", err
	}
	reply, err := bufio.NewReader(c).ReadString('\n')
	return strings.TrimSpace(reply), err
}

// mustSay is say, failing the test on any error.
func mustSay(t *testing.T, ep, line string) string {
	t.Helper()
	reply, err := say(t, ep, line)
	if err != nil {
		t.Fatalf("%s over %s: %v", line, ep, err)
	}
	return reply
}

// refusesDial asserts nothing accepts on ep any more.
func refusesDial(t *testing.T, ep string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if c, err := endpoint.Dial(ctx, ep); err == nil {
		_ = c.Close()
		t.Fatalf("%s still accepts connections", ep)
	}
}

// heldPorts is how many ports the runtime holds.
func heldPorts(r *Runtime) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.ports)
}

// TestRelayedEndpoints checks a tcp home over a unix-only backend: the
// backend serves the unix socket, Clone returns a relayed tcp endpoint,
// bytes round-trip, and the relay ends with the fiber in every way a
// fiber ends.
func TestRelayedEndpoints(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 4, WBudgetBytes: 64 * mib}
	fence := core.Fence{GrantUID: "g1", Epoch: 1, Seq: 1}
	spec := core.CloneSpec{Grant: g, Fence: fence}
	cases := []struct {
		name string
		be   func() backend.Backend
		mod  func(*Config)
		// before runs after PrepareTemplate, before the clone, and may
		// return a cleanup.
		before  func(t *testing.T, r *Runtime) func()
		errText string
		check   func(t *testing.T, r *Runtime, be *sandboxBackend, h core.FiberHandle)
	}{
		{name: "a unix-only backend on an inet4 home: a relayed tcp endpoint, bytes round-trip, release ends it all",
			be: func() backend.Backend { return relayBackend(core.TierSnapshot) },
			check: func(t *testing.T, r *Runtime, be *sandboxBackend, h core.FiberHandle) {
				sock := filepath.Join(r.cfg.RunDir, "g1", "1-1.sock")
				if h.Endpoint != "tcp://127.0.0.1:20000" {
					t.Fatalf("endpoint = %s, want the relayed port", h.Endpoint)
				}
				if ff := be.fiber(h.ID); ff.spec.Endpoint != sock {
					t.Fatalf("the backend was told to serve on %s, want the unix socket %s", ff.spec.Endpoint, sock)
				}
				if got := mustSay(t, h.Endpoint, "ping"); got != "g1/1/1:ping" {
					t.Fatalf("ping through the relay = %q", got)
				}
				// A connection held open across the release ends with the fiber.
				ctx := context.Background()
				held, err := endpoint.Dial(ctx, h.Endpoint)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = held.Close() }()
				if _, err := fmt.Fprintln(held, "hold"); err != nil {
					t.Fatal(err)
				}
				if reply, err := bufio.NewReader(held).ReadString('\n'); err != nil || reply != "g1/1/1:hold\n" {
					t.Fatalf("held reply = %q %v", reply, err)
				}
				if err := r.Release(ctx, h.ID, false); err != nil {
					t.Fatal(err)
				}
				_ = held.SetReadDeadline(time.Now().Add(2 * time.Second))
				if n, err := held.Read(make([]byte, 1)); err == nil || n != 0 {
					t.Fatalf("the held connection outlived the fiber: read %d %v", n, err)
				}
				refusesDial(t, h.Endpoint)
				if exists(sock) || heldPorts(r) != 0 {
					t.Fatalf("socket exists %v, %d ports held; want neither", exists(sock), heldPorts(r))
				}
			}},
		{name: "an inet6 home relays on the IPv6 loopback",
			be: func() backend.Backend { return relayBackend(core.TierSnapshot) },
			mod: func(c *Config) {
				c.Endpoints = endpoint.Policy{Family: endpoint.Inet6, Host: "::1", PortMin: 20000, PortMax: 20001}
			},
			before: func(t *testing.T, _ *Runtime) func() {
				l, err := net.Listen("tcp6", "[::1]:0")
				if err != nil {
					t.Skipf("no IPv6 loopback: %v", err)
				}
				_ = l.Close()
				return nil
			},
			check: func(t *testing.T, _ *Runtime, _ *sandboxBackend, h core.FiberHandle) {
				if h.Endpoint != "tcp://[::1]:20000" {
					t.Fatalf("endpoint = %s", h.Endpoint)
				}
				if got := mustSay(t, h.Endpoint, "ping"); got != "g1/1/1:ping" {
					t.Fatalf("ping through the relay = %q", got)
				}
			}},
		{name: "a clone the backend refuses closes the relay and frees the port",
			be: func() backend.Backend {
				sb := relayBackend(core.TierSnapshot)
				sb.cloneErr = errors.New("fake: restore failed")
				return sb
			}, errText: "restore failed",
			check: func(t *testing.T, r *Runtime, _ *sandboxBackend, _ core.FiberHandle) {
				refusesDial(t, "tcp://127.0.0.1:20000")
				if heldPorts(r) != 0 || r.root.Child("g1").Child("f-1-1").Exists() {
					t.Fatalf("%d ports held, leaf exists %v", heldPorts(r), r.root.Child("g1").Child("f-1-1").Exists())
				}
			}},
		{name: "a port the agent cannot bind fails the clone and leaves nothing; freed, the next clone takes it",
			be: func() backend.Backend { return relayBackend(core.TierSnapshot) },
			before: func(t *testing.T, _ *Runtime) func() {
				l, err := net.Listen("tcp4", "127.0.0.1:20000")
				if err != nil {
					t.Skipf("port 20000 busy: %v", err)
				}
				return func() { _ = l.Close() }
			}, errText: "relay for",
			check: func(t *testing.T, r *Runtime, be *sandboxBackend, _ core.FiberHandle) {
				if heldPorts(r) != 0 || r.root.Child("g1").Child("f-1-1").Exists() || be.fiber("g1/1/1") != nil {
					t.Fatal("the refused clone left a port, a leaf or a backend fiber")
				}
			}},
		{name: "the warm instance's end closes the relay",
			be: func() backend.Backend { return relayBackend(core.TierSnapshot) },
			check: func(t *testing.T, r *Runtime, be *sandboxBackend, h core.FiberHandle) {
				mustSay(t, h.Endpoint, "ping")
				be.warmGone("g1")
				if e := waitExit(t, r); e.FiberID != h.ID {
					t.Fatalf("exit = %+v", e)
				}
				refusesDial(t, h.Endpoint)
			}},
		{name: "a fiber that dies closes its relay",
			be: func() backend.Backend { return relayBackend(core.TierSnapshot) },
			check: func(t *testing.T, r *Runtime, be *sandboxBackend, h core.FiberHandle) {
				be.die(h.ID, "exit:3")
				if e := waitExit(t, r); e.FiberID != h.ID || e.Reason != "exit" {
					t.Fatalf("exit = %+v", e)
				}
				refusesDial(t, h.Endpoint)
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mod := func(c *Config) { c.Endpoints = tcpPolicy }
			if tc.mod != nil {
				mod = tc.mod
			}
			be := tc.be()
			r := newTestRuntime(t, be, mod)
			if !r.Relays() {
				t.Fatal("the home does not relay")
			}
			ctx := context.Background()
			if err := r.PrepareTemplate(ctx, g); err != nil {
				t.Fatalf("PrepareTemplate: %v", err)
			}
			if tc.before != nil {
				if cleanup := tc.before(t, r); cleanup != nil {
					defer cleanup()
				}
			}
			h, err := r.Clone(ctx, spec)
			switch {
			case tc.errText != "" && (err == nil || !strings.Contains(err.Error(), tc.errText)):
				t.Fatalf("Clone = %+v, %v, want an error mentioning %q", h, err, tc.errText)
			case tc.errText == "" && err != nil:
				t.Fatalf("Clone: %v", err)
			}
			tc.check(t, r, be.(*sandboxBackend), h)
		})
	}
}

// TestRelayedResume checks park and resume of a relayed fiber: the
// manifest names the socket, the relay ends with the park, and the
// resumed fiber gets a relay on its parked port, or any free one when
// that is held.
func TestRelayedResume(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 4, WBudgetBytes: 64 * mib}
	next := core.Fence{GrantUID: "g1", Epoch: 2, Seq: 1}
	// byHand writes a delta directory with the given manifest.
	byHand := func(t *testing.T, f *parkFixture, m manifest) string {
		t.Helper()
		dir := filepath.Join(f.r.cfg.DeltaDir, "g1", "by-hand")
		write(t, dir, map[string]string{"pages-1.img": "pages"})
		if err := writeJSON(filepath.Join(dir, "manifest.json"), m); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	parkFirst := func(t *testing.T, f *parkFixture) string {
		t.Helper()
		ref, err := f.r.Park(context.Background(), f.h.ID, false)
		if err != nil {
			t.Fatalf("Park: %v", err)
		}
		return ref
	}
	cases := []struct {
		name    string
		be      func() backend.Backend
		ref     func(t *testing.T, f *parkFixture) string
		errText string
		check   func(t *testing.T, f *parkFixture, ref string, h core.FiberHandle)
	}{
		{name: "park ends the relay and names the socket; resume relays the parked port to the socket bound again",
			be: func() backend.Backend { return relayBackend(core.TierSnapshot) }, ref: parkFirst,
			check: func(t *testing.T, f *parkFixture, ref string, h core.FiberHandle) {
				sock := filepath.Join(f.r.cfg.RunDir, "g1", "1-1.sock")
				m := readManifest(t, ref)
				if m.Endpoint != "tcp://127.0.0.1:20000" || m.Relay != sock {
					t.Fatalf("manifest = %+v, want the tcp endpoint and the relay socket %s", m, sock)
				}
				if h.ID != "g1/2/1" || h.Endpoint != "tcp://127.0.0.1:20000" {
					t.Fatalf("resumed handle = %+v, want the parked port", h)
				}
				sb := f.be.(*sandboxBackend)
				if ff := sb.fiber("g1/2/1"); ff.resume == nil || ff.resume.Endpoint != sock {
					t.Fatalf("the backend was told to resume on %+v, want the socket %s", ff.resume, sock)
				}
				if got := mustSay(t, h.Endpoint, "ping"); got != "g1/2/1:ping" {
					t.Fatalf("ping after resume = %q", got)
				}
				// The new fence is published beside the socket, the one
				// path the fiber knows, as for a unix endpoint.
				fenceFn := sock + ".fence"
				if b, err := os.ReadFile(fenceFn); err != nil || string(b) != "g1/2/1\n" {
					t.Fatalf("fence file = %q %v", b, err)
				}
				f.r.mu.Lock()
				holder := f.r.ports[20000]
				f.r.mu.Unlock()
				if holder != "g1/2/1" {
					t.Fatalf("port 20000 held by %q", holder)
				}
				if err := f.r.Release(context.Background(), h.ID, true); err != nil {
					t.Fatal(err)
				}
				refusesDial(t, h.Endpoint)
				if exists(fenceFn) || heldPorts(f.r) != 0 {
					t.Fatalf("fence file exists %v, %d ports held", exists(fenceFn), heldPorts(f.r))
				}
			}},
		{name: "a parked port another fiber holds: the resume takes a free one",
			be: func() backend.Backend { return relayBackend(core.TierSnapshot) },
			ref: func(t *testing.T, f *parkFixture) string {
				// The fixture's fiber runs on 20000. This delta was parked
				// on 20000 elsewhere.
				return byHand(t, f, manifest{Fence: "g1/1/9", Backend: "fake", Endpoint: "tcp://10.0.0.9:20000",
					Relay: "/elsewhere/run/g1/1-9.sock"})
			},
			check: func(t *testing.T, f *parkFixture, _ string, h core.FiberHandle) {
				if h.Endpoint != "tcp://127.0.0.1:20001" {
					t.Fatalf("resumed on %s, want the free port on this home's address", h.Endpoint)
				}
				sock := filepath.Join(f.r.cfg.RunDir, "g1", "1-9.sock")
				if ff := f.be.(*sandboxBackend).fiber("g1/2/1"); ff.resume.Endpoint != sock {
					t.Fatalf("the backend was told to resume on %s, want %s", ff.resume.Endpoint, sock)
				}
				if got := mustSay(t, h.Endpoint, "ping"); got != "g1/2/1:ping" {
					t.Fatalf("ping = %q", got)
				}
				if got := mustSay(t, f.h.Endpoint, "ping"); got != "g1/1/1:ping" {
					t.Fatalf("the first fiber's ping = %q", got)
				}
			}},
		{name: "a relayed delta on a home whose backend binds tcp itself",
			be: func() backend.Backend { return newSandboxBackend(core.TierSnapshot) },
			ref: func(t *testing.T, f *parkFixture) string {
				return byHand(t, f, manifest{Fence: "g1/1/9", Backend: "fake", Endpoint: "tcp://127.0.0.1:20001", Relay: "/x/1-9.sock"})
			}, errText: "parked behind a relay",
			check: func(t *testing.T, f *parkFixture, _ string, _ core.FiberHandle) {
				if f.r.root.Child("g1").Child("f-2-1").Exists() || heldPorts(f.r) != 1 {
					t.Fatal("the refused resume left its leaf or a port")
				}
			}},
		{name: "a delta that bound tcp itself on a relaying home",
			be: func() backend.Backend { return relayBackend(core.TierSnapshot) },
			ref: func(t *testing.T, f *parkFixture) string {
				return byHand(t, f, manifest{Fence: "g1/1/9", Backend: "fake", Endpoint: "tcp://127.0.0.1:20001"})
			}, errText: "needs a relay",
			check: func(t *testing.T, f *parkFixture, _ string, _ core.FiberHandle) {
				if f.r.root.Child("g1").Child("f-2-1").Exists() || heldPorts(f.r) != 1 {
					t.Fatal("the refused resume left its leaf or a port")
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newParkFixture(t, tc.be(), g, func(c *Config) { c.Endpoints = tcpPolicy })
			ref := tc.ref(t, f)
			h, err := f.r.Clone(context.Background(), core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: next})
			switch {
			case tc.errText != "" && (err == nil || !strings.Contains(err.Error(), tc.errText)):
				t.Fatalf("resume = %+v, %v, want an error mentioning %q", h, err, tc.errText)
			case tc.errText == "" && err != nil:
				t.Fatalf("resume: %v", err)
			}
			tc.check(t, f, ref, h)
		})
	}
}

// TestRelayedParkRefusesCallers checks that after a park the relayed
// endpoint refuses connections, as a parked proc listener does, and
// that a park the backend refuses leaves the relay serving.
func TestRelayedParkRefusesCallers(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 4, WBudgetBytes: 64 * mib}
	cases := []struct {
		name    string
		parkErr error
		// serving is whether the endpoint still answers after the park.
		serving bool
	}{
		{name: "a park ends the relay"},
		{name: "a park the backend refuses leaves the relay serving", parkErr: errors.New("fake: dump failed"), serving: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sb := relayBackend(core.TierSnapshot)
			sb.parkErr = tc.parkErr
			f := newParkFixture(t, sb, g, func(c *Config) { c.Endpoints = tcpPolicy })
			if got := mustSay(t, f.h.Endpoint, "ping"); got != "g1/1/1:ping" {
				t.Fatalf("ping = %q", got)
			}
			_, err := f.r.Park(context.Background(), f.h.ID, false)
			if (err != nil) != (tc.parkErr != nil) {
				t.Fatalf("Park = %v, want error %v", err, tc.parkErr)
			}
			if tc.serving {
				if got := mustSay(t, f.h.Endpoint, "ping"); got != "g1/1/1:ping" {
					t.Fatalf("ping after a refused park = %q", got)
				}
				return
			}
			refusesDial(t, f.h.Endpoint)
			f.r.mu.Lock()
			holder := f.r.ports[20000]
			f.r.mu.Unlock()
			if holder != f.h.ID {
				t.Fatalf("after the park port 20000 is held by %q, want the parked fiber", holder)
			}
		})
	}
}

// TestRelayClose checks that closing the runtime ends every relay, since
// the backend's Close ends the fibers without reporting their exits.
func TestRelayClose(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 4, WBudgetBytes: 64 * mib}
	cases := []struct {
		name   string
		fibers int
	}{
		{name: "one relayed fiber", fibers: 1},
		{name: "every relayed fiber", fibers: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRuntime(t, relayBackend(core.TierSnapshot), func(c *Config) { c.Endpoints = tcpPolicy })
			ctx := context.Background()
			if err := r.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			var eps []string
			for i := 1; i <= tc.fibers; i++ {
				h, err := r.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g1", Epoch: 1, Seq: uint64(i)}})
				if err != nil {
					t.Fatal(err)
				}
				mustSay(t, h.Endpoint, "ping")
				eps = append(eps, h.Endpoint)
			}
			r.Close()
			for _, ep := range eps {
				refusesDial(t, ep)
			}
		})
	}
}

// TestReleaseKeepsPortUntilExit checks that a release, discarding or
// not, gives a running fiber's port back only once the fiber has ended
// and its relay closed, so a clone meanwhile cannot be handed a port the
// relay still binds.
func TestReleaseKeepsPortUntilExit(t *testing.T) {
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 4, WBudgetBytes: 64 * mib}
	cases := []struct {
		name    string
		discard bool
	}{
		{name: "a discarding release", discard: true},
		{name: "a release"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sb := relayBackend(core.TierSnapshot)
			f := newParkFixture(t, sb, g, func(c *Config) { c.Endpoints = tcpPolicy })
			// The fiber ignores the kill for a while.
			sb.mu.Lock()
			sb.noExit = true
			sb.mu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			if err := f.r.Release(ctx, f.h.ID, tc.discard); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Release = %v, want the wait for the exit to time out", err)
			}
			f.r.mu.Lock()
			holder := f.r.ports[20000]
			f.r.mu.Unlock()
			if holder != f.h.ID {
				t.Fatalf("port 20000 held by %q while the fiber's relay still binds it, want %s", holder, f.h.ID)
			}
			if got := mustSay(t, f.h.Endpoint, "ping"); got != "g1/1/1:ping" {
				t.Fatalf("ping = %q", got)
			}
			// Its end frees the port with the relay.
			sb.die(f.h.ID, "signal:SIGKILL")
			waitFor(t, "the port to be freed", func() bool { return heldPorts(f.r) == 0 })
			refusesDial(t, f.h.Endpoint)
		})
	}
}
