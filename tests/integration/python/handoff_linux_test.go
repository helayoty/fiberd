//go:build linux && integration

package pythontest

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	procbackend "github.com/helayoty/fiberd/pkg/backend/proc"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/handoff"
	"github.com/helayoty/fiberd/pkg/runtime/host"
	"github.com/helayoty/fiberd/pkg/tlsconf"
	"github.com/helayoty/fiberd/pkg/tlsconf/tlsconftest"
)

// TestHandoff pins what a Python handoff fiber does with the identity
// fiberd sends down its channel, on proc, under the sync reference
// template and the async one in both of its forms. It terminates TLS
// with the grant's key, verifies the caller's certificate against the
// home's CA bundle, serves the one caller the grant is bound to and
// closes on any other before an application byte, and never has the key
// as a file.
func TestHandoff(t *testing.T) {
	ctx := context.Background()
	ca := tlsconftest.NewCA(t, "ca")
	caller := ca.Client(t, "caller")
	other := ca.Client(t, "other")
	stranger := tlsconftest.NewCA(t, "stranger").Client(t, "stranger")
	templates := []struct {
		name, template string
		payload        []byte
	}{
		{name: "sync serve", template: backends[0].template},
		{name: "async serve_async", template: python + " " + filepath.Join(testdata, "asyncref.py")},
		{name: "async connections", template: python + " " + filepath.Join(testdata, "asyncref.py"), payload: []byte(`{"mode":"connections"}`)},
	}
	cases := []struct {
		name string
		cert tls.Certificate
		// cmd is the request line and want its reply. A caller not served
		// gets no reply at all, which served false says.
		cmd, want string
		served    bool
	}{
		{name: "the bound caller is served", cert: caller.TLS(), cmd: "ping", want: "pong", served: true},
		{name: "the key is not a file", cert: caller.TLS(), cmd: "read RUN/GRANT/handoff.key", want: "-", served: true},
		{name: "no key path in the environment", cert: caller.TLS(), cmd: "getenv FIBERD_TLS_KEY", want: "-", served: true},
		{name: "another certificate under the CA is closed before a byte", cert: other.TLS(), cmd: "ping"},
		{name: "a certificate outside the CA fails the handshake", cert: stranger.TLS(), cmd: "ping"},
	}
	for _, tt := range templates {
		t.Run(tt.name, func(t *testing.T) {
			rt, run := openHandoffProc(t, tt.template, ca.CertPEM())
			g := core.Grant{UID: "gho", TemplateDigest: "sha256:pyref", FiberMax: 4, WBudgetBytes: 64 << 20,
				CallerThumbprint: tlsconf.Thumbprint(caller.Cert), Policy: core.Policy{EndpointMode: core.EndpointHandoff}}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatalf("prepare: %v", err)
			}
			h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 20 * time.Second, Payload: tt.payload})
			if err != nil {
				t.Fatalf("clone: %v", err)
			}
			t.Cleanup(func() { _ = rt.Release(ctx, h.ID, true) })
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					cmd := strings.NewReplacer("RUN", run, "GRANT", g.UID).Replace(tc.cmd)
					got, err := tryTalk(handOff(t, rt, h.ID, tc.cert), cmd)
					if !tc.served {
						if err == nil {
							t.Fatalf("%s answered %q, want the connection closed", tc.name, got)
						}
						return
					}
					if err != nil {
						t.Fatalf("%s: %v", cmd, err)
					}
					if got != tc.want {
						t.Fatalf("%s = %q, want %q", cmd, got, tc.want)
					}
				})
			}
			if _, err := os.Stat(filepath.Join(run, g.UID, "handoff.key")); err == nil {
				t.Fatalf("%s/handoff.key exists on the host", g.UID)
			}
		})
	}
}

// openHandoffProc is openProc with a router that hands connections
// through Deliver, a home key and the CA bundle the fibers verify their
// callers against. It also returns the run directory.
func openHandoffProc(t *testing.T, template string, ca []byte) (core.Runtime, string) {
	t.Helper()
	name := unique("pyho")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	run := filepath.Join("/tmp", "fz-"+name)
	rt := open(t, name, host.Config{Backend: procbackend.New(procbackend.Options{}), Templates: map[string]string{"default": template},
		CgroupRoot: filepath.Join(cgRoot, name), RunDir: run, Handoff: &handoff.Router{}, HandoffKey: key, HandoffCA: ca})
	return rt, run
}

// handOff connects to a handoff fiber the way fiberd does, as the proc
// suite's helper of the same name. One end of a fresh socket pair goes to
// the fiber and the other comes back as the caller's TLS client
// presenting cert, pinned to the key the home advertises for the fiber.
func handOff(t *testing.T, rt core.Runtime, fiberID string, cert tls.Certificate) net.Conn {
	t.Helper()
	key, pin, ok := rt.(core.HandoffRouter).HandoffRoute(fiberID)
	if !ok || pin == "" {
		t.Fatalf("no handoff route for %s", fiberID)
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	theirs := os.NewFile(uintptr(fds[1]), "handed")
	defer func() { _ = theirs.Close() }()
	if err := rt.(interface {
		Deliver(string, *os.File) error
	}).Deliver(fiberID, theirs); err != nil {
		_ = syscall.Close(fds[0])
		t.Fatalf("deliver to %s: %v", fiberID, err)
	}
	ours := os.NewFile(uintptr(fds[0]), "ours")
	defer func() { _ = ours.Close() }()
	c, err := net.FileConn(ours)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Client(c, handoff.ClientConfig(key, pin, cert))
}

// tryTalk sends one line on c, returns the reply and closes c. A refused
// caller sees the handshake fail or the connection close with no reply,
// which is the error.
func tryTalk(c net.Conn, line string) (string, error) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintln(c, line); err != nil {
		return "", err
	}
	reply, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(reply), nil
}
