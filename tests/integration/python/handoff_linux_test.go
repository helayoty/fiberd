//go:build linux && integration

package pythontest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
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
// with the grant's key, serves the one caller the grant is bound to,
// fails the handshake itself for any other certificate, whether or not
// the home's CA stands behind it, and never has the key as a file.
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
		// gets a TLS alert from the fiber's failed handshake instead,
		// never a plain close after one, which served false says.
		cmd, want string
		served    bool
	}{
		{name: "the bound caller is served", cert: caller.TLS(), cmd: "ping", want: "pong", served: true},
		{name: "the key is not a file", cert: caller.TLS(), cmd: "read RUN/GRANT/handoff.key", want: "-", served: true},
		{name: "no key path in the environment", cert: caller.TLS(), cmd: "getenv FIBERD_TLS_KEY", want: "-", served: true},
		{name: "another certificate under the CA fails the handshake itself", cert: other.TLS()},
		{name: "a certificate outside the CA fails the handshake itself", cert: stranger.TLS()},
	}
	for _, tt := range templates {
		t.Run(tt.name, func(t *testing.T) {
			rt, run := openHandoffProc(t, tt.template, &handoff.Router{})
			g := core.Grant{UID: "gho", TemplateDigest: "sha256:pyref", FiberMax: 4, WBudgetBytes: 64 << 20,
				CallerThumbprint: tlsconf.Thumbprint(caller.Cert), Policy: core.Policy{EndpointMode: core.EndpointHandoff}}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatalf("prepare: %v", err)
			}
			h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 20 * time.Second,
				Payload: tt.payload, CallerCert: caller.Cert.Raw})
			if err != nil {
				t.Fatalf("clone: %v", err)
			}
			t.Cleanup(func() { _ = rt.Release(ctx, h.ID, true) })
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					if !tc.served {
						if err := refusal(handOff(t, rt, h.ID, tc.cert)); !isAlert(err) {
							t.Fatalf("%s got %v, want the fiber's handshake alert", tc.name, err)
						}
						return
					}
					cmd := strings.NewReplacer("RUN", run, "GRANT", g.UID).Replace(tc.cmd)
					got, err := tryTalk(handOff(t, rt, h.ID, tc.cert), cmd)
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

// TestHandoffClient pins that a caller written with fiberd.client reaches
// a Python handoff fiber through the home's router with the fiber's
// certificate from the Clone as the handshake's one trust anchor. A
// fiber presenting any other certificate fails the handshake itself,
// before the key pin is looked at, and a pin that names another key is
// refused before a byte is sent.
func TestHandoffClient(t *testing.T) {
	requireClient(t)
	ctx := context.Background()
	ca := tlsconftest.NewCA(t, "ca")
	caller := ca.Client(t, "caller")
	dir := t.TempDir()
	certFile, keyFile := caller.Write(t, dir, "caller")
	router := &handoff.Router{}
	rt, _ := openHandoffProc(t, backends[0].template, router)
	router.Deliver = rt.(interface {
		Deliver(string, *os.File) error
	}).Deliver
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() { _ = router.Serve(l) }()
	g := core.Grant{UID: "ghc", TemplateDigest: "sha256:pyref", FiberMax: 4, WBudgetBytes: 64 << 20,
		CallerThumbprint: tlsconf.Thumbprint(caller.Cert), Policy: core.Policy{EndpointMode: core.EndpointHandoff}}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 20 * time.Second, CallerCert: caller.Cert.Raw})
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	t.Cleanup(func() { _ = rt.Release(ctx, h.ID, true) })
	key, pin, cert, ok := rt.(core.HandoffRouter).HandoffRoute(h.ID)
	if !ok {
		t.Fatalf("no handoff route for %s", h.ID)
	}
	otherKey := make([]byte, 32)
	if _, err := rand.Read(otherKey); err != nil {
		t.Fatal(err)
	}
	otherID, err := handoff.Derive(otherKey, g.UID)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		pin       string
		cert      []byte
		wantReply string
		wantError string
	}{
		{name: "the fiber's certificate and pin from the Clone are served", pin: pin, cert: cert, wantReply: "pong"},
		{name: "another certificate fails the handshake itself", pin: pin, cert: otherID.Cert, wantError: "SSLCertVerificationError"},
		{name: "a pin naming another key is refused before a byte is sent", pin: otherID.KeySHA256, cert: cert, wantError: "KeyMismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _ := json.Marshal(map[string]any{"endpoint": "tcp://" + l.Addr().String(), "routing_key": key, "server_key_sha256": tc.pin,
				"server_cert": base64.StdEncoding.EncodeToString(tc.cert), "cert": certFile, "key": keyFile})
			cmd := exec.Command(python, filepath.Join(testdata, "handoffclient.py"))
			cmd.Stdin = bytes.NewReader(cfg)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("handoffclient.py: %v\n%s%s", err, out, stderr.String())
			}
			var got struct{ Reply, Error string }
			if err := json.Unmarshal(bytes.TrimSpace(out), &got); err != nil {
				t.Fatalf("handoffclient.py printed %q: %v", out, err)
			}
			if got.Reply != tc.wantReply || got.Error != tc.wantError {
				t.Fatalf("dial_handoff = %+v, want reply %q error %q", got, tc.wantReply, tc.wantError)
			}
		})
	}
}

// openHandoffProc is openProc with router, whose Deliver the test wires
// when it serves a listener, and a home key. It also returns the run
// directory.
func openHandoffProc(t *testing.T, template string, router *handoff.Router) (core.Runtime, string) {
	t.Helper()
	name := unique("pyho")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	run := filepath.Join("/tmp", "fz-"+name)
	rt := open(t, name, host.Config{Backend: procbackend.New(procbackend.Options{}), Templates: map[string]string{"default": template},
		CgroupRoot: filepath.Join(cgRoot, name), RunDir: run, Handoff: router, HandoffKey: key})
	return rt, run
}

// handOff connects to a handoff fiber the way fiberd does, as the proc
// suite's helper of the same name. One end of a fresh socket pair goes to
// the fiber and the other comes back as the caller's TLS client
// presenting cert, pinned to the key the home advertises for the fiber.
func handOff(t *testing.T, rt core.Runtime, fiberID string, cert tls.Certificate) net.Conn {
	t.Helper()
	key, pin, _, ok := rt.(core.HandoffRouter).HandoffRoute(fiberID)
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

// tryTalk sends one line on c, returns the reply and closes c.
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
