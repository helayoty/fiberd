package consumer_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/helayoty/fiberd/pkg/consumer"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/handoff"
	"github.com/helayoty/fiberd/pkg/rpc"
	"github.com/helayoty/fiberd/pkg/runtime/stub"
	"github.com/helayoty/fiberd/pkg/tlsconf"
	"github.com/helayoty/fiberd/pkg/tlsconf/tlsconftest"
)

type home struct {
	agent  *core.Agent
	health *core.SourceHealth
	client *consumer.Client
}

func newHome(t *testing.T, tier core.Tier) *home {
	t.Helper()
	health := core.NewSourceHealth(10*time.Second, time.Now())
	ag := &core.Agent{
		NodeID: "node-a", Ledger: core.NewLedger(1), Budget: core.NewBudget(1000, 256<<20),
		Runtime: stub.NewWithTier(tier), Verify: grant.InsecureJSONVerifier{},
		Health: health, StatusInterval: 20 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go ag.Run(ctx)
	lis := bufconn.Listen(1 << 20)
	gs := rpc.NewGRPCServer(&rpc.Server{Agent: ag, Issuer: "https://issuer.test", RetryAfter: 2 * time.Second})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	c := consumer.New(conn)
	t.Cleanup(func() { _ = c.Close() })
	return &home{agent: ag, health: health, client: c}
}

func jsonGrant(t *testing.T, g core.Grant) string {
	t.Helper()
	b, err := protojson.Marshal(grant.ToProto(g))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// One session runs its whole life in order. It creates, attaches to the
// same fiber, parks, resumes under the next fence and releases. A second
// release finds nothing.
func TestCloneAttachParkResume(t *testing.T) {
	h := newHome(t, core.TierCheckpoint)
	ctx := context.Background()
	g := jsonGrant(t, core.Grant{UID: "g1", Audience: "node-a", Tenant: "acme", FiberMax: 2})

	var first, last consumer.Fiber // the session's first and latest clone
	clone := func() (*consumer.Fiber, error) {
		f, err := h.client.Clone(ctx, g, "S", time.Second, nil)
		return &f, err
	}
	park := func() (*consumer.Fiber, error) { return nil, h.client.Park(ctx, first.ID, true) }
	release := func(discard bool) func() (*consumer.Fiber, error) {
		return func() (*consumer.Fiber, error) { return nil, h.client.Release(ctx, last.ID, discard) }
	}
	steps := []struct {
		name         string
		op           func() (*consumer.Fiber, error) // nil fiber means not a clone
		wantKind     consumer.Kind
		wantSeq      uint64
		sameFiber    bool // the clone serves the first clone's fiber
		wantNotFound bool
	}{
		{name: "the first clone of a session creates under fence 1", op: clone, wantKind: consumer.Create, wantSeq: 1},
		{name: "a second clone attaches to the same fiber", op: clone, wantKind: consumer.Attach, wantSeq: 1, sameFiber: true},
		{name: "the fiber parks", op: park},
		{name: "the parked session resumes under fence 2", op: clone, wantKind: consumer.Resume, wantSeq: 2},
		{name: "the resumed fiber releases", op: release(true)},
		{name: "releasing it twice is NotFound", op: release(false), wantNotFound: true},
	}
	for _, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			f, err := st.op()
			if st.wantNotFound {
				if !consumer.NotFound(err) {
					t.Fatalf("err = %v, want NotFound", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if f == nil {
				return
			}
			if f.Kind != st.wantKind || f.Endpoint == "" || f.Fence.Seq != st.wantSeq {
				t.Fatalf("clone = %+v, want kind %v at fence seq %d with an endpoint", f, st.wantKind, st.wantSeq)
			}
			if st.sameFiber && f.ID != first.ID {
				t.Fatalf("clone = %+v, want fiber %s", f, first.ID)
			}
			if first.ID == "" {
				first = *f
			}
			last = *f
		})
	}
}

// Misses come back as typed errors. A healthy lane gives *Deferred, the
// ordinary path. A dead lane gives *Shed with retry_after. A tier gap is
// not a miss. It is a *TierGap.
func TestMissesAreTyped(t *testing.T) {
	cases := []struct {
		name     string
		tier     core.Tier // the home's
		minTier  core.Tier // the grant's
		full     bool      // a first clone has taken the grant's only fiber
		laneDown bool
		want     func(error) bool
	}{
		{name: "a full grant with the lane healthy is *Deferred from the issuer", tier: core.TierCheckpoint, full: true,
			want: func(err error) bool {
				var def *consumer.Deferred
				return errors.As(err, &def) && def.Issuer == "https://issuer.test"
			}},
		{name: "a full grant with the lane down is *Shed with retry 2s", tier: core.TierCheckpoint, full: true, laneDown: true,
			want: func(err error) bool {
				var shed *consumer.Shed
				return errors.As(err, &shed) && shed.RetryAfter == 2*time.Second
			}},
		{name: "min_tier above the home is *TierGap, not a miss", tier: core.TierWarm, minTier: core.TierCheckpoint,
			want: func(err error) bool {
				var gap *consumer.TierGap
				return errors.As(err, &gap)
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHome(t, tc.tier)
			ctx := context.Background()
			g := jsonGrant(t, core.Grant{UID: "g2", Audience: "node-a", FiberMax: 1, MinTier: tc.minTier})
			if tc.full {
				if _, err := h.client.Clone(ctx, g, "", time.Second, nil); err != nil {
					t.Fatal(err)
				}
			}
			if tc.laneDown {
				h.health.MarkSync(time.Now().Add(-time.Hour))
			}
			_, err := h.client.Clone(ctx, g, "", time.Second, nil)
			if !tc.want(err) {
				t.Fatalf("clone = %v (%T)", err, err)
			}
		})
	}
}

// Watch streams per-grant status to the callback until it reports what
// the home is running.
func TestWatchStreamsStatus(t *testing.T) {
	cases := []struct {
		name        string
		clones      int
		wantRunning uint32
	}{
		{name: "one clone is reported running", clones: 1, wantRunning: 1},
		{name: "two clones of the grant are both reported", clones: 2, wantRunning: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHome(t, core.TierCheckpoint)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			g := jsonGrant(t, core.Grant{UID: "g4", Audience: "node-a", Tenant: "acme", FiberMax: 2})
			for i := 0; i < tc.clones; i++ {
				if _, err := h.client.Clone(ctx, g, "", time.Second, nil); err != nil {
					t.Fatal(err)
				}
			}
			seen := make(chan consumer.Status, 8)
			go func() { _ = h.client.Watch(ctx, func(s consumer.Status) { seen <- s }) }()
			deadline := time.After(3 * time.Second)
			for {
				select {
				case s := <-seen:
					if s.GrantUID == "g4" && s.Running == tc.wantRunning {
						return
					}
				case <-deadline:
					t.Fatalf("no status for g4 with running=%d", tc.wantRunning)
				}
			}
		})
	}
}

// selfSigned is a caller's client certificate and its x5t#S256.
func selfSigned(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	p := tlsconftest.SelfSigned(t, &x509.Certificate{})
	return p.TLS(), tlsconf.Thumbprint(p.Cert)
}

// A handoff fiber is dialed over TLS with its routing key as SNI. The
// caller presents the grant's certificate and pins the fiber's key. The
// fake fiber accepts only the caller and echoes the server name it got.
func TestDialHandoff(t *testing.T) {
	id, err := handoff.Derive(bytes.Repeat([]byte{7}, 32), "g1")
	if err != nil {
		t.Fatal(err)
	}
	other, err := handoff.Derive(bytes.Repeat([]byte{8}, 32), "g1")
	if err != nil {
		t.Fatal(err)
	}
	caller, callerX5t := selfSigned(t)
	stranger, _ := selfSigned(t)
	pair, err := tls.X509KeyPair(id.CertPEM, id.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			if tlsconf.Thumbprint(leaf) != callerX5t {
				return errors.New("not the grant's caller")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				tc := c.(*tls.Conn)
				line, err := bufio.NewReader(tc).ReadString('\n')
				if err == nil {
					_, _ = fmt.Fprintf(tc, "%s %s", tc.ConnectionState().ServerName, line)
				}
			}()
		}
	}()
	routed := consumer.Fiber{ID: "g1/1/1", Endpoint: "tcp://" + l.Addr().String(), RoutingKey: "k", ServerKeySHA256: id.KeySHA256}

	cases := []struct {
		name  string
		fiber func() consumer.Fiber
		cert  tls.Certificate
		want  string
		// wantErr is the expected error. Unset with want empty, any error passes.
		wantErr error
	}{
		{name: "routed by key, caller accepted, key pinned", fiber: func() consumer.Fiber { return routed }, cert: caller, want: "k.fiberd hi\n"},
		{
			name:    "a direct fiber has no route",
			fiber:   func() consumer.Fiber { f := routed; f.RoutingKey = ""; return f },
			cert:    caller,
			wantErr: consumer.ErrNotHandoff,
		},
		{
			name:    "a handoff endpoint must be tcp",
			fiber:   func() consumer.Fiber { f := routed; f.Endpoint = "unix:///tmp/x.sock"; return f },
			cert:    caller,
			wantErr: consumer.ErrNotHandoff,
		},
		{
			name:    "a fiber holding another key is refused",
			fiber:   func() consumer.Fiber { f := routed; f.ServerKeySHA256 = other.KeySHA256; return f },
			cert:    caller,
			wantErr: handoff.ErrKeyMismatch,
		},
		{name: "the fiber refuses another caller", fiber: func() consumer.Fiber { return routed }, cert: stranger},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			got, err := func() (string, error) {
				c, err := tc.fiber().DialHandoff(ctx, tc.cert)
				if err != nil {
					return "", err
				}
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				if _, err := fmt.Fprintln(c, "hi"); err != nil {
					return "", err
				}
				return bufio.NewReader(c).ReadString('\n')
			}()
			if got != tc.want {
				t.Fatalf("reply = %q (%v), want %q", got, err, tc.want)
			}
			if tc.want == "" && err == nil {
				t.Fatal("want an error")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
