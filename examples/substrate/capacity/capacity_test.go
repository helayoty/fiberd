package capacity_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/helayoty/fiberd/examples/substrate/capacity"
	ateletpb "github.com/helayoty/fiberd/examples/substrate/proto/atelet"
)

func write(t *testing.T, dir, name, s string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func limits(kv ...string) *ateletpb.WorkerResources {
	wr := &ateletpb.WorkerResources{Actors: capacity.Actors}
	if len(kv) == 0 {
		return wr
	}
	wr.Resources = &ateletpb.Resources{}
	for i := 0; i < len(kv); i += 2 {
		wr.Resources.Limits = append(wr.Resources.Limits, &ateletpb.Limits{Name: kv[i], Quantity: kv[i+1]})
	}
	return wr
}

// TestRead checks what a worker reports for each state of its downward
// API files.
func TestRead(t *testing.T) {
	cases := []struct {
		name        string
		cpu, memory string // "" leaves the file out
		want        *ateletpb.WorkerResources
	}{
		{name: "both limits", cpu: "1000\n", memory: "1073741824\n", want: limits("cpu", "1000m", "memory", "1073741824")},
		{name: "a fractional cpu", cpu: "250", memory: "268435456", want: limits("cpu", "250m", "memory", "268435456")},
		{name: "no files: one actor, no limits", want: limits()},
		{name: "only memory", memory: "1024", want: limits("memory", "1024")},
		{name: "a cpu that is not a number", cpu: "lots", memory: "1024", want: limits("memory", "1024")},
		{name: "a zero memory is none", cpu: "500", memory: "0", want: limits("cpu", "500m")},
		{name: "a negative cpu is none", cpu: "-5", want: limits()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.cpu != "" {
				write(t, dir, capacity.CPUFile, tc.cpu)
			}
			if tc.memory != "" {
				write(t, dir, capacity.MemoryFile, tc.memory)
			}
			if got := capacity.Read(dir); !proto.Equal(got, tc.want) {
				t.Fatalf("Read = %v, want %v", got, tc.want)
			}
		})
	}
}

// pki is a CA and the Pod certificates it issues, as Substrate's
// podidentity signer does.
type pki struct {
	t   *testing.T
	ca  *x509.Certificate
	key *ecdsa.PrivateKey
	pem string
}

func newPKI(t *testing.T) *pki {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	return &pki{t: t, ca: ca, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

var oidPodIdentity = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 12, 1}

// issue returns a PEM bundle (key and certificate) for a Pod with the
// SPIFFE id on the node. An empty node leaves the PodIdentity out.
func (p *pki) issue(spiffe, node string, eku x509.ExtKeyUsage) string {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		p.t.Fatal(err)
	}
	u, _ := url.Parse(spiffe)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}, URIs: []*url.URL{u}}
	if node != "" {
		v, _ := json.Marshal(map[string]string{"Namespace": "ns", "ServiceAccountName": "sa", "ServiceAccountUID": "sau",
			"PodName": "p", "PodUID": "pu", "NodeName": node, "NodeUID": node + "-uid"})
		tmpl.ExtraExtensions = []pkix.Extension{{Id: oidPodIdentity, Value: v}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.key)
	if err != nil {
		p.t.Fatal(err)
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		p.t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}))
}

// shortDir is a temp dir short enough for a unix socket path.
func shortDir(t *testing.T) string {
	d, err := os.MkdirTemp("", "cap")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// atelet is a fake AteomSupport server that fails the first `refuse`
// calls, as atelet does before the Worker record exists.
type atelet struct {
	ateletpb.UnimplementedAteomSupportServer
	mu     sync.Mutex
	refuse int
	calls  int
	got    *ateletpb.WorkerResources
}

func (a *atelet) SetWorkerCapacity(_ context.Context, req *ateletpb.SetWorkerCapacityRequest) (*ateletpb.SetWorkerCapacityResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	if a.calls <= a.refuse {
		return nil, status.Error(codes.NotFound, "worker not found")
	}
	a.got = req.GetCapacity()
	return &ateletpb.SetWorkerCapacityResponse{}, nil
}

func (a *atelet) result() (int, *ateletpb.WorkerResources) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls, a.got
}

// serve runs a on a unix socket in dir, with TLS when serverBundle is set.
func serve(t *testing.T, dir string, a *atelet, serverBundle, clientCA string) string {
	t.Helper()
	var opts []grpc.ServerOption
	if serverBundle != "" {
		cert, err := tls.X509KeyPair([]byte(serverBundle), []byte(serverBundle))
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM([]byte(clientCA))
		opts = append(opts, grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13,
			Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool})))
	}
	sock := filepath.Join(dir, "ateom-support.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(opts...)
	ateletpb.RegisterAteomSupportServer(gs, a)
	go func() { _ = gs.Serve(l) }()
	t.Cleanup(gs.Stop)
	return sock
}

// TestReport checks that the report reaches atelet on this node and no
// one else, and that it outlasts atelet's refusals.
func TestReport(t *testing.T) {
	ca, other := newPKI(t), newPKI(t)
	worker := ca.issue("spiffe://cluster.local/ns/team/sa/worker", "n1", x509.ExtKeyUsageClientAuth)
	want := limits("cpu", "1000m", "memory", "1073741824")
	cases := []struct {
		name   string
		plain  bool   // no TLS on either side
		server string // atelet's bundle
		refuse int
		err    string // "" means accepted
	}{
		{name: "plaintext (tests)", plain: true},
		{name: "atelet on this node", server: ca.issue(capacity.AteletID, "n1", x509.ExtKeyUsageServerAuth)},
		{name: "retries until the Worker record exists", server: ca.issue(capacity.AteletID, "n1", x509.ExtKeyUsageServerAuth), refuse: 2},
		{name: "atelet on another node", server: ca.issue(capacity.AteletID, "n2", x509.ExtKeyUsageServerAuth),
			err: "atelet is on node n2"},
		{name: "a peer that is not atelet", server: ca.issue("spiffe://cluster.local/ns/ate-system/sa/other", "n1", x509.ExtKeyUsageServerAuth),
			err: "the peer is not " + capacity.AteletID},
		{name: "atelet with no node", server: ca.issue(capacity.AteletID, "", x509.ExtKeyUsageServerAuth),
			err: "no PodIdentity with a node"},
		{name: "a certificate from another CA", server: other.issue(capacity.AteletID, "n1", x509.ExtKeyUsageServerAuth),
			err: "certificate signed by unknown authority"},
		{name: "a certificate not for serving", server: ca.issue(capacity.AteletID, "n1", x509.ExtKeyUsageClientAuth),
			err: "incompatible key usage"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := shortDir(t)
			limitsDir := t.TempDir()
			write(t, limitsDir, capacity.CPUFile, "1000")
			write(t, limitsDir, capacity.MemoryFile, "1073741824")
			cfg := capacity.Config{Dir: limitsDir, Backoff: time.Millisecond}
			a := &atelet{refuse: tc.refuse}
			if tc.plain {
				cfg.Socket = serve(t, dir, a, "", "")
			} else {
				cfg.Socket = serve(t, dir, a, tc.server, ca.pem)
				cfg.CredentialBundle = write(t, dir, "cred.pem", worker)
				cfg.TrustBundle = write(t, dir, "trust.pem", ca.pem)
			}
			r, err := capacity.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			// A refused handshake is retried until the context ends.
			timeout := 5 * time.Second
			if tc.err != "" {
				timeout = 200 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			err = r.Run(ctx)
			calls, got := a.result()
			if tc.err == "" {
				if err != nil || !proto.Equal(got, want) || calls != tc.refuse+1 {
					t.Fatalf("Run = %v, atelet got %v after %d calls, want %v after %d", err, got, calls, want, tc.refuse+1)
				}
				return
			}
			if err == nil || got != nil {
				t.Fatalf("Run = %v, atelet got %v, want a refused handshake", err, got)
			}
			// The handshake error is logged per attempt, then Run ends with ctx.
			if _, herr := handshake(cfg); herr == nil || !strings.Contains(herr.Error(), tc.err) {
				t.Fatalf("handshake = %v, want an error with %q", herr, tc.err)
			}
		})
	}
}

// handshake makes one report and returns its error, so a test sees why
// atelet was refused.
func handshake(cfg capacity.Config) (*ateletpb.SetWorkerCapacityResponse, error) {
	r, err := capacity.New(cfg)
	if err != nil {
		return nil, err
	}
	return r.Once(context.Background())
}

// TestNew checks the TLS material a worker refuses to start with.
func TestNew(t *testing.T) {
	ca := newPKI(t)
	dir := t.TempDir()
	good := write(t, dir, "good.pem", ca.issue("spiffe://cluster.local/ns/team/sa/worker", "n1", x509.ExtKeyUsageClientAuth))
	noNode := write(t, dir, "nonode.pem", ca.issue("spiffe://cluster.local/ns/team/sa/worker", "", x509.ExtKeyUsageClientAuth))
	trust := write(t, dir, "trust.pem", ca.pem)
	junk := write(t, dir, "junk.pem", "not pem")
	cases := []struct {
		name, cred, trust, err string
	}{
		{name: "no TLS at all is plaintext", cred: "", trust: ""},
		{name: "a bundle and a trust bundle", cred: good, trust: trust},
		{name: "a bundle without a trust bundle", cred: good, err: "both the credential bundle and the trust bundle"},
		{name: "a trust bundle without a bundle", trust: trust, err: "both the credential bundle and the trust bundle"},
		{name: "a bundle that cannot be read", cred: "/nonexistent/cred.pem", trust: trust, err: "credential bundle"},
		{name: "a bundle that is not a key pair", cred: junk, trust: trust, err: "credential bundle " + junk},
		{name: "a Pod certificate with no node", cred: noNode, trust: trust, err: "no PodIdentity with a node"},
		{name: "a trust bundle that cannot be read", cred: good, trust: "/nonexistent/trust.pem", err: "trust bundle"},
		{name: "a trust bundle with no certificates", cred: good, trust: junk, err: "holds no certificates"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := capacity.New(capacity.Config{CredentialBundle: tc.cred, TrustBundle: tc.trust})
			if tc.err == "" {
				if err != nil {
					t.Fatalf("New = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("New = %v, want an error with %q", err, tc.err)
			}
		})
	}
}

// TestRunEndsWithItsContext checks that a worker whose atelet never
// answers stops reporting when it stops.
func TestRunEndsWithItsContext(t *testing.T) {
	cases := []struct {
		name string
		wait time.Duration
	}{
		{name: "already cancelled", wait: 0},
		{name: "cancelled while retrying", wait: 50 * time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := capacity.New(capacity.Config{Socket: filepath.Join(shortDir(t), "none.sock"), Dir: t.TempDir(), Backoff: time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			if tc.wait == 0 {
				cancel()
			} else {
				time.AfterFunc(tc.wait, cancel)
			}
			if err := r.Run(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("Run = %v, want context.Canceled", err)
			}
		})
	}
}
