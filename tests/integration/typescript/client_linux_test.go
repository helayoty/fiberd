//go:build linux && integration

package typescripttest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/encoding/protojson"

	procbackend "github.com/helayoty/fiberd/pkg/backend/proc"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/handoff"
	"github.com/helayoty/fiberd/pkg/rpc"
	"github.com/helayoty/fiberd/pkg/runtime/host"
	"github.com/helayoty/fiberd/pkg/tlsconf"
	"github.com/helayoty/fiberd/pkg/tlsconf/tlsconftest"
	"github.com/helayoty/fiberd/tests/internal/testenv"
)

var cgRoot, zygote, sdk string

func TestMain(m *testing.M) {
	testenv.OwnMountNamespace()
	cgRoot = testenv.RequireCgroupRoot("typescript")
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	sdk = filepath.Join(testenv.RepoRoot(), "sdk", "typescript", "dist")
	check := exec.Command("node", "-e", "require(process.argv[1])", sdk)
	if out, err := check.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "typescript client unavailable: run npm ci --ignore-scripts --prefix sdk/typescript and make typescript-build before integration tests: %v\n%s", err, out)
		return 1
	}
	dir, err := os.MkdirTemp("", "fiberd-ts-build-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}()
	zygote, err = testenv.BuildZygote(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return m.Run()
}

type boundVerifier struct{ thumbprint string }

func (v boundVerifier) Verify(ctx context.Context, token []byte) (core.Grant, error) {
	g, err := grant.InsecureJSONVerifier{}.Verify(ctx, token)
	g.CallerThumbprint = v.thumbprint
	return g, err
}

func TestClient(t *testing.T) {
	for _, mode := range []string{"direct", "handoff"} {
		t.Run(mode, func(t *testing.T) {
			cfg := serveHome(t, mode == "handoff")
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			input, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(ctx, "node", "testdata/client.cjs", sdk)
			cmd.Stdin = bytes.NewReader(input)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("TypeScript %s client: %v\n%s", mode, err, out)
			}
			t.Logf("%s", out)
		})
	}
}

func serveHome(t *testing.T, routed bool) map[string]any {
	t.Helper()
	dir, err := os.MkdirTemp("/var/lib", "fiberd-ts-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	run, err := os.MkdirTemp("", "fzts")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(run) })
	cfg := host.Config{
		Backend:    procbackend.New(procbackend.Options{}),
		Templates:  map[string]string{"default": zygote + " --heap-mb 8"},
		CgroupRoot: filepath.Join(cgRoot, filepath.Base(dir)), RunDir: run,
		DeltaDir: filepath.Join(dir, "deltas"), TemplateCache: filepath.Join(dir, "templates"),
	}
	g := core.Grant{UID: "gts", Audience: "node-a", Tenant: "acme", TemplateDigest: "sha256:ref",
		FiberMax: 1, WBudgetBytes: 64 << 20, Policy: core.Policy{Isolation: core.Trusted}}
	var verify core.Verifier = grant.InsecureJSONVerifier{}
	var opts []grpc.ServerOption
	var handoffListener net.Listener
	result := map[string]any{}
	if routed {
		ca := tlsconftest.NewCA(t, "ca")
		caller := ca.Client(t, "caller")
		cert, key := caller.Write(t, dir, "caller")
		caFile, _ := ca.Write(t, dir, "ca")
		strangerCert, strangerKey := ca.Client(t, "stranger").Write(t, dir, "stranger")
		result["tls"] = map[string]string{"cert": cert, "key": key, "ca": caFile}
		result["stranger"] = map[string]string{"cert": strangerCert, "key": strangerKey}
		verify = boundVerifier{thumbprint: tlsconf.Thumbprint(caller.Cert)}
		opts = append(opts, grpc.Creds(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{ca.Server(t).TLS()},
			ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ca.Pool(),
		})))
		g.Policy.EndpointMode = core.EndpointHandoff
		cfg.HandoffKey = make([]byte, 32)
		if _, err := rand.Read(cfg.HandoffKey); err != nil {
			t.Fatal(err)
		}
		cfg.Handoff = &handoff.Router{}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		handoffListener = listener
		cfg.Handoff.Advertise = "tcp://" + listener.Addr().String()
		other, err := handoff.Derive(cfg.HandoffKey, "other-grant")
		if err != nil {
			t.Fatal(err)
		}
		result["otherCert"], result["otherPin"] = base64.StdEncoding.EncodeToString(other.Cert), other.KeySHA256
	}
	rt, err := host.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rt.Close)
	if routed {
		cfg.Handoff.Deliver = rt.Deliver
		go func() { _ = cfg.Handoff.Serve(handoffListener) }()
		t.Cleanup(func() {
			if cfg.Handoff.Stats().Routed < 2 {
				t.Error("client did not reach the handoff router before and after resume")
			}
		})
	}
	ag := &core.Core{
		NodeID: "node-a", Ledger: core.NewLedger(1), RateLimit: core.NewRateLimit(1000, 256<<20),
		Runtime: rt, Verify: verify, Health: core.NewSourceHealth(time.Minute, time.Now()), StatusInterval: 20 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go ag.Run(ctx)
	server := rpc.NewGRPCServer(&rpc.Server{Core: ag, Issuer: "https://issuer.test", RetryAfter: 2 * time.Second}, opts...)
	t.Cleanup(server.Stop)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	token, err := protojson.Marshal(grant.ToProto(g))
	if err != nil {
		t.Fatal(err)
	}
	result["target"], result["token"] = fmt.Sprintf("localhost:%d", listener.Addr().(*net.TCPAddr).Port), string(token)
	return result
}
