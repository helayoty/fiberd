// Command sessioncheck is one session's round trip as a consumer sees
// it: mint a grant, Clone a named session, speak HTTP to the fiber over
// the endpoint Clone returned, Park it, Clone the same session again (a
// RESUME) and check the counter survived, then Release with discard.
//
// It is the Kubernetes acceptance's check that a fiber behind a Pod IP is
// reachable from another Pod, which the conformance suite (run from the
// host) cannot dial. The template must be the reference zygote in --http
// mode.
//
//	sessioncheck -target 10.244.0.9:8484 -node-id conform-gvisor-grant \
//	    -issuer-key /tmp/issuer-key.json -issuer http://grant-issuer.fiberd-system.svc:8080 \
//	    -isolation UNTRUSTED -want-scheme tcp
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/helayoty/fiberd/pkg/consumer"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/endpoint"
	"github.com/helayoty/fiberd/pkg/grant"
)

type opts struct {
	target, nodeID, issuerKey, issuerURL string
	isolation, session, wantScheme       string
	timeout                              time.Duration
}

func main() {
	var o opts
	flag.StringVar(&o.target, "target", "127.0.0.1:8484", "Fibers service (plaintext)")
	flag.StringVar(&o.nodeID, "node-id", "", "grant audience: the home's node id")
	flag.StringVar(&o.issuerKey, "issuer-key", "", "private JWK to mint the grant with")
	flag.StringVar(&o.issuerURL, "issuer", "", "issuer URL")
	flag.StringVar(&o.isolation, "isolation", "UNTRUSTED", "the grant's isolation, UNTRUSTED or TRUSTED")
	flag.StringVar(&o.session, "session", "s1", "the session name to clone, park and resume")
	flag.StringVar(&o.wantScheme, "want-scheme", "", "fail unless the endpoint has this scheme (tcp or unix)")
	flag.DurationVar(&o.timeout, "timeout", 2*time.Minute, "give up after")
	flag.Parse()
	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "sessioncheck:", err)
		os.Exit(1)
	}
}

func run(o opts) error {
	if o.issuerKey == "" || o.issuerURL == "" || o.nodeID == "" {
		return fmt.Errorf("need -issuer-key, -issuer and -node-id")
	}
	key, err := grant.LoadKey(o.issuerKey)
	if err != nil {
		return err
	}
	iso, err := core.ParseIsolation(o.isolation)
	if err != nil {
		return fmt.Errorf("-isolation: %w", err)
	}
	g := core.Grant{
		UID: fmt.Sprintf("check-%d", time.Now().Unix()), Audience: o.nodeID, TemplateDigest: "sha256:check",
		FiberMax: 2, WBudgetBytes: 32 << 20, LeaseExpiry: time.Now().Add(time.Hour),
		Policy: core.Policy{Isolation: iso},
	}
	tok, err := (&grant.Issuer{Key: key, URL: o.issuerURL}).Mint(g)
	if err != nil {
		return fmt.Errorf("mint: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	conn, err := grpc.NewClient(o.target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("dial %s: %w", o.target, err)
	}
	c := consumer.New(conn)
	defer func() { _ = c.Close() }()

	f, err := c.Clone(ctx, tok, o.session, 30*time.Second, nil)
	if err != nil {
		return fmt.Errorf("clone: %w", err)
	}
	fmt.Printf("sessioncheck: %s clone -> %s %s\n", o.session, f.ID, f.Endpoint)
	ep, err := endpoint.Parse(f.Endpoint)
	if err != nil {
		return err
	}
	if o.wantScheme != "" && ep.Scheme != o.wantScheme {
		return fmt.Errorf("endpoint %s has scheme %s, want %s", f.Endpoint, ep.Scheme, o.wantScheme)
	}
	if err := expect(ctx, f.Endpoint, http.MethodPost, "/incr", "1"); err != nil {
		return err
	}
	if err := expect(ctx, f.Endpoint, http.MethodGet, "/count", "1"); err != nil {
		return err
	}
	fmt.Printf("sessioncheck: POST /incr and GET /count over %s: counter 1\n", f.Endpoint)
	if err := c.Park(ctx, f.ID, true); err != nil {
		return fmt.Errorf("park: %w", err)
	}
	if _, err := httpDo(ctx, f.Endpoint, http.MethodGet, "/count"); err == nil {
		return fmt.Errorf("parked endpoint %s still answers", f.Endpoint)
	}
	fmt.Printf("sessioncheck: parked, %s refuses\n", f.Endpoint)
	r, err := c.Clone(ctx, tok, o.session, 60*time.Second, nil)
	if err != nil {
		return fmt.Errorf("clone after park: %w", err)
	}
	if r.Kind != consumer.Resume {
		return fmt.Errorf("clone after park is %s, want RESUME", r.Kind)
	}
	fmt.Printf("sessioncheck: resume -> %s %s\n", r.ID, r.Endpoint)
	if err := expect(ctx, r.Endpoint, http.MethodGet, "/count", "1"); err != nil {
		return fmt.Errorf("after resume: %w", err)
	}
	if err := expect(ctx, r.Endpoint, http.MethodPost, "/incr", "2"); err != nil {
		return fmt.Errorf("after resume: %w", err)
	}
	fmt.Printf("sessioncheck: state kept across park and resume: counter 2\n")
	if err := c.Release(ctx, r.ID, true); err != nil {
		return fmt.Errorf("release: %w", err)
	}
	fmt.Println("sessioncheck: ok")
	return nil
}

// expect does one request and checks the trimmed body.
func expect(ctx context.Context, ep, method, path, want string) error {
	got, err := httpDo(ctx, ep, method, path)
	if err != nil {
		return fmt.Errorf("%s %s%s: %w", method, ep, path, err)
	}
	if got != want {
		return fmt.Errorf("%s %s%s = %q, want %q", method, ep, path, got, want)
	}
	return nil
}

// httpDo sends one request to the fiber's HTTP server over its endpoint,
// unix or tcp, and returns the trimmed body.
func httpDo(ctx context.Context, ep, method, path string) (string, error) {
	tr := &http.Transport{DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (conn net.Conn, err error) { return endpoint.Dial(ctx, ep) }}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, method, "http://fiber"+path, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return strings.TrimSpace(string(body)), nil
}
