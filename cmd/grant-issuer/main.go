// Command grant-issuer is the reference issuer: it holds one signing key,
// mints CapacityGrant JWTs, and serves the OIDC discovery document and JWKS
// that homes verify against.
//
//	grant-issuer keygen -alg EdDSA -out key.json
//	grant-issuer mint   -key key.json -issuer http://issuer:8686 -aud node-a \
//	                    -tenant team-a -template sha256:... -max 8 -warm 2 -w-budget 64Mi \
//	                    -min-tier FIBER_WARM -isolation TRUSTED -ttl 10m > grant.jwt
//	grant-issuer serve  -key key.json -addr :8686 [-issuer http://issuer:8686]
//
// An integration runs the same issuer inside its control plane; the
// Kubernetes example's grant-controller is one (examples/kubernetes).
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/helayoty/fiberd/internal/cli"
	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/tlsconf"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches a subcommand. It returns exit code 0 on success or -h,
// 2 for a usage error, and 1 when the subcommand fails.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return cli.Run(args, "usage: grant-issuer keygen|mint|serve [flags]; -h on a subcommand for its flags", map[string]cli.Command{
		"keygen": func(a []string) error { return keygen(a, stdout, stderr) },
		"mint":   func(a []string) error { return mint(a, stdout, stderr) },
		"serve":  func(a []string) error { return serve(ctx, a, stderr) },
	}, stderr)
}

func keygen(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	alg := fs.String("alg", "EdDSA", "signature algorithm, EdDSA or ES256. A256GCM writes a delta seal key (-delta-seal-key) instead")
	out := fs.String("out", "key.json", "where to write the private JWK (mode 0600)")
	if err := cli.ParseFlags(fs, args, stderr); err != nil {
		return err
	}
	var key *jose.JSONWebKey
	var err error
	if *alg == "A256GCM" {
		key, err = artifact.GenerateSealKey()
	} else {
		key, err = grant.GenerateKey(jose.SignatureAlgorithm(*alg))
	}
	if err != nil {
		return err
	}
	if err := grant.SaveKey(*out, key); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "wrote %s kid=%s alg=%s\n", *out, key.KeyID, key.Algorithm)
	return nil
}

func mint(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("mint", flag.ContinueOnError)
	keyPath := fs.String("key", "key.json", "private JWK from keygen")
	issuer := fs.String("issuer", "", "issuer URL (iss; where serve publishes the keys)")
	aud := fs.String("aud", "", "audience: the home's node id")
	uid := fs.String("uid", "", "grant uid (default: random)")
	template := fs.String("template", "", "template digest (OCI digest of the zygote artifact or image)")
	tenant := fs.String("tenant", "", "the grant's tenant, which its named sessions are filed under (a grant without one runs anonymous fibers only)")
	maxF := fs.Uint("max", 1, "fibers.max")
	warm := fs.Uint("warm", 0, "fibers.warm")
	wBudget := fs.String("w-budget", "0", "per-fiber dirtied working set ceiling, bytes with optional Ki/Mi/Gi suffix (0 = unlimited)")
	minTier := fs.String("min-tier", "FIBER_BASIC", "lowest tier that may serve the grant")
	ttl := fs.Duration("ttl", 10*time.Minute, "lease: exp = now + ttl (negative for an already-expired grant)")
	durability := fs.String("durability", "best-effort", "audit durability: best-effort or sync")
	psiShed := fs.Float64("psi-shed", 0, "PSI memory some avg10 (%) at which the home sheds new clones")
	psiPark := fs.Float64("psi-park", 0, "PSI memory some avg10 (%) at which the home parks sessions")
	devBudget := fs.String("device-budget", "0", "per-fiber slice of the engine's device state, bytes with optional Ki/Mi/Gi suffix (0 = no device)")
	devClass := fs.String("device-class", "", "device class the budget is for (gpu, sim; empty = any)")
	bindCert := fs.String("bind-cert", "", "PEM client certificate the grant is bound to (cnf x5t#S256). Homes serving mutual TLS require it")
	isolation := fs.String("isolation", "UNTRUSTED", "UNTRUSTED (only gvisor or hyperlight homes serve it) or TRUSTED (any home, including proc and runc)")
	endpointMode := fs.String("endpoint-mode", "DIRECT", "DIRECT (each fiber listens) or HANDOFF (proc and runc homes route TLS connections to fibers, which check the -bind-cert caller)")
	if err := cli.ParseFlags(fs, args, stderr); err != nil {
		return err
	}

	if *issuer == "" || *aud == "" {
		return errors.New("mint: -issuer and -aud are required")
	}
	key, err := grant.LoadKey(*keyPath)
	if err != nil {
		return err
	}
	tier, err := core.ParseTier(*minTier)
	if err != nil {
		return err
	}
	iso, err := core.ParseIsolation(*isolation)
	if err != nil {
		return fmt.Errorf("-isolation: %w", err)
	}
	mode, err := core.ParseEndpointMode(*endpointMode)
	if err != nil {
		return fmt.Errorf("-endpoint-mode: %w", err)
	}
	w, err := parseBytes(*wBudget)
	if err != nil {
		return fmt.Errorf("-w-budget: %w", err)
	}
	dev, err := parseBytes(*devBudget)
	if err != nil {
		return fmt.Errorf("-device-budget: %w", err)
	}
	var d core.Durability
	switch strings.ToLower(*durability) {
	case "best-effort", "best_effort", "besteffort":
		d = core.BestEffort
	case "sync":
		d = core.Sync
	default:
		return fmt.Errorf("-durability: %q", *durability)
	}
	if *uid == "" {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		*uid = "g-" + hex.EncodeToString(b)
	}
	now := time.Now()
	g := core.Grant{
		UID: *uid, Audience: *aud, TemplateDigest: *template, Tenant: *tenant,
		FiberMax: int(*maxF), FiberWarm: int(*warm), WBudgetBytes: w, MinTier: tier,
		LeaseExpiry:  now.Add(*ttl).Truncate(time.Second),
		Policy:       core.Policy{Durability: d, PSISomeAvg10Shed: *psiShed, PSISomeAvg10Park: *psiPark, Isolation: iso, EndpointMode: mode},
		DeviceBudget: core.DeviceBudget{Bytes: dev, Class: *devClass},
	}
	if *bindCert != "" {
		if g.CallerThumbprint, err = tlsconf.ThumbprintFile(*bindCert); err != nil {
			return fmt.Errorf("-bind-cert: %w", err)
		}
	}
	is := &grant.Issuer{Key: key, URL: *issuer}
	tok, err := is.Mint(g)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(stdout, tok)
	return nil
}

func serve(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	keyPath := fs.String("key", "key.json", "private JWK from keygen")
	addr := fs.String("addr", ":8686", "listen address")
	issuer := fs.String("issuer", "", "issuer URL as verifiers will name it (default http://<addr>)")
	if err := cli.ParseFlags(fs, args, stderr); err != nil {
		return err
	}
	key, err := grant.LoadKey(*keyPath)
	if err != nil {
		return err
	}
	if *issuer == "" {
		*issuer = defaultIssuer(*addr)
	}
	is := &grant.Issuer{Key: key, URL: *issuer}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: is.Handler(), ReadHeaderTimeout: 5 * time.Second}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); _ = srv.Close() }()
	log.New(stderr, "", log.LstdFlags).Printf("grant-issuer serving %s (kid=%s alg=%s) on %s", *issuer, key.KeyID, key.Algorithm, ln.Addr())
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// defaultIssuer is the issuer URL http://<addr> for a listen address,
// with localhost for an address that names no host.
func defaultIssuer(addr string) string {
	if strings.HasPrefix(addr, ":") {
		addr = "localhost" + addr
	}
	return "http://" + addr
}

func parseBytes(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	mult := uint64(1)
	for _, suf := range []struct {
		s string
		m uint64
	}{{"Ki", 1 << 10}, {"Mi", 1 << 20}, {"Gi", 1 << 30}, {"K", 1000}, {"M", 1000 * 1000}, {"G", 1000 * 1000 * 1000}} {
		if strings.HasSuffix(s, suf.s) {
			s, mult = strings.TrimSuffix(s, suf.s), suf.m
			break
		}
	}
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, err
	}
	return n * mult, nil
}
