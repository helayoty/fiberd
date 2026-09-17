// Command grant-issuer is the reference issuer: it holds one signing key,
// mints CapacityGrant JWTs, and serves the OIDC discovery document and JWKS
// that homes verify against.
//
//	grant-issuer keygen -alg EdDSA -out key.json
//	grant-issuer mint   -key key.json -issuer http://issuer:8686 -aud node-a \
//	                    -template sha256:... -max 8 -warm 2 -w-budget 64Mi \
//	                    -min-tier FIBER_WARM -ttl 10m > grant.jwt
//	grant-issuer serve  -key key.json -addr :8686 [-issuer http://issuer:8686]
//
// The Kubernetes controller (phase 3k) is a fourth subcommand on this
// binary, using the same key and handler.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "mint":
		err = mint(os.Args[2:])
	case "serve":
		err = serve(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		err = fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: grant-issuer keygen|mint|serve [flags]; -h on a subcommand for its flags")
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	alg := fs.String("alg", "EdDSA", "signature algorithm: EdDSA or ES256")
	out := fs.String("out", "key.json", "where to write the private JWK (mode 0600)")
	_ = fs.Parse(args)
	key, err := grant.GenerateKey(jose.SignatureAlgorithm(*alg))
	if err != nil {
		return err
	}
	if err := grant.SaveKey(*out, key); err != nil {
		return err
	}
	fmt.Printf("wrote %s kid=%s alg=%s\n", *out, key.KeyID, key.Algorithm)
	return nil
}

func mint(args []string) error {
	fs := flag.NewFlagSet("mint", flag.ExitOnError)
	keyPath := fs.String("key", "key.json", "private JWK from keygen")
	issuer := fs.String("issuer", "", "issuer URL (iss; where serve publishes the keys)")
	aud := fs.String("aud", "", "audience: the home's node id")
	uid := fs.String("uid", "", "grant uid (default: random)")
	template := fs.String("template", "", "template digest (OCI digest of the zygote artifact or image)")
	maxF := fs.Uint("max", 1, "fibers.max")
	warm := fs.Uint("warm", 0, "fibers.warm")
	wBudget := fs.String("w-budget", "0", "per-fiber dirtied working set ceiling, bytes with optional Ki/Mi/Gi suffix (0 = unlimited)")
	minTier := fs.String("min-tier", "FIBER_BASIC", "lowest tier that may serve the grant")
	ttl := fs.Duration("ttl", 10*time.Minute, "lease: exp = now + ttl (negative for an already-expired grant)")
	durability := fs.String("durability", "best-effort", "audit durability: best-effort or sync")
	psiShed := fs.Float64("psi-shed", 0, "PSI memory some avg10 (%) at which the home sheds new clones")
	psiPark := fs.Float64("psi-park", 0, "PSI memory some avg10 (%) at which the home parks sessions")
	_ = fs.Parse(args)

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
	w, err := parseBytes(*wBudget)
	if err != nil {
		return fmt.Errorf("-w-budget: %w", err)
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
		UID: *uid, Audience: *aud, TemplateDigest: *template,
		FiberMax: int(*maxF), FiberWarm: int(*warm), WBudgetBytes: w, MinTier: tier,
		LeaseExpiry: now.Add(*ttl).Truncate(time.Second),
		Policy:      core.Policy{Durability: d, PSISomeAvg10Shed: *psiShed, PSISomeAvg10Park: *psiPark},
	}
	is := &grant.Issuer{Key: key, URL: *issuer}
	tok, err := is.Mint(g)
	if err != nil {
		return err
	}
	fmt.Println(tok)
	return nil
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	keyPath := fs.String("key", "key.json", "private JWK from keygen")
	addr := fs.String("addr", ":8686", "listen address")
	issuer := fs.String("issuer", "", "issuer URL as verifiers will name it (default http://<addr>)")
	_ = fs.Parse(args)
	key, err := grant.LoadKey(*keyPath)
	if err != nil {
		return err
	}
	if *issuer == "" {
		host := *addr
		if strings.HasPrefix(host, ":") {
			host = "localhost" + host
		}
		*issuer = "http://" + host
	}
	is := &grant.Issuer{Key: key, URL: *issuer}
	srv := &http.Server{Addr: *addr, Handler: is.Handler(), ReadHeaderTimeout: 5 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); _ = srv.Close() }()
	log.Printf("grant-issuer serving %s (kid=%s alg=%s) on %s", *issuer, key.KeyID, key.Algorithm, *addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
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
