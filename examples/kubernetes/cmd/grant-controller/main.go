// Command grant-controller is the Kubernetes issuer: fiberd's reference
// issuer (pkg/grant) run as a controller. The key lives in a Secret, the
// discovery document and JWKS are served on -addr, and every
// CapacityGrant resource is reconciled into a grant Pod running fiberd-k8s
// and a signed grant projected into it (examples/kubernetes/controller).
//
//	grant-controller [-addr :8080] [-issuer <url>] [-key-secret grant-issuer-key] [-poll 2s]
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/helayoty/fiberd/pkg/grant"

	"github.com/helayoty/fiberd/examples/kubernetes/controller"
	"github.com/helayoty/fiberd/examples/kubernetes/kube"
)

// Where the cluster client and this Pod's namespace come from, and a hook
// told the address discovery is served on. Tests replace them.
var (
	inCluster    = kube.InCluster
	podNamespace = kube.Namespace
	serving      = func(net.Addr) {}
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, flag.CommandLine, os.Args[1:])
	stop()
	if err != nil {
		log.Fatal(err)
	}
}

// run is the controller with its flags bound on fs and parsed from args.
// It returns once ctx ends.
func run(ctx context.Context, fs *flag.FlagSet, args []string) error {
	addr := fs.String("addr", ":8080", "listen address for discovery and the JWKS")
	issuer := fs.String("issuer", "", "issuer URL as grant Pods verify it (default http://grant-issuer.<namespace>.svc:8080)")
	ns := fs.String("namespace", "", "namespace holding the key Secret (default: this Pod's)")
	keySecret := fs.String("key-secret", "grant-issuer-key", "Secret holding the private JWK as key.json; generated when missing")
	poll := fs.Duration("poll", 2*time.Second, "reconcile cadence")
	if err := fs.Parse(args); err != nil {
		return err
	}
	client, err := inCluster()
	if err != nil {
		return err
	}
	if *ns == "" {
		if *ns, err = podNamespace(); err != nil {
			return err
		}
	}
	if *issuer == "" {
		*issuer = "http://grant-issuer." + *ns + ".svc:8080"
	}
	key, err := controller.EnsureKey(ctx, client, *ns, *keySecret)
	if err != nil {
		return err
	}
	is := &grant.Issuer{Key: key, URL: *issuer}
	// Listen before reconciling. A grant minted while nothing serves the
	// JWKS is one no grant Pod can verify.
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: is.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("controller: serve: %v", err)
		}
	}()
	log.Printf("grant-controller serving %s (kid=%s alg=%s) on %s", *issuer, key.KeyID, key.Algorithm, ln.Addr())
	serving(ln.Addr())
	c := &controller.Controller{Client: client, Issuer: is, Poll: *poll}
	c.Run(ctx)
	return srv.Close()
}
