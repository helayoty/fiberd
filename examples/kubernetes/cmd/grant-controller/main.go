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
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/helayoty/fiberd/pkg/grant"

	"github.com/helayoty/fiberd/examples/kubernetes/controller"
	"github.com/helayoty/fiberd/examples/kubernetes/kube"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	addr := flag.String("addr", ":8080", "listen address for discovery and the JWKS")
	issuer := flag.String("issuer", "", "issuer URL as grant Pods verify it (default http://grant-issuer.<namespace>.svc:8080)")
	ns := flag.String("namespace", "", "namespace holding the key Secret (default: this Pod's)")
	keySecret := flag.String("key-secret", "grant-issuer-key", "Secret holding the private JWK as key.json; generated when missing")
	poll := flag.Duration("poll", 2*time.Second, "reconcile cadence")
	flag.Parse()
	client, err := kube.InCluster()
	if err != nil {
		return err
	}
	if *ns == "" {
		if *ns, err = kube.Namespace(); err != nil {
			return err
		}
	}
	if *issuer == "" {
		*issuer = "http://grant-issuer." + *ns + ".svc:8080"
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	key, err := controller.EnsureKey(ctx, client, *ns, *keySecret)
	if err != nil {
		return err
	}
	is := &grant.Issuer{Key: key, URL: *issuer}
	srv := &http.Server{Addr: *addr, Handler: is.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	go func() {
		log.Printf("grant-controller serving %s (kid=%s alg=%s) on %s", *issuer, key.KeyID, key.Algorithm, *addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("controller: serve: %v", err)
		}
	}()
	c := &controller.Controller{Client: client, Issuer: is, Poll: *poll}
	c.Run(ctx)
	return nil
}
