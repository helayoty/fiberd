// Command fiberd-k8s is fiberd for a Kubernetes grant Pod: the
// library (pkg/fiberd) plus the Kubernetes home. It is what the
// issuer controller runs as PID 1 of every grant Pod. Every fiberd flag
// applies; -grants-dir defaults to the projected grant volume and the
// Pod's cgroup replaces -cgroup-root. With -healthz it is the Pod's
// liveness and startup probe instead of fiberd.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"time"

	"github.com/helayoty/fiberd/pkg/fiberd"
	"github.com/helayoty/fiberd/pkg/grant"
	fhome "github.com/helayoty/fiberd/pkg/home"

	"github.com/helayoty/fiberd/examples/kubernetes/home"
)

func main() {
	if err := run(flag.CommandLine, os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

// run is fiberd with its flags bound on fs and parsed from args. With
// -healthz it only checks the running fiberd and returns.
func run(fs *flag.FlagSet, args []string) error {
	var c fiberd.Config
	c.Bind(fs)
	healthz := fs.Bool("healthz", false, "check the running fiberd's /healthz on the admin socket under -state, then exit: 0 on 200, 1 otherwise, as when its audit spool is poisoned. The grant Pod's liveness and startup probes run it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *healthz {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		return c.Healthz(ctx)
	}
	if err := c.NarrowCaps(); err != nil {
		return err
	}
	return fiberd.Run(&c, kubernetes)
}

// kubernetes is the home factory: what the Kubernetes home needs from
// fiberd's configuration.
func kubernetes(c *fiberd.Config, _ *grant.Cache) (fhome.Home, error) {
	fam, err := c.Family()
	if err != nil {
		return nil, err
	}
	return home.New(home.Config{
		GrantsDir: c.Node.GrantsDir, StaleTTL: c.Node.StaleTTL, Devices: c.Node.Devices, Family: fam,
	})
}
