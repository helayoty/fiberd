// Command fiberd-k8s is the fiberd agent for a Kubernetes grant Pod: the
// agent library (pkg/agent) plus the Kubernetes home. It is what the
// issuer controller runs as PID 1 of every grant Pod. Every fiberd flag
// applies; -grants-dir defaults to the projected grant volume and the
// Pod's cgroup replaces -cgroup-root. With -healthz it is the Pod's
// liveness and startup probe instead of the agent.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"time"

	"github.com/helayoty/fiberd/pkg/agent"
	"github.com/helayoty/fiberd/pkg/grant"
	fhome "github.com/helayoty/fiberd/pkg/home"

	"github.com/helayoty/fiberd/examples/kubernetes/home"
)

func main() {
	if err := run(flag.CommandLine, os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

// run is the agent with its flags bound on fs and parsed from args. With
// -healthz it only checks the running agent and returns.
func run(fs *flag.FlagSet, args []string) error {
	var c agent.Config
	c.Bind(fs)
	healthz := fs.Bool("healthz", false, "check the running agent's /healthz on the admin socket under -state, then exit: 0 on 200, 1 otherwise, as when its audit spool is poisoned. The grant Pod's liveness and startup probes run it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c.Finish()
	if *healthz {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		return c.Healthz(ctx)
	}
	if err := c.NarrowCaps(); err != nil {
		return err
	}
	return agent.Run(&c, kubernetes)
}

// kubernetes is the home factory: what the Kubernetes home needs from
// the agent's configuration.
func kubernetes(c *agent.Config, _ *grant.Cache) (fhome.Home, error) {
	fam, err := c.Family()
	if err != nil {
		return nil, err
	}
	port, err := c.ListenPort()
	if err != nil {
		return nil, err
	}
	return home.New(home.Config{
		GrantsDir: c.GrantsDir, StaleTTL: c.StaleTTL, Devices: c.Devices, Family: fam, ListenPort: port,
	})
}
