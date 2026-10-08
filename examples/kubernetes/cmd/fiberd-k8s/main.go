// Command fiberd-k8s is the fiberd agent for a Kubernetes grant Pod: the
// agent library (pkg/agent) plus the Kubernetes home. It is what the
// issuer controller runs as PID 1 of every grant Pod. Every fiberd flag
// applies; -grants-dir defaults to the projected grant volume and the
// Pod's cgroup replaces -cgroup-root.
package main

import (
	"flag"
	"log"
	"os"

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

// run is the agent with its flags bound on fs and parsed from args.
func run(fs *flag.FlagSet, args []string) error {
	var c agent.Config
	c.Bind(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	c.Finish()
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
