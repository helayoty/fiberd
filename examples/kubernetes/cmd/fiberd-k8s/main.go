// Command fiberd-k8s is the fiberd agent for a Kubernetes grant Pod: the
// agent library (pkg/agent) plus the Kubernetes home. It is what the
// issuer controller runs as PID 1 of every grant Pod. Every fiberd flag
// applies; -grants-dir defaults to the projected grant volume and the
// Pod's cgroup replaces -cgroup-root.
package main

import (
	"flag"
	"log"

	"github.com/helayoty/fiberd/pkg/agent"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	fhome "github.com/helayoty/fiberd/pkg/home"

	"github.com/helayoty/fiberd/examples/kubernetes/home"
)

func main() {
	var c agent.Config
	c.Bind(flag.CommandLine)
	flag.Parse()
	c.Finish()
	if err := agent.Run(&c, kubernetes); err != nil {
		log.Fatal(err)
	}
}

// kubernetes is the home factory: what the Kubernetes home needs from
// the agent's configuration.
func kubernetes(c *agent.Config, _ core.Verifier, _ *grant.Cache) (fhome.Home, error) {
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
