// Command fiberd is the grant agent on a standalone host: one process per
// home instance. It verifies signed grants offline, mints fibers under
// them through a runtime, and serves the grant protocol (api/grant/v1)
// over gRPC. The agent itself is pkg/agent; this binary adds the
// standalone home. An integration with another environment builds its
// own binary the same way (examples/kubernetes/cmd/fiberd-k8s).
//
// Startup order is fixed: epoch++ -> reconcile -> open RPC. The agent
// serves nothing until its view of the home is real.
package main

import (
	"flag"
	"log"
	"os"

	"github.com/helayoty/fiberd/pkg/agent"
)

func main() {
	var c agent.Config
	c.Bind(flag.CommandLine)
	flag.Parse()
	c.Finish()
	if err := agent.Run(&c, agent.Standalone); err != nil {
		log.Fatal(err)
	}
	os.Exit(0)
}
