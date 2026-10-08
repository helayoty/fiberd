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
	"context"
	"errors"
	"flag"
	"io"
	"log"
	"os"

	"github.com/helayoty/fiberd/pkg/agent"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stderr))
}

// run is fiberd until ctx ends, SIGINT or SIGTERM. It returns exit code
// 0 for a clean stop or -h, 2 for bad flags, and 1 when the agent fails.
func run(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("fiberd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c agent.Config
	c.Bind(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	c.Finish()
	logger := log.New(stderr, "", log.LstdFlags)
	if err := c.NarrowCaps(); err != nil {
		logger.Print(err)
		return 1
	}
	if err := agent.RunContext(ctx, &c, agent.Standalone); err != nil {
		logger.Print(err)
		return 1
	}
	return 0
}
