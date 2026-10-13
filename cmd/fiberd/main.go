// Command fiberd is fiberd on a standalone host: one process per
// home instance. It verifies signed grants offline, mints fibers under
// them through a runtime, and serves the grant protocol (api/grant/v1)
// over gRPC. fiberd itself is pkg/fiberd; this binary adds the
// standalone home. An integration with another environment builds its
// own binary the same way (examples/kubernetes/cmd/fiberd-k8s).
//
// Startup order is fixed: epoch++ -> reconcile -> open RPC. fiberd
// serves nothing until its view of the home is real.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/helayoty/fiberd/internal/cli"
	"github.com/helayoty/fiberd/pkg/fiberd"
)

// version is set at link time with -ldflags "-X main.version=v0.1.0".
var version string

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

// run is fiberd until ctx ends, SIGINT or SIGTERM. It returns exit code
// 0 for a clean stop, -h or -version, 2 for bad flags, and 1 when the
// fiberd fails.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fiberd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c fiberd.Config
	c.Bind(fs)
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVersion {
		_, _ = fmt.Fprintln(stdout, "fiberd", cli.Version(version))
		return 0
	}
	logger := log.New(stderr, "", log.LstdFlags)
	if err := c.NarrowCaps(); err != nil {
		logger.Print(err)
		return 1
	}
	if err := fiberd.RunContext(ctx, &c, fiberd.Standalone); err != nil {
		logger.Print(err)
		return 1
	}
	return 0
}
