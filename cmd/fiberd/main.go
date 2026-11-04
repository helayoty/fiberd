// Command fiberd verifies signed grants offline, mints fibers under them
// through a runtime, and serves the grant protocol (api/grant/v1) over
// gRPC. One process serves one home instance. fiberd itself is
// pkg/fiberd.
//
//	fiberd [flags]                      serve this home
//	fiberd run [flags] TEMPLATE [args]  try a template on this machine
//	fiberd healthz [flags]              ask a running fiberd for /healthz
//	fiberd readyz [flags]               ask a running fiberd for /readyz
//
// -home picks the home fiberd runs in. standalone, the default, is a
// plain host. kubernetes is a grant Pod, whose identity the downward API
// fills through POD_NAME, POD_NAMESPACE and POD_UID. Homes are core and
// live under pkg/home. Control planes, such as the controller that
// creates grant Pods, are separate projects that pin this module.
//
// healthz and readyz take the same flags, so -state names the admin
// socket. They need no Pod identity. A liveness probe can exec healthz,
// and a readiness probe that should see a drain can exec readyz, which
// also fails while fiberd drains.
//
// Startup order is fixed: epoch++ -> reconcile -> open RPC. fiberd
// serves nothing until its view of the home is real.
//
// The exit code is 0 for a clean stop, -h or -version, 2 for bad flags
// or usage, and 1 when fiberd or a probe fails.
package main

import (
	"context"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Azure/fiberd/internal/cli"
	"github.com/Azure/fiberd/pkg/fiberd"
	kubehome "github.com/Azure/fiberd/pkg/home/kubernetes"
)

// version is set at link time with -ldflags "-X main.version=v0.1.0".
var version string

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

// run is fiberd until ctx ends, SIGINT or SIGTERM. It returns exit code
// 0 for a clean stop, -h or -version, 2 for bad flags or usage, and 1
// when fiberd or a probe fails.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return hostEnv().run(ctx, args, stdout, stderr)
}

// run is run with what it takes from the host in e.
func (e env) run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "run":
			ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
			defer stop()
			return cli.Run(args, "usage: fiberd run [flags] TEMPLATE [args]", map[string]cli.Command{
				"run": func(a []string) error { return runTemplate(ctx, a, stdout, stderr) },
			}, stderr)
		case healthzCmd, readyzCmd:
			return e.probe(ctx, args[0], args[1:], stdout, stderr)
		}
	}
	o, code, done := e.parse(serveCmd, args, stdout, stderr)
	if done {
		return code
	}
	if o.home == kubehome.Name {
		return e.serveKubernetes(ctx, o, stderr)
	}
	return serveStandalone(ctx, o, stderr)
}

// serveStandalone runs fiberd on a plain host, logging on stderr.
func serveStandalone(ctx context.Context, o *options, stderr io.Writer) int {
	logger := log.New(stderr, "", log.LstdFlags)
	if err := o.fiberd.PrepareMounts(); err != nil {
		logger.Print(err)
		return 1
	}
	if err := o.fiberd.NarrowCaps(); err != nil {
		logger.Print(err)
		return 1
	}
	if err := fiberd.RunContext(ctx, &o.fiberd, fiberd.Standalone); err != nil {
		logger.Print(err)
		return 1
	}
	return 0
}
