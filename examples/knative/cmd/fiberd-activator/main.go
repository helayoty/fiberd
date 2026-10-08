// Command fiberd-activator serves Knative-style scale-from-zero with
// fibers: each revision is a session on a fiberd home (a Hyperlight
// sandbox backend), cloned on the first request, attached to after,
// parked when idle, resumed on the next request. See the activator
// package.
//
//	fiberd-activator -home 127.0.0.1:8484 -listen :8080 \
//	    -revision hello=@hello.jwt -revision api=@api.jwt,concurrency=4,mode=http -idle 30s
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/helayoty/fiberd/pkg/consumer"

	"github.com/helayoty/fiberd/examples/knative/activator"
)

type revisionFlags []activator.Revision

func (r *revisionFlags) String() string { return fmt.Sprint(len(*r)) }

// Set parses name=<jwt|@file>[,concurrency=N][,mode=line|http].
func (r *revisionFlags) Set(v string) error {
	name, rest, ok := strings.Cut(v, "=")
	if !ok || name == "" {
		return errors.New("-revision: want name=<jwt|@file>[,concurrency=N][,mode=line|http]")
	}
	parts := strings.Split(rest, ",")
	rev := activator.Revision{Name: name, Grant: parts[0]}
	if path, ok := strings.CutPrefix(rev.Grant, "@"); ok {
		b, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("-revision %s: %w", name, err)
		}
		rev.Grant = strings.TrimSpace(string(b))
	}
	for _, opt := range parts[1:] {
		k, val, _ := strings.Cut(opt, "=")
		switch k {
		case "concurrency":
			n, err := strconv.Atoi(val)
			if err != nil {
				return fmt.Errorf("-revision %s: concurrency: %w", name, err)
			}
			rev.Concurrency = n
		case "mode":
			rev.Mode = val
		default:
			return fmt.Errorf("-revision %s: unknown option %q", name, k)
		}
	}
	*r = append(*r, rev)
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stderr, nil)
	stop()
	var usage usageError
	switch {
	case errors.Is(err, flag.ErrHelp):
	case errors.As(err, &usage):
		os.Exit(2) // the flag package has printed the error and the usage
	case err != nil:
		log.Fatal(err)
	}
}

// usageError is a bad command line, already reported with the usage.
type usageError struct{ error }

func (e usageError) Unwrap() error { return e.error }

// run parses args (usage and flag errors go to out), serves until ctx
// ends, and returns nil once it has stopped cleanly. ready, when set, is
// told the bound HTTP address before serving starts.
func run(ctx context.Context, args []string, out io.Writer, ready func(net.Addr)) error {
	fs := flag.NewFlagSet("fiberd-activator", flag.ContinueOnError)
	fs.SetOutput(out)
	var revs revisionFlags
	home := fs.String("home", "127.0.0.1:8484", "the fiberd home's gRPC address")
	listen := fs.String("listen", ":8080", "HTTP listen address")
	idle := fs.Duration("idle", 30*time.Second, "park a revision's fiber after this long without requests (0 = never)")
	deadline := fs.Duration("clone-deadline", 5*time.Second, "runtime budget per Clone")
	fs.Var(&revs, "revision", "a revision: name=<jwt|@file>[,concurrency=N][,mode=line|http] (repeatable)")
	if err := fs.Parse(args); err != nil {
		return usageError{err}
	}
	client, err := consumer.Dial(ctx, *home)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	act, err := activator.New(client, activator.Config{Revisions: revs, Idle: *idle, CloneDeadline: *deadline})
	if err != nil {
		return err
	}
	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	if ready != nil {
		ready(lis.Addr())
	}
	go act.Run(ctx)
	srv := &http.Server{Handler: act, ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	log.Printf("fiberd-activator: %d revision(s) on %s, home %s, idle park after %s", len(revs), lis.Addr(), *home, *idle)
	if err := srv.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
