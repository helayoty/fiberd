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
	"log"
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
	var revs revisionFlags
	home := flag.String("home", "127.0.0.1:8484", "the fiberd home's gRPC address")
	listen := flag.String("listen", ":8080", "HTTP listen address")
	idle := flag.Duration("idle", 30*time.Second, "park a revision's fiber after this long without requests (0 = never)")
	deadline := flag.Duration("clone-deadline", 5*time.Second, "runtime budget per Clone")
	flag.Var(&revs, "revision", "a revision: name=<jwt|@file>[,concurrency=N][,mode=line|http] (repeatable)")
	flag.Parse()
	if err := run(*home, *listen, *idle, *deadline, revs); err != nil {
		log.Fatal(err)
	}
}

func run(home, listen string, idle, deadline time.Duration, revs []activator.Revision) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client, err := consumer.Dial(ctx, home)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	act, err := activator.New(client, activator.Config{Revisions: revs, Idle: idle, CloneDeadline: deadline})
	if err != nil {
		return err
	}
	go act.Run(ctx)
	srv := &http.Server{Addr: listen, Handler: act, ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	log.Printf("fiberd-activator: %d revision(s) on %s, home %s, idle park after %s", len(revs), listen, home, idle)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
