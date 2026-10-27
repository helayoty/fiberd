package main

// fiberd run tries a template on this machine with one command.
//
//	fiberd run examples/hello/hello.py
//	fiberd run -n 50 -time examples/hello/hello.py
//	fiberd run -park examples/hello/counter.py
//	fiberd run -n 3 -max 2 examples/hello/hello.py
//	fiberd run -payload world -- bin/mytemplate --flag
//
// It starts fiberd inside this process on the proc backend, admits one
// grant, clones -n fibers (one by default) from the template, asks each
// once, then releases them and stops fiberd. -park asks each fiber
// twice, parks it, resumes its session and asks it once more. -time adds
// the clones' p50 and p99, and -max shows a clone refused past the
// grant. It is for trying a template, not for serving one. It needs
// Linux.
//
// On a terminal it shows a table, a row per step with what the fiber
// said. Piped, or with -o raw, stdout gets only the fibers' bytes and
// its notes go to stderr.
//
// -trust picks how the grant and the API are secured. The only mode so
// far is insecure, the default, with an unsigned grant
// (-verifier=insecure-json) and a plaintext API on loopback, so nothing
// run that way belongs on a shared host.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/helayoty/fiberd/internal/cli"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/endpoint"
	"github.com/helayoty/fiberd/pkg/fiberd"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/sdk/go/client"
)

// runNode is the -node-id fiberd runs as under run, and the audience of
// its grant.
const runNode = "fiberd-run"

func runTemplate(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	payload := fs.String("payload", "", "bytes each fiber gets with its Clone")
	var o plan
	fs.IntVar(&o.n, "n", 1, "fibers to clone from the one warm template, all running at once")
	fs.IntVar(&o.max, "max", 0, "fibers the grant holds (default -n). Clones past it are refused, and run says so")
	fs.BoolVar(&o.park, "park", false, "after each fiber answers, park it, resume its session and ask it again")
	fs.BoolVar(&o.time, "time", false, "report the clones' p50 and p99, and in raw output the first clone's time and each park and resume time")
	output := fs.String("o", "auto", "output: table (a row per step), raw (only the fibers' bytes, with its notes on stderr), or auto (table on a terminal, raw otherwise)")
	state := fs.String("state", "", "fiberd's state directory (default a fresh one, removed after)")
	cgroup := fs.String("cgroup-root", "", "delegated cgroup v2 subtree fiberd carves (default fiberd's own)")
	trust := fs.String("trust", "insecure", "how grants and the API are secured: insecure (an unsigned grant, a plaintext API on loopback)")
	timeout := fs.Duration("timeout", time.Minute, "how long the template may take to warm and the fibers to answer")
	verbose := fs.Bool("v", false, "show fiberd's log")
	if err := cli.ParseFlags(fs, args, stderr); err != nil {
		return err
	}
	o.payload = []byte(*payload)
	argv, err := templateCommand(fs.Args(), os.Getenv("PYTHONPATH"))
	if err != nil {
		return err
	}
	if _, err := trustArgs(*trust); err != nil {
		return err
	}
	if err := o.check(); err != nil {
		return err
	}
	o.template = strings.Join(fs.Args(), " ")
	v, err := newView(*output, stdout, stderr, o.park, o.time)
	if err != nil {
		return err
	}
	if goruntime.GOOS != "linux" {
		return errors.New("fiberd run: the proc backend needs Linux. On a Mac, run it in the dev container (hack/dev/run.sh bash)")
	}
	c, err := runConfig(*state, *cgroup, *trust, argv)
	if err != nil {
		return err
	}
	// This may re-execute fiberd with fewer capabilities, so it comes
	// before anything a re-exec would leave behind.
	if err := c.NarrowCaps(); err != nil {
		return err
	}
	if *state == "" {
		// Short, since fiber sockets live under it.
		dir, err := os.MkdirTemp("", "fz")
		if err != nil {
			return err
		}
		defer func() { _ = os.RemoveAll(dir) }()
		c.Node.StateDir = dir
	}
	if !*verbose {
		// fiberd logs through the standard logger.
		prev := log.Writer()
		log.SetOutput(io.Discard)
		defer log.SetOutput(prev)
	}
	tok, err := devGrant(time.Now(), o.max)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	addr := make(chan net.Addr, 1)
	c.Ready = func(g, _, _ net.Addr) { addr <- g }
	runCtx, stopFiberd := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- fiberd.RunContext(runCtx, c, fiberd.Standalone) }()
	defer func() { stopFiberd(); <-done }()
	select {
	case a := <-addr:
		return o.run(ctx, a.String(), tok, v)
	case err := <-done:
		done <- err // the deferred stop reads it too
		return fmt.Errorf("fiberd run: fiberd stopped: %w", err)
	case <-ctx.Done():
		return fmt.Errorf("fiberd run: fiberd did not start: %w", ctx.Err())
	}
}

// templateCommand is the command fiberd starts the template with. A .py
// file runs under python3. fiberd gives a template no environment but
// PATH, so a PYTHONPATH set here is passed on through env. fiberd splits
// the command on spaces, so no argument may hold one.
func templateCommand(args []string, pythonPath string) ([]string, error) {
	if len(args) == 0 {
		return nil, errors.New("fiberd run: name the template, such as examples/hello/hello.py")
	}
	for _, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\n") {
			return nil, fmt.Errorf("fiberd run: argument %q is empty or holds a space, which fiberd's -template cannot carry", a)
		}
	}
	argv := append([]string(nil), args...)
	// fiberd starts the template in a directory of its own, so a
	// relative path is made absolute here.
	if strings.Contains(argv[0], "/") {
		abs, err := filepath.Abs(argv[0])
		if err != nil {
			return nil, err
		}
		argv[0] = abs
	}
	if strings.HasSuffix(argv[0], ".py") {
		argv = append([]string{"python3"}, argv...)
	}
	if pythonPath != "" {
		if strings.ContainsAny(pythonPath, " \t\n") {
			return nil, fmt.Errorf("fiberd run: PYTHONPATH %q holds a space, which fiberd's -template cannot carry", pythonPath)
		}
		argv = append([]string{"env", "PYTHONPATH=" + pythonPath}, argv...)
	}
	return argv, nil
}

// trustArgs are fiberd's flags for a -trust mode. insecure is the only
// one so far. A signed mode would add an issuer, signed grants and TLS.
func trustArgs(trust string) ([]string, error) {
	switch trust {
	case "insecure":
		return []string{"-insecure-plaintext", "-verifier", "insecure-json"}, nil
	}
	return nil, fmt.Errorf("fiberd run: -trust %q unknown, want insecure", trust)
}

// runConfig is fiberd on loopback, secured as trust says, with the
// template as the default for every digest.
func runConfig(state, cgroup, trust string, argv []string) (*fiberd.Config, error) {
	sec, err := trustArgs(trust)
	if err != nil {
		return nil, err
	}
	fs := flag.NewFlagSet("fiberd", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var c fiberd.Config
	c.Bind(fs)
	args := append([]string{"-node-id", runNode, "-listen", "127.0.0.1:0", "-runtime", "proc",
		"-template", "default=" + strings.Join(argv, " ")}, sec...)
	if state != "" {
		args = append(args, "-state", state)
	}
	if cgroup != "" {
		args = append(args, "-cgroup-root", cgroup)
	}
	if err := fs.Parse(args); err != nil {
		return nil, fmt.Errorf("fiberd run: fiberd flags: %w", err)
	}
	return &c, nil
}

// devGrant is a grant of n fibers for this home, unsigned, as -trust
// insecure takes it. It is TRUSTED because proc fibers share the host
// kernel.
func devGrant(now time.Time, n int) (string, error) {
	g := core.Grant{UID: "hello", Audience: runNode, Tenant: "fiberd-run", FiberMax: n, MinTier: core.TierBasic,
		LeaseExpiry: now.Add(10 * time.Minute)}
	g.Policy.Isolation = core.Trusted
	tok, err := protojson.Marshal(grant.ToProto(g))
	if err != nil {
		return "", err
	}
	return string(tok), nil
}

// plan is what run does with the fibers once fiberd serves.
type plan struct {
	// template is the command run was given, as the table names it.
	template string
	// n fibers are cloned. The grant holds max of them.
	n, max  int
	payload []byte
	// park parks each fiber after it answers, resumes its session and
	// asks it again.
	park bool
	// time reports the clones' p50 and p99.
	time bool
}

// check refuses counts below 1, and makes max n when it was not given.
func (o *plan) check() error {
	if o.n < 1 {
		return fmt.Errorf("fiberd run: -n %d, want 1 or more", o.n)
	}
	if o.max == 0 {
		o.max = o.n
	}
	if o.max < 1 {
		return fmt.Errorf("fiberd run: -max %d, want 1 or more", o.max)
	}
	return nil
}

// session is the i'th fiber's session. Only a park needs one to resume,
// so without -park every fiber is anonymous.
func (o *plan) session(i int) string {
	if !o.park {
		return ""
	}
	return fmt.Sprintf("s%d", i+1)
}

// run clones n fibers from the one warm template, so they run side by
// side, then asks each once, in clone order, and releases them all. With
// park it also asks each a second time, parks it, resumes its session
// and asks once more. A clone past max is refused, and v shows it, since
// that is what -max asks to see. v shows every step.
func (o *plan) run(ctx context.Context, addr, tok string, v view) error {
	cl, err := client.Dial(ctx, addr)
	if err != nil {
		return err
	}
	defer func() { _ = cl.Close() }()
	type live struct {
		client.Fiber
		session string
	}
	fibers := make([]live, 0, o.n)
	defer func() {
		for _, f := range fibers {
			_ = cl.Release(context.Background(), f.ID, true)
		}
	}()
	v.start(o.template, o.n)
	var took []time.Duration
	var refused []refusal
	for i := range o.n {
		start := time.Now()
		f, err := clone(ctx, cl, tok, o.session(i), o.payload)
		var deferred *client.Deferred
		if errors.As(err, &deferred) && i >= o.max {
			refused = append(refused, refusal{clone: i + 1, max: o.max, err: deferred})
			continue
		}
		if err != nil {
			return err
		}
		took = append(took, time.Since(start))
		fibers = append(fibers, live{Fiber: f, session: o.session(i)})
	}
	parked := 0
	for i, f := range fibers {
		says, err := read(ctx, f.Fiber)
		if err != nil {
			return err
		}
		v.step(step{fiber: f.ID, event: eventClone, session: f.session, took: took[i], says: says})
		if !o.park {
			continue
		}
		if says, err = read(ctx, f.Fiber); err != nil {
			return err
		}
		v.step(step{fiber: f.ID, event: eventAsk, session: f.session, says: says})
		start := time.Now()
		if err := cl.Park(ctx, f.ID, true); err != nil {
			return fmt.Errorf("fiberd run: park %s (proc parks only with criu 4.2 or later, and -v shows whether fiberd found one): %w", f.ID, err)
		}
		v.step(step{fiber: f.ID, event: eventPark, session: f.session, took: time.Since(start)})
		start = time.Now()
		r, err := clone(ctx, cl, tok, f.session, o.payload)
		if err != nil {
			return err
		}
		resumed := time.Since(start)
		fibers[i].Fiber = r
		if r.Kind != client.Resume {
			return fmt.Errorf("fiberd run: session %s came back as %s, not RESUME, so its state is gone", f.session, r.Kind)
		}
		if says, err = read(ctx, r); err != nil {
			return err
		}
		v.step(step{fiber: r.ID, event: eventResume, session: f.session, took: resumed, says: says})
		parked++
	}
	for _, r := range refused {
		v.refused(r)
	}
	v.end(summary{fibers: len(fibers), refused: len(refused), max: o.max, parked: parked, took: took})
	return nil
}

// clone is one Clone of session, anonymous when it is "". A shed, which
// a template still warming answers with, is retried after its hint
// until ctx ends.
func clone(ctx context.Context, cl *client.Client, tok, session string, payload []byte) (client.Fiber, error) {
	for {
		deadline, _ := ctx.Deadline()
		f, err := cl.Clone(ctx, tok, session, time.Until(deadline), payload)
		var shed *client.Shed
		if !errors.As(err, &shed) {
			if err != nil {
				return client.Fiber{}, fmt.Errorf("fiberd run: clone: %w", err)
			}
			return f, nil
		}
		select {
		case <-ctx.Done():
			return client.Fiber{}, fmt.Errorf("fiberd run: clone: %w", err)
		case <-time.After(max(shed.RetryAfter, 100*time.Millisecond)):
		}
	}
}

// read returns what fiber f sends on one connection, until it closes
// the connection. A fiber gets 1 MiB at most.
func read(ctx context.Context, f client.Fiber) ([]byte, error) {
	conn, err := endpoint.Dial(ctx, f.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("fiberd run: dial fiber %s: %w", f.ID, err)
	}
	defer func() { _ = conn.Close() }()
	if d, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(d)
	}
	b, err := io.ReadAll(io.LimitReader(conn, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("fiberd run: read fiber %s: %w", f.ID, err)
	}
	return b, nil
}
