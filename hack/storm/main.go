// Command storm drives an overcommit storm against a fiberd home and
// reports whether the pressure ladder parked fibers before the kernel
// killed anything. It is the measurement behind the phase 3 acceptance
// "kubelet never OOM-kills the Pod under a 2x overcommit storm".
//
// It mints one grant, clones N named sessions, then makes every fiber
// dirty its heap in steps until the aggregate demand is `-overcommit`
// times the grant's ceiling. Meanwhile it samples the grant cgroup's
// memory.current and PSI, the ledger status stream, and the container's
// own OOM counter. Exit status is non-zero if the container recorded an
// OOM kill, if no fiber was parked, or if the agent stopped reporting.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/endpoint"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/sys/cgroup"
)

type opts struct {
	target, nodeID, issuerKey, issuerURL, cgRoot, rootEvents string
	fibers                                                   int
	ceiling, step                                            uint64
	overcommit                                               float64
	round, timeout                                           time.Duration
}

func main() {
	var o opts
	flag.StringVar(&o.target, "target", "127.0.0.1:18484", "Fibers service")
	flag.StringVar(&o.nodeID, "node-id", "storm-node", "grant audience")
	flag.StringVar(&o.issuerKey, "issuer-key", "", "private JWK to mint the grant with")
	flag.StringVar(&o.issuerURL, "issuer", "", "issuer URL")
	flag.IntVar(&o.fibers, "fibers", 8, "named sessions to clone")
	flag.Uint64Var(&o.ceiling, "ceiling", 160<<20, "the grant's block ceiling the home was started with (bytes)")
	flag.Float64Var(&o.overcommit, "overcommit", 2, "aggregate demand as a multiple of the ceiling")
	flag.Uint64Var(&o.step, "step", 2<<20, "bytes each fiber dirties per round")
	flag.DurationVar(&o.round, "round", 250*time.Millisecond, "pause between rounds")
	flag.StringVar(&o.cgRoot, "cgroup-root", envOr("FIBERD_CGROUP_ROOT", "/sys/fs/cgroup/fiberd"), "home's cgroup root")
	flag.StringVar(&o.rootEvents, "container-events", "/sys/fs/cgroup/memory.events", "container-level memory.events (OOM counter)")
	flag.DurationVar(&o.timeout, "timeout", 90*time.Second, "give up after")
	flag.Parse()
	os.Exit(run(o))
}

type fib struct {
	id, endpoint string
	dirtied      uint64
	gone         bool
}

func run(o opts) int {
	if o.issuerKey == "" || o.issuerURL == "" {
		return fatal("need -issuer-key and -issuer")
	}
	key, err := grant.LoadKey(o.issuerKey)
	if err != nil {
		return fatal("%v", err)
	}
	perFiber := uint64(float64(o.ceiling) * o.overcommit / float64(o.fibers))
	g := core.Grant{
		UID: fmt.Sprintf("storm-%d", time.Now().Unix()), Audience: o.nodeID, TemplateDigest: "sha256:storm",
		FiberMax: o.fibers, WBudgetBytes: perFiber + 8<<20, LeaseExpiry: time.Now().Add(time.Hour),
		Policy: core.Policy{PSISomeAvg10Shed: 5, PSISomeAvg10Park: 10},
	}
	tok, err := (&grant.Issuer{Key: key, URL: o.issuerURL}).Mint(g)
	if err != nil {
		return fatal("mint: %v", err)
	}
	fmt.Printf("storm: grant %s fibers=%d ceiling=%dMiB demand=%dMiB (%.1fx) per-fiber=%dMiB w_budget=%dMiB\n",
		g.UID, o.fibers, o.ceiling>>20, uint64(float64(o.ceiling)*o.overcommit)>>20, o.overcommit, perFiber>>20, g.WBudgetBytes>>20)

	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	conn, err := grpc.NewClient(o.target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fatal("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	api := grantv1.NewFibersClient(conn)

	oomBefore := oomKills(o.rootEvents)
	grantCG := cgroup.Root(o.cgRoot).Child(g.UID)

	// Status stream: latest running/parked for our grant.
	var stMu sync.Mutex
	var latest *grantv1.Status
	go func() {
		stream, err := api.Watch(ctx, &emptypb.Empty{})
		if err != nil {
			return
		}
		for {
			st, err := stream.Recv()
			if err != nil {
				return
			}
			if st.GetGrantUid() == g.UID {
				stMu.Lock()
				latest = st
				stMu.Unlock()
			}
		}
	}()
	status := func() (running, parked uint32, ok bool) {
		stMu.Lock()
		defer stMu.Unlock()
		if latest == nil {
			return 0, 0, false
		}
		return latest.GetRunning(), latest.GetParked(), true
	}

	var fs []*fib
	for i := 0; i < o.fibers; i++ {
		r, err := api.Clone(ctx, &grantv1.CloneRequest{GrantJwt: tok, Session: fmt.Sprintf("s%d", i)})
		if err != nil {
			return fatal("clone s%d: %v", i, err)
		}
		fs = append(fs, &fib{id: r.GetFiberId(), endpoint: r.GetEndpoint()})
	}
	fmt.Printf("storm: %d fibers running; dirtying %dMiB per round per fiber\n", len(fs), o.step>>20)

	start := time.Now()
	var firstPark time.Time
	var firstParkPSI float64
	var maxCurrent uint64
	fmt.Printf("%8s %10s %8s %8s %8s %10s\n", "t", "grant.cur", "psi", "running", "parked", "demand")
	for time.Since(start) < o.timeout {
		// One round: every live fiber dirties one more step, concurrently,
		// each with a short timeout so throttled ones do not stall the
		// timeline.
		var wg sync.WaitGroup
		allDone := true
		for _, f := range fs {
			if f.gone || f.dirtied >= perFiber {
				continue
			}
			allDone = false
			f.dirtied += o.step
			wg.Add(1)
			go func(f *fib) {
				defer wg.Done()
				if err := say(f.endpoint, fmt.Sprintf("dirty %d", f.dirtied), time.Second); err != nil {
					// A unix endpoint whose socket is gone was parked or
					// killed; a tcp endpoint that refuses the connection
					// is the same. A timeout is a fiber throttled under
					// memory.high, which is the ladder working: keep it.
					var dialErr *dialError
					switch p := endpoint.UnixPath(f.endpoint); {
					case p != "":
						if _, statErr := os.Stat(p); statErr != nil {
							f.gone = true
						}
					case errors.As(err, &dialErr) && !dialErr.timeout:
						f.gone = true
					}
				}
			}(f)
		}
		wg.Wait()
		cur, _ := grantCG.MemoryCurrent()
		if cur > maxCurrent {
			maxCurrent = cur
		}
		psi, _ := grantCG.PSI()
		running, parked, _ := status()
		var demand uint64
		for _, f := range fs {
			demand += f.dirtied
		}
		fmt.Printf("%8s %8dMiB %7.1f%% %8d %8d %8dMiB\n", time.Since(start).Round(100*time.Millisecond),
			cur>>20, psi.SomeAvg10, running, parked, demand>>20)
		if parked > 0 && firstPark.IsZero() {
			firstPark = time.Now()
			firstParkPSI = psi.SomeAvg10
		}
		if allDone || running == 0 {
			break
		}
		time.Sleep(o.round)
	}
	time.Sleep(2 * time.Second) // let the ladder settle
	running, parked, ok := status()
	oomAfter := oomKills(o.rootEvents)
	fmt.Println()
	fmt.Printf("storm: max grant memory.current = %d MiB (ceiling %d MiB); container OOM kills before=%d after=%d\n",
		maxCurrent>>20, o.ceiling>>20, oomBefore, oomAfter)
	if !firstPark.IsZero() {
		fmt.Printf("storm: first park observed at t=%s with PSI some avg10 = %.1f%%\n", firstPark.Sub(start).Round(100*time.Millisecond), firstParkPSI)
	}
	fmt.Printf("storm: final ledger: running=%d parked=%d\n", running, parked)
	rc := 0
	if oomAfter > oomBefore {
		fmt.Println("storm: FAIL container recorded an OOM kill: the ladder lost the race")
		rc = 1
	}
	if firstPark.IsZero() {
		fmt.Println("storm: FAIL no fiber was parked")
		rc = 1
	}
	if !ok {
		fmt.Println("storm: FAIL no status from the agent (did it die?)")
		rc = 1
	}
	if rc == 0 {
		fmt.Println("storm: PASS park fired before any OOM kill")
	}
	return rc
}

// dialError is a failure to reach the endpoint at all, with whether it
// was the dial timing out (throttled) or being refused (gone).
type dialError struct {
	err     error
	timeout bool
}

func (e *dialError) Error() string { return e.err.Error() }
func (e *dialError) Unwrap() error { return e.err }

// say sends one line to a fiber endpoint and waits for the reply.
func say(ep, line string, to time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), to)
	defer cancel()
	c, err := endpoint.Dial(ctx, ep)
	if err != nil {
		var ne net.Error
		return &dialError{err: err, timeout: errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())}
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(to))
	if _, err := fmt.Fprintln(c, line); err != nil {
		return err
	}
	_, err = bufio.NewReader(c).ReadString('\n')
	return err
}

func oomKills(path string) uint64 {
	n, _ := cgroup.Root(filepath.Dir(path)).OOMKills()
	return n
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func fatal(format string, args ...any) int {
	fmt.Fprintf(os.Stderr, "storm: "+format+"\n", args...)
	return 2
}
