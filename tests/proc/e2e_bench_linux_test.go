//go:build linux

package proctest

import (
	"context"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/helayoty/fiberd/pkg/backend"
	procbackend "github.com/helayoty/fiberd/pkg/backend/proc"
	"github.com/helayoty/fiberd/pkg/consumer"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/rpc"
	"github.com/helayoty/fiberd/pkg/runtime/host"
)

// TestE2ECloneNumbers measures Clone as a consumer sees it, over gRPC on
// loopback TCP with a JWKS-verified grant and the agent, host runtime and
// fork backend wired as fiberd wires them. It prints numbers rather than
// asserting them, and splits each round trip into stages keyed by fiber.
//
//	host     host runtime work around the backend, such as the cgroup
//	         leaf, run directory and endpoint
//	zygote   CLONE to CLONED on the control socket, with any wait behind
//	         other clones
//	audit    the create record, also fsynced when durability is sync
//	agent    everything else, including verify, which is also shown alone
//
// FIBERD_BENCH=1 enables it. The audit spool and snapshot live in
// FIBERD_BENCH_STATE. Point it at a disk to see what a sync record costs,
// because /tmp in the dev container is a tmpfs where fsync is free. The
// transport is plaintext, because the mutual TLS handshake is per
// connection, not per clone.
func TestE2ECloneNumbers(t *testing.T) {
	if os.Getenv("FIBERD_BENCH") == "" {
		t.Skip("set FIBERD_BENCH=1 to run the end-to-end clone measurement")
	}
	cases := []struct {
		name       string
		durability core.Durability
		clones     int  // per round
		burst      bool // issue a round's clones at once, otherwise one after another
		rounds     int  // bursts, each released before the next
		noStore    bool // run without the ledger snapshot store
	}{
		{name: "sequential, best-effort audit", durability: core.BestEffort, clones: 100, rounds: 1},
		{name: "sequential, sync audit", durability: core.Sync, clones: 100, rounds: 1},
		{name: "sequential, best-effort audit, no snapshot store", durability: core.BestEffort, clones: 100, rounds: 1, noStore: true},
		{name: "50-way burst, best-effort audit", durability: core.BestEffort, clones: 50, burst: true, rounds: 5},
		{name: "50-way burst, sync audit", durability: core.Sync, clones: 50, burst: true, rounds: 5},
		{name: "50-way burst, best-effort audit, no snapshot store", durability: core.BestEffort, clones: 50, burst: true, rounds: 5, noStore: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newE2EHome(t, !tc.noStore)
			ctx := context.Background()
			tok := h.mint(t, tc.durability)
			clone := func() (consumer.Fiber, time.Duration, error) {
				start := time.Now()
				f, err := h.client.Clone(ctx, tok, "", 5*time.Second, nil)
				return f, time.Since(start), err
			}

			// The first clone admits the grant, boots the zygote and
			// fetches the JWKS. That is paid once per grant and reported apart.
			f, d, err := clone()
			if err != nil {
				t.Fatalf("first clone: %v", err)
			}
			t.Logf("first clone (admit, warm template, JWKS fetch): %s", d.Round(time.Millisecond))
			if err := h.client.Release(ctx, f.ID, false); err != nil {
				t.Fatal(err)
			}
			h.clock.take()

			// Round trips by fiber. Releases stamp nothing, so a
			// sequential run releases as it goes and a burst releases
			// its round before the next.
			var mu sync.Mutex
			rtt := make(map[string]time.Duration)
			var walls []time.Duration
			for r := 0; r < tc.rounds; r++ {
				var fibers []string
				var wg sync.WaitGroup
				start := time.Now()
				for i := 0; i < tc.clones; i++ {
					one := func(i int) {
						f, d, err := clone()
						if err != nil {
							t.Errorf("round %d clone %d: %v", r, i, err)
							return
						}
						mu.Lock()
						rtt[f.ID] = d
						fibers = append(fibers, f.ID)
						mu.Unlock()
						if !tc.burst {
							if err := h.client.Release(ctx, f.ID, false); err != nil {
								t.Errorf("release %s: %v", f.ID, err)
							}
						}
					}
					if !tc.burst {
						one(i)
						continue
					}
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						one(i)
					}(i)
				}
				wg.Wait()
				walls = append(walls, time.Since(start))
				if tc.burst {
					for _, id := range fibers {
						_ = h.client.Release(ctx, id, false)
					}
				}
			}
			breakdown(t, rtt, h.clock.take())
			if tc.burst {
				report(t, fmt.Sprintf("burst wall time (%d rounds of %d)", tc.rounds, tc.clones), walls)
			}
		})
	}
}

// breakdown reports the round trips and how each splits across stages.
func breakdown(t *testing.T, rtt map[string]time.Duration, stamps []stamp) {
	t.Helper()
	by := make(map[string]map[string]time.Duration)
	var verify []time.Duration
	for _, s := range stamps {
		if s.stage == stageVerify {
			verify = append(verify, s.d)
			continue
		}
		if by[s.stage] == nil {
			by[s.stage] = make(map[string]time.Duration)
		}
		by[s.stage][s.fiber] += s.d
	}
	var total, hostPrep, zygote, audit, agent []time.Duration
	for id, d := range rtt {
		rt, zy, au := by[stageRuntime][id], by[stageZygote][id], by[stageAudit][id]
		total = append(total, d)
		hostPrep = append(hostPrep, rt-zy)
		zygote = append(zygote, zy)
		audit = append(audit, au)
		agent = append(agent, d-rt-au)
	}
	report(t, fmt.Sprintf("client round trip (n=%d)", len(total)), total)
	report(t, "  host", hostPrep)
	report(t, "  zygote", zygote)
	report(t, "  audit", audit)
	report(t, "  agent", agent)
	report(t, "    of which verify", verify)
}

// Stages the timed seams record.
const (
	stageVerify  = "verify"
	stageRuntime = "runtime"
	stageZygote  = "zygote"
	stageAudit   = "audit"
)

// stamp is one timed stage of the clone that births fiber.
type stamp struct {
	stage, fiber string
	d            time.Duration
}

// stageClock collects stamps until they are taken.
type stageClock struct {
	mu     sync.Mutex
	stamps []stamp
}

func (c *stageClock) since(stage, fiber string, start time.Time) {
	d := time.Since(start)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stamps = append(c.stamps, stamp{stage: stage, fiber: fiber, d: d})
}

// take returns what was recorded and starts over.
func (c *stageClock) take() []stamp {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stamps
	c.stamps = nil
	return s
}

// The timed seams embed the concrete types, so every optional interface
// the agent or the host runtime looks for is still there.
type timedVerifier struct {
	core.Verifier
	clock *stageClock
}

func (v timedVerifier) Verify(ctx context.Context, token []byte) (core.Grant, error) {
	defer v.clock.since(stageVerify, "", time.Now())
	return v.Verifier.Verify(ctx, token)
}

type timedRuntime struct {
	*host.Runtime
	clock *stageClock
}

func (r timedRuntime) Clone(ctx context.Context, spec core.CloneSpec) (core.FiberHandle, error) {
	defer r.clock.since(stageRuntime, spec.Fence.String(), time.Now())
	return r.Runtime.Clone(ctx, spec)
}

type timedBackend struct {
	*procbackend.Backend
	clock *stageClock
}

func (b timedBackend) Clone(ctx context.Context, warmID string, spec backend.FiberSpec) (backend.Fiber, error) {
	defer b.clock.since(stageZygote, spec.Fence, time.Now())
	return b.Backend.Clone(ctx, warmID, spec)
}

// timedAuditor times only create records. Exits and releases write
// records of their own that are no clone's cost.
type timedAuditor struct {
	core.Auditor
	clock *stageClock
}

func (a timedAuditor) Append(ctx context.Context, d core.Durability, rec core.AuditRecord) error {
	if rec.Event != core.ActCreate.String() {
		return a.Auditor.Append(ctx, d, rec)
	}
	defer a.clock.since(stageAudit, rec.FiberID, time.Now())
	return a.Auditor.Append(ctx, d, rec)
}

const benchNode = "bench-node"

// e2eHome is one fiberd home behind a gRPC listener, with its own issuer.
type e2eHome struct {
	client *consumer.Client
	issuer *grant.Issuer
	clock  *stageClock
}

// newE2EHome wires a home as pkg/agent does for -runtime proc
// -verifier jwks, with the timed seams in place. store adds the ledger
// snapshot store fiberd keeps under its state directory.
func newE2EHome(t *testing.T, store bool) *e2eHome {
	t.Helper()
	clock := &stageClock{}
	// The run directory holds unix sockets, so its path must stay short.
	run, err := os.MkdirTemp("/tmp", "fz-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(run) })
	rt, err := newHost(host.Config{
		Backend:    timedBackend{Backend: procbackend.New(procbackend.Options{}).(*procbackend.Backend), clock: clock},
		Templates:  map[string]string{"default": zygoteBin + " --heap-mb 32"},
		CgroupRoot: filepath.Join(cgRoot, fmt.Sprintf("e%d-%d", os.Getpid(), time.Now().UnixNano()%1_000_000)),
		RunDir:     run,
	})
	if err != nil {
		t.Fatal(err)
	}
	hr := rt.(*host.Runtime)
	t.Cleanup(hr.Close)

	key, err := grant.GenerateKey(jose.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	is := &grant.Issuer{Key: key}
	srv := httptest.NewServer(is.Handler())
	t.Cleanup(srv.Close)
	is.URL = srv.URL

	state := t.TempDir()
	if base := os.Getenv("FIBERD_BENCH_STATE"); base != "" {
		if state, err = os.MkdirTemp(base, "e2e-"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(state) })
	}
	spool, err := core.OpenSpool(state, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = spool.Close() })
	ag := &core.Agent{
		NodeID:  benchNode,
		Ledger:  core.NewLedger(1),
		Budget:  core.NewBudget(core.DefaultBaseRate, core.DefaultRefW), // fiberd's thrash budget
		Runtime: timedRuntime{Runtime: hr, clock: clock},
		Audit:   timedAuditor{Auditor: spool, clock: clock},
		Verify:  timedVerifier{Verifier: &grant.Verifier{Cache: &grant.Cache{IssuerURL: srv.URL}, Audience: benchNode}, clock: clock},
		Health:  core.NewSourceHealth(time.Hour, time.Now()),
	}
	if store {
		ag.Store = &core.SnapshotStore{Path: filepath.Join(state, "ledger.json")}
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go ag.Run(ctx)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := rpc.NewGRPCServer(&rpc.Server{Agent: ag, Issuer: srv.URL, RetryAfter: time.Second})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	c, err := consumer.Dial(ctx, lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &e2eHome{client: c, issuer: is, clock: clock}
}

// mint signs a trusted grant for the reference template with no fiber
// cap, so the measurement never meets a capacity miss.
func (h *e2eHome) mint(t *testing.T, d core.Durability) string {
	t.Helper()
	tok, err := h.issuer.Mint(core.Grant{
		UID: fmt.Sprintf("bench-%d", time.Now().UnixNano()), Audience: benchNode, TemplateDigest: "sha256:ref",
		LeaseExpiry: time.Now().Add(time.Hour).Truncate(time.Second),
		Policy:      core.Policy{Durability: d, Isolation: core.Trusted},
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}
