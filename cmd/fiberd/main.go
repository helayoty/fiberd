package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"fiberd/pkg/adapter"
	"fiberd/pkg/core"
	"fiberd/pkg/k8s"
	"fiberd/pkg/runtime/stub"
)

// nopAudit discards every audit event.
//
// TODO(poc): this is a stand-in, not the audit spool the contract requires.
// core.Auditor is specified as "append-locally, ship-async", and under
// durability SYNC Append must not return until the record is remote (Clone
// acks after it). nopAudit persists nothing and always returns nil, so SYNC
// grants get no durability guarantee and BEST_EFFORT grants leave no local
// trail. Implement a real Auditor: append to a local durable spool, ship
// asynchronously to the audit sink, and block in Append only under SYNC until
// the record is durable/remote.
type nopAudit struct{}

func (nopAudit) Append(context.Context, string, core.Fence, string) error { return nil }

// baseRate reads FIBERD_BASE_RATE (clones/sec) so demos can pick a budget
// small enough to actually trip; default matches the placeholder curve.
func baseRate() float64 {
	if v := os.Getenv("FIBERD_BASE_RATE"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			return f
		}
	}
	return 200
}

func main() {
	dir := os.Getenv("FIBERD_STATE")
	if dir == "" {
		dir = "/var/lib/fiberd"
	}
	_ = os.MkdirAll(dir, 0o700)

	// Startup order is fixed: epoch++ → CRI reconcile → open RPC.
	// The agent serves nothing until its view of the node is real.
	ep, err := core.OpenEpochStore(dir)
	if err != nil {
		log.Fatalf("epoch: %v", err)
	}
	log.Printf("fiberd epoch=%d (all prior fences invalid)", ep.Current())

	rt := stub.New()
	led := core.NewLedger(ep.Current())
	if fibers, err := rt.List(context.Background(), ""); err == nil {
		// Reconcile: reality wins; orphans from the previous epoch would be
		// reaped here (stub starts empty).
		log.Printf("reconcile: %d fibers running", len(fibers))
		// TODO(poc): this is a log line, not a reconcile. The Ledger doc
		// comment promises authoritative state "rebuilt at startup from
		// Runtime.List reconciled against the on-disk snapshot, discrepancies
		// resolving in favor of what is actually running." None of that
		// happens: there is no on-disk snapshot of grants/sessions/fibers, so
		// nothing is reloaded into `led`, and orphaned instances from a prior
		// epoch are neither adopted nor torn down. Implement (1) a durable
		// snapshot of the ledger (grants, sessions with fences, fiber refs)
		// persisted under FIBERD_STATE, and (2) a reconcile that seeds `led`
		// from the snapshot, matches it against rt.List, and reaps runtime
		// instances with no live grant.
	}

	staleTTL := 30 * time.Second
	if v := os.Getenv("FIBERD_STALE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			staleTTL = d
		}
	}
	laneDies := time.Duration(0) // FIBERD_LANE_DIES_AFTER, e.g. "5s"; 0 = never
	if v := os.Getenv("FIBERD_LANE_DIES_AFTER"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			laneDies = d
		}
	}
	fiberMax := 128
	if v := os.Getenv("FIBERD_DEMO_MAX"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			fiberMax = n
		}
	}
	log.Printf("staleTTL=%s laneDies=%s fiberMax=%d", staleTTL, laneDies, fiberMax)
	health := core.NewSourceHealth(staleTTL, time.Now())

	ag := &core.Agent{
		Ledger:  led,
		Budget:  core.NewBudget(baseRate(), 256<<20), // placeholders until the rig speaks
		Runtime: rt,
		Audit:   nopAudit{},
		Verify:  k8s.JWKSVerifier{},
		Health:  health,
		SandboxFor: func(uid string) (string, bool) {
			return "sbx-" + uid, true // stub; adapters own this mapping
		},
	}

	// Async lane: grants in. Skeleton feeds one grant by hand.
	src := &k8s.Source{Events: make(chan adapter.GrantEvent, 1)}
	src.Events <- adapter.GrantEvent{Kind: adapter.GrantAdded,
		Grant: adapter.Grant{UID: "demo", FiberMax: fiberMax, SandboxID: "sbx-demo"}}
	go func() {
		ch, err := src.Watch(context.Background())
		if err != nil {
			return
		}
		health.MarkSync(time.Now()) // watch established: idle is not unreachability
		// This source has no wire heartbeat; tick while the watch is held.
		// A real informer replaces the ticker with relist / watch errors.
		tick := time.NewTicker(staleTTL / 2)
		defer tick.Stop()
		var deadCh <-chan time.Time
		if laneDies > 0 {
			deadCh = time.After(laneDies)
		}
		for {
			select {
			case ev, ok := <-ch:
				if !ok {
					return // watch gone; lastSync stops advancing → stale
				}
				health.MarkSync(time.Now())
				switch ev.Kind {
				case adapter.GrantAdded:
					led.AdmitGrant(ev.Grant.UID, ev.Grant.SandboxID, ev.Grant.FiberMax)
				case adapter.GrantRevoked:
					led.RevokeGrant(ev.Grant.UID)
				}
			case <-tick.C:
				health.MarkSync(time.Now())
			case <-deadCh:
				log.Printf("grant lane simulated death (FIBERD_LANE_DIES_AFTER=%s)", laneDies)
				return
			}
		}
	}()

	// Readiness + epoch introspection: poll this before driving load.
	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"epoch":            ep.Current(),
			"grantLaneHealthy": health.Healthy(time.Now()),
		})
	})

	// Warm path. JSON/HTTP in the skeleton; gRPC + mTLS in the real agent.
	http.HandleFunc("/v0/clone", func(w http.ResponseWriter, r *http.Request) {
		var req core.CloneRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Deadline == 0 {
			req.Deadline = 10 * time.Millisecond
		}
		resp, code, err := ag.Clone(r.Context(), []byte(r.Header.Get("Authorization")), req)
		switch code {
		case core.Shed:
			w.Header().Set("Retry-After", "1")
			http.Error(w, err.Error(), http.StatusTooManyRequests)
		case core.DeferredFallback:
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
		default:
			_ = json.NewEncoder(w).Encode(resp)
		}
	})

	log.Println("fiberd warm path on :8484 — apiserver not required beyond this point")
	log.Fatal(http.ListenAndServe(":8484", nil))
}
