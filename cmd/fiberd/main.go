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
	}

	ag := &core.Agent{
		Ledger:  led,
		Budget:  core.NewBudget(baseRate(), 256<<20), // placeholders until the rig speaks
		Runtime: rt,
		Audit:   nopAudit{},
		Verify:  k8s.JWKSVerifier{},
		SandboxFor: func(uid string) (string, bool) {
			return "sbx-" + uid, true // stub; adapters own this mapping
		},
	}

	// Async lane: grants in. Skeleton feeds one grant by hand.
	src := &k8s.Source{Events: make(chan adapter.GrantEvent, 1)}
	src.Events <- adapter.GrantEvent{Kind: adapter.GrantAdded,
		Grant: adapter.Grant{UID: "demo", FiberMax: 128, SandboxID: "sbx-demo"}}
	go func() {
		ch, _ := src.Watch(context.Background())
		for ev := range ch {
			switch ev.Kind {
			case adapter.GrantAdded:
				led.AdmitGrant(ev.Grant.UID, ev.Grant.SandboxID, ev.Grant.FiberMax)
			case adapter.GrantRevoked:
				led.RevokeGrant(ev.Grant.UID)
			}
		}
	}()

	// Readiness + epoch introspection: poll this before driving load.
	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]uint64{"epoch": ep.Current()})
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
