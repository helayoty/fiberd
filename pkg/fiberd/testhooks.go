//go:build fiberd_testhooks

package fiberd

import (
	"encoding/json"
	"flag"
	"net/http"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/home"
)

// IssuerReachableSetter is the override behind POST /issuer. A home
// implements it to take part.
type IssuerReachableSetter interface{ SetIssuerReachable(reachable bool) }

// testHooks are the test-only admin controls, built only with the
// fiberd_testhooks tag. A release binary has neither -admin-unsafe nor
// the handlers behind it, nor the cadence flags (see testhooks_off.go).
type testHooks struct{ adminUnsafe bool }

// bind adds -admin-unsafe and the cadence flags on timing, which the
// conformance runs turn down so the suite finishes in seconds.
func (t *testHooks) bind(fs *flag.FlagSet, timing *Timing) {
	fs.BoolVar(&t.adminUnsafe, "admin-unsafe", false, "enable test-only admin controls (POST /issuer, POST /scope-lost)")
	fs.DurationVar(&timing.StatusEvery, "status-interval", 0, "W sampling and Watch cadence (0 is one second)")
	fs.DurationVar(&timing.PressureEvery, "pressure-interval", 0, "pressure ladder evaluation cadence (0 is one second, negative disables the ladder)")
}

// register adds POST /issuer and POST /scope-lost to the admin socket.
// Both refuse unless fiberd was started with -admin-unsafe.
func (t *testHooks) register(admin *http.ServeMux, h home.Home, c *core.Core, healthz func() map[string]any) {
	admin.HandleFunc("POST /issuer", func(w http.ResponseWriter, r *http.Request) {
		if !t.adminUnsafe {
			http.Error(w, "admin controls disabled; start with -admin-unsafe", http.StatusForbidden)
			return
		}
		var body struct {
			Reachable bool `json:"reachable"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		setter, ok := h.(IssuerReachableSetter)
		if !ok {
			http.Error(w, "home "+h.Name()+" has no issuer override", http.StatusNotImplemented)
			return
		}
		setter.SetIssuerReachable(body.Reachable)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(healthz())
	})
	admin.HandleFunc("POST /scope-lost", func(w http.ResponseWriter, r *http.Request) {
		// A stand-in for a scope the home can lose while running, as a
		// Kubernetes home does when its namespace, issuer or claim goes
		// away under it.
		if !t.adminUnsafe {
			http.Error(w, "admin controls disabled; start with -admin-unsafe", http.StatusForbidden)
			return
		}
		epoch, err := c.BumpEpoch(r.Context(), "scope lost (admin)")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]uint64{"epoch": epoch})
	})
}
