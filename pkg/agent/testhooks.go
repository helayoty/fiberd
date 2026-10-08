//go:build fiberd_testhooks

package agent

import (
	"encoding/json"
	"flag"
	"net/http"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/home"
)

// LaneSetter is the lane override behind POST /lane. A home implements
// it to take part.
type LaneSetter interface{ SetLane(healthy bool) }

// testHooks are the test-only admin controls, built only with the
// fiberd_testhooks tag. A release binary has neither -admin-unsafe nor
// the handlers behind it (see testhooks_off.go).
type testHooks struct{ adminUnsafe bool }

func (t *testHooks) bind(fs *flag.FlagSet) {
	fs.BoolVar(&t.adminUnsafe, "admin-unsafe", false, "enable test-only admin controls (POST /lane, POST /scope-lost)")
}

// register adds POST /lane and POST /scope-lost to the admin socket.
// Both refuse unless the agent was started with -admin-unsafe.
func (t *testHooks) register(admin *http.ServeMux, h home.Home, ag *core.Agent, healthz func() map[string]any) {
	admin.HandleFunc("POST /lane", func(w http.ResponseWriter, r *http.Request) {
		if !t.adminUnsafe {
			http.Error(w, "admin controls disabled; start with -admin-unsafe", http.StatusForbidden)
			return
		}
		var body struct {
			Healthy bool `json:"healthy"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		lane, ok := h.(LaneSetter)
		if !ok {
			http.Error(w, "home "+h.Name()+" has no lane override", http.StatusNotImplemented)
			return
		}
		lane.SetLane(body.Healthy)
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
		epoch, err := ag.BumpEpoch(r.Context(), "scope lost (admin)")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]uint64{"epoch": epoch})
	})
}
