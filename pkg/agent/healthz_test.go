package agent_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/helayoty/fiberd/pkg/agent"
)

// TestHealthzAudit runs the agent and poisons its audit spool. The admin
// socket and the JSON gateway then answer /healthz with 503 and
// "poisoned", without the fsync error, and Config.Healthz reports it. A healthy spool answers 200 with
// "ok". The lane key stays in the body, so the two are read apart.
func TestHealthzAudit(t *testing.T) {
	cases := []struct {
		name   string
		poison error
		status int
		audit  string
	}{
		{name: "a healthy spool is 200 and ok", status: http.StatusOK, audit: "ok"},
		{name: "a poisoned spool is 503 without the fsync error", poison: errors.New("sync audit.jsonl: input/output error"),
			status: http.StatusServiceUnavailable, audit: "poisoned"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var poison atomic.Pointer[error]
			c := newConfig(t, stateDir(t), "-http", "127.0.0.1:0")
			agent.SetAuditHealth(c, func() error {
				if p := poison.Load(); p != nil {
					return *p
				}
				return nil
			})
			r := start(t, c, agent.Standalone)
			// The spool fails while the agent runs, as a real fsync does.
			if tc.poison != nil {
				poison.Store(&tc.poison)
			}
			code, admin := adminDo(t, c, http.MethodGet, "/healthz", "")
			var gw map[string]any
			gcode := getJSON(t, http.DefaultClient, "http://"+r.http.String()+"/healthz", &gw)
			for face, got := range map[string]struct {
				code int
				body map[string]any
			}{"admin socket": {code, admin}, "gateway": {gcode, gw}} {
				if got.code != tc.status || got.body["audit"] != tc.audit || got.body["grantLaneHealthy"] != true {
					t.Fatalf("%s healthz = %d %v, want %d with audit %q and a healthy lane", face, got.code, got.body, tc.status, tc.audit)
				}
			}
			err := c.Healthz(context.Background())
			if tc.poison == nil && err != nil || tc.poison != nil && (err == nil || !strings.Contains(err.Error(), tc.audit)) {
				t.Fatalf("Healthz = %v, want the audit state %q", err, tc.audit)
			}
		})
	}
}
