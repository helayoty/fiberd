package fiberd_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Azure/fiberd/pkg/fiberd"
)

// TestHealthzAudit runs fiberd and poisons its audit spool. The admin
// socket and the JSON gateway then answer /healthz with 503 and
// "poisoned", without the fsync error. Config.Healthz and Config.Readyz
// report it. A healthy spool answers 200 with "ok". The lane key stays
// in the body, so the two are read apart. The admin socket's /readyz
// answers the same while fiberd is not draining.
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
			fiberd.SetAuditHealth(c, func() error {
				if p := poison.Load(); p != nil {
					return *p
				}
				return nil
			})
			r := start(t, c, fiberd.Standalone)
			// The spool fails while fiberd runs, as a real fsync does.
			if tc.poison != nil {
				poison.Store(&tc.poison)
			}
			code, admin := adminDo(t, c, http.MethodGet, "/healthz", "")
			rcode, ready := adminDo(t, c, http.MethodGet, "/readyz", "")
			var gw map[string]any
			gcode := getJSON(t, http.DefaultClient, "http://"+r.http.String()+"/healthz", &gw)
			for face, got := range map[string]struct {
				code int
				body map[string]any
			}{"admin socket": {code, admin}, "admin readyz": {rcode, ready}, "gateway": {gcode, gw}} {
				if got.code != tc.status || got.body["audit"] != tc.audit || got.body["issuerReachable"] != true || got.body["draining"] != nil {
					t.Fatalf("%s healthz = %d %v, want %d with audit %q and a healthy lane", face, got.code, got.body, tc.status, tc.audit)
				}
			}
			for probe, check := range map[string]func(context.Context) error{"Healthz": c.Healthz, "Readyz": c.Readyz} {
				err := check(context.Background())
				if tc.poison == nil && err != nil || tc.poison != nil && (err == nil || !strings.Contains(err.Error(), tc.audit)) {
					t.Fatalf("%s = %v, want the audit state %q", probe, err, tc.audit)
				}
			}
		})
	}
}

// TestProbe serves a fake admin socket and checks what Config.Healthz
// and Config.Readyz make of each answer. A 200 is nil. A 503 is an error
// that names the probe and keeps the body, so a draining fiberd reads
// apart from a poisoned spool. A socket nobody serves is an error too.
func TestProbe(t *testing.T) {
	cases := []struct {
		name  string
		probe string // Healthz or Readyz
		// path is the path the fake answers. Others are 404.
		path   string
		status int
		body   string
		down   bool // nothing listens on the admin socket
		want   []string
	}{
		{name: "healthz 200 is nil", probe: "Healthz", path: "/healthz", status: http.StatusOK, body: `{"audit":"ok"}`},
		{name: "healthz 503 keeps the body", probe: "Healthz", path: "/healthz", status: http.StatusServiceUnavailable,
			body: `{"audit":"poisoned"}`, want: []string{"healthz: ", "503", "poisoned"}},
		{name: "healthz unreachable", probe: "Healthz", down: true, want: []string{"healthz: "}},
		{name: "readyz 200 is nil", probe: "Readyz", path: "/readyz", status: http.StatusOK, body: `{"audit":"ok"}`},
		{name: "readyz 503 while draining", probe: "Readyz", path: "/readyz", status: http.StatusServiceUnavailable,
			body: `{"audit":"ok","draining":true}`, want: []string{"readyz: ", "503", `"draining":true`}},
		{name: "readyz 503 on a poisoned spool", probe: "Readyz", path: "/readyz", status: http.StatusServiceUnavailable,
			body: `{"audit":"poisoned"}`, want: []string{"readyz: ", "503", "poisoned"}},
		{name: "readyz unreachable", probe: "Readyz", down: true, want: []string{"readyz: "}},
		{name: "readyz asks /readyz, not /healthz", probe: "Readyz", path: "/healthz", status: http.StatusOK,
			want: []string{"readyz: ", "404"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newConfig(t, stateDir(t))
			if !tc.down {
				serveAdmin(t, c.AdminSocket(), tc.path, tc.status, tc.body)
			}
			check := map[string]func(context.Context) error{"Healthz": c.Healthz, "Readyz": c.Readyz}[tc.probe]
			err := check(context.Background())
			if len(tc.want) == 0 {
				if err != nil {
					t.Fatalf("%s = %v, want nil", tc.probe, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("%s = nil, want an error with %q", tc.probe, tc.want)
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Fatalf("%s = %q, want it to contain %q", tc.probe, err, w)
				}
			}
		})
	}
}

// serveAdmin answers GET path on a unix socket at sock with status and
// body, until the test ends.
func serveAdmin(t *testing.T, sock, path string, status int, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(sock), 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+path, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
}
