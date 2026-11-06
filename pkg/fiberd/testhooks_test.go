//go:build fiberd_testhooks

package fiberd_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grantv1 "github.com/Azure/fiberd/api/grant/v1"
	"github.com/Azure/fiberd/pkg/fiberd"
	"github.com/Azure/fiberd/pkg/grant"
	"github.com/Azure/fiberd/pkg/home"
)

// TestTimingFlags checks that the testhooks build binds the cadence flags
// on Timing, which no flag reaches in a release build.
func TestTimingFlags(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		want    fiberd.Timing
		wantErr string
	}{
		{name: "unset is the core's default"},
		{name: "both cadences", args: []string{"-status-interval", "50ms", "-pressure-interval", "200ms"},
			want: fiberd.Timing{StatusEvery: 50 * time.Millisecond, PressureEvery: 200 * time.Millisecond}},
		{name: "a negative pressure interval turns the ladder off", args: []string{"-pressure-interval", "-1s"},
			want: fiberd.Timing{PressureEvery: -time.Second}},
		{name: "a bad duration is refused", args: []string{"-status-interval", "soon"}, wantErr: "invalid value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := parse(tc.args...)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("parse: %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || c.Timing != tc.want {
				t.Fatalf("Timing = %+v, %v, want %+v", c.Timing, err, tc.want)
			}
		})
	}
}

// TestAdminUnsafeSelfAdmit checks that -admin-unsafe lifts the home's
// self-admit UID, and that a testhooks build without the flag keeps it.
func TestAdminUnsafeSelfAdmit(t *testing.T) {
	cases := []struct {
		name   string
		unsafe bool
		want   codes.Code
	}{
		{name: "another UID is refused without -admin-unsafe", want: codes.Unauthenticated},
		{name: "-admin-unsafe admits another UID", unsafe: true, want: codes.OK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var args []string
			if tc.unsafe {
				args = append(args, "-admin-unsafe")
			}
			r := start(t, newConfig(t, stateDir(t), args...), selfAdmitting("own"))
			_, err := dial(t, r.grpc, nil).Clone(context.Background(),
				&grantv1.CloneRequest{GrantJwt: jsonGrant(t, testGrant("foreign"))})
			if status.Code(err) != tc.want {
				t.Fatalf("Clone of another UID: %v, want %v", err, tc.want)
			}
			if err := r.stop(t); err != nil {
				t.Fatal(err)
			}
			noRunGoroutines(t)
		})
	}
}

// bareHome is a home without an issuer override. Embedding home.Home
// promotes only the interface's methods, so SetIssuerReachable is not one of them.
type bareHome struct{ home.Home }

// TestAdminControls checks that the test-only admin controls refuse unless
// fiberd runs with -admin-unsafe. With it, POST /issuer drives the home
// lane and POST /scope-lost bumps the epoch.
func TestAdminControls(t *testing.T) {
	cases := []struct {
		name       string
		unsafe     bool
		bare       bool // the home has no issuer override
		breakEpoch bool // the epoch cannot be persisted
		path, body string
		wantCode   int
		want       map[string]any // fields of the reply
		wantBump   uint64         // how far the epoch moves
	}{
		{name: "issuer refused without -admin-unsafe", path: "/issuer", body: `{"reachable":false}`, wantCode: http.StatusForbidden},
		{name: "scope-lost refused without -admin-unsafe", path: "/scope-lost", wantCode: http.StatusForbidden},
		{name: "issuer with a bad body", unsafe: true, path: "/issuer", body: `{"reachable":`, wantCode: http.StatusBadRequest},
		{name: "issuer on a home without an override", unsafe: true, bare: true, path: "/issuer", body: `{"reachable":false}`,
			wantCode: http.StatusNotImplemented},
		{name: "issuer down", unsafe: true, path: "/issuer", body: `{"reachable":false}`, wantCode: http.StatusOK,
			want: map[string]any{"issuerReachable": false}},
		{name: "issuer up", unsafe: true, path: "/issuer", body: `{"reachable":true}`, wantCode: http.StatusOK,
			want: map[string]any{"issuerReachable": true}},
		{name: "scope-lost bumps the epoch", unsafe: true, path: "/scope-lost", wantCode: http.StatusOK, wantBump: 1},
		{name: "scope-lost with an unwritable epoch", unsafe: true, breakEpoch: true, path: "/scope-lost",
			wantCode: http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := stateDir(t)
			nh := fiberd.Standalone
			if tc.bare {
				nh = func(c *fiberd.Config, jwks *grant.Cache) (home.Home, error) {
					h, err := fiberd.Standalone(c, jwks)
					return bareHome{h}, err
				}
			}
			var args []string
			if tc.unsafe {
				args = append(args, "-admin-unsafe")
			}
			r := start(t, newConfig(t, state, args...), nh)
			before := epochOf(t, r.c)
			if tc.breakEpoch {
				epoch := filepath.Join(state, "private", "epoch")
				if err := os.Remove(epoch); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Join(epoch, "x"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			code, out := adminDo(t, r.c, http.MethodPost, tc.path, tc.body)
			if code != tc.wantCode {
				t.Fatalf("POST %s = %d, want %d", tc.path, code, tc.wantCode)
			}
			for k, v := range tc.want {
				if out[k] != v {
					t.Fatalf("reply %s = %v, want %v (%v)", k, out[k], v, out)
				}
			}
			after := epochOf(t, r.c)
			if after != before+tc.wantBump {
				t.Fatalf("epoch %d -> %d, want +%d", before, after, tc.wantBump)
			}
			if tc.wantBump > 0 && out["epoch"] != float64(after) {
				t.Fatalf("reply epoch %v, want %d", out["epoch"], after)
			}
			if err := r.stop(t); err != nil {
				t.Fatal(err)
			}
			noRunGoroutines(t)
		})
	}
}
