//go:build !fiberd_testhooks

package fiberd_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/helayoty/fiberd/pkg/fiberd"
)

// TestReleaseHasNoTestFlags checks that a release build has neither
// -admin-unsafe nor the cadence flags.
func TestReleaseHasNoTestFlags(t *testing.T) {
	cases := []struct {
		flag, value string
	}{
		{flag: "-admin-unsafe"},
		{flag: "-status-interval", value: "10ms"},
		{flag: "-pressure-interval", value: "10ms"},
	}
	for _, tc := range cases {
		t.Run(tc.flag, func(t *testing.T) {
			args := []string{tc.flag}
			if tc.value != "" {
				args = append(args, tc.value)
			}
			if _, err := parse(args...); err == nil || !strings.Contains(err.Error(), strings.TrimPrefix(tc.flag, "-")) {
				t.Fatalf("%s parsed: %v, want it undefined", tc.flag, err)
			}
		})
	}
}

// TestReleaseHasNoAdminControls checks that a release build's admin
// socket serves no test-only control.
func TestReleaseHasNoAdminControls(t *testing.T) {
	cases := []struct {
		name, path string
	}{
		{name: "no issuer override", path: "/issuer"},
		{name: "no scope-lost", path: "/scope-lost"},
	}
	r := start(t, newConfig(t, stateDir(t)), fiberd.Standalone)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code, _ := adminDo(t, r.c, http.MethodPost, tc.path, `{"reachable":false}`); code != http.StatusNotFound {
				t.Fatalf("POST %s = %d, want 404", tc.path, code)
			}
		})
	}
}
