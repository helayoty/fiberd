//go:build !fiberd_testhooks

package agent_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/helayoty/fiberd/pkg/agent"
)

// TestReleaseHasNoAdminControls checks that a release build has no
// -admin-unsafe flag, and its admin socket serves no test-only control.
func TestReleaseHasNoAdminControls(t *testing.T) {
	cases := []struct {
		name, path string
	}{
		{name: "no lane override", path: "/lane"},
		{name: "no scope-lost", path: "/scope-lost"},
	}
	if _, err := parse("-admin-unsafe"); err == nil || !strings.Contains(err.Error(), "admin-unsafe") {
		t.Fatalf("-admin-unsafe parsed: %v, want it undefined", err)
	}
	r := start(t, newConfig(t, stateDir(t)), agent.Standalone)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code, _ := adminDo(t, r.c, http.MethodPost, tc.path, `{"healthy":false}`); code != http.StatusNotFound {
				t.Fatalf("POST %s = %d, want 404", tc.path, code)
			}
		})
	}
}
