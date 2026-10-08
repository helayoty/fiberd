package artifact

import (
	"errors"
	"fmt"
	"testing"

	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote/errcode"
)

// TestIsNotFound covers every phrasing of a miss. oras reports a 404 as
// errdef.ErrNotFound itself, so the other two only come from registries
// and clients that phrase it their own way.
func TestIsNotFound(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "oras's not found, wrapped", err: fmt.Errorf("resolve: %w", errdef.ErrNotFound), want: true},
		{name: "an error response with status 404", err: &errcode.ErrorResponse{Method: "GET", StatusCode: 404}, want: true},
		{name: "a message that says so", err: errors.New("MANIFEST_UNKNOWN: manifest Not Found"), want: true},
		{name: "an error response with status 500", err: &errcode.ErrorResponse{Method: "GET", StatusCode: 500}},
		{name: "any other error", err: errors.New("connection refused")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isNotFound(c.err); got != c.want {
				t.Fatalf("isNotFound(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}
