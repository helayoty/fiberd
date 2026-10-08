package rpc

import (
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
)

// httpCode is reached through the gateway only with the codes the agent
// produces. The rest of the mapping is pinned here.
func TestHTTPCode(t *testing.T) {
	cases := []struct {
		code codes.Code
		want int
	}{
		{code: codes.OK, want: http.StatusOK},
		{code: codes.InvalidArgument, want: http.StatusBadRequest},
		{code: codes.Unauthenticated, want: http.StatusUnauthorized},
		{code: codes.NotFound, want: http.StatusNotFound},
		{code: codes.FailedPrecondition, want: http.StatusPreconditionFailed},
		{code: codes.ResourceExhausted, want: http.StatusTooManyRequests},
		{code: codes.Unavailable, want: http.StatusServiceUnavailable},
		{code: codes.Internal, want: http.StatusInternalServerError},
		{code: codes.Unknown, want: http.StatusInternalServerError},
		{code: codes.PermissionDenied, want: http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.code.String(), func(t *testing.T) {
			if got := httpCode(tc.code); got != tc.want {
				t.Fatalf("httpCode(%v) = %d, want %d", tc.code, got, tc.want)
			}
		})
	}
}
