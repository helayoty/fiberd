package rpc

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/protoadapt"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/core"
)

// Miss policy: every miss carries a grantv1.Miss detail. Never a bare code.
//
//	core.Shed             -> ResourceExhausted + Miss{SHED, retry_after_s}
//	core.DeferredFallback -> Unavailable       + Miss{DEFERRED_FALLBACK, issuer}
//	core.NeedsTier        -> FailedPrecondition
//	core.Invalid          -> InvalidArgument
//	core.Unauthenticated  -> Unauthenticated
//	core.NotFound         -> NotFound
//	core.NoWorkspace      -> FailedPrecondition + NoWorkspace
//	core.OverBudget       -> ResourceExhausted, no Miss
//	core.Internal         -> Internal
func (s *Server) ToError(code core.StatusCode, err error) error {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	switch code {
	case core.OK:
		return nil
	case core.Shed:
		return withDetail(codes.ResourceExhausted, msg, &grantv1.Miss{
			Code:        grantv1.MissCode_SHED,
			RetryAfterS: uint32(s.retryAfter().Seconds()),
			Issuer:      s.Issuer,
		})
	case core.DeferredFallback:
		miss := &grantv1.Miss{Code: grantv1.MissCode_DEFERRED_FALLBACK, Issuer: s.Issuer}
		var rm *core.RemoteMiss
		if errors.As(err, &rm) {
			miss.PreferredHome = rm.PreferredHome
		}
		return withDetail(codes.Unavailable, msg, miss)
	case core.NeedsTier:
		return status.Error(codes.FailedPrecondition, msg)
	case core.Invalid:
		return status.Error(codes.InvalidArgument, msg)
	case core.Unauthenticated:
		return status.Error(codes.Unauthenticated, msg)
	case core.NotFound:
		return status.Error(codes.NotFound, msg)
	case core.NoWorkspace:
		return withDetail(codes.FailedPrecondition, msg, &grantv1.NoWorkspace{})
	case core.OverBudget:
		return status.Error(codes.ResourceExhausted, msg)
	default:
		return status.Error(codes.Internal, msg)
	}
}

func withDetail(c codes.Code, msg string, detail protoadapt.MessageV1) error {
	st, err := status.New(c, msg).WithDetails(detail)
	if err != nil {
		// Cannot happen for a registered message type; fail loudly rather
		// than return a bare code that violates the protocol.
		panic("rpc: attach detail: " + err.Error())
	}
	return st.Err()
}

// MissFromError extracts the Miss detail from a gRPC error, for clients
// and the conformance suite.
func MissFromError(err error) (*grantv1.Miss, bool) {
	st, ok := status.FromError(err)
	if !ok {
		return nil, false
	}
	for _, d := range st.Details() {
		if m, ok := d.(*grantv1.Miss); ok {
			return m, true
		}
	}
	return nil, false
}

// IsNoWorkspace reports whether err is the refusal of a file call on a
// fiber whose grant has no workspace.
func IsNoWorkspace(err error) bool {
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.FailedPrecondition {
		return false
	}
	for _, d := range st.Details() {
		if _, ok := d.(*grantv1.NoWorkspace); ok {
			return true
		}
	}
	return false
}

// IsMiss reports whether err is one of the two miss outcomes.
func IsMiss(err error) bool {
	_, ok := MissFromError(err)
	return ok
}

var errNoDeadline = errors.New("rpc: deadline already passed")
