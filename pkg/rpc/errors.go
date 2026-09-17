package rpc

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
		return withMiss(codes.ResourceExhausted, msg, &grantv1.Miss{
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
		return withMiss(codes.Unavailable, msg, miss)
	case core.NeedsTier:
		return status.Error(codes.FailedPrecondition, msg)
	case core.Invalid:
		return status.Error(codes.InvalidArgument, msg)
	case core.Unauthenticated:
		return status.Error(codes.Unauthenticated, msg)
	case core.NotFound:
		return status.Error(codes.NotFound, msg)
	default:
		return status.Error(codes.Internal, msg)
	}
}

func withMiss(c codes.Code, msg string, miss *grantv1.Miss) error {
	st, err := status.New(c, msg).WithDetails(miss)
	if err != nil {
		// Cannot happen for a registered message type; fail loudly rather
		// than return a bare code that violates the protocol.
		panic("rpc: attach Miss detail: " + err.Error())
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

// IsMiss reports whether err is one of the two miss outcomes.
func IsMiss(err error) bool {
	_, ok := MissFromError(err)
	return ok
}

var errNoDeadline = errors.New("rpc: deadline already passed")
