package rpc

import (
	"context"
	"net/http"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/helayoty/fiberd/pkg/tlsconf"
)

type callerKey struct{}

// WithCaller records the verified caller on ctx.
func WithCaller(ctx context.Context, c tlsconf.Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

// CallerFrom is the verified caller of the request. ok is false on a
// plaintext listener, where there is no caller identity.
func CallerFrom(ctx context.Context) (tlsconf.Caller, bool) {
	c, ok := ctx.Value(callerKey{}).(tlsconf.Caller)
	return c, ok
}

func grpcCaller(ctx context.Context) context.Context {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ctx
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return ctx
	}
	if c, ok := tlsconf.CallerOf(info.State.PeerCertificates); ok {
		return WithCaller(ctx, c)
	}
	return ctx
}

// CallerInterceptor puts the TLS peer's identity on every unary call's
// context.
func CallerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		return handler(grpcCaller(ctx), req)
	}
}

type callerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s callerStream) Context() context.Context { return s.ctx }

// CallerStreamInterceptor is CallerInterceptor for streaming calls.
func CallerStreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, callerStream{ServerStream: ss, ctx: grpcCaller(ss.Context())})
	}
}

func httpCaller(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			if c, ok := tlsconf.CallerOf(r.TLS.PeerCertificates); ok {
				r = r.WithContext(WithCaller(r.Context(), c))
			}
		}
		next.ServeHTTP(w, r)
	})
}
