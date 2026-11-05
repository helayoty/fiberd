package rpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/Azure/fiberd/pkg/tlsconf"
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

// errUnnamedCaller refuses a TLS peer whose certificate key has no
// thumbprint. A request without a caller is served as plaintext and sees
// every grant, so that peer must never reach a handler.
var errUnnamedCaller = status.Error(codes.Unauthenticated, "client certificate key cannot name a caller")

// namer names a peer from its verified chain, as tlsconf.CallerOf does.
type namer func(chain []*x509.Certificate) (tlsconf.Caller, bool)

// peerName is what naming one TLS peer decided.
type peerName struct {
	caller tlsconf.Caller
	named  bool
	// err refuses every request of a peer that presented a certificate
	// and has no name.
	err error
}

// namePeer names the peer that presented chain. Every path that names a
// peer goes through it, so the refusal is decided in one place.
func namePeer(name namer, chain []*x509.Certificate) peerName {
	c, ok := name(chain)
	switch {
	case ok:
		return peerName{caller: c, named: true}
	case len(chain) > 0:
		return peerName{err: errUnnamedCaller}
	}
	return peerName{}
}

// namedTLSInfo is the auth info of a connection accepted with ServerCreds.
// It is the connection's TLS info with the peer's name beside it.
type namedTLSInfo struct {
	credentials.TLSInfo
	peer peerName
}

// serverCreds are TLS credentials whose server handshake names the peer.
type serverCreds struct {
	credentials.TransportCredentials
	name namer
}

// ServerCreds are the TLS credentials of a server that names its callers.
// A connection's peer is named once, at its handshake, and the caller
// interceptors read that name on every call. The auth info of such a
// connection embeds credentials.TLSInfo and is not that type, so code that
// asserts credentials.TLSInfo does not match it.
func ServerCreds(cfg *tls.Config) credentials.TransportCredentials {
	return newServerCreds(cfg, tlsconf.CallerOf)
}

func newServerCreds(cfg *tls.Config, name namer) *serverCreds {
	return &serverCreds{TransportCredentials: credentials.NewTLS(cfg), name: name}
}

func (c *serverCreds) ServerHandshake(raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, info, err := c.TransportCredentials.ServerHandshake(raw)
	if err != nil {
		return conn, info, err
	}
	return conn, c.authInfo(info), nil
}

// authInfo is a finished handshake's auth info with its peer named. A peer
// without a name keeps its connection and is refused per call, so it gets
// a status and not a failed handshake.
func (c *serverCreds) authInfo(info credentials.AuthInfo) credentials.AuthInfo {
	tlsInfo, ok := info.(credentials.TLSInfo)
	if !ok {
		return info
	}
	return &namedTLSInfo{TLSInfo: tlsInfo, peer: namePeer(c.name, tlsInfo.State.PeerCertificates)}
}

// Clone keeps the wrapper, since the wrapped credentials clone themselves
// bare.
func (c *serverCreds) Clone() credentials.TransportCredentials {
	return &serverCreds{TransportCredentials: c.TransportCredentials.Clone(), name: c.name}
}

func grpcCaller(ctx context.Context) (context.Context, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ctx, nil
	}
	var who peerName
	switch info := p.AuthInfo.(type) {
	case *namedTLSInfo:
		who = info.peer
	case credentials.TLSInfo:
		// A server on bare TLS credentials stored no name at the handshake.
		who = namePeer(tlsconf.CallerOf, info.State.PeerCertificates)
	default:
		return ctx, nil
	}
	switch {
	case who.err != nil:
		return nil, who.err
	case who.named:
		return WithCaller(ctx, who.caller), nil
	}
	return ctx, nil
}

// CallerInterceptor puts the TLS peer's identity on every unary call's
// context. A peer whose certificate cannot name it is Unauthenticated.
func CallerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, err := grpcCaller(ctx)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
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
		ctx, err := grpcCaller(ss.Context())
		if err != nil {
			return err
		}
		return handler(srv, callerStream{ServerStream: ss, ctx: ctx})
	}
}

type connPeerKey struct{}

// connPeer holds the name of one gateway connection's peer. ConnContext
// runs ahead of the TLS handshake, so the connection's first request fills
// it. HTTP/2 serves a connection's requests concurrently, hence the Once.
type connPeer struct {
	name namer
	once sync.Once
	peer peerName
}

// ConnContext is the http.Server.ConnContext hook of a server that serves
// a Gateway. With it the gateway names a connection's peer once. A handler
// served without it names the peer on every request.
func ConnContext(ctx context.Context, _ net.Conn) context.Context {
	return withConnPeer(ctx, tlsconf.CallerOf)
}

func withConnPeer(ctx context.Context, name namer) context.Context {
	// Refused until named, so a naming that panics never leaves the rest
	// of the connection's requests without a caller.
	return context.WithValue(ctx, connPeerKey{}, &connPeer{name: name, peer: peerName{err: errUnnamedCaller}})
}

func (c *connPeer) get(chain []*x509.Certificate) peerName {
	c.once.Do(func() { c.peer = namePeer(c.name, chain) })
	return c.peer
}

// httpPeer is the name of the TLS peer behind r.
func httpPeer(r *http.Request) peerName {
	if c, ok := r.Context().Value(connPeerKey{}).(*connPeer); ok {
		return c.get(r.TLS.PeerCertificates)
	}
	return namePeer(tlsconf.CallerOf, r.TLS.PeerCertificates)
}

func (g *Gateway) httpCaller(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			who := httpPeer(r)
			switch {
			case who.err != nil:
				g.reply(w, nil, who.err)
				return
			case who.named:
				r = r.WithContext(WithCaller(r.Context(), who.caller))
			}
		}
		next.ServeHTTP(w, r)
	})
}
