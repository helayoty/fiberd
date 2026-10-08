// Package rpc serves the grant protocol (api/grant/v1) over gRPC on top of
// a core.Agent, and optionally exposes a thin JSON gateway. It owns the
// mapping from core.StatusCode to gRPC codes and Miss details; the core
// stays transport-agnostic.
package rpc

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
)

// DefaultRetryAfter is what SHED tells the caller to wait.
const DefaultRetryAfter = time.Second

// Server implements grantv1.FibersServer.
type Server struct {
	grantv1.UnimplementedFibersServer

	Agent *core.Agent
	// Issuer is reported in every Miss so a DEFERRED caller knows which
	// control plane to fall back through.
	Issuer     string
	RetryAfter time.Duration
}

// NewGRPCServer builds a grpc.Server with the caller and admission
// interceptors and the Fibers service registered. Pass
// grpc.Creds(credentials.NewTLS(cfg)) for mutual TLS.
func NewGRPCServer(s *Server, opts ...grpc.ServerOption) *grpc.Server {
	opts = append(opts,
		grpc.ChainUnaryInterceptor(CallerInterceptor(), AdmissionInterceptor()),
		grpc.ChainStreamInterceptor(CallerStreamInterceptor()))
	gs := grpc.NewServer(opts...)
	grantv1.RegisterFibersServer(gs, s)
	return gs
}

func (s *Server) retryAfter() time.Duration {
	if s.RetryAfter > 0 {
		return s.RetryAfter
	}
	return DefaultRetryAfter
}

func (s *Server) Clone(ctx context.Context, req *grantv1.CloneRequest) (*grantv1.CloneResponse, error) {
	// No deadline on the wire: the agent picks the action's default
	// (fork-scale for create, sub-second for resume).
	var deadline time.Duration
	if d, ok := grant.Deadline(req.GetDeadline(), time.Now()); ok {
		if d <= 0 {
			return nil, s.ToError(core.Invalid, errNoDeadline)
		}
		deadline = d
	}
	creq := core.CloneRequest{
		GrantJWT: []byte(req.GetGrantJwt()),
		Session:  req.GetSession(),
		Deadline: deadline,
		Payload:  req.GetPayload(),
	}
	if c, ok := CallerFrom(ctx); ok {
		creq.CallerThumbprint = c.Thumbprint
	}
	resp, code, err := s.Agent.Clone(ctx, creq)
	if code != core.OK {
		return nil, s.ToError(code, err)
	}
	return &grantv1.CloneResponse{
		FiberId:         resp.FiberID,
		Endpoint:        resp.Endpoint,
		Fence:           fenceToProto(resp.Fence),
		Kind:            kindToProto(resp.Kind),
		RoutingKey:      resp.RoutingKey,
		ServerKeySha256: resp.ServerKeySHA256,
	}, nil
}

// owns reports whether the request's caller may see or act on grant uid,
// which holds when the grant is bound to the caller's certificate. A
// plaintext request has no caller identity and sees everything.
func (s *Server) owns(ctx context.Context, grantUID string) bool {
	c, ok := CallerFrom(ctx)
	return !ok || s.Agent.Ledger.GrantBoundTo(grantUID, c.Thumbprint)
}

// ownsFiber is owns for a running fiber's grant. An unknown fiber is left
// to the agent, which answers NotFound itself.
func (s *Server) ownsFiber(ctx context.Context, fiberID string) bool {
	f, ok := s.Agent.Ledger.Fiber(fiberID)
	return !ok || s.owns(ctx, f.GrantUID)
}

// visible filters statuses down to the caller's grants.
func (s *Server) visible(ctx context.Context, sts []core.Status) []core.Status {
	out := sts[:0:0]
	for _, st := range sts {
		if s.owns(ctx, st.GrantUID) {
			out = append(out, st)
		}
	}
	return out
}

// Park and Release answer NotFound, never PermissionDenied, for another
// caller's fiber, so a fiber ID reveals nothing about who holds it.
func (s *Server) Park(ctx context.Context, req *grantv1.ParkRequest) (*emptypb.Empty, error) {
	if !s.ownsFiber(ctx, req.GetFiberId()) {
		return nil, s.ToError(core.NotFound, core.ErrFiberUnknown)
	}
	_, code, err := s.Agent.Park(ctx, req.GetFiberId(), req.GetSync())
	if code != core.OK {
		return nil, s.ToError(code, err)
	}
	return &emptypb.Empty{}, nil
}

func (s *Server) Release(ctx context.Context, req *grantv1.ReleaseRequest) (*emptypb.Empty, error) {
	if !s.ownsFiber(ctx, req.GetFiberId()) {
		return nil, s.ToError(core.NotFound, core.ErrFiberUnknown)
	}
	code, err := s.Agent.Release(ctx, req.GetFiberId(), req.GetDiscard())
	if code != core.OK {
		return nil, s.ToError(code, err)
	}
	return &emptypb.Empty{}, nil
}

// Watch streams one Status per admitted grant of the caller on every
// change and at least every status interval, until the client goes away.
func (s *Server) Watch(_ *emptypb.Empty, stream grantv1.Fibers_WatchServer) error {
	ctx := stream.Context()
	for batch := range s.Agent.Watch(ctx) {
		for _, st := range s.visible(ctx, batch) {
			if err := stream.Send(StatusToProto(st)); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

func fenceToProto(f core.Fence) *grantv1.Fence {
	return &grantv1.Fence{GrantUid: f.GrantUID, Epoch: f.Epoch, Seq: f.Seq}
}

// FenceFromProto is the inverse of the fence mapping, for clients.
func FenceFromProto(f *grantv1.Fence) core.Fence {
	return core.Fence{GrantUID: f.GetGrantUid(), Epoch: f.GetEpoch(), Seq: f.GetSeq()}
}

func kindToProto(a core.Action) grantv1.CloneKind {
	switch a {
	case core.ActAttach:
		return grantv1.CloneKind_ATTACH
	case core.ActResume:
		return grantv1.CloneKind_RESUME
	default:
		return grantv1.CloneKind_CREATE
	}
}

// StatusToProto converts a ledger status to the wire message.
func StatusToProto(st core.Status) *grantv1.Status {
	return &grantv1.Status{
		GrantUid:   st.GrantUID,
		Running:    uint32(st.Running),
		Parked:     uint32(st.Parked),
		WUsedBytes: st.WUsedBytes,
		Latest:     fenceToProto(st.Latest),
	}
}
