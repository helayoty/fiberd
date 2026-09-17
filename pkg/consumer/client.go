// Package consumer is the grant protocol from the caller's side: a client
// for Clone, Park, Release and Watch that turns the two miss outcomes
// into typed errors a consumer branches on. A consumer (a Knative
// activator, a container shim, a virtual node) calls Clone with the
// signed grant it holds; on DEFERRED_FALLBACK it takes its ordinary path
// (create the thing the slow way, or route to the home that holds the
// session's state), on SHED it waits retry_after and tries again.
// Nothing here knows which home it talks to.
package consumer

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/rpc"
)

// Kind is how a Clone was served.
type Kind = grantv1.CloneKind

const (
	Create = grantv1.CloneKind_CREATE
	Attach = grantv1.CloneKind_ATTACH
	Resume = grantv1.CloneKind_RESUME
)

// Fiber is what a successful Clone returns.
type Fiber struct {
	ID       string
	Endpoint string // a URL to dial as given (unix://..., tcp://...)
	Fence    Fence
	Kind     Kind
}

// Fence is the fiber's incarnation.
type Fence struct {
	GrantUID   string
	Epoch, Seq uint64
}

func (f Fence) String() string { return fmt.Sprintf("%s/%d/%d", f.GrantUID, f.Epoch, f.Seq) }

// Shed is the miss with the control plane unreachable: the home refuses
// to mint and says when to ask again. The consumer waits and retries;
// it does not fall back, because the fallback path needs the same
// control plane.
type Shed struct {
	RetryAfter time.Duration
	Issuer     string
}

func (e *Shed) Error() string {
	return fmt.Sprintf("shed: control plane unreachable, retry after %s", e.RetryAfter)
}

// Deferred is the miss with the control plane healthy: the home cannot
// serve this clone (no capacity, expired grant, session too large to
// move) and the consumer takes its ordinary path. PreferredHome, when
// set, is where the session's parked state lives.
type Deferred struct {
	Issuer        string
	PreferredHome string
	Reason        string
}

func (e *Deferred) Error() string {
	if e.PreferredHome != "" {
		return fmt.Sprintf("deferred: %s (session lives on %s)", e.Reason, e.PreferredHome)
	}
	return "deferred: " + e.Reason
}

// TierGap: the grant or the parked session needs a tier this home does
// not offer. Not a miss; the grant was placed on the wrong home.
type TierGap struct{ Reason string }

func (e *TierGap) Error() string { return "tier gap: " + e.Reason }

// Client talks to one home.
type Client struct {
	conn *grpc.ClientConn
	api  grantv1.FibersClient
}

// Dial connects to a home's gRPC address (plaintext: the grant carries
// the authorization, and the home is reached inside the environment
// that placed it).
func Dial(ctx context.Context, target string) (*Client, error) {
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn, api: grantv1.NewFibersClient(conn)}, nil
}

// New wraps an existing connection (tests, bufconn).
func New(conn *grpc.ClientConn) *Client {
	return &Client{conn: conn, api: grantv1.NewFibersClient(conn)}
}

func (c *Client) Close() error { return c.conn.Close() }

// Clone resolves session (empty: an anonymous fiber) under the grant,
// within deadline. Errors are *Shed, *Deferred, *TierGap or the raw
// gRPC error for anything else.
func (c *Client) Clone(ctx context.Context, grantJWT, session string, deadline time.Duration, payload []byte) (Fiber, error) {
	req := &grantv1.CloneRequest{GrantJwt: grantJWT, Session: session, Payload: payload}
	if deadline > 0 {
		req.Deadline = timestamppb.New(time.Now().Add(deadline))
	}
	r, err := c.api.Clone(ctx, req)
	if err != nil {
		return Fiber{}, classify(err)
	}
	f := Fiber{ID: r.GetFiberId(), Endpoint: r.GetEndpoint(), Kind: r.GetKind()}
	if fe := r.GetFence(); fe != nil {
		f.Fence = Fence{GrantUID: fe.GetGrantUid(), Epoch: fe.GetEpoch(), Seq: fe.GetSeq()}
	}
	return f, nil
}

// CloneRetry is Clone that waits out SHED: it retries after each
// retry_after until ctx ends. DEFERRED and everything else return at
// once.
func (c *Client) CloneRetry(ctx context.Context, grantJWT, session string, deadline time.Duration, payload []byte) (Fiber, error) {
	for {
		f, err := c.Clone(ctx, grantJWT, session, deadline, payload)
		var shed *Shed
		if !errors.As(err, &shed) {
			return f, err
		}
		wait := shed.RetryAfter
		if wait <= 0 {
			wait = time.Second
		}
		select {
		case <-ctx.Done():
			return Fiber{}, fmt.Errorf("%w (last: %w)", ctx.Err(), err)
		case <-time.After(wait):
		}
	}
}

// Park checkpoints the fiber; with sync the reply waits for the delta
// to be durable.
func (c *Client) Park(ctx context.Context, fiberID string, sync bool) error {
	_, err := c.api.Park(ctx, &grantv1.ParkRequest{FiberId: fiberID, Sync: sync})
	return classify(err)
}

// Release ends the fiber; with discard its session's parked delta goes
// too.
func (c *Client) Release(ctx context.Context, fiberID string, discard bool) error {
	_, err := c.api.Release(ctx, &grantv1.ReleaseRequest{FiberId: fiberID, Discard: discard})
	return classify(err)
}

// Status is one grant's line of the Watch stream.
type Status struct {
	GrantUID        string
	Running, Parked uint32
	WUsedBytes      uint64
	Latest          Fence
}

// Watch streams status until ctx ends or the stream breaks; fn is called
// for every line.
func (c *Client) Watch(ctx context.Context, fn func(Status)) error {
	stream, err := c.api.Watch(ctx, &emptypb.Empty{})
	if err != nil {
		return err
	}
	for {
		st, err := stream.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		s := Status{GrantUID: st.GetGrantUid(), Running: st.GetRunning(), Parked: st.GetParked(), WUsedBytes: st.GetWUsedBytes()}
		if l := st.GetLatest(); l != nil {
			s.Latest = Fence{GrantUID: l.GetGrantUid(), Epoch: l.GetEpoch(), Seq: l.GetSeq()}
		}
		fn(s)
	}
}

// NotFound reports a Park or Release of a fiber the home does not know:
// a prior epoch's fence, or one already gone.
func NotFound(err error) bool { return status.Code(err) == codes.NotFound }

// classify turns the protocol's errors into the typed ones.
func classify(err error) error {
	if err == nil {
		return nil
	}
	if miss, ok := rpc.MissFromError(err); ok {
		switch miss.GetCode() {
		case grantv1.MissCode_SHED:
			return &Shed{RetryAfter: time.Duration(miss.GetRetryAfterS()) * time.Second, Issuer: miss.GetIssuer()}
		case grantv1.MissCode_DEFERRED_FALLBACK:
			return &Deferred{Issuer: miss.GetIssuer(), PreferredHome: miss.GetPreferredHome(), Reason: status.Convert(err).Message()}
		}
	}
	if status.Code(err) == codes.FailedPrecondition {
		return &TierGap{Reason: status.Convert(err).Message()}
	}
	return err
}
