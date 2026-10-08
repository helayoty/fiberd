package capacity

import (
	"context"

	ateletpb "github.com/helayoty/fiberd/examples/substrate/proto/atelet"
)

// Once makes one report, so a test sees why atelet refused it.
func (r *Reporter) Once(ctx context.Context) (*ateletpb.SetWorkerCapacityResponse, error) {
	return &ateletpb.SetWorkerCapacityResponse{}, r.once(ctx, &ateletpb.SetWorkerCapacityRequest{Capacity: Read(r.cfg.Dir)})
}
