package kubernetes

import "context"

// What the external tests reach into.

var (
	PickResourceClaimVersion = pickResourceClaimVersion
	KubeDefaults             = kubeDefaults
	IsClaimNotFound          = isClaimNotFound
	WarmMessage              = warmMessage
	ZygoteCondition          = zygoteCondition
	ClaimNames               = claimNames
	PodIP                    = podIP
)

const (
	PodIPWait  = podIPWait
	PodIPRetry = podIPRetry
)

// Once runs one poll round now, as a tick would.
func (h *Home) Once(ctx context.Context) error { return h.poll.Once(ctx) }

// PendingLosses is how many scope-loss reasons wait for delivery.
func (h *Home) PendingLosses() int { return h.losses.Pending() }
