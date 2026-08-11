// Package k8s is the in-cluster home. v0 needs ZERO cluster changes: the
// GrantSource is an informer on balloon pods carrying grant annotations, the
// SandboxProvider inherits the pod sandbox and cgroup slice kubelet already
// built, and the Verifier validates SA JWTs against cached JWKS — never
// TokenReview. v1 swaps fibers to CRI containers behind the tolerance gate;
// v2 swaps the informer to the real Grant kind. The core never notices.
package k8s

import (
	"context"

	"fiberd/pkg/adapter"
)

// Source watches grants. Real implementation: client-go informer; kept
// dependency-free in the skeleton so the module builds with stdlib only.
type Source struct{ Events chan adapter.GrantEvent }

func (s *Source) Watch(ctx context.Context) (<-chan adapter.GrantEvent, error) {
	return s.Events, nil
}

// Sandboxes locates the grant pod's existing sandbox via CRI
// ListPodSandbox filtered on the pod UID — kubelet built it; we ride it.
type Sandboxes struct{}

func (Sandboxes) EnsureSandbox(_ context.Context, g adapter.Grant) (string, error) {
	if g.SandboxID != "" {
		return g.SandboxID, nil
	}
	return "", context.Canceled // TODO: CRI ListPodSandbox lookup
}

// JWKSVerifier validates the caller's projected SA token offline against
// the cluster's cached JWKS (ServiceAccountIssuerDiscovery). Revocation
// window = min(token TTL, cache TTL) — stated, bounded, accepted.
type JWKSVerifier struct{}

func (JWKSVerifier) Verify(_ context.Context, _ []byte, _ string) error {
	return nil // TODO: cached JWKS signature + aud + exp checks
}
