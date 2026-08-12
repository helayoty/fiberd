// Package standalone is the non-Kubernetes home. The signing that was an
// escalation in-cluster is the default here: without the authenticated
// apiserver→kubelet watch channel, the signature IS the channel.
package standalone

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"fiberd/pkg/adapter"
)

// SignedGrant is the portable proof that admission and billing already
// happened, verifiable offline by the agent with no platform round trip.
type SignedGrant struct {
	Payload []byte `json:"payload"` // canonical JSON of adapter.Grant + expiry
	Sig     []byte `json:"sig"`
}

type Verifier struct {
	Issuer ed25519.PublicKey
}

var ErrBadSignature = errors.New("standalone: grant signature invalid")

// Verify implements core.Verifier: token is the SignedGrant for grantUID.
func (v Verifier) Verify(_ context.Context, token []byte, grantUID string) error {
	var sg SignedGrant
	if err := json.Unmarshal(token, &sg); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if !ed25519.Verify(v.Issuer, sg.Payload, sg.Sig) {
		return ErrBadSignature
	}
	var g adapter.Grant
	if err := json.Unmarshal(sg.Payload, &g); err != nil {
		return fmt.Errorf("payload: %w", err)
	}
	if g.UID != grantUID {
		return fmt.Errorf("grant mismatch: signed %q, requested %q", g.UID, grantUID)
	}
	if !g.Expiry.IsZero() && time.Now().After(g.Expiry) {
		return fmt.Errorf("grant expired %s ago", time.Since(g.Expiry).Round(time.Second))
	}
	return nil
}

// Sandboxes owns the hierarchy itself — the row where the Kubernetes column
// pays its cohabitation tax and this one simply doesn't. The real
// implementation calls RunPodSandbox on the CRI socket and creates the
// cgroup slice; the stub records intent.
type Sandboxes struct{}

func (Sandboxes) EnsureSandbox(_ context.Context, g adapter.Grant) (string, error) {
	return "sbx-" + g.UID, nil // TODO: RunPodSandbox + cgroup slice
}
