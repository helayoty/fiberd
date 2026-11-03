package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/helayoty/fiberd/pkg/core"
)

// Scope-loss reasons. Each fires once per home lifetime.
const (
	reasonPodGone              = "pod gone"
	reasonPodReplaced          = "pod replaced"
	reasonPodTerminating       = "pod terminating"
	reasonNamespaceTerminating = "namespace terminating"
)

func reasonClaimDeleted(name string) string    { return "resource claim " + name + " deleted" }
func reasonClaimUnreadable(name string) string { return "resource claim " + name + " unreadable" }

// round asks the API server about the Pod, its namespace and the
// metadata of every ResourceClaim the Pod names, in that order. The Pod
// answering is liveness. The Pod gone or replaced ends the round there,
// as a loss. The Pod terminating, the namespace gone or terminating and
// a claim deleted are losses too, and the round goes on, so every loss
// one round finds is queued in that order. A cluster that serves no
// ResourceClaims leaves the claims unreadable. Once they have been so for
// the stale TTL, each is a loss. Any other read error fails the round,
// and the health, the stored Pod and the snapshot stay as they were.
//
// A round that answered in full stores the Pod and its scope snapshot,
// and sends a readiness gate the control plane does not hold yet again.
func (h *Home) round(ctx context.Context) error {
	ns, name := h.cfg.PodNamespace, h.cfg.PodName
	p, err := h.cfg.Kube.GetPod(ctx, ns, name)
	switch {
	case apierrors.IsNotFound(err):
		h.lose(reasonPodGone)
		return nil
	case err != nil:
		return fmt.Errorf("pod %s/%s: %w", ns, name, err)
	case string(p.UID) != h.cfg.PodUID:
		h.lose(reasonPodReplaced)
		return nil
	case p.DeletionTimestamp != nil:
		h.lose(reasonPodTerminating)
	}

	n, err := h.cfg.Kube.GetNamespace(ctx, ns)
	switch {
	case apierrors.IsNotFound(err):
		h.lose(reasonNamespaceTerminating)
	case err != nil:
		return fmt.Errorf("namespace %s: %w", ns, err)
	case n.DeletionTimestamp != nil || n.Status.Phase == corev1.NamespaceTerminating:
		h.lose(reasonNamespaceTerminating)
	}

	claims := claimNames(p)
	unreadable := false
	for _, claim := range claims {
		c, err := h.cfg.Kube.GetResourceClaim(ctx, ns, claim)
		switch {
		case errors.Is(err, ErrNoResourceClaims):
			unreadable = true
		case isClaimNotFound(err, claim):
			h.lose(reasonClaimDeleted(claim))
		case err != nil:
			return fmt.Errorf("resource claim %s/%s: %w", ns, claim, err)
		case c.DeletionTimestamp != nil:
			h.lose(reasonClaimDeleted(claim))
		}
	}
	for _, claim := range h.unreadableFor(claims, unreadable) {
		h.lose(reasonClaimUnreadable(claim))
	}

	h.store(p, claims)

	if changed, err := h.gate.Republish(ctx); err != nil {
		if changed {
			h.log.Error(err, "Readiness gate not set, retrying every poll round")
		}
	} else if changed {
		h.log.Info("Readiness gate set again")
	}
	return nil
}

// unreadableFor keeps the clock of the claims being unreadable and
// returns the claims that have been so for the stale TTL. The clock
// starts at the first round that could not read them and resets once a
// round reads them again.
func (h *Home) unreadableFor(claims []string, unreadable bool) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !unreadable {
		h.unreadableSince = time.Time{}
		return nil
	}
	now := h.cfg.Clock.Now()
	if h.unreadableSince.IsZero() {
		h.unreadableSince = now
	}
	if now.Sub(h.unreadableSince) < h.cfg.StaleTTL {
		return nil
	}
	return claims
}

// lose queues a scope-loss reason and logs it when it is new.
func (h *Home) lose(reason string) {
	if h.losses.Lose(reason) {
		h.log.Info("Lost scope", "reason", reason)
	}
}

// pod is the last Pod stored, read and stored now when there is none yet.
// A Pod read with another UID is a replacement. It is an error, and
// nothing is stored.
func (h *Home) pod(ctx context.Context) (*corev1.Pod, error) {
	h.mu.Lock()
	p := h.self
	h.mu.Unlock()
	if p != nil {
		return p, nil
	}
	p, err := h.cfg.Kube.GetPod(ctx, h.cfg.PodNamespace, h.cfg.PodName)
	if err != nil {
		return nil, err
	}
	if string(p.UID) != h.cfg.PodUID {
		return nil, fmt.Errorf("pod UID %q, want %q", p.UID, h.cfg.PodUID)
	}
	h.store(p, claimNames(p))
	return p, nil
}

// store keeps p as the last Pod, with the claims it names and the scope
// snapshot the two make.
func (h *Home) store(p *corev1.Pod, claims []string) {
	scope := scopeOf(h.cfg, p, claims)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.self, h.claims, h.scope = p, claims, scope
}

// claimNames lists the ResourceClaims behind the Pod's resourceClaims,
// sorted and without repeats. A claim is named by the status when the
// kubelet generated its name, else by the spec. An entry with neither is
// a template the kubelet has not resolved yet and is skipped.
func claimNames(p *corev1.Pod) []string {
	byRef := map[string]string{}
	for _, st := range p.Status.ResourceClaimStatuses {
		if st.ResourceClaimName != nil {
			byRef[st.Name] = *st.ResourceClaimName
		}
	}
	var names []string
	for _, rc := range p.Spec.ResourceClaims {
		name := byRef[rc.Name]
		if name == "" && rc.ResourceClaimName != nil {
			name = *rc.ResourceClaimName
		}
		if name != "" {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

func joinClaims(claims []string) string { return strings.Join(claims, ",") }

// scopeOf is the scope the Pod asserts, what the configuration knows and
// then what a Pod read adds, one resource_claim per ResourceClaim.
func scopeOf(cfg Config, p *corev1.Pod, claims []string) []core.ScopeClaim {
	s := []core.ScopeClaim{
		{Name: "namespace", Value: cfg.PodNamespace},
		{Name: "pod", Value: cfg.PodName},
		{Name: "pod_uid", Value: cfg.PodUID},
	}
	if p != nil {
		if sa := p.Spec.ServiceAccountName; sa != "" {
			s = append(s, core.ScopeClaim{Name: "service_account", Value: sa})
		}
		if n := p.Spec.NodeName; n != "" {
			s = append(s, core.ScopeClaim{Name: "node", Value: n})
		}
	}
	for _, claim := range claims {
		s = append(s, core.ScopeClaim{Name: "resource_claim", Value: claim})
	}
	return s
}
