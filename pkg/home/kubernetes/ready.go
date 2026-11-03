package kubernetes

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// PodConditionZygoteReady is the Pod condition fiberd sets once a
	// template is warm. The Kubernetes controller lists it as a readiness
	// gate on every grant Pod, so the Pod joins its Service only then.
	PodConditionZygoteReady = "fiberd.io/zygote-ready"
	// ReasonTemplateWarm is the condition's reason while it is True. At
	// least one grant has a warm template.
	ReasonTemplateWarm = "TemplateWarm"
	// ReasonNoWarmTemplate is the condition's reason while it is False.
	// No grant has a warm template yet, or the last one went cold.
	ReasonNoWarmTemplate = "NoWarmTemplate"
)

// publishGate is what the readiness gate sends. It patches the Pod
// condition for the warm set into the Pod's status with a strategic merge
// patch, which merges conditions by type.
func (h *Home) publishGate(ctx context.Context, warm []string) error {
	body, err := conditionPatch(zygoteCondition(warm, h.cfg.Clock.Now()))
	if err != nil {
		return err
	}
	return h.cfg.Kube.PatchPodStatus(ctx, h.cfg.PodNamespace, h.cfg.PodName, body)
}

// zygoteCondition is the condition for the warm set, stamped now. The
// gate publishes only when "any template is warm" flips, so every patch
// is a transition.
func zygoteCondition(warm []string, now time.Time) corev1.PodCondition {
	cond := corev1.PodCondition{
		Type:               corev1.PodConditionType(PodConditionZygoteReady),
		Status:             corev1.ConditionFalse,
		Reason:             ReasonNoWarmTemplate,
		Message:            warmMessage(len(warm)),
		LastTransitionTime: metav1.NewTime(now.UTC().Truncate(time.Second)),
	}
	if len(warm) > 0 {
		cond.Status, cond.Reason = corev1.ConditionTrue, ReasonTemplateWarm
	}
	return cond
}

// warmMessage counts the grants with a warm template. The grant UIDs
// stay out of the Pod.
func warmMessage(n int) string {
	if n == 1 {
		return "1 grant warm"
	}
	return fmt.Sprintf("%d grants warm", n)
}

// conditionPatch is the strategic merge patch that sets cond on a Pod's
// status. Only the fields fiberd owns are sent, so nothing else on the
// condition is cleared.
func conditionPatch(cond corev1.PodCondition) ([]byte, error) {
	type condition struct {
		Type               corev1.PodConditionType `json:"type"`
		Status             corev1.ConditionStatus  `json:"status"`
		Reason             string                  `json:"reason"`
		Message            string                  `json:"message"`
		LastTransitionTime metav1.Time             `json:"lastTransitionTime"`
	}
	patch := map[string]any{"status": map[string]any{"conditions": []condition{{
		Type: cond.Type, Status: cond.Status, Reason: cond.Reason, Message: cond.Message,
		LastTransitionTime: cond.LastTransitionTime,
	}}}}
	return json.Marshal(patch)
}
