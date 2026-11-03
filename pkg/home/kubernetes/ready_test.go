package kubernetes_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/helayoty/fiberd/pkg/home/kubernetes"
)

// TestWarmMessage checks the condition message for every size of warm
// set. It counts, and names no grant.
func TestWarmMessage(t *testing.T) {
	cases := []struct {
		name string
		warm int
		want string
	}{
		{name: "none", want: "0 grants warm"},
		{name: "one", warm: 1, want: "1 grant warm"},
		{name: "two", warm: 2, want: "2 grants warm"},
		{name: "many", warm: 12, want: "12 grants warm"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := kubernetes.WarmMessage(c.warm); got != c.want {
				t.Fatalf("WarmMessage = %q, want %q", got, c.want)
			}
		})
	}
}

// TestZygoteCondition checks the condition built for a warm set. Every
// patch is a transition, stamped with the clock's now.
func TestZygoteCondition(t *testing.T) {
	now := testStart.Add(1500 * time.Millisecond)
	cases := []struct {
		name       string
		warm       []string
		wantStatus corev1.ConditionStatus
		wantReason string
	}{
		{name: "a warm template is True", warm: []string{"g1"}, wantStatus: corev1.ConditionTrue, wantReason: kubernetes.ReasonTemplateWarm},
		{name: "two warm templates are True", warm: []string{"g1", "g2"}, wantStatus: corev1.ConditionTrue, wantReason: kubernetes.ReasonTemplateWarm},
		{name: "none is False", wantStatus: corev1.ConditionFalse, wantReason: kubernetes.ReasonNoWarmTemplate},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := kubernetes.ZygoteCondition(c.warm, now)
			if got.Type != corev1.PodConditionType(kubernetes.PodConditionZygoteReady) {
				t.Fatalf("type %q", got.Type)
			}
			if got.Status != c.wantStatus || got.Reason != c.wantReason {
				t.Fatalf("condition %s/%s, want %s/%s", got.Status, got.Reason, c.wantStatus, c.wantReason)
			}
			if want := metav1.NewTime(now.Truncate(time.Second)); !got.LastTransitionTime.Equal(&want) {
				t.Fatalf("transition %v, want %v", got.LastTransitionTime, want)
			}
			if got.Message != kubernetes.WarmMessage(len(c.warm)) {
				t.Fatalf("message %q", got.Message)
			}
			for _, uid := range c.warm {
				if strings.Contains(got.Message, uid) {
					t.Fatalf("message %q names grant %s", got.Message, uid)
				}
			}
		})
	}
}

// TestPublishReady checks what reaches the Pod: the condition after a
// sequence of calls, the patch shape, and the transition time taken from
// the clock on every patch, even over a condition the Pod already holds.
func TestPublishReady(t *testing.T) {
	type call struct {
		uid   string
		ready bool
		// step moves the clock before the call.
		step time.Duration
	}
	earlier := metav1.NewTime(testStart.Add(-time.Hour))
	cases := []struct {
		name           string
		existing       *corev1.PodCondition // on the Pod before the home reads it
		calls          []call
		wantPatches    int
		wantStatus     corev1.ConditionStatus
		wantReason     string
		wantTransition metav1.Time
	}{
		{name: "a warm template sets the gate", calls: []call{{uid: "g1", ready: true}}, wantPatches: 1,
			wantStatus: corev1.ConditionTrue, wantReason: kubernetes.ReasonTemplateWarm, wantTransition: metav1.NewTime(testStart)},
		{name: "the last template going cold clears it, stamped then",
			calls: []call{{uid: "g1", ready: true}, {uid: "g1", ready: false, step: 5 * time.Second}}, wantPatches: 2,
			wantStatus: corev1.ConditionFalse, wantReason: kubernetes.ReasonNoWarmTemplate, wantTransition: metav1.NewTime(testStart.Add(5 * time.Second))},
		{name: "a second warm template changes nothing on the Pod",
			calls: []call{{uid: "g1", ready: true}, {uid: "g2", ready: true, step: 5 * time.Second}}, wantPatches: 1,
			wantStatus: corev1.ConditionTrue, wantReason: kubernetes.ReasonTemplateWarm, wantTransition: metav1.NewTime(testStart)},
		{name: "a condition the Pod already holds is stamped now",
			existing: &corev1.PodCondition{Type: corev1.PodConditionType(kubernetes.PodConditionZygoteReady), Status: corev1.ConditionTrue, LastTransitionTime: earlier},
			calls:    []call{{uid: "g1", ready: true}}, wantPatches: 1,
			wantStatus: corev1.ConditionTrue, wantReason: kubernetes.ReasonTemplateWarm, wantTransition: metav1.NewTime(testStart)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newTestHome(t)
			if c.existing != nil {
				p := livePod()
				p.Status.Conditions = []corev1.PodCondition{*c.existing}
				h.kube.SetPod(p)
				if err := h.Once(context.Background()); err != nil {
					t.Fatalf("round: %v", err)
				}
			}
			for _, call := range c.calls {
				h.clock.Step(call.step)
				if err := h.PublishReady(context.Background(), call.uid, call.ready); err != nil {
					t.Fatalf("PublishReady(%s, %v): %v", call.uid, call.ready, err)
				}
			}
			patches := h.kube.Patches()
			if len(patches) != c.wantPatches {
				t.Fatalf("patches %d, want %d", len(patches), c.wantPatches)
			}
			var body struct {
				Status struct {
					Conditions []map[string]any `json:"conditions"`
				} `json:"status"`
			}
			if err := json.Unmarshal(patches[len(patches)-1], &body); err != nil {
				t.Fatalf("the patch is not JSON: %v", err)
			}
			if n := len(body.Status.Conditions); n != 1 {
				t.Fatalf("the patch carries %d conditions, want 1", n)
			}
			for _, key := range []string{"type", "status", "reason", "message", "lastTransitionTime"} {
				if _, ok := body.Status.Conditions[0][key]; !ok {
					t.Fatalf("the patch condition lacks %q: %s", key, patches[len(patches)-1])
				}
			}
			cond := h.condition(t)
			if cond.Status != c.wantStatus || cond.Reason != c.wantReason {
				t.Fatalf("condition %s/%s, want %s/%s", cond.Status, cond.Reason, c.wantStatus, c.wantReason)
			}
			if !cond.LastTransitionTime.Equal(&c.wantTransition) {
				t.Fatalf("transition %v, want %v", cond.LastTransitionTime, c.wantTransition)
			}
			if h.Ready() != (c.wantStatus == corev1.ConditionTrue) {
				t.Fatalf("Ready = %v with the condition %s", h.Ready(), cond.Status)
			}
		})
	}
}
