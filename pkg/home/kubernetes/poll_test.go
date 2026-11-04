package kubernetes_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	"github.com/Azure/fiberd/pkg/core"
	"github.com/Azure/fiberd/pkg/home/kubernetes"
)

var claimsResource = schema.GroupResource{Group: "resource.k8s.io", Resource: "resourceclaims"}

// bare404 is what the API server answers for a path it does not serve:
// NotFound with no object named.
func bare404() error {
	return &apierrors.StatusError{ErrStatus: metav1.Status{
		Status: metav1.StatusFailure, Code: http.StatusNotFound, Reason: metav1.StatusReasonNotFound,
		Message: "the server could not find the requested resource",
	}}
}

// notFoundOfKind is a NotFound whose details carry kind and name as given.
func notFoundOfKind(kind, name string) error {
	return &apierrors.StatusError{ErrStatus: metav1.Status{
		Status: metav1.StatusFailure, Code: http.StatusNotFound, Reason: metav1.StatusReasonNotFound,
		Details: &metav1.StatusDetails{Kind: kind, Name: name},
	}}
}

func forbidden(name string) error {
	return apierrors.NewForbidden(claimsResource, name, errors.New("no access"))
}

// terminating is a Pod or Namespace with a deletion timestamp.
func terminating[T interface{ GetObjectMeta() metav1.Object }](o T) T {
	now := metav1.Now()
	o.GetObjectMeta().SetDeletionTimestamp(&now)
	return o
}

// podWithClaims is livePod naming the given claims instead of its one.
func podWithClaims(names ...string) *corev1.Pod {
	p := livePod()
	p.Spec.ResourceClaims, p.Status.ResourceClaimStatuses = nil, nil
	for i, name := range names {
		ref := "claim-" + string(rune('a'+i))
		p.Spec.ResourceClaims = append(p.Spec.ResourceClaims, corev1.PodResourceClaim{Name: ref, ResourceClaimTemplateName: ptr.To(name)})
		p.Status.ResourceClaimStatuses = append(p.Status.ResourceClaimStatuses, corev1.PodResourceClaimStatus{Name: ref, ResourceClaimName: ptr.To(name)})
	}
	return p
}

// stored reports whether the home holds a Pod snapshot, which carries the
// node name only a Pod read knows.
func stored(h *testHome) bool {
	return slices.Contains(h.Scope(), core.ScopeClaim{Name: "node", Value: "node-1"})
}

// TestPollRound walks one poll round through what the cluster can say
// and checks the losses it queues in order, the error it reports, whether
// the health was marked and whether the Pod was stored. The health is
// stale before every round, so a mark shows.
func TestPollRound(t *testing.T) {
	cases := []struct {
		name       string
		setup      func(h *testHome)
		wantLosses []string
		wantErr    string
		// endsEarly means the round read nothing after the Pod.
		endsEarly   bool
		wantHealthy bool
		wantStored  bool
	}{
		{name: "a live Pod, namespace and claim mark the health", setup: func(*testHome) {}, wantHealthy: true, wantStored: true},
		{name: "the Pod gone is a loss and ends the round", setup: func(h *testHome) { h.kube.SetPod(nil) },
			wantLosses: []string{"pod gone"}, endsEarly: true, wantHealthy: true},
		{name: "the Pod replaced under its name is a loss and ends the round", setup: func(h *testHome) {
			p := livePod()
			p.UID = types.UID("another")
			h.kube.SetPod(p)
		}, wantLosses: []string{"pod replaced"}, endsEarly: true, wantHealthy: true},
		{name: "the Pod terminating is a loss and the round goes on", setup: func(h *testHome) { h.kube.SetPod(terminating(livePod())) },
			wantLosses: []string{"pod terminating"}, wantHealthy: true, wantStored: true},
		{name: "the namespace in the terminating phase is a loss", setup: func(h *testHome) {
			h.kube.SetNamespace(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace},
				Status: corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating}})
		}, wantLosses: []string{"namespace terminating"}, wantHealthy: true, wantStored: true},
		{name: "the namespace with a deletion timestamp is a loss", setup: func(h *testHome) {
			h.kube.SetNamespace(terminating(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}))
		}, wantLosses: []string{"namespace terminating"}, wantHealthy: true, wantStored: true},
		{name: "the namespace gone is the same loss", setup: func(h *testHome) { h.kube.SetNamespace(nil) },
			wantLosses: []string{"namespace terminating"}, wantHealthy: true, wantStored: true},
		{name: "a claim being deleted is a loss", setup: func(h *testHome) { h.kube.SetClaim(testClaim, true) },
			wantLosses: []string{"resource claim grant-pod-gpu deleted"}, wantHealthy: true, wantStored: true},
		{name: "a claim gone is the same loss", setup: func(h *testHome) { h.kube.RemoveClaim(testClaim) },
			wantLosses: []string{"resource claim grant-pod-gpu deleted"}, wantHealthy: true, wantStored: true},
		{name: "every loss of one round is queued in order", setup: func(h *testHome) {
			h.kube.SetPod(terminating(livePod()))
			h.kube.SetNamespace(nil)
			h.kube.SetClaim(testClaim, true)
		}, wantLosses: []string{"pod terminating", "namespace terminating", "resource claim grant-pod-gpu deleted"},
			wantHealthy: true, wantStored: true},
		{name: "a Pod the API server cannot answer for fails the round", setup: func(h *testHome) { h.kube.SetPodErr(errors.New("no route")) },
			wantErr: "pod tenant-a/grant-pod: no route", endsEarly: true},
		{name: "a namespace read error fails the round", setup: func(h *testHome) { h.kube.SetNamespaceErr(errors.New("no route")) },
			wantErr: "namespace tenant-a: no route"},
		{name: "an unreadable claim fails the round and is no loss", setup: func(h *testHome) { h.kube.SetClaimErr(testClaim, forbidden(testClaim)) },
			wantErr: "resource claim tenant-a/grant-pod-gpu: "},
		{name: "a cluster without resource.k8s.io answers, and the claim is unreadable for now",
			setup: func(h *testHome) { h.kube.SetNoResourceClaims(true) }, wantHealthy: true, wantStored: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newTestHome(t)
			c.setup(h)
			h.clock.Step(testStaleTTL)
			now := h.clock.Now()
			if h.Health().Healthy(now) {
				t.Fatal("the health is not stale before the round")
			}
			err := h.Once(context.Background())
			if (err != nil) != (c.wantErr != "") || (err != nil && !strings.Contains(err.Error(), c.wantErr)) {
				t.Fatalf("round = %v, want %q", err, c.wantErr)
			}
			if got := h.Health().Healthy(now); got != c.wantHealthy {
				t.Fatalf("healthy = %v, want %v", got, c.wantHealthy)
			}
			if got := stored(h); got != c.wantStored {
				t.Fatalf("Pod stored %v, want %v, scope %v", got, c.wantStored, h.Scope())
			}
			if n := h.kube.Calls("GetNamespace"); (n == 0) != c.endsEarly {
				t.Fatalf("the namespace was read %d times, ends early %v", n, c.endsEarly)
			}
			if n := h.PendingLosses(); n != len(c.wantLosses) {
				t.Fatalf("losses pending %d, want %d\n%s", n, len(c.wantLosses), h.logs)
			}
			if n := h.logs.count(`"msg"="Lost scope"`); n != len(c.wantLosses) {
				t.Fatalf("Lost scope logged %d times, want %d\n%s", n, len(c.wantLosses), h.logs)
			}
			for _, reason := range c.wantLosses {
				if h.logs.count(`"msg"="Lost scope"`, `"reason"="`+reason+`"`) != 1 {
					t.Fatalf("the loss %q was not logged once\n%s", reason, h.logs)
				}
			}
		})
	}
}

// TestPollClaimNotFound checks which NotFound answers count as a deleted
// claim. The API server names the missing object by kind or by name. A
// bare 404, what a group the server does not serve answers, carries no
// details and is an error like any other.
func TestPollClaimNotFound(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantLoss bool
	}{
		{name: "a NotFound naming the claim is a deletion", err: apierrors.NewNotFound(claimsResource, testClaim), wantLoss: true},
		{name: "a NotFound of the resourceclaims kind is a deletion whatever it names", err: apierrors.NewNotFound(claimsResource, "other"), wantLoss: true},
		{name: "the kind is matched ignoring case", err: notFoundOfKind("ResourceClaims", "other"), wantLoss: true},
		{name: "a NotFound naming the claim under another kind is a deletion", err: notFoundOfKind("things", testClaim), wantLoss: true},
		{name: "a NotFound naming another object of another kind is not", err: notFoundOfKind("things", "other")},
		{name: "a bare 404 is not a deletion", err: bare404()},
		{name: "a forbidden is not a deletion", err: forbidden(testClaim)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := kubernetes.IsClaimNotFound(c.err, testClaim); got != c.wantLoss {
				t.Fatalf("IsClaimNotFound = %v, want %v", got, c.wantLoss)
			}
			h := newTestHome(t)
			h.kube.SetClaimErr(testClaim, c.err)
			err := h.Once(context.Background())
			if (err == nil) != c.wantLoss {
				t.Fatalf("round = %v, want an error %v", err, !c.wantLoss)
			}
			if got := h.PendingLosses() == 1; got != c.wantLoss {
				t.Fatalf("loss queued %v, want %v", got, c.wantLoss)
			}
		})
	}
}

// TestPollUnreadableClaimGoesStale checks that a claim the home cannot
// read makes the home unhealthy after the stale TTL instead of a loss.
func TestPollUnreadableClaimGoesStale(t *testing.T) {
	cases := []struct {
		name   string
		rounds int
	}{
		{name: "one failed round", rounds: 1},
		{name: "failed rounds for a whole stale TTL", rounds: int(testStaleTTL / testPoll)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newTestHome(t)
			h.kube.SetClaimErr(testClaim, forbidden(testClaim))
			for range c.rounds {
				if err := h.Once(context.Background()); err == nil {
					t.Fatal("the round answered with an unreadable claim")
				}
				h.clock.Step(testPoll)
			}
			if h.PendingLosses() != 0 {
				t.Fatal("an unreadable claim was a loss")
			}
			if wantHealthy := c.rounds*int(testPoll) < int(testStaleTTL); h.Health().Healthy(h.clock.Now()) != wantHealthy {
				t.Fatalf("healthy = %v after %d failed rounds, want %v", !wantHealthy, c.rounds, wantHealthy)
			}
		})
	}
}

// rep is v repeated n times.
func rep(v bool, n int) []bool { return slices.Repeat([]bool{v}, n) }

// TestPollClaimsUnreadable checks the clock on a cluster that serves no
// ResourceClaims. The rounds answer, so the health is marked. The claims
// are a loss once they have been unreadable for the stale TTL, and a
// round that reads them resets the clock.
func TestPollClaimsUnreadable(t *testing.T) {
	ttl := int(testStaleTTL / testPoll)
	cases := []struct {
		name string
		// rounds says per round, one poll interval apart, whether the
		// cluster serves ResourceClaims.
		rounds     []bool
		wantLosses int
	}{
		{name: "unreadable for less than the stale TTL fires nothing", rounds: rep(false, ttl)},
		{name: "unreadable for the stale TTL fires the loss once", rounds: rep(false, ttl+2), wantLosses: 1},
		{name: "readable again resets the clock",
			rounds: slices.Concat(rep(false, ttl-1), rep(true, 1), rep(false, ttl))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newTestHome(t)
			for i, served := range c.rounds {
				h.kube.SetNoResourceClaims(!served)
				if err := h.Once(context.Background()); err != nil {
					t.Fatalf("round %d: %v", i, err)
				}
				if !h.Health().Healthy(h.clock.Now()) {
					t.Fatalf("not healthy after round %d", i)
				}
				h.clock.Step(testPoll)
			}
			if n := h.PendingLosses(); n != c.wantLosses {
				t.Fatalf("losses pending %d, want %d\n%s", n, c.wantLosses, h.logs)
			}
			if c.wantLosses > 0 && h.logs.count(`"reason"="resource claim grant-pod-gpu unreadable"`) != 1 {
				t.Fatalf("the loss was not logged once\n%s", h.logs)
			}
			if n := h.logs.count(`"msg"="API server did not answer"`); n != 0 {
				t.Fatalf("a cluster without ResourceClaims was logged as not answering\n%s", h.logs)
			}
		})
	}
}

// TestPollErrorsLoggedOnce checks that an API error is logged once per
// distinct message and the API answering again once.
func TestPollErrorsLoggedOnce(t *testing.T) {
	e1, e2 := errors.New("no route"), errors.New("forbidden")
	cases := []struct {
		name          string
		rounds        []error // the Pod read error per round
		wantErrors    int
		wantRecovered int
	}{
		{name: "the same error twice is logged once", rounds: []error{e1, e1}, wantErrors: 1},
		{name: "a different message is logged again", rounds: []error{e1, e2, e1}, wantErrors: 3},
		{name: "answering again is logged once", rounds: []error{e1, e1, nil, nil}, wantErrors: 1, wantRecovered: 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newTestHome(t)
			for _, err := range c.rounds {
				h.kube.SetPodErr(err)
				_ = h.Once(context.Background())
			}
			if n := h.logs.count(`"msg"="API server did not answer"`); n != c.wantErrors {
				t.Fatalf("errors logged %d, want %d\n%s", n, c.wantErrors, h.logs)
			}
			if n := h.logs.count(`"msg"="API server answered again"`); n != c.wantRecovered {
				t.Fatalf("recoveries logged %d, want %d\n%s", n, c.wantRecovered, h.logs)
			}
		})
	}
}

// TestPollRoundTimeout checks that a round the API server never answers
// is cut off after one poll interval and reported as a timeout.
func TestPollRoundTimeout(t *testing.T) {
	cases := []struct {
		name string
		hang bool
		want int
	}{
		{name: "a hanging round is cut off and logged", hang: true, want: 1},
		{name: "an answered round is not", want: 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newTestHome(t)
			h.kube.SetHang(c.hang)
			stop := h.run(t)
			defer stop()
			waitFor(t, "the first round", func() bool { return h.kube.Calls("GetPod") >= 1 })
			// The poll ticker waits, and a hanging round adds its timer.
			want := 1
			if c.hang {
				want = 2
			}
			waitFor(t, "the clock's waiters", func() bool { return h.clock.Waiters() >= want })
			h.clock.Step(testPoll)
			if c.hang {
				waitFor(t, "the timeout", func() bool { return h.logs.count("poll round timed out") >= 1 })
			} else {
				waitFor(t, "the second round", func() bool { return h.kube.Calls("GetPod") >= 2 })
			}
			if n := h.logs.count("poll round timed out"); n != c.want {
				t.Fatalf("timeouts logged %d, want %d\n%s", n, c.want, h.logs)
			}
		})
	}
}

// TestPollRetriesGate checks that a readiness gate the API server refused
// is sent again by the next poll round, and one it took is not.
func TestPollRetriesGate(t *testing.T) {
	cases := []struct {
		name        string
		patchErr    error
		wantPatches int
	}{
		{name: "a refused gate is sent again by the next round", patchErr: errors.New("conflict"), wantPatches: 1},
		{name: "a gate the server took is not sent again", wantPatches: 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newTestHome(t)
			h.kube.SetPatchErr(c.patchErr)
			err := h.PublishReady(context.Background(), "g1", true)
			if (err != nil) != (c.patchErr != nil) {
				t.Fatalf("PublishReady = %v, want %v", err, c.patchErr)
			}
			h.kube.SetPatchErr(nil)
			if err := h.Once(context.Background()); err != nil {
				t.Fatalf("round: %v", err)
			}
			if n := len(h.kube.Patches()); n != c.wantPatches {
				t.Fatalf("patches %d, want %d", n, c.wantPatches)
			}
			if cond := h.condition(t); cond.Status != corev1.ConditionTrue || cond.Reason != kubernetes.ReasonTemplateWarm {
				t.Fatalf("condition %s/%s, want True/%s", cond.Status, cond.Reason, kubernetes.ReasonTemplateWarm)
			}
			if c.patchErr != nil && h.logs.count(`"msg"="Readiness gate set again"`) != 1 {
				t.Fatalf("the recovery was not logged once\n%s", h.logs)
			}
		})
	}
}

// TestClaimNames checks which ResourceClaims a Pod names, from its
// resourceClaims and their statuses.
func TestClaimNames(t *testing.T) {
	cases := []struct {
		name   string
		spec   []corev1.PodResourceClaim
		status []corev1.PodResourceClaimStatus
		want   []string
	}{
		{name: "a status without a claim name is a template not resolved yet, skipped",
			spec:   []corev1.PodResourceClaim{{Name: "gpu", ResourceClaimTemplateName: ptr.To("gpu-tmpl")}},
			status: []corev1.PodResourceClaimStatus{{Name: "gpu"}}},
		{name: "the status name wins over the spec name",
			spec:   []corev1.PodResourceClaim{{Name: "gpu", ResourceClaimName: ptr.To("from-spec")}},
			status: []corev1.PodResourceClaimStatus{{Name: "gpu", ResourceClaimName: ptr.To("from-status")}},
			want:   []string{"from-status"}},
		{name: "the spec name without a status",
			spec: []corev1.PodResourceClaim{{Name: "gpu", ResourceClaimName: ptr.To("from-spec")}},
			want: []string{"from-spec"}},
		{name: "sorted",
			spec: []corev1.PodResourceClaim{{Name: "z", ResourceClaimName: ptr.To("zeta")}, {Name: "a", ResourceClaimName: ptr.To("alpha")}},
			want: []string{"alpha", "zeta"}},
		{name: "deduplicated",
			spec: []corev1.PodResourceClaim{{Name: "one", ResourceClaimName: ptr.To("shared")}, {Name: "two", ResourceClaimName: ptr.To("shared")}},
			want: []string{"shared"}},
		{name: "no claims at all"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &corev1.Pod{}
			p.Spec.ResourceClaims, p.Status.ResourceClaimStatuses = c.spec, c.status
			if got := kubernetes.ClaimNames(p); !slices.Equal(got, c.want) {
				t.Fatalf("ClaimNames = %v, want %v", got, c.want)
			}
		})
	}
}
