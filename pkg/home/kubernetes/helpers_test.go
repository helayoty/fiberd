package kubernetes_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	testingclock "k8s.io/utils/clock/testing"

	"github.com/Azure/fiberd/pkg/endpoint"
	"github.com/Azure/fiberd/pkg/home/kubernetes"
	"github.com/Azure/fiberd/pkg/home/kubernetes/fake"
)

const (
	testNamespace = "tenant-a"
	testPod       = "grant-pod"
	testPodUID    = "pod-uid-1"
	testClaim     = "grant-pod-gpu"
	testStaleTTL  = 10 * time.Second
	testPoll      = time.Second
)

var testStart = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

// logBuffer collects what the home logged, one line per call, in funcr's
// key-value form.
type logBuffer struct {
	mu    sync.Mutex
	lines []string
}

func (b *logBuffer) logger() logr.Logger {
	return funcr.New(func(_, args string) {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.lines = append(b.lines, args)
	}, funcr.Options{})
}

// count is how many lines hold every one of the substrings.
func (b *logBuffer) count(substrs ...string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, line := range b.lines {
		ok := true
		for _, s := range substrs {
			ok = ok && strings.Contains(line, s)
		}
		if ok {
			n++
		}
	}
	return n
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.Join(b.lines, "\n")
}

// testHome is a Home over a fake cluster and a fake clock.
type testHome struct {
	*kubernetes.Home
	kube  *fake.Kube
	clock *testingclock.FakeClock
	logs  *logBuffer
}

// livePod is the grant Pod as the kubelet leaves it once it runs: both
// address families, a service account, a node and one bound claim.
func livePod() *corev1.Pod {
	claim := testClaim
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: testPod, Namespace: testNamespace, UID: types.UID(testPodUID)},
		Spec: corev1.PodSpec{
			ServiceAccountName: "fiberd-grant",
			NodeName:           "node-1",
			ResourceClaims:     []corev1.PodResourceClaim{{Name: "gpu", ResourceClaimTemplateName: &claim}},
		},
		Status: corev1.PodStatus{
			PodIP:                 "10.0.0.1",
			PodIPs:                []corev1.PodIP{{IP: "10.0.0.1"}, {IP: "fd00::1"}},
			ResourceClaimStatuses: []corev1.PodResourceClaimStatus{{Name: "gpu", ResourceClaimName: &claim}},
		},
	}
}

// newTestHome builds a home around livePod in a cluster that holds it,
// its namespace and its claim. opts change the configuration first.
func newTestHome(t *testing.T, opts ...func(*kubernetes.Config)) *testHome {
	t.Helper()
	k := fake.New(testNamespace)
	k.SetPod(livePod())
	k.SetClaim(testClaim, false)
	fc := testingclock.NewFakeClock(testStart)
	logs := &logBuffer{}
	cfg := kubernetes.Config{
		Kube: k, PodName: testPod, PodNamespace: testNamespace, PodUID: testPodUID,
		StaleTTL: testStaleTTL, Poll: testPoll, Family: endpoint.Inet4,
		CgroupRoot: t.TempDir(), Clock: fc, Logger: logs.logger(),
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	h, err := kubernetes.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(h.Close)
	return &testHome{Home: h, kube: k, clock: fc, logs: logs}
}

// run starts Run and returns what stops it. The test fails when Run has
// not returned after the stop.
func (h *testHome) run(t *testing.T) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); h.Run(ctx) }()
	return func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("Run did not return after its context ended")
		}
	}
}

// waitFor polls cond until it holds or ten seconds pass.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("waited for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// condition is the zygote-ready condition the fake cluster holds.
func (h *testHome) condition(t *testing.T) corev1.PodCondition {
	t.Helper()
	p := h.kube.Pod()
	if p == nil {
		t.Fatal("the Pod is gone")
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodConditionType(kubernetes.PodConditionZygoteReady) {
			return c
		}
	}
	t.Fatal("the Pod carries no zygote-ready condition")
	return corev1.PodCondition{}
}
