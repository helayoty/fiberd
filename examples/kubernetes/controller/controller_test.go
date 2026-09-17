package controller_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"

	"github.com/helayoty/fiberd/examples/kubernetes/controller"
	"github.com/helayoty/fiberd/examples/kubernetes/kube"
	"github.com/helayoty/fiberd/examples/kubernetes/kube/kubetest"
)

const issuerURL = "http://grant-issuer.fiberd-system.svc:8080"

func seed(t *testing.T, srv *kubetest.Server) {
	srv.Put("/apis/fiberd.io/v1alpha1/namespaces/tenant-a/capacitygrants/conform", map[string]any{
		"apiVersion": "fiberd.io/v1alpha1", "kind": "CapacityGrant",
		"metadata": map[string]any{"name": "conform", "namespace": "tenant-a", "uid": "cg-uid-1"},
		"spec": map[string]any{
			"template": "sha256:conform",
			"fibers":   map[string]any{"max": 8, "warm": 1},
			"wBudget":  "32Mi", "minTier": "FIBER_CHECKPOINT", "lease": "10m",
			"deviceBudget": map[string]any{"bytes": "4Mi", "class": "sim"},
			"pod": map[string]any{
				"image": "fiberd:kind", "runtime": "proc", "unsafeAdmin": true,
				"args":      []string{"-template", "default=/usr/local/bin/refzygote --heap-mb 32"},
				"resources": map[string]any{"limits": map[string]any{"memory": "512Mi"}},
				"devices":   []string{"/dev/sim0"},
			},
		},
	})
	t.Cleanup(srv.Close)
}

func newController(t *testing.T, srv *kubetest.Server, now *time.Time) *controller.Controller {
	client := &kube.Client{Base: srv.URL()}
	key, err := controller.EnsureKey(context.Background(), client, "fiberd-system", "grant-issuer-key")
	if err != nil {
		t.Fatal(err)
	}
	// Loading again returns the same key.
	again, err := controller.EnsureKey(context.Background(), client, "fiberd-system", "grant-issuer-key")
	if err != nil || again.KeyID != key.KeyID {
		t.Fatalf("second EnsureKey: %v (kid %s vs %s)", err, again.KeyID, key.KeyID)
	}
	return &controller.Controller{Client: client, Issuer: &grant.Issuer{Key: key, URL: issuerURL}, Now: func() time.Time { return *now }}
}

func TestReconcileCreatesPodMintsGrantAndMirrorsStatus(t *testing.T) {
	srv := kubetest.New()
	seed(t, srv)
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	c := newController(t, srv, &now)
	ctx := context.Background()
	if err := c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}

	// The Pod: agent as PID 1, home k8s, gate, projected grant, owner.
	raw := srv.Get("/api/v1/namespaces/tenant-a/pods/conform-grant")
	if raw == nil {
		t.Fatal("grant pod not created")
	}
	var p controller.Pod
	b, _ := json.Marshal(raw)
	_ = json.Unmarshal(b, &p)
	if p.Spec.ReadinessGates[0].ConditionType != controller.ReadyCondition {
		t.Fatalf("readiness gate = %+v", p.Spec.ReadinessGates)
	}
	if p.Metadata.OwnerReferences[0].UID != "cg-uid-1" || p.Metadata.Labels[controller.GrantLabel] != "conform" {
		t.Fatalf("pod metadata = %+v", p.Metadata)
	}
	args := strings.Join(p.Spec.Containers[0].Args, " ")
	if cmd := p.Spec.Containers[0].Command; len(cmd) != 1 || cmd[0] != "fiberd-k8s" {
		t.Fatalf("command = %v, want fiberd-k8s (the agent library plus the Kubernetes home)", cmd)
	}
	for _, want := range []string{"-verifier jwks", "-issuer " + issuerURL, "-runtime proc", "-grants-dir " + controller.GrantsMount,
		"-endpoint-family inet4", "-devices /dev/sim0", "-admin-unsafe", "-template default=/usr/local/bin/refzygote --heap-mb 32", "-jwks-max-stale 10m0s"} {
		if !strings.Contains(args, want) {
			t.Fatalf("args %q lack %q", args, want)
		}
	}
	if !p.Spec.Containers[0].SecurityContext.Privileged || p.Spec.Volumes[0].Secret.SecretName != "conform-grant" {
		t.Fatalf("container = %+v volumes = %+v", p.Spec.Containers[0].SecurityContext, p.Spec.Volumes)
	}
	if p.Spec.Containers[0].Env[0].Name != "FIBERD_NODE_ID" || p.Spec.Containers[0].Env[0].ValueFrom.FieldRef.FieldPath != "metadata.name" {
		t.Fatalf("node id env = %+v", p.Spec.Containers[0].Env)
	}

	// The Secret: a JWT the Pod verifies, addressed to the Pod, the grant
	// uid being the resource's uid, expiring one lease from now.
	sec := srv.Get("/api/v1/namespaces/tenant-a/secrets/conform-grant")
	if sec == nil {
		t.Fatal("grant secret not created")
	}
	tok := sec["stringData"].(map[string]any)[controller.GrantsFile].(string)
	pub := c.Issuer.Key.Public()
	g, err := grant.Verify(tok, &pub, grant.VerifyOptions{Audience: "conform-grant", Issuer: issuerURL})
	if err != nil {
		t.Fatal(err)
	}
	if g.UID != "cg-uid-1" || g.FiberMax != 8 || g.WBudgetBytes != 32<<20 || g.MinTier != core.TierCheckpoint ||
		g.DeviceBudget.Bytes != 4<<20 || g.DeviceBudget.Class != "sim" || !g.LeaseExpiry.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("minted grant = %+v", g)
	}
	if refs := sec["metadata"].(map[string]any)["ownerReferences"].([]any); len(refs) != 1 {
		t.Fatalf("secret owner refs = %v", refs)
	}

	// Status: uid, pod, issued/expires; not placed, not ready yet.
	st := status(t, srv)
	if st.GrantUID != "cg-uid-1" || st.PodName != "conform-grant" || st.Placed || st.Ready || st.ExpiresAt != now.Add(10*time.Minute).Format(time.RFC3339) {
		t.Fatalf("status = %+v", st)
	}

	// The scheduler places the Pod and the agent sets the gate.
	pod := srv.Get("/api/v1/namespaces/tenant-a/pods/conform-grant")
	pod["spec"].(map[string]any)["nodeName"] = "kind-worker"
	pod["status"] = map[string]any{"podIP": "10.244.0.9",
		"conditions": []any{map[string]any{"type": controller.ReadyCondition, "status": "True"}}}
	now = now.Add(time.Minute)
	if err := c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	st = status(t, srv)
	if !st.Placed || st.Node != "kind-worker" || !st.Ready || st.Endpoint != "10.244.0.9:8484" {
		t.Fatalf("status after placement = %+v", st)
	}
	// A minute in, the grant is not renewed: same expiry.
	if st.ExpiresAt != now.Add(9*time.Minute).Format(time.RFC3339) {
		t.Fatalf("renewed too early: %s", st.ExpiresAt)
	}

	// Past half-life it is renewed: same uid, later expiry, same Secret.
	now = now.Add(5 * time.Minute)
	if err := c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	st = status(t, srv)
	if st.ExpiresAt != now.Add(10*time.Minute).Format(time.RFC3339) {
		t.Fatalf("not renewed at half-life: %s (now %s)", st.ExpiresAt, now.Format(time.RFC3339))
	}
	tok2 := srv.Get("/api/v1/namespaces/tenant-a/secrets/conform-grant")["stringData"].(map[string]any)[controller.GrantsFile].(string)
	g2, err := grant.Verify(tok2, &pub, grant.VerifyOptions{Audience: "conform-grant", Issuer: issuerURL})
	if err != nil || g2.UID != g.UID || !g2.LeaseExpiry.After(g.LeaseExpiry) {
		t.Fatalf("renewed grant = %+v (%v)", g2, err)
	}

	// Deleting the resource takes its Pod and Secret with it (the garbage
	// collector's job; the fake does what it does).
	srv.Delete("/apis/fiberd.io/v1alpha1/namespaces/tenant-a/capacitygrants/conform")
	if srv.Get("/api/v1/namespaces/tenant-a/pods/conform-grant") != nil || srv.Get("/api/v1/namespaces/tenant-a/secrets/conform-grant") != nil {
		t.Fatal("dependents survived the owner's deletion")
	}
	if err := c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidSpecLandsInStatus(t *testing.T) {
	srv := kubetest.New()
	seed(t, srv)
	cg := srv.Get("/apis/fiberd.io/v1alpha1/namespaces/tenant-a/capacitygrants/conform")
	cg["spec"].(map[string]any)["wBudget"] = "lots"
	now := time.Now()
	c := newController(t, srv, &now)
	if err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := status(t, srv)
	if !strings.Contains(st.Message, "spec.wBudget") {
		t.Fatalf("status message = %q, want the spec error", st.Message)
	}
	if srv.Get("/api/v1/namespaces/tenant-a/secrets/conform-grant") != nil {
		t.Fatal("a grant was minted from an invalid spec")
	}
}

func TestEnsureKeyReadsAnExistingSecret(t *testing.T) {
	srv := kubetest.New()
	t.Cleanup(srv.Close)
	key, _ := grant.GenerateKey(jose.ES256)
	raw, _ := json.Marshal(key)
	srv.Put("/api/v1/namespaces/fiberd-system/secrets/grant-issuer-key", map[string]any{
		"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": "grant-issuer-key"},
		"data": map[string]any{"key.json": raw},
	})
	got, err := controller.EnsureKey(context.Background(), &kube.Client{Base: srv.URL()}, "fiberd-system", "grant-issuer-key")
	if err != nil || got.KeyID != key.KeyID || got.Algorithm != "ES256" {
		t.Fatalf("EnsureKey = %+v (%v)", got, err)
	}
}

func status(t *testing.T, srv *kubetest.Server) controller.Status {
	t.Helper()
	raw := srv.Get("/apis/fiberd.io/v1alpha1/namespaces/tenant-a/capacitygrants/conform")
	if raw == nil {
		t.Fatal("capacitygrant gone")
	}
	var cg controller.CapacityGrant
	b, _ := json.Marshal(raw)
	if err := json.Unmarshal(b, &cg); err != nil {
		t.Fatal(err)
	}
	return cg.Status
}
