package controller_test

import (
	"context"
	"encoding/json"
	"reflect"
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

const (
	issuerURL  = "http://grant-issuer.fiberd-system.svc:8080"
	cgPath     = "/apis/fiberd.io/v1alpha1/namespaces/tenant-a/capacitygrants/conform"
	statusPath = cgPath + "/status"
	listPath   = "/apis/fiberd.io/v1alpha1/capacitygrants"
	podPath    = "/api/v1/namespaces/tenant-a/pods/conform-grant"
	podsPath   = "/api/v1/namespaces/tenant-a/pods"
	secretPath = "/api/v1/namespaces/tenant-a/secrets/conform-grant"
	secretsDir = "/api/v1/namespaces/tenant-a/secrets"
	keyPath    = "/api/v1/namespaces/fiberd-system/secrets/grant-issuer-key"
)

func seed(t *testing.T, srv *kubetest.Server) {
	srv.Put(cgPath, map[string]any{
		"apiVersion": "fiberd.io/v1alpha1", "kind": "CapacityGrant",
		"metadata": map[string]any{"name": "conform", "namespace": "tenant-a", "uid": "cg-uid-1"},
		"spec": map[string]any{
			"template": "sha256:conform",
			"fibers":   map[string]any{"max": 8, "warm": 1},
			"wBudget":  "32Mi", "minTier": "FIBER_CHECKPOINT", "isolation": "TRUSTED", "lease": "10m",
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
	return &controller.Controller{Client: client, Issuer: &grant.Issuer{Key: key, URL: issuerURL}, Now: func() time.Time { return *now }}
}

// verbs lists "METHOD path" for calls, to compare a pass's API traffic.
func verbs(calls []kubetest.Call) []string {
	out := make([]string, 0, len(calls))
	for _, c := range calls {
		out = append(out, c.Method+" "+c.Path)
	}
	return out
}

// minted verifies the grant in the Secret against the controller's key.
func minted(t *testing.T, srv *kubetest.Server, c *controller.Controller) core.Grant {
	t.Helper()
	sec := srv.Get(secretPath)
	if sec == nil {
		t.Fatal("grant secret not created")
	}
	tok, _ := sec["stringData"].(map[string]any)[controller.GrantsFile].(string)
	pub := c.Issuer.Key.Public()
	g, err := grant.Verify(tok, &pub, grant.VerifyOptions{Audience: "conform-grant", Issuer: issuerURL})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// TestReconcileLifecycle walks one CapacityGrant through its life. Each step
// is one controller pass or cluster event, and builds on the state the
// previous one left.
func TestReconcileLifecycle(t *testing.T) {
	srv := kubetest.New()
	seed(t, srv)
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	c := newController(t, srv, &now)
	ctx := context.Background()
	var first core.Grant     // the grant minted by the first pass
	mark := len(srv.Calls()) // calls before the current step

	steps := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"the first pass creates the Pod, then the Secret, then writes the status", func(t *testing.T) {
			if err := c.Reconcile(ctx); err != nil {
				t.Fatal(err)
			}
			calls := srv.Calls()[mark:]
			want := []string{"GET " + listPath, "GET " + podPath, "POST " + podsPath, "GET " + secretPath, "POST " + secretsDir, "PATCH " + statusPath}
			if got := verbs(calls); !reflect.DeepEqual(got, want) {
				t.Fatalf("calls = %v, want %v", got, want)
			}
			var p controller.Pod
			if err := json.Unmarshal([]byte(calls[2].Body), &p); err != nil || p.Metadata.Name != "conform-grant" {
				t.Fatalf("created pod = %s (%v)", calls[2].Body, err)
			}
			// The Pod is built from the spec (TestBuildPod has the details),
			// with the lease as the JWKS staleness bound.
			args := strings.Join(p.Spec.Containers[0].Args, " ")
			for _, want := range []string{"-node-id $(FIBERD_NODE_ID)", "-runtime proc", "-jwks-max-stale 10m0s", "-devices /dev/sim0",
				"-admin-unsafe", "-template default=/usr/local/bin/refzygote --heap-mb 32"} {
				if !strings.Contains(args, want) {
					t.Fatalf("args %q lack %q", args, want)
				}
			}
			if p.Spec.Containers[0].Image != "fiberd:kind" || string(p.Spec.Containers[0].Resources) != `{"limits":{"memory":"512Mi"}}` {
				t.Fatalf("container = %+v", p.Spec.Containers[0])
			}
			if ct := calls[5].ContentType; ct != "application/merge-patch+json" {
				t.Fatalf("status patch content type = %q", ct)
			}
			if srv.Get(podPath) == nil {
				t.Fatal("grant pod not stored")
			}
		}},
		{"the Secret holds a JWT addressed to the Pod, uid the resource's, expiring one lease from now", func(t *testing.T) {
			g := minted(t, srv, c)
			if g.UID != "cg-uid-1" || g.FiberMax != 8 || g.FiberWarm != 1 || g.WBudgetBytes != 32<<20 || g.MinTier != core.TierCheckpoint ||
				g.TemplateDigest != "sha256:conform" || g.Policy.Isolation != core.Trusted || g.DeviceBudget.Bytes != 4<<20 ||
				g.DeviceBudget.Class != "sim" || !g.LeaseExpiry.Equal(now.Add(10*time.Minute)) {
				t.Fatalf("minted grant = %+v", g)
			}
			sec := srv.Get(secretPath)
			meta := sec["metadata"].(map[string]any)
			refs, _ := meta["ownerReferences"].([]any)
			if len(refs) != 1 || refs[0].(map[string]any)["uid"] != "cg-uid-1" || refs[0].(map[string]any)["controller"] != true {
				t.Fatalf("secret owner refs = %v", refs)
			}
			if meta["labels"].(map[string]any)[controller.GrantLabel] != "conform" {
				t.Fatalf("secret labels = %v", meta["labels"])
			}
			first = g
		}},
		{"status names the grant, the Pod and the expiry; not placed, not ready yet", func(t *testing.T) {
			want := controller.Status{GrantUID: "cg-uid-1", PodName: "conform-grant",
				IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339)}
			if st := status(t, srv); st != want {
				t.Fatalf("status = %+v, want %+v", st, want)
			}
			mark = len(srv.Calls())
		}},
		{"a pass with nothing new writes nothing", func(t *testing.T) {
			now = now.Add(time.Minute)
			if err := c.Reconcile(ctx); err != nil {
				t.Fatal(err)
			}
			want := []string{"GET " + listPath, "GET " + podPath, "GET " + secretPath}
			if got := verbs(srv.Calls()[mark:]); !reflect.DeepEqual(got, want) {
				t.Fatalf("calls = %v, want only the reads %v", got, want)
			}
		}},
		{"placement and the agent's gate mirror into status; the grant is not renewed yet", func(t *testing.T) {
			srv.Update(podPath, func(pod map[string]any) {
				pod["spec"].(map[string]any)["nodeName"] = "kind-worker"
				pod["status"] = map[string]any{"podIP": "10.244.0.9", "conditions": []any{
					map[string]any{"type": "Other", "status": "True"},
					map[string]any{"type": controller.ReadyCondition, "status": "True"}}}
			})
			if err := c.Reconcile(ctx); err != nil {
				t.Fatal(err)
			}
			st := status(t, srv)
			if !st.Placed || st.Node != "kind-worker" || !st.Ready || st.Endpoint != "10.244.0.9:8484" {
				t.Fatalf("status after placement = %+v", st)
			}
			if st.ExpiresAt != first.LeaseExpiry.Format(time.RFC3339) {
				t.Fatalf("renewed too early: %s", st.ExpiresAt)
			}
		}},
		{"past half-life the grant is renewed in the same Secret: same uid, later expiry", func(t *testing.T) {
			now = now.Add(5 * time.Minute)
			mark = len(srv.Calls())
			if err := c.Reconcile(ctx); err != nil {
				t.Fatal(err)
			}
			var patch *kubetest.Call
			for _, call := range srv.Calls()[mark:] {
				if call.Method == "PATCH" && call.Path == secretPath {
					patch = &call
				}
			}
			if patch == nil || patch.ContentType != "application/merge-patch+json" || !strings.Contains(patch.Body, `"stringData":{"grant.jwt":"`) {
				t.Fatalf("secret renewal patch = %+v", patch)
			}
			st := status(t, srv)
			if st.ExpiresAt != now.Add(10*time.Minute).Format(time.RFC3339) || st.IssuedAt != now.Format(time.RFC3339) {
				t.Fatalf("not renewed at half-life: %+v (now %s)", st, now.Format(time.RFC3339))
			}
			g := minted(t, srv, c)
			if g.UID != first.UID || !g.LeaseExpiry.After(first.LeaseExpiry) {
				t.Fatalf("renewed grant = %+v", g)
			}
		}},
		// A regression test: the merge patch kept the old Pod's node and
		// endpoint after the Pod was replaced.
		{"a replaced Pod clears the old node and endpoint from status", func(t *testing.T) {
			srv.Delete(podPath)
			if err := c.Reconcile(ctx); err != nil {
				t.Fatal(err)
			}
			if srv.Get(podPath) == nil {
				t.Fatal("deleted grant pod not re-created")
			}
			st := status(t, srv)
			if st.Placed || st.Ready || st.Node != "" || st.Endpoint != "" || st.GrantUID != "cg-uid-1" {
				t.Fatalf("status after the Pod was replaced = %+v", st)
			}
		}},
		// Deletion is the garbage collector's job. The fake API server does it here.
		{"deleting the resource takes its Pod and Secret with it", func(t *testing.T) {
			srv.Delete(cgPath)
			if srv.Get(podPath) != nil || srv.Get(secretPath) != nil {
				t.Fatal("dependents survived the owner's deletion")
			}
			mark = len(srv.Calls())
			if err := c.Reconcile(ctx); err != nil {
				t.Fatal(err)
			}
			if got := verbs(srv.Calls()[mark:]); !reflect.DeepEqual(got, []string{"GET " + listPath}) {
				t.Fatalf("calls = %v, want only the list", got)
			}
		}},
	}
	for _, step := range steps {
		if !t.Run(step.name, step.run) {
			return // later steps build on this one
		}
	}
}

// TestReconcileRenewal checks when a pass mints a new grant, starting from
// the state one pass at t0 leaves.
func TestReconcileRenewal(t *testing.T) {
	cases := []struct {
		name  string
		after time.Duration                                  // how long after the first pass
		event func(srv *kubetest.Server)                     // what changed in the cluster
		want  string                                         // the Secret write, or "" for none
		check func(t *testing.T, g core.Grant, t0 time.Time) // the grant now in the Secret
	}{
		{name: "before half-life nothing is minted", after: 4 * time.Minute},
		{name: "past half-life the Secret is patched", after: 6 * time.Minute, want: "PATCH " + secretPath},
		{name: "a deleted Secret is created again at once", after: time.Minute, want: "POST " + secretsDir,
			event: func(srv *kubetest.Server) { srv.Delete(secretPath) }},
		{name: "a status naming another grant renews", after: time.Minute, want: "PATCH " + secretPath,
			event: func(srv *kubetest.Server) {
				srv.Update(cgPath, func(o map[string]any) { o["status"].(map[string]any)["grantUID"] = "older" })
			}},
		{name: "a status whose expiry does not parse renews", after: time.Minute, want: "PATCH " + secretPath,
			event: func(srv *kubetest.Server) {
				srv.Update(cgPath, func(o map[string]any) { o["status"].(map[string]any)["expiresAt"] = "soon" })
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := kubetest.New()
			seed(t, srv)
			t0 := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
			now := t0
			c := newController(t, srv, &now)
			if err := c.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			if tc.event != nil {
				tc.event(srv)
			}
			now = t0.Add(tc.after)
			mark := len(srv.Calls())
			if err := c.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			var writes []string
			for _, v := range verbs(srv.Calls()[mark:]) {
				if strings.Contains(v, "/secrets") && !strings.HasPrefix(v, "GET") {
					writes = append(writes, v)
				}
			}
			wantExpiry := t0.Add(10 * time.Minute)
			if tc.want != "" {
				wantExpiry = now.Add(10 * time.Minute)
				if len(writes) != 1 || writes[0] != tc.want {
					t.Fatalf("secret writes = %v, want [%s]", writes, tc.want)
				}
			} else if len(writes) != 0 {
				t.Fatalf("secret writes = %v, want none", writes)
			}
			if g := minted(t, srv, c); !g.LeaseExpiry.Equal(wantExpiry) {
				t.Fatalf("grant expiry = %s, want %s", g.LeaseExpiry, wantExpiry)
			}
			if st := status(t, srv); st.ExpiresAt != wantExpiry.Format(time.RFC3339) || st.GrantUID != "cg-uid-1" {
				t.Fatalf("status = %+v, want expiry %s", st, wantExpiry)
			}
		})
	}
}

// TestReconcileMintsTheSpec checks how each optional spec field reaches the
// minted grant.
func TestReconcileMintsTheSpec(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(spec map[string]any)
		check  func(g core.Grant, now time.Time) bool
	}{
		{"no lease is ten minutes", func(spec map[string]any) { delete(spec, "lease") },
			func(g core.Grant, now time.Time) bool { return g.LeaseExpiry.Equal(now.Add(10 * time.Minute)) }},
		{"a lease of 90s is 90s", func(spec map[string]any) { spec["lease"] = "90s" },
			func(g core.Grant, now time.Time) bool { return g.LeaseExpiry.Equal(now.Add(90 * time.Second)) }},
		{"no minimum tier is the basic tier", func(spec map[string]any) { delete(spec, "minTier") },
			func(g core.Grant, _ time.Time) bool { return g.MinTier == core.TierBasic }},
		{"no isolation is unspecified, which is untrusted", func(spec map[string]any) { delete(spec, "isolation") },
			func(g core.Grant, _ time.Time) bool { return g.Policy.Isolation.Untrusted() }},
		{"no durability is best effort", func(spec map[string]any) { delete(spec, "durability") },
			func(g core.Grant, _ time.Time) bool { return g.Policy.Durability == core.BestEffort }},
		{"durability best_effort is best effort", func(spec map[string]any) { spec["durability"] = "Best_Effort" },
			func(g core.Grant, _ time.Time) bool { return g.Policy.Durability == core.BestEffort }},
		{"durability sync is sync", func(spec map[string]any) { spec["durability"] = "sync" },
			func(g core.Grant, _ time.Time) bool { return g.Policy.Durability == core.Sync }},
		{"the session class passes through", func(spec map[string]any) { spec["sessionClass"] = "gold" },
			func(g core.Grant, _ time.Time) bool { return g.Policy.SessionClass == "gold" }},
		{"no device budget is none", func(spec map[string]any) { delete(spec, "deviceBudget") },
			func(g core.Grant, _ time.Time) bool { return g.DeviceBudget == core.DeviceBudget{} }},
		{"no W budget is unlimited", func(spec map[string]any) { delete(spec, "wBudget") },
			func(g core.Grant, _ time.Time) bool { return g.WBudgetBytes == 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := kubetest.New()
			seed(t, srv)
			srv.Update(cgPath, func(o map[string]any) { tc.mutate(o["spec"].(map[string]any)) })
			now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
			c := newController(t, srv, &now)
			if err := c.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			if g := minted(t, srv, c); !tc.check(g, now) {
				t.Fatalf("minted grant = %+v", g)
			}
			if st := status(t, srv); st.Message != "" {
				t.Fatalf("status message = %q, want none", st.Message)
			}
		})
	}
}

// TestReconcileInvalidSpecLandsInStatus checks that a spec the controller
// cannot turn into a grant is reported on the resource and mints nothing,
// and that the report goes once the spec is fixed.
func TestReconcileInvalidSpecLandsInStatus(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(spec map[string]any)
		message string
	}{
		{"an unparseable W budget", func(spec map[string]any) { spec["wBudget"] = "lots" }, "spec.wBudget"},
		{"a lease that is not a duration", func(spec map[string]any) { spec["lease"] = "forever" }, "spec.lease"},
		{"a negative lease", func(spec map[string]any) { spec["lease"] = "-1m" }, "spec.lease"},
		{"an unknown minimum tier", func(spec map[string]any) { spec["minTier"] = "FIBER_PLATINUM" }, "spec.minTier"},
		{"an unknown isolation", func(spec map[string]any) { spec["isolation"] = "HOSTILE" }, "spec.isolation"},
		{"an unknown durability", func(spec map[string]any) { spec["durability"] = "maybe" }, "spec.durability"},
		{"an unparseable device budget", func(spec map[string]any) { spec["deviceBudget"].(map[string]any)["bytes"] = "huge" }, "spec.deviceBudget.bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := kubetest.New()
			seed(t, srv)
			var good map[string]any
			srv.Update(cgPath, func(o map[string]any) {
				b, _ := json.Marshal(o["spec"])
				_ = json.Unmarshal(b, &good)
				tc.mutate(o["spec"].(map[string]any))
			})
			now := time.Now()
			c := newController(t, srv, &now)
			if err := c.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			st := status(t, srv)
			if !strings.Contains(st.Message, tc.message) || st.GrantUID != "cg-uid-1" || st.PodName != "conform-grant" {
				t.Fatalf("status = %+v, want the %s error", st, tc.message)
			}
			if srv.Get(secretPath) != nil {
				t.Fatal("a grant was minted from an invalid spec")
			}
			// A regression test: the merge patch of a good pass left the
			// old message in place.
			srv.Update(cgPath, func(o map[string]any) { o["spec"] = good })
			if err := c.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			if st := status(t, srv); st.Message != "" || st.ExpiresAt == "" {
				t.Fatalf("status after the spec was fixed = %+v, want no message and a grant", st)
			}
		})
	}
}

// TestReconcileAPIFailures checks what a pass does when the API server
// refuses one of its calls. A failure lands in the resource's status, and
// a conflict means another writer won, which is no failure.
func TestReconcileAPIFailures(t *testing.T) {
	cases := []struct {
		name       string
		prep       func(srv *kubetest.Server, c *controller.Controller)
		wantErr    string // what Reconcile returns
		message    string // in the status; "" means none
		wantSecret bool
		check      func(t *testing.T, srv *kubetest.Server, calls []kubetest.Call) // calls of the pass
	}{
		{name: "the list failing is Reconcile's error",
			prep:    func(srv *kubetest.Server, _ *controller.Controller) { srv.Fail("GET", listPath, 500, 1) },
			wantErr: "list capacitygrants"},
		{name: "reading the Pod failing is reported",
			prep:    func(srv *kubetest.Server, _ *controller.Controller) { srv.Fail("GET", podPath, 500, 1) },
			message: "get pod: kube: 500"},
		{name: "creating the Pod failing is reported",
			prep:    func(srv *kubetest.Server, _ *controller.Controller) { srv.Fail("POST", podsPath, 403, 1) },
			message: "create pod: kube: 403"},
		{name: "a Pod another writer created first is no failure",
			prep:       func(srv *kubetest.Server, _ *controller.Controller) { srv.Fail("POST", podsPath, 409, 1) },
			wantSecret: true},
		{name: "reading the Secret failing is reported",
			prep:    func(srv *kubetest.Server, _ *controller.Controller) { srv.Fail("GET", secretPath, 500, 1) },
			message: "get secret: kube: 500"},
		{name: "creating the Secret failing is reported",
			prep:    func(srv *kubetest.Server, _ *controller.Controller) { srv.Fail("POST", secretsDir, 500, 1) },
			message: "create secret: kube: 500"},
		{name: "a Secret another writer created first is no failure",
			prep: func(srv *kubetest.Server, _ *controller.Controller) { srv.Fail("POST", secretsDir, 409, 1) },
			check: func(t *testing.T, srv *kubetest.Server, _ []kubetest.Call) {
				if st := status(t, srv); st.ExpiresAt == "" {
					t.Fatalf("status = %+v, want the minted grant's expiry", st)
				}
			}},
		{name: "updating an existing Secret failing is reported",
			prep: func(srv *kubetest.Server, _ *controller.Controller) {
				srv.Put(secretPath, map[string]any{"metadata": map[string]any{"name": "conform-grant"}})
				srv.Fail("PATCH", secretPath, 500, 1)
			},
			message: "update secret: kube: 500", wantSecret: true},
		{name: "minting failing is reported",
			prep:    func(_ *kubetest.Server, c *controller.Controller) { c.Issuer = &grant.Issuer{Key: c.Issuer.Key} },
			message: "mint: grant: issuer needs a key and a URL"},
		{name: "a status that cannot be written is tried once more, with the error, and the pass goes on",
			prep: func(srv *kubetest.Server, _ *controller.Controller) {
				srv.Put("/apis/fiberd.io/v1alpha1/namespaces/tenant-b/capacitygrants/other",
					map[string]any{"spec": map[string]any{"pod": map[string]any{"image": "i"}}})
				srv.Fail("PATCH", statusPath, 500, 0)
			},
			wantSecret: true,
			check: func(t *testing.T, srv *kubetest.Server, calls []kubetest.Call) {
				var patches []string
				for _, c := range calls {
					if c.Method == "PATCH" && c.Path == statusPath {
						patches = append(patches, c.Body)
					}
				}
				if len(patches) != 2 || !strings.Contains(patches[1], `"message":"kube: 500`) {
					t.Fatalf("status patches = %v, want the status and then the error", patches)
				}
				if srv.Get("/api/v1/namespaces/tenant-b/pods/other-grant") == nil {
					t.Fatal("the next resource was not reconciled")
				}
			}},
		{name: "a resource being deleted is left to the garbage collector",
			prep: func(srv *kubetest.Server, _ *controller.Controller) {
				srv.Update(cgPath, func(o map[string]any) {
					o["metadata"].(map[string]any)["deletionTimestamp"] = "2026-09-17T12:00:00Z"
				})
			},
			check: func(t *testing.T, _ *kubetest.Server, calls []kubetest.Call) {
				if got := verbs(calls); !reflect.DeepEqual(got, []string{"GET " + listPath}) {
					t.Fatalf("calls = %v, want only the list", got)
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := kubetest.New()
			seed(t, srv)
			now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
			c := newController(t, srv, &now)
			tc.prep(srv, c)
			calls := len(srv.Calls())
			err := c.Reconcile(context.Background())
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Reconcile = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.check != nil {
				tc.check(t, srv, srv.Calls()[calls:])
			}
			if st := status(t, srv); tc.message == "" && st.Message != "" || !strings.Contains(st.Message, tc.message) {
				t.Fatalf("status message = %q, want %q", st.Message, tc.message)
			}
			if got := srv.Get(secretPath) != nil; got != tc.wantSecret {
				t.Fatalf("secret exists = %v, want %v", got, tc.wantSecret)
			}
		})
	}
}

// TestRun checks the reconcile loop: a failed pass is logged and retried
// on the next tick, and Run returns once ctx ends without waiting for one.
func TestRun(t *testing.T) {
	cases := []struct {
		name     string
		poll     time.Duration
		cancel   bool // end ctx before Run starts
		failList int  // list calls that fail first
	}{
		{name: "an ended context returns at once, not after the default 2s tick", cancel: true},
		{name: "a failed pass is retried on the next tick", poll: 5 * time.Millisecond, failList: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := kubetest.New()
			seed(t, srv)
			if tc.failList > 0 {
				srv.Fail("GET", listPath, 500, tc.failList)
			}
			client := &kube.Client{Base: srv.URL()}
			key, err := controller.EnsureKey(context.Background(), client, "fiberd-system", "grant-issuer-key")
			if err != nil {
				t.Fatal(err)
			}
			mark := len(srv.Calls())
			c := &controller.Controller{Client: client, Issuer: &grant.Issuer{Key: key, URL: issuerURL}, Poll: tc.poll}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			start := time.Now()
			done := make(chan struct{})
			go func() { c.Run(ctx); close(done) }()
			if !tc.cancel {
				for deadline := time.Now().Add(5 * time.Second); status(t, srv).ExpiresAt == ""; time.Sleep(time.Millisecond) {
					if time.Now().After(deadline) {
						t.Fatal("Run never reconciled the resource")
					}
				}
				cancel()
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Run did not return after ctx ended")
			}
			lists := 0
			for _, v := range verbs(srv.Calls()[mark:]) {
				if v == "GET "+listPath {
					lists++
				}
			}
			if tc.cancel {
				if took := time.Since(start); took >= time.Second || lists != 0 {
					t.Fatalf("Run took %s and listed %d times, want an immediate return with no request", took, lists)
				}
				return
			}
			if lists < tc.failList+1 {
				t.Fatalf("list calls = %d, want the %d failures and a pass", lists, tc.failList)
			}
			// The clock is the real one when Now is unset.
			exp, err := time.Parse(time.RFC3339, status(t, srv).ExpiresAt)
			if err != nil || exp.Before(start.Add(10*time.Minute).Truncate(time.Second)) || exp.After(time.Now().Add(10*time.Minute)) {
				t.Fatalf("expiry %v (%v), want ten minutes from the real clock", exp, err)
			}
		})
	}
}

// TestEnsureKey checks that EnsureKey generates the issuer's signing key into
// a Secret once, and reads it back after that.
func TestEnsureKey(t *testing.T) {
	es256, _ := grant.GenerateKey(jose.ES256)
	es256JSON, _ := json.Marshal(es256)
	cases := []struct {
		name    string
		data    map[string]any // the Secret's data. Nil means no Secret
		prep    func(srv *kubetest.Server)
		wantKID string // empty accepts whatever was generated
		wantAlg string
		wantErr string
		calls   []string // the API calls of the first EnsureKey, when checked
	}{
		{name: "a missing Secret gets a generated EdDSA key, and loading again returns it", wantAlg: "EdDSA",
			calls: []string{"GET " + keyPath, "POST /api/v1/namespaces/fiberd-system/secrets"}},
		{name: "an existing Secret is read as it is", data: map[string]any{"key.json": es256JSON}, wantKID: es256.KeyID, wantAlg: "ES256",
			calls: []string{"GET " + keyPath}},
		{name: "a Secret another replica created between the read and the create is read back",
			prep: func(srv *kubetest.Server) {
				srv.Fail("GET", keyPath, 404, 1)
				srv.Put(keyPath, map[string]any{"data": map[string]any{"key.json": es256JSON}})
			},
			wantKID: es256.KeyID, wantAlg: "ES256",
			calls: []string{"GET " + keyPath, "POST /api/v1/namespaces/fiberd-system/secrets", "GET " + keyPath}},
		{name: "a Secret without key.json is an error", data: map[string]any{}, wantErr: "has no key.json"},
		{name: "a Secret whose key.json is not a JWK is an error", data: map[string]any{"key.json": []byte("{")}, wantErr: "key.json"},
		{name: "a read failing for another reason is the error",
			prep: func(srv *kubetest.Server) { srv.Fail("GET", keyPath, 500, 1) }, wantErr: "kube: 500"},
		{name: "a create failing is the error",
			prep:    func(srv *kubetest.Server) { srv.Fail("POST", "/api/v1/namespaces/fiberd-system/secrets", 403, 1) },
			wantErr: "kube: 403"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := kubetest.New()
			t.Cleanup(srv.Close)
			if tc.data != nil {
				srv.Put(keyPath, map[string]any{
					"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": "grant-issuer-key"},
					"data": tc.data,
				})
			}
			if tc.prep != nil {
				tc.prep(srv)
			}
			client := &kube.Client{Base: srv.URL()}
			got, err := controller.EnsureKey(context.Background(), client, "fiberd-system", "grant-issuer-key")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("EnsureKey = %+v (%v), want an error with %q", got, err, tc.wantErr)
				}
				return
			}
			if err != nil || (tc.wantKID != "" && got.KeyID != tc.wantKID) || got.Algorithm != tc.wantAlg || got.IsPublic() {
				t.Fatalf("EnsureKey = %+v (%v), want private kid %q alg %s", got, err, tc.wantKID, tc.wantAlg)
			}
			if tc.calls != nil {
				if v := verbs(srv.Calls()); !reflect.DeepEqual(v, tc.calls) {
					t.Fatalf("calls = %v, want %v", v, tc.calls)
				}
			}
			again, err := controller.EnsureKey(context.Background(), client, "fiberd-system", "grant-issuer-key")
			if err != nil || again.KeyID != got.KeyID {
				t.Fatalf("second EnsureKey: %v (kid %s vs %s)", err, again.KeyID, got.KeyID)
			}
		})
	}
}

// TestParseBytes checks the byte counts a spec may give.
func TestParseBytes(t *testing.T) {
	cases := []struct {
		in      string
		want    uint64
		wantErr bool
	}{
		{in: "", want: 0},
		{in: "  ", want: 0},
		{in: "4096", want: 4096},
		{in: " 3Ki ", want: 3 << 10},
		{in: "32Mi", want: 32 << 20},
		{in: "2Gi", want: 2 << 30},
		{in: "5K", want: 5000},
		{in: "7M", want: 7_000_000},
		{in: "1G", want: 1_000_000_000},
		{in: "12 Mi", want: 12 << 20},
		{in: "Mi", wantErr: true},
		{in: "-1", wantErr: true},
		{in: "1.5Gi", wantErr: true},
		{in: "lots", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := controller.ParseBytes(tc.in)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("ParseBytes(%q) = %d, %v; want %d, error %v", tc.in, got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func status(t *testing.T, srv *kubetest.Server) controller.Status {
	t.Helper()
	raw := srv.Get(cgPath)
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
