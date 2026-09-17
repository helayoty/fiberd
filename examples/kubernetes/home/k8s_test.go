package home_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/endpoint"

	"github.com/helayoty/fiberd/examples/kubernetes/home"
	"github.com/helayoty/fiberd/examples/kubernetes/kube"
)

// fakeAPI is the four paths the home touches, with knobs the tests turn.
type fakeAPI struct {
	mu          sync.Mutex
	nsGone      bool
	nsDeleting  bool
	claimGone   bool
	podGone     bool
	patches     []map[string]any
	tokens      []string // bearer tokens seen
	srv         *httptest.Server
	ns, pod, cl string
}

func newFakeAPI(t *testing.T) *fakeAPI {
	f := &fakeAPI{ns: "tenant-a", pod: "grant-x-0", cl: "grant-x-0-gpu-abc12"}
	mux := http.NewServeMux()
	podPath := "/api/v1/namespaces/" + f.ns + "/pods/" + f.pod
	mux.HandleFunc("GET "+podPath, func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.tokens = append(f.tokens, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if f.podGone {
			notFound(w)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"metadata": map[string]any{"name": f.pod, "namespace": f.ns, "uid": "uid-1"},
			"spec": map[string]any{
				"nodeName": "node-7", "serviceAccountName": "fiberd-grant",
				"resourceClaims": []map[string]any{{"name": "gpu", "resourceClaimTemplateName": "gpu-tpl"}},
			},
			"status": map[string]any{
				"podIP":                 "10.1.2.3",
				"podIPs":                []map[string]string{{"ip": "10.1.2.3"}, {"ip": "fd00::3"}},
				"resourceClaimStatuses": []map[string]string{{"name": "gpu", "resourceClaimName": f.cl}},
			},
		})
	})
	mux.HandleFunc("PATCH "+podPath+"/status", func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/strategic-merge-patch+json" {
			http.Error(w, "content type "+ct, http.StatusUnsupportedMediaType)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var p map[string]any
		if err := json.Unmarshal(body, &p); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.patches = append(f.patches, p)
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	})
	mux.HandleFunc("GET /api/v1/namespaces/"+f.ns, func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.nsGone {
			notFound(w)
			return
		}
		meta := map[string]any{"name": f.ns}
		phase := "Active"
		if f.nsDeleting {
			meta["deletionTimestamp"] = "2026-09-17T00:00:00Z"
			phase = "Terminating"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"metadata": meta, "status": map[string]any{"phase": phase}})
	})
	mux.HandleFunc("GET /apis/resource.k8s.io/v1/namespaces/"+f.ns+"/resourceclaims/"+f.cl, func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.claimGone {
			notFound(w)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"name": f.cl}})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func notFound(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"kind":"Status","message":"not found","code":404}`))
}

// saToken is an unsigned JWT shaped like a projected service-account
// token; the home only peeks at its issuer.
func saToken(iss string) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"k"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + iss + `","sub":"system:serviceaccount:tenant-a:fiberd-grant"}`))
	return hdr + "." + body + ".sig"
}

func newHome(t *testing.T, f *fakeAPI, fam endpoint.Family) (*home.Home, string) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte(saToken("https://kubernetes.default.svc")), 0o600); err != nil {
		t.Fatal(err)
	}
	// A fake cgroup root that already delegates memory and pids.
	cg := filepath.Join(dir, "cgroup")
	_ = os.MkdirAll(cg, 0o755)
	_ = os.WriteFile(filepath.Join(cg, "cgroup.subtree_control"), []byte("memory pids\n"), 0o644)
	_ = os.WriteFile(filepath.Join(cg, "cgroup.procs"), nil, 0o644)
	h, err := home.New(home.Config{
		Client:    &kube.Client{Base: f.srv.URL, TokenFile: tokenFile},
		Namespace: f.ns, PodName: f.pod, GrantsDir: filepath.Join(dir, "grants"), Poll: 20 * time.Millisecond,
		StaleTTL: 100 * time.Millisecond, CgroupRoot: cg, Devices: []string{"/dev/sim0"}, Family: fam,
		ListenPort: "8484", TokenFile: tokenFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h, tokenFile
}

func TestScopeEndpointFabricAndReadinessGate(t *testing.T) {
	f := newFakeAPI(t)
	h, _ := newHome(t, f, endpoint.Inet4)
	if h.Name() != "k8s" || !strings.HasSuffix(h.CgroupRoot(), "/cgroup/fiberd") {
		t.Fatalf("name %q cgroup root %q", h.Name(), h.CgroupRoot())
	}
	if got := f.tokens; len(got) == 0 || got[0] == "" {
		t.Fatal("own-Pod read carried no bearer token")
	}
	want := map[string]string{"namespace": "tenant-a", "pod": "grant-x-0", "pod_uid": "uid-1", "service_account": "fiberd-grant",
		"node": "node-7", "issuer": "https://kubernetes.default.svc", "resource_claim": f.cl}
	got := map[string]string{}
	for _, c := range h.Scope() {
		got[c.Name] = c.Value
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("scope %s = %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
	if h.EndpointHost() != "10.1.2.3" || h.AdvertisedEndpoint() != "10.1.2.3:8484" {
		t.Fatalf("inet4 endpoint host %q advertised %q", h.EndpointHost(), h.AdvertisedEndpoint())
	}
	h6, _ := newHome(t, f, endpoint.Inet6)
	if h6.EndpointHost() != "fd00::3" || h6.AdvertisedEndpoint() != "[fd00::3]:8484" {
		t.Fatalf("inet6 endpoint host %q advertised %q", h6.EndpointHost(), h6.AdvertisedEndpoint())
	}
	fc, release, err := h.Fabric(context.Background(), core.Grant{UID: "g"})
	if err != nil || fc.Kind != "dra" || fc.Detail != f.cl || len(fc.Devices) != 1 {
		t.Fatalf("fabric = %+v (%v)", fc, err)
	}
	release()

	ctx := context.Background()
	if err := h.PublishReady(ctx, "g1", true); err != nil {
		t.Fatal(err)
	}
	if err := h.PublishReady(ctx, "g2", true); err != nil {
		t.Fatal(err)
	}
	if err := h.PublishReady(ctx, "g1", false); err != nil {
		t.Fatal(err)
	}
	if err := h.PublishReady(ctx, "g2", false); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	statuses := make([]string, 0, len(f.patches))
	for _, p := range f.patches {
		conds := p["status"].(map[string]any)["conditions"].([]any)
		c := conds[0].(map[string]any)
		if c["type"] != home.ReadyCondition {
			t.Fatalf("condition type %v", c["type"])
		}
		statuses = append(statuses, c["status"].(string))
	}
	if strings.Join(statuses, ",") != "True,True,True,False" {
		t.Fatalf("gate statuses = %v, want True,True,True,False (False only once no grant is warm)", statuses)
	}
}

func TestLivenessAndScopeLoss(t *testing.T) {
	cases := []struct {
		name   string
		trip   func(f *fakeAPI)
		reason string
	}{
		{"namespace terminating", func(f *fakeAPI) { f.nsDeleting = true }, "namespace tenant-a terminating"},
		{"namespace gone", func(f *fakeAPI) { f.nsGone = true }, "namespace tenant-a gone"},
		{"claim gone", func(f *fakeAPI) { f.claimGone = true }, "resource claim " + "grant-x-0-gpu-abc12" + " gone"},
		{"pod gone", func(f *fakeAPI) { f.podGone = true }, "pod tenant-a/grant-x-0 gone"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t)
			h, _ := newHome(t, f, endpoint.Inet4)
			var mu sync.Mutex
			var reasons []string
			h.OnScopeLost(func(_ context.Context, reason string) {
				mu.Lock()
				reasons = append(reasons, reason)
				mu.Unlock()
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go h.Run(ctx)
			time.Sleep(120 * time.Millisecond)
			if !h.Health().Healthy(time.Now()) {
				t.Fatal("API server answering: lane must be healthy")
			}
			f.mu.Lock()
			tc.trip(f)
			f.mu.Unlock()
			time.Sleep(200 * time.Millisecond)
			mu.Lock()
			defer mu.Unlock()
			if len(reasons) != 1 || reasons[0] != tc.reason {
				t.Fatalf("scope-loss reasons = %v, want exactly one %q", reasons, tc.reason)
			}
		})
	}
}

func TestIssuerRotationIsScopeLoss(t *testing.T) {
	f := newFakeAPI(t)
	h, tokenFile := newHome(t, f, endpoint.Inet4)
	var mu sync.Mutex
	var reasons []string
	h.OnScopeLost(func(_ context.Context, reason string) {
		mu.Lock()
		reasons = append(reasons, reason)
		mu.Unlock()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)
	time.Sleep(80 * time.Millisecond)
	// A rotated token from the same issuer is nothing; a different issuer
	// is scope loss, and the scope now names the new issuer.
	_ = os.WriteFile(tokenFile, []byte(saToken("https://kubernetes.default.svc")), 0o600)
	time.Sleep(120 * time.Millisecond)
	_ = os.WriteFile(tokenFile, []byte(saToken("https://issuer.example/new")), 0o600)
	time.Sleep(150 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(reasons) != 1 || !strings.Contains(reasons[0], "issuer changed") {
		t.Fatalf("reasons = %v", reasons)
	}
	for _, c := range h.Scope() {
		if c.Name == "issuer" && c.Value != "https://issuer.example/new" {
			t.Fatalf("scope issuer = %q after rotation", c.Value)
		}
	}
}

func TestAPIServerSilenceIsUnhealthy(t *testing.T) {
	f := newFakeAPI(t)
	h, _ := newHome(t, f, endpoint.Inet4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)
	time.Sleep(60 * time.Millisecond)
	f.srv.Close()
	time.Sleep(250 * time.Millisecond)
	if h.Health().Healthy(time.Now()) {
		t.Fatal("API server unreachable past the stale TTL: lane must be stale")
	}
	h.SetLane(true)
	if !h.Health().Healthy(time.Now()) {
		t.Fatal("SetLane(true) must recover the lane")
	}
}
