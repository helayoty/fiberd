package home_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/endpoint"
	fhome "github.com/helayoty/fiberd/pkg/home"

	"github.com/helayoty/fiberd/examples/kubernetes/home"
	"github.com/helayoty/fiberd/examples/kubernetes/kube"
	"github.com/helayoty/fiberd/examples/kubernetes/kube/kubetest"
)

// The cluster the home's Pod lives in.
const (
	ns        = "tenant-a"
	podName   = "grant-x-0"
	claimName = "grant-x-0-gpu-abc12"
	podPath   = "/api/v1/namespaces/" + ns + "/pods/" + podName
	nsPath    = "/api/v1/namespaces/" + ns
	claimPath = "/apis/resource.k8s.io/v1/namespaces/" + ns + "/resourceclaims/" + claimName
	issuer    = "https://kubernetes.default.svc"
)

// podObject is the home's own Pod as the API server serves it.
func podObject(name string) map[string]any {
	return map[string]any{
		"metadata": map[string]any{"name": name, "namespace": ns, "uid": "uid-1"},
		"spec": map[string]any{
			"nodeName": "node-7", "serviceAccountName": "fiberd-grant",
			"resourceClaims": []any{map[string]any{"name": "gpu", "resourceClaimTemplateName": "gpu-tpl"}},
		},
		"status": map[string]any{
			"podIP":                 "10.1.2.3",
			"podIPs":                []any{map[string]any{"ip": "10.1.2.3"}, map[string]any{"ip": "fd00::3"}},
			"resourceClaimStatuses": []any{map[string]any{"name": "gpu", "resourceClaimName": claimName}},
		},
	}
}

// newCluster is an API server holding the Pod, its namespace and its claim.
func newCluster(t *testing.T) *kubetest.Server {
	srv := kubetest.New()
	t.Cleanup(srv.Close)
	srv.Put(podPath, podObject(podName))
	srv.Put(nsPath, map[string]any{"metadata": map[string]any{"name": ns}, "status": map[string]any{"phase": "Active"}})
	srv.Put(claimPath, map[string]any{"metadata": map[string]any{"name": claimName}})
	return srv
}

// saToken is an unsigned JWT shaped like a projected service-account
// token; the home only peeks at its issuer.
func saToken(iss string) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"k"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + iss + `","sub":"system:serviceaccount:tenant-a:fiberd-grant"}`))
	return hdr + "." + body + ".sig"
}

// config is a home configuration against srv, with a token file and a fake
// cgroup root that already delegates memory and pids.
func config(t *testing.T, srv *kubetest.Server) (home.Config, string) {
	dir := t.TempDir()
	// The bearer and the watched token are the same file in a Pod. Here
	// they are two, so a test can take the watched one away alone.
	tokenFile, bearer := filepath.Join(dir, "token"), filepath.Join(dir, "bearer")
	for _, f := range []string{tokenFile, bearer} {
		if err := os.WriteFile(f, []byte(saToken(issuer)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cg := filepath.Join(dir, "cgroup")
	_ = os.MkdirAll(cg, 0o755)
	_ = os.WriteFile(filepath.Join(cg, "cgroup.subtree_control"), []byte("memory pids\n"), 0o644)
	_ = os.WriteFile(filepath.Join(cg, "cgroup.procs"), nil, 0o644)
	return home.Config{
		Client:    &kube.Client{Base: srv.URL(), TokenFile: bearer},
		Namespace: ns, PodName: podName, GrantsDir: filepath.Join(dir, "grants"), Poll: 20 * time.Millisecond,
		StaleTTL: 100 * time.Millisecond, CgroupRoot: cg, Devices: []string{"/dev/sim0"}, Family: endpoint.Inet4,
		ListenPort: "8484", TokenFile: tokenFile,
	}, tokenFile
}

func newHome(t *testing.T, srv *kubetest.Server) (*home.Home, string) {
	cfg, tokenFile := config(t, srv)
	h, err := home.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return h, tokenFile
}

// scopeOf is the value of one scope claim, or "" when the home has none.
func scopeOf(h *home.Home, claim string) string {
	for _, c := range h.Scope() {
		if c.Name == claim {
			return c.Value
		}
	}
	return ""
}

// claim reads one scope claim, for TestHomeFromItsPod's rows.
func claim(name string) func(*testing.T, *home.Home, *kubetest.Server) string {
	return func(_ *testing.T, h *home.Home, _ *kubetest.Server) string { return scopeOf(h, name) }
}

func endpointHost(_ *testing.T, h *home.Home, _ *kubetest.Server) string { return h.EndpointHost() }

func fabric(t *testing.T, h *home.Home, _ *kubetest.Server) string {
	fc, release, err := h.Fabric(context.Background(), core.Grant{UID: "g"})
	if err != nil {
		t.Fatalf("fabric: %v", err)
	}
	release()
	return fc.Kind + "|" + fc.Detail + "|" + strings.Join(fc.Devices, ",")
}

// setStatus replaces fields of the seeded Pod's status.
func setStatus(fields map[string]any) func(map[string]any) {
	return func(p map[string]any) {
		for k, v := range fields {
			p["status"].(map[string]any)[k] = v
		}
	}
}

// TestHomeFromItsPod checks what the home reads off its own Pod at start,
// using the service-account token as bearer, and what it derives from that.
func TestHomeFromItsPod(t *testing.T) {
	cases := []struct {
		name  string
		pod   func(p map[string]any) // changes the seeded Pod
		cfg   func(c *home.Config)
		token string // the token file's content, or "" for a valid one
		got   func(t *testing.T, h *home.Home, srv *kubetest.Server) string
		want  string
	}{
		{name: "the home is named k8s",
			got: func(_ *testing.T, h *home.Home, _ *kubetest.Server) string { return h.Name() }, want: "k8s"},
		{name: "the cgroup root is fiberd under the delegated root",
			got: func(_ *testing.T, h *home.Home, _ *kubetest.Server) string {
				r := h.CgroupRoot()
				return filepath.Join(filepath.Base(filepath.Dir(r)), filepath.Base(r))
			}, want: "cgroup/fiberd"},
		{name: "the own-Pod read carries the service-account token as bearer",
			got: func(t *testing.T, _ *home.Home, srv *kubetest.Server) string {
				calls := srv.Calls()
				if len(calls) == 0 || calls[0].Method != "GET" || calls[0].Path != podPath {
					t.Fatalf("calls = %+v, want the own Pod read first", calls)
				}
				return calls[0].Authorization
			}, want: "Bearer " + saToken(issuer)},
		{name: "scope names the namespace", got: claim("namespace"), want: ns},
		{name: "scope names the pod", got: claim("pod"), want: podName},
		{name: "scope names the pod uid", got: claim("pod_uid"), want: "uid-1"},
		{name: "scope names the service account", got: claim("service_account"), want: "fiberd-grant"},
		{name: "scope names the node", got: claim("node"), want: "node-7"},
		{name: "scope names the token's issuer", got: claim("issuer"), want: issuer},
		{name: "scope names the bound resource claim", got: claim("resource_claim"), want: claimName},
		{name: "scope lists the claims sorted: generated names from the status, else the spec's",
			pod: func(p map[string]any) {
				p["spec"].(map[string]any)["resourceClaims"] = []any{
					map[string]any{"name": "gpu", "resourceClaimTemplateName": "gpu-tpl"},
					map[string]any{"name": "nic", "resourceClaimName": "a-shared-nic"},
					map[string]any{"name": "pending", "resourceClaimTemplateName": "not-generated-yet"},
				}
			},
			got: claim("resource_claim"), want: "a-shared-nic," + claimName},
		{name: "a bare Pod's scope is the namespace and the name only",
			pod: func(p map[string]any) {
				p["metadata"].(map[string]any)["uid"] = ""
				p["spec"] = map[string]any{}
				p["status"] = map[string]any{"podIP": "10.1.2.3"}
			},
			token: "not-a-jwt",
			got: func(_ *testing.T, h *home.Home, _ *kubetest.Server) string {
				b, _ := json.Marshal(h.Scope())
				return string(b)
			}, want: `[{"Name":"namespace","Value":"tenant-a"},{"Name":"pod","Value":"grant-x-0"}]`},
		{name: "a token whose payload is not base64 names no issuer",
			token: "a.%%%.c", got: claim("issuer"), want: ""},
		{name: "a token whose payload is not JSON names no issuer",
			token: "a." + base64.RawURLEncoding.EncodeToString([]byte("[")) + ".c", got: claim("issuer"), want: ""},
		{name: "no token file names no issuer",
			cfg: func(c *home.Config) { c.TokenFile = filepath.Join(t.TempDir(), "missing") }, got: claim("issuer"), want: ""},
		{name: "inet4: the endpoint host is the Pod's IPv4 address", got: endpointHost, want: "10.1.2.3"},
		{name: "inet4: the advertised endpoint is host:port",
			got: func(_ *testing.T, h *home.Home, _ *kubetest.Server) string { return h.AdvertisedEndpoint() }, want: "10.1.2.3:8484"},
		{name: "inet6: the endpoint host is the Pod's IPv6 address",
			cfg: func(c *home.Config) { c.Family = endpoint.Inet6 }, got: endpointHost, want: "fd00::3"},
		{name: "inet6: the advertised endpoint is [host]:port",
			cfg: func(c *home.Config) { c.Family = endpoint.Inet6 },
			got: func(_ *testing.T, h *home.Home, _ *kubetest.Server) string { return h.AdvertisedEndpoint() }, want: "[fd00::3]:8484"},
		{name: "unix: the endpoint host is still the Pod's IPv4 address",
			cfg: func(c *home.Config) { c.Family = endpoint.Unix }, got: endpointHost, want: "10.1.2.3"},
		{name: "no family set: the endpoint host is the Pod's IPv4 address",
			cfg: func(c *home.Config) { c.Family = "" }, got: endpointHost, want: "10.1.2.3"},
		{name: "a Pod with only status.podIP uses it",
			pod: setStatus(map[string]any{"podIPs": nil, "podIP": "10.9.9.9"}), got: endpointHost, want: "10.9.9.9"},
		{name: "an address that does not parse is skipped",
			pod: setStatus(map[string]any{"podIPs": []any{map[string]any{"ip": "bogus"}, map[string]any{"ip": "10.4.4.4"}}}),
			got: endpointHost, want: "10.4.4.4"},
		{name: "unix with no address: no endpoint host and nothing advertised",
			pod: setStatus(map[string]any{"podIPs": nil, "podIP": ""}), cfg: func(c *home.Config) { c.Family = endpoint.Unix },
			got: func(_ *testing.T, h *home.Home, _ *kubetest.Server) string {
				return h.EndpointHost() + "|" + h.AdvertisedEndpoint()
			},
			want: "|"},
		{name: "the fabric is the Pod's DRA claim and its devices", got: fabric, want: "dra|" + claimName + "|/dev/sim0"},
		{name: "devices without a claim are a static fabric",
			pod: func(p map[string]any) { delete(p["spec"].(map[string]any), "resourceClaims") }, got: fabric, want: "static||/dev/sim0"},
		{name: "no claim and no devices is no fabric",
			pod: func(p map[string]any) { delete(p["spec"].(map[string]any), "resourceClaims") },
			cfg: func(c *home.Config) { c.Devices = nil }, got: fabric, want: "||"},
		{name: "the stale TTL defaults to 30s",
			cfg: func(c *home.Config) { c.StaleTTL = 0 },
			got: func(_ *testing.T, h *home.Home, _ *kubetest.Server) string {
				now := time.Now()
				b, _ := json.Marshal([]bool{h.Health().Healthy(now.Add(29 * time.Second)), h.Health().Healthy(now.Add(31 * time.Second))})
				return string(b)
			}, want: "[true,false]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newCluster(t)
			if tc.pod != nil {
				srv.Update(podPath, tc.pod)
			}
			cfg, tokenFile := config(t, srv)
			if tc.token != "" {
				if err := os.WriteFile(tokenFile, []byte(tc.token), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.cfg != nil {
				tc.cfg(&cfg)
			}
			h, err := home.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if got := tc.got(t, h, srv); got != tc.want {
				t.Fatalf("got %q, want %q (scope: %v)", got, tc.want, h.Scope())
			}
		})
	}
}

// TestNew checks what New refuses, and the defaults it fills in.
func TestNew(t *testing.T) {
	hostname, _ := os.Hostname()
	cases := []struct {
		name    string
		prep    func(t *testing.T, srv *kubetest.Server, c *home.Config)
		wantErr string
		check   func(t *testing.T, h *home.Home, srv *kubetest.Server)
	}{
		{name: "no client outside a cluster is an error",
			prep: func(t *testing.T, _ *kubetest.Server, c *home.Config) {
				t.Setenv("KUBERNETES_SERVICE_HOST", "")
				c.Client = nil
			},
			wantErr: "not in a cluster"},
		{name: "no namespace and no projected namespace file is an error",
			prep: func(t *testing.T, _ *kubetest.Server, c *home.Config) {
				if _, err := os.Stat(kube.NamespaceFile); err == nil {
					t.Skip("running in a Pod: the projected namespace file exists")
				}
				c.Namespace = ""
			},
			wantErr: "kube: namespace"},
		{name: "the own Pod unreadable is an error",
			prep:    func(_ *testing.T, srv *kubetest.Server, _ *home.Config) { srv.Fail("GET", podPath, 403, 1) },
			wantErr: "k8s: read own Pod tenant-a/grant-x-0: kube: 403"},
		{name: "a cgroup root without the memory controller is an error",
			prep: func(t *testing.T, _ *kubetest.Server, c *home.Config) {
				if err := os.WriteFile(filepath.Join(c.CgroupRoot, "cgroup.controllers"), []byte("pids\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "no memory controller"},
		{name: "no pod name is the hostname",
			prep: func(_ *testing.T, srv *kubetest.Server, c *home.Config) {
				c.PodName = ""
				srv.Put("/api/v1/namespaces/"+ns+"/pods/"+hostname, podObject(hostname))
			},
			check: func(t *testing.T, h *home.Home, _ *kubetest.Server) {
				if got := scopeOf(h, "pod"); got != hostname {
					t.Fatalf("pod = %q, want the hostname %q", got, hostname)
				}
			}},
		{name: "no token file is the projected token, absent here, so no issuer",
			prep: func(t *testing.T, _ *kubetest.Server, c *home.Config) {
				if _, err := os.Stat(kube.TokenFile); err == nil {
					t.Skip("running in a Pod: the projected token exists")
				}
				c.TokenFile = ""
			},
			check: func(t *testing.T, h *home.Home, _ *kubetest.Server) {
				if got := scopeOf(h, "issuer"); got != "" {
					t.Fatalf("issuer = %q, want none", got)
				}
			}},
		{name: "no grants dir is the projected grant volume",
			prep: func(t *testing.T, _ *kubetest.Server, c *home.Config) {
				if _, err := os.Stat("/var/run/fiberd/grants"); err == nil {
					t.Skip("the default grants dir exists here")
				}
				if os.Geteuid() == 0 {
					t.Skip("root could create the default grants dir")
				}
				c.GrantsDir = ""
			},
			check: func(t *testing.T, h *home.Home, _ *kubetest.Server) {
				_, err := h.Grants(context.Background())
				if err == nil || !strings.Contains(err.Error(), "/var/run/fiberd") {
					t.Fatalf("Grants = %v, want an error about the default dir", err)
				}
			}},
		{name: "no cgroup root is /sys/fs/cgroup",
			prep: func(t *testing.T, _ *kubetest.Server, c *home.Config) {
				if runtime.GOOS == "linux" {
					t.Skip("on Linux this would delegate the real cgroup")
				}
				c.CgroupRoot = ""
			},
			wantErr: "/sys/fs/cgroup"},
		{name: "a tcp family waits for the kubelet to write the Pod's IP",
			prep: func(t *testing.T, srv *kubetest.Server, _ *home.Config) {
				srv.Update(podPath, setStatus(map[string]any{"podIP": "", "podIPs": nil}))
				// The IP lands once New has read the Pod without one.
				go func() {
					for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
						if len(srv.Calls()) > 0 {
							srv.Update(podPath, setStatus(map[string]any{"podIP": "10.7.7.7"}))
							return
						}
					}
				}()
			},
			check: func(t *testing.T, h *home.Home, srv *kubetest.Server) {
				if got := h.EndpointHost(); got != "10.7.7.7" {
					t.Fatalf("endpoint host = %q, want the IP written later", got)
				}
				if n := len(srv.Calls()); n < 2 {
					t.Fatalf("the Pod was read %d times, want a retry", n)
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newCluster(t)
			cfg, _ := config(t, srv)
			tc.prep(t, srv, &cfg)
			h, err := home.New(cfg)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("New = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, h, srv)
		})
	}
}

// TestGrants checks the grant lane, which reads *.jwt files from the
// projected volume.
func TestGrants(t *testing.T) {
	cases := []struct {
		name    string
		prep    func(t *testing.T, dir string)
		want    string // the token of the first event
		wantErr bool
	}{
		{name: "a projected grant file is delivered",
			prep: func(t *testing.T, dir string) {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "grant.jwt"), []byte("tok"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "tok"},
		{name: "a grants dir that cannot be made is an error",
			prep: func(t *testing.T, dir string) {
				if err := os.WriteFile(dir, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newCluster(t)
			cfg, _ := config(t, srv)
			h, err := home.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			tc.prep(t, cfg.GrantsDir)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ch, err := h.Grants(ctx)
			if tc.wantErr {
				if err == nil {
					t.Fatal("Grants on a file: want an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			select {
			case ev := <-ch:
				if ev.Kind != fhome.GrantAdded || string(ev.Token) != tc.want {
					t.Fatalf("event = %+v, want %q added", ev, tc.want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no grant event")
			}
		})
	}
}

// TestReadinessGate checks the gate, one Pod condition over every grant the
// agent holds. It reads False only once no grant is warm, and its transition
// time moves only when its status does. The Pod starts with the gate open,
// as an agent left it before a restart.
func TestReadinessGate(t *testing.T) {
	const opened = "2020-01-01T00:00:00Z"
	srv := newCluster(t)
	srv.Update(podPath, setStatus(map[string]any{"conditions": []any{map[string]any{
		"type": home.ReadyCondition, "status": "True", "reason": "ZygoteWarm",
		"message": "grant g0 template is warm", "lastTransitionTime": opened,
	}}}))
	h, _ := newHome(t, srv)
	steps := []struct {
		name    string
		grant   string
		ready   bool
		fail    bool // the API server refuses the patch
		status  string
		reason  string
		message string
		moved   bool // the transition time is now, else the one before
	}{
		// A publish that keeps the status must keep the transition time.
		{"the first grant warm keeps the gate open, and its time", "g1", true, false, "True", "ZygoteWarm", "grant g1 template is warm", false},
		{"a second grant warm keeps it open, and its time", "g2", true, false, "True", "ZygoteWarm", "grant g2 template is warm", false},
		{"one grant cold while another is warm keeps it open, and its time", "g1", false, false, "True", "ZygoteWarm", "grant g1 template is warm", false},
		{"the last grant cold closes it, and its time moves", "g2", false, false, "False", "NoWarmTemplate", "no grant has a warm template", true},
		{"a refused patch is the error, and the gate keeps what it had", "g3", true, true, "False", "NoWarmTemplate", "no grant has a warm template", false},
		{"the next patch carries what the refused one would have, and its time moves", "g4", true, false, "True", "ZygoteWarm", "grant g4 template is warm", true},
	}
	since := opened
	for _, step := range steps {
		ok := t.Run(step.name, func(t *testing.T) {
			if step.fail {
				srv.Fail("PATCH", podPath+"/status", 500, 1)
			}
			mark, began := len(srv.Calls()), time.Now().Truncate(time.Second)
			err := h.PublishReady(context.Background(), step.grant, step.ready)
			if step.fail != (err != nil) {
				t.Fatalf("PublishReady = %v, want an error: %v", err, step.fail)
			}
			calls := srv.Calls()[mark:]
			if len(calls) != 1 || calls[0].Method != "PATCH" || calls[0].Path != podPath+"/status" ||
				calls[0].ContentType != "application/strategic-merge-patch+json" {
				t.Fatalf("calls = %+v, want one strategic status patch", calls)
			}
			// The stored Pod has exactly one gate condition, merged by type.
			conds, _ := srv.Get(podPath)["status"].(map[string]any)["conditions"].([]any)
			if len(conds) != 1 {
				t.Fatalf("conditions = %v, want one", conds)
			}
			c := conds[0].(map[string]any)
			if c["type"] != home.ReadyCondition || c["status"] != step.status || c["reason"] != step.reason || c["message"] != step.message {
				t.Fatalf("gate = %v, want %s %s %q", c, step.status, step.reason, step.message)
			}
			got, _ := c["lastTransitionTime"].(string)
			at, err := time.Parse(time.RFC3339, got)
			switch {
			case err != nil:
				t.Fatalf("lastTransitionTime: %v", err)
			case step.moved && at.Before(began):
				t.Fatalf("lastTransitionTime = %s, want it moved to now", got)
			case !step.moved && got != since:
				t.Fatalf("lastTransitionTime = %s, want it kept at %s", got, since)
			}
			since = got
		})
		if !ok {
			return // later steps build on this one
		}
	}
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// podReads counts the liveness reads of the own Pod, one per poll.
func podReads(srv *kubetest.Server) int {
	n := 0
	for _, c := range srv.Calls() {
		if c.Method == "GET" && c.Path == podPath {
			n++
		}
	}
	return n
}

// TestLivenessAndScopeLoss checks that the lane is healthy while the API
// server answers, and that each trip is reported as scope loss exactly
// once. A failing API server or a token rotated by the same issuer is not
// scope loss.
func TestLivenessAndScopeLoss(t *testing.T) {
	cases := []struct {
		name       string
		trip       func(srv *kubetest.Server, tokenFile string)
		reason     string            // empty means no scope loss
		scope      map[string]string // claims expected afterwards
		stale      bool              // the lane goes stale
		noCallback bool              // no OnScopeLost before the trip
	}{
		{name: "namespace terminating", reason: "namespace tenant-a terminating",
			trip: func(srv *kubetest.Server, _ string) {
				srv.Update(nsPath, func(o map[string]any) { o["status"].(map[string]any)["phase"] = "Terminating" })
			}},
		{name: "namespace marked for deletion", reason: "namespace tenant-a terminating",
			trip: func(srv *kubetest.Server, _ string) {
				srv.Update(nsPath, func(o map[string]any) {
					o["metadata"].(map[string]any)["deletionTimestamp"] = "2026-09-17T00:00:00Z"
				})
			}},
		{name: "namespace gone", reason: "namespace tenant-a gone",
			trip: func(srv *kubetest.Server, _ string) { srv.Delete(nsPath) }},
		{name: "claim gone", reason: "resource claim " + claimName + " gone",
			trip: func(srv *kubetest.Server, _ string) { srv.Delete(claimPath) }},
		{name: "claim being deleted", reason: "resource claim " + claimName + " being deleted",
			trip: func(srv *kubetest.Server, _ string) {
				srv.Update(claimPath, func(o map[string]any) {
					o["metadata"].(map[string]any)["deletionTimestamp"] = "2026-09-17T00:00:00Z"
				})
			}},
		{name: "a namespace read failing is no loss, and the claims are still checked",
			reason: "resource claim " + claimName + " gone",
			trip: func(srv *kubetest.Server, _ string) {
				srv.Fail("GET", nsPath, 500, 0)
				srv.Delete(claimPath)
			}},
		{name: "pod gone", reason: "pod tenant-a/grant-x-0 gone", stale: true,
			trip: func(srv *kubetest.Server, _ string) { srv.Delete(podPath) }},
		{name: "the Pod read failing is no loss, and the lane goes stale", stale: true,
			trip: func(srv *kubetest.Server, _ string) { srv.Fail("GET", podPath, 500, 0) }},
		{name: "a claim read failing is no loss",
			trip: func(srv *kubetest.Server, _ string) { srv.Fail("GET", claimPath, 503, 0) }},
		{name: "an unreadable token file is no loss",
			trip:  func(_ *kubetest.Server, tokenFile string) { _ = os.Remove(tokenFile) },
			scope: map[string]string{"issuer": issuer}},
		{name: "a rotated token from the same issuer is nothing",
			trip: func(_ *kubetest.Server, tokenFile string) {
				_ = os.WriteFile(tokenFile, []byte(saToken(issuer)), 0o600)
			},
			scope: map[string]string{"issuer": issuer}},
		{name: "a token from a different issuer is scope loss, and the scope names the new issuer",
			trip: func(_ *kubetest.Server, tokenFile string) {
				_ = os.WriteFile(tokenFile, []byte(saToken("https://issuer.example/new")), 0o600)
			},
			reason: "service account issuer changed from " + issuer + " to https://issuer.example/new",
			scope:  map[string]string{"issuer": "https://issuer.example/new"}},
		{name: "a loss before any callback is set is not fatal, and is not replayed later", noCallback: true,
			trip: func(srv *kubetest.Server, _ string) { srv.Delete(claimPath) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newCluster(t)
			h, tokenFile := newHome(t, srv)
			var mu sync.Mutex
			var reasons []string
			record := func(_ context.Context, reason string) {
				mu.Lock()
				reasons = append(reasons, reason)
				mu.Unlock()
			}
			got := func() []string {
				mu.Lock()
				defer mu.Unlock()
				return append([]string(nil), reasons...)
			}
			if !tc.noCallback {
				h.OnScopeLost(record)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() { h.Run(ctx); close(done) }()
			defer func() { cancel(); <-done }()
			waitFor(t, "the first liveness probe", func() bool { return podReads(srv) > 0 && h.Health().Healthy(time.Now()) })
			tc.trip(srv, tokenFile)
			// Three more polls start after the trip, so at least two
			// finished with it in place.
			after := podReads(srv)
			if tc.reason != "" {
				waitFor(t, "the scope loss", func() bool { return len(got()) > 0 })
			}
			waitFor(t, "two more polls", func() bool { return podReads(srv) >= after+3 })
			if tc.noCallback {
				h.OnScopeLost(record)
				after = podReads(srv)
				waitFor(t, "two more polls", func() bool { return podReads(srv) >= after+3 })
			}
			switch r := got(); {
			case tc.reason == "" && len(r) != 0:
				t.Fatalf("scope-loss reasons = %v, want none", r)
			case tc.reason != "" && (len(r) != 1 || r[0] != tc.reason):
				t.Fatalf("scope-loss reasons = %v, want exactly one %q", r, tc.reason)
			}
			if tc.stale {
				waitFor(t, "the lane to go stale", func() bool { return !h.Health().Healthy(time.Now()) })
			} else {
				waitFor(t, "the lane healthy while the Pod answers", func() bool { return h.Health().Healthy(time.Now()) })
			}
			for k, v := range tc.scope {
				if got := scopeOf(h, k); got != v {
					t.Fatalf("scope %s = %q, want %q", k, got, v)
				}
			}
		})
	}
}

// TestLaneHealth checks that the lane follows the API server and that
// SetLane overrides it. The steps share one home and run in order.
func TestLaneHealth(t *testing.T) {
	srv := newCluster(t)
	h, _ := newHome(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	healthy := func() bool { return h.Health().Healthy(time.Now()) }
	steps := []struct {
		name string
		act  func(t *testing.T)
		want bool
	}{
		{"the API server answering keeps the lane healthy", func(t *testing.T) {
			waitFor(t, "a liveness probe", healthy)
		}, true},
		{"SetLane(false) makes the lane stale, and answers do not revive it", func(t *testing.T) {
			h.SetLane(false)
			after := podReads(srv)
			waitFor(t, "two more polls", func() bool { return podReads(srv) >= after+3 })
		}, false},
		{"SetLane(true) recovers the lane", func(*testing.T) { h.SetLane(true) }, true},
		{"the API server unreachable past the stale TTL makes the lane stale", func(t *testing.T) {
			srv.Close()
			waitFor(t, "the lane to go stale", func() bool { return !healthy() })
		}, false},
	}
	for _, step := range steps {
		ok := t.Run(step.name, func(t *testing.T) {
			step.act(t)
			if got := healthy(); got != step.want {
				t.Fatalf("healthy = %v, want %v", got, step.want)
			}
		})
		if !ok {
			return // later steps build on this one
		}
	}
}
