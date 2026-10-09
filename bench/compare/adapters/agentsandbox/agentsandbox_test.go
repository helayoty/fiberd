package agentsandbox

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/helayoty/fiberd/bench/compare"

	"github.com/helayoty/fiberd/examples/kubernetes/kube"
	"github.com/helayoty/fiberd/examples/kubernetes/kube/kubetest"
)

func counter(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = bufio.NewReader(c).ReadString('\n')
			_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n1\n"))
			_ = c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

const (
	poolPath  = ext + "ns/sandboxwarmpools/counter"
	tmplPath  = ext + "ns/sandboxtemplates/counter"
	claimPath = ext + "ns/sandboxclaims/claim-x"
	sbPath    = core + "ns/sandboxes/sb-1"
)

func newAdapter(t *testing.T, srv *kubetest.Server, replicas int, rc string) *Adapter {
	t.Helper()
	a, err := New(Options{Kube: &kube.Client{Base: srv.URL(), HTTP: &http.Client{Timeout: 5 * time.Second}}, Namespace: "ns",
		Image: "img", Replicas: replicas, RuntimeClass: rc, Port: counter(t), Poll: time.Millisecond, Wait: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestTemplateResources(t *testing.T) {
	cases := []struct {
		name         string
		cpu, memory  string
		wantLimits   map[string]any
		wantRequests map[string]any
	}{
		{name: "a CPU limit reserves only the small request", cpu: "250m", memory: "64Mi",
			wantLimits: map[string]any{"cpu": "250m", "memory": "64Mi"}, wantRequests: map[string]any{"cpu": "10m"}},
		{name: "no CPU limit, no request", memory: "64Mi", wantLimits: map[string]any{"memory": "64Mi"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := New(Options{Kube: &kube.Client{}, Namespace: "ns", Image: "img", CPU: tc.cpu, Memory: tc.memory})
			if err != nil {
				t.Fatal(err)
			}
			tmpl := a.Template()["spec"].(map[string]any)
			if got := tmpl["networkPolicyManagement"]; got != "Unmanaged" {
				t.Errorf("networkPolicyManagement %v, want Unmanaged so the client can reach the sandbox", got)
			}
			spec := tmpl["podTemplate"].(map[string]any)["spec"].(map[string]any)
			res := spec["containers"].([]any)[0].(map[string]any)["resources"].(map[string]any)
			if got := res["limits"]; !reflect.DeepEqual(got, tc.wantLimits) {
				t.Errorf("limits %v, want %v", got, tc.wantLimits)
			}
			got, _ := res["requests"].(map[string]any)
			if tc.wantRequests == nil && got != nil || tc.wantRequests != nil && !reflect.DeepEqual(got, tc.wantRequests) {
				t.Errorf("requests %v, want %v", got, tc.wantRequests)
			}
		})
	}
}

func TestSetup(t *testing.T) {
	cases := []struct {
		name     string
		replicas int
		ready    int
		existing bool
		rc       string
		wantErr  bool
	}{
		{name: "pool of 1 fills", replicas: 1, ready: 1},
		{name: "pool of 5 under gvisor fills", replicas: 5, ready: 5, rc: "gvisor"},
		{name: "existing template and pool are patched, not refused", replicas: 2, ready: 2, existing: true},
		{name: "a pool that never fills times out", replicas: 3, ready: 1, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := kubetest.New()
			defer srv.Close()
			a := newAdapter(t, srv, tc.replicas, tc.rc)
			if tc.existing {
				srv.Put(tmplPath, a.Template())
				old := a.Pool()
				old["spec"].(map[string]any)["replicas"] = 99
				srv.Put(poolPath, old)
			}
			// The controller fills the pool once Setup has made it, however
			// late that is under load.
			go func() {
				for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(time.Millisecond) {
					if srv.Update(poolPath, func(obj map[string]any) { obj["status"] = map[string]any{"readyReplicas": tc.ready} }) {
						return
					}
				}
			}()
			err := a.Setup(context.Background())
			if (err != nil) != tc.wantErr {
				t.Fatalf("err %v, want error %v", err, tc.wantErr)
			}
			pool := srv.Get(poolPath)
			if got := pool["spec"].(map[string]any)["replicas"]; got != float64(tc.replicas) {
				t.Errorf("replicas %v, want %d", got, tc.replicas)
			}
			tmpl := srv.Get(tmplPath)
			spec := tmpl["spec"].(map[string]any)["podTemplate"].(map[string]any)["spec"].(map[string]any)
			if rc, _ := spec["runtimeClassName"].(string); rc != tc.rc {
				t.Errorf("runtimeClassName %q, want %q", rc, tc.rc)
			}
		})
	}
}

func TestClaim(t *testing.T) {
	cases := []struct {
		name   string
		resume bool
	}{
		{name: "claim, podIPs, first byte, delete"},
		{name: "suspend and run again", resume: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := kubetest.New()
			defer srv.Close()
			a := newAdapter(t, srv, 1, "")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			h, err := a.Activate(ctx, "x")
			if err != nil {
				t.Fatal(err)
			}
			if srv.Get(claimPath) == nil {
				t.Fatal("claim not created")
			}
			setIPs := func(ips []any) {
				srv.Update(claimPath, func(obj map[string]any) {
					obj["status"] = map[string]any{"sandbox": map[string]any{"name": "sb-1", "podIPs": ips}}
				})
			}
			go func() { time.Sleep(20 * time.Millisecond); setIPs([]any{"127.0.0.1"}) }()
			h, fb, err := a.Ready(ctx, h)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(h.Addr, "127.0.0.1:") || fb.IsZero() || h.Meta["sandbox"] != "sb-1" {
				t.Errorf("handle %+v", h)
			}
			if tc.resume {
				srv.Put(sbPath, map[string]any{"spec": map[string]any{"operatingMode": "Running"},
					"status": map[string]any{"podIPs": []any{"127.0.0.1"}}})
				go func() {
					time.Sleep(20 * time.Millisecond)
					srv.Update(sbPath, func(obj map[string]any) { obj["status"] = map[string]any{} })
				}()
				if err := a.Park(ctx, h); err != nil {
					t.Fatal(err)
				}
				nh, err := a.Resume(ctx, h)
				if err != nil {
					t.Fatal(err)
				}
				if nh.Addr != "" || nh.Meta["sandbox"] != "sb-1" {
					t.Errorf("resumed handle %+v should have no address yet", nh)
				}
				var modes []string
				for _, c := range srv.Calls() {
					if c.Method == http.MethodPatch && c.Path == sbPath {
						modes = append(modes, c.Body)
					}
				}
				if len(modes) != 2 || !strings.Contains(modes[0], "Suspended") || !strings.Contains(modes[1], "Running") {
					t.Errorf("mode patches %v", modes)
				}
				if _, _, err := a.Ready(ctx, nh); err != nil {
					t.Fatal(err)
				}
			}
			if err := a.Release(ctx, h); err != nil {
				t.Fatal(err)
			}
			if srv.Get(claimPath) != nil {
				t.Error("claim not deleted")
			}
		})
	}
}

// owned is a Sandbox's metadata with one controller owner.
func owned(kind, name string) map[string]any {
	return map[string]any{"metadata": map[string]any{"ownerReferences": []map[string]any{
		{"apiVersion": "x/v1", "kind": kind, "name": name, "uid": "u-" + name, "controller": true}}}}
}

// seedSandboxes puts Sandboxes with their Pods and cgroups in place:
// two the pool "counter" still owns, one a claim took, one of another
// pool. Each Pod is charged its index in MiB.
func seedSandboxes(t *testing.T, srv *kubetest.Server) string {
	t.Helper()
	root := t.TempDir()
	for i, sb := range []struct{ name, ownerKind, owner string }{
		{"counter-a", "SandboxWarmPool", "counter"}, {"counter-b", "SandboxWarmPool", "counter"},
		{"counter-c", "SandboxClaim", "claim-x"}, {"other-a", "SandboxWarmPool", "other"},
	} {
		srv.Put(core+"ns/sandboxes/"+sb.name, owned(sb.ownerKind, sb.owner))
		uid := "uid-" + sb.name
		srv.Put("/api/v1/namespaces/ns/pods/"+sb.name, map[string]any{"metadata": map[string]any{"uid": uid}})
		dir := filepath.Join(root, "kubepods", "pod"+uid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "memory.current"), []byte(strconv.Itoa((i+1)<<20)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestDensity(t *testing.T) {
	cases := []struct {
		name    string
		handles []compare.Handle
		// refilling: counter-b's Pod has no cgroup yet and the pool is
		// not full until it has, as right after a density burst.
		refilling bool
		want      int64
	}{
		{name: "standing is the pool's unclaimed sandboxes only", want: 1<<20 + 2<<20},
		{name: "standing waits for a refilling pool to be full", refilling: true, want: 1<<20 + 2<<20},
		{name: "handles are charged their own sandboxes", handles: []compare.Handle{{ID: "claim-x", Meta: map[string]string{"sandbox": "counter-c"}}}, want: 3 << 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := kubetest.New()
			defer srv.Close()
			a := newAdapter(t, srv, 2, "")
			a.o.CgroupRoot = seedSandboxes(t, srv)
			pool := a.Pool()
			pool["status"] = map[string]any{"readyReplicas": 2}
			if tc.refilling {
				pool["status"] = map[string]any{"readyReplicas": 1}
				b, held := filepath.Join(a.o.CgroupRoot, "kubepods", "poduid-counter-b"), filepath.Join(t.TempDir(), "b")
				if err := os.Rename(b, held); err != nil {
					t.Fatal(err)
				}
				go func() {
					time.Sleep(100 * time.Millisecond)
					_ = os.Rename(held, b)
					srv.Update(poolPath, func(obj map[string]any) { obj["status"] = map[string]any{"readyReplicas": 2} })
				}()
			}
			srv.Put(poolPath, pool)
			got, err := a.Density(context.Background(), tc.handles)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("density %d, want %d", got, tc.want)
			}
		})
	}
}

func TestCleanup(t *testing.T) {
	cases := []struct {
		name     string
		standing bool
	}{
		{name: "the pool and the template are deleted", standing: true},
		{name: "nothing standing is not an error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := kubetest.New()
			defer srv.Close()
			a := newAdapter(t, srv, 1, "")
			if tc.standing {
				srv.Put(tmplPath, a.Template())
				srv.Put(poolPath, a.Pool())
			}
			if err := a.Cleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
			if srv.Get(poolPath) != nil || srv.Get(tmplPath) != nil {
				t.Error("the pool or the template survived Cleanup")
			}
		})
	}
}

// pool is a fake agent-sandbox controller on the kubetest server. Each
// claim takes a ready sandbox, and the pool replaces it only refill
// later, as a real pool starts a new Pod. short lists the bursts whose
// first claim found the pool less than full.
type pool struct {
	srv      *kubetest.Server
	kube     *kube.Client
	refill   time.Duration
	replicas int
	mu       sync.Mutex
	ready    int
	seen     map[string]bool
	short    []string
}

// set writes the ready count to the pool's status, under p.mu.
func (p *pool) set() {
	p.srv.Update(poolPath, func(obj map[string]any) { obj["status"] = map[string]any{"readyReplicas": p.ready} })
}

func (p *pool) run(ctx context.Context) {
	for ctx.Err() == nil {
		p.mu.Lock()
		p.set()
		p.mu.Unlock()
		var list struct {
			Items []struct {
				Metadata kube.ObjectMeta `json:"metadata"`
				Status   map[string]any  `json:"status"`
			} `json:"items"`
		}
		_ = p.kube.Get(ctx, ext+"ns/sandboxclaims", &list)
		for _, c := range list.Items {
			if c.Status != nil {
				continue
			}
			p.mu.Lock()
			// A claim is named after its run, burst and index, so the
			// name without the index names the burst.
			burst := c.Metadata.Name[:strings.LastIndex(c.Metadata.Name, "-")]
			if !p.seen[burst] {
				p.seen[burst] = true
				if p.ready < p.replicas {
					p.short = append(p.short, fmt.Sprintf("%s found %d of %d ready", burst, p.ready, p.replicas))
				}
			}
			if p.ready > 0 {
				p.ready--
				p.set()
				p.srv.Update(ext+"ns/sandboxclaims/"+c.Metadata.Name, func(obj map[string]any) {
					obj["status"] = map[string]any{"sandbox": map[string]any{"name": "sb-" + c.Metadata.Name, "podIPs": []any{"127.0.0.1"}}}
				})
				time.AfterFunc(p.refill, func() {
					p.mu.Lock()
					defer p.mu.Unlock()
					p.ready++
					p.set()
				})
			}
			p.mu.Unlock()
		}
		time.Sleep(time.Millisecond)
	}
}

func TestBurstsStartOnAFullPool(t *testing.T) {
	cases := []struct {
		name     string
		replicas int
		bursts   []int
	}{
		{name: "pool of 1, bursts of 1", replicas: 1, bursts: []int{1}},
		{name: "pool of 2, bursts of 2 then 1", replicas: 2, bursts: []int{2, 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := kubetest.New()
			defer srv.Close()
			a := newAdapter(t, srv, tc.replicas, "")
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			p := &pool{srv: srv, kube: a.o.Kube, refill: 300 * time.Millisecond, replicas: tc.replicas, ready: tc.replicas, seen: map[string]bool{}}
			go p.run(ctx)
			var out bytes.Buffer
			r := &compare.Runner{Adapter: a, System: "s", Class: "c", Runs: 2, Bursts: tc.bursts, Poll: time.Millisecond, Out: &out}
			if err := r.Run(ctx); err != nil {
				t.Fatal(err)
			}
			p.mu.Lock()
			short := p.short
			p.mu.Unlock()
			if len(short) > 0 {
				t.Errorf("bursts started on a pool that was not full: %v", short)
			}
			n := 0
			for _, line := range bytes.Split(bytes.TrimSpace(out.Bytes()), []byte("\n")) {
				var rec compare.Record
				if err := json.Unmarshal(line, &rec); err != nil {
					t.Fatal(err)
				}
				if rec.Kind != "activation" {
					continue
				}
				n++
				if rec.Error != "" {
					t.Errorf("activation %s: %s", rec.ID, rec.Error)
				}
			}
			if want := 3 * sum(tc.bursts); n != want {
				t.Errorf("activations %d, want %d", n, want)
			}
		})
	}
}

func sum(xs []int) int {
	n := 0
	for _, x := range xs {
		n += x
	}
	return n
}
