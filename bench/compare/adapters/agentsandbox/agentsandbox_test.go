package agentsandbox

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

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
			go func() {
				time.Sleep(20 * time.Millisecond)
				srv.Update(poolPath, func(obj map[string]any) { obj["status"] = map[string]any{"readyReplicas": tc.ready} })
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
