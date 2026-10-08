package home

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/endpoint"

	"github.com/helayoty/fiberd/examples/kubernetes/kube"
	"github.com/helayoty/fiberd/examples/kubernetes/kube/kubetest"
)

// TestNewGivesUpWithoutAnAddress checks that New stops waiting for the
// Pod's IP once podIPWait has passed, for a tcp family only.
func TestNewGivesUpWithoutAnAddress(t *testing.T) {
	cases := []struct {
		name    string
		family  endpoint.Family
		wantErr string
	}{
		{name: "inet4 without an IPv4 address gives up", family: endpoint.Inet4, wantErr: "k8s: the Pod got no inet4 address within 1s"},
		{name: "inet6 without an IPv6 address gives up", family: endpoint.Inet6, wantErr: "k8s: the Pod got no inet6 address within 1s"},
		{name: "unix needs no address", family: endpoint.Unix},
	}
	oldWait, oldRetry := podIPWait, podIPRetry
	// One read, then the wait ends before a retry is due.
	podIPWait, podIPRetry = time.Second, time.Hour
	t.Cleanup(func() { podIPWait, podIPRetry = oldWait, oldRetry })
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := kubetest.New()
			t.Cleanup(srv.Close)
			srv.Put("/api/v1/namespaces/ns/pods/p", map[string]any{"status": map[string]any{"podIP": "10.0.0.1"}})
			if tc.family == endpoint.Inet4 {
				srv.Put("/api/v1/namespaces/ns/pods/p", map[string]any{"status": map[string]any{"podIPs": []any{map[string]any{"ip": "fd00::1"}}}})
			}
			cg := t.TempDir()
			if err := os.WriteFile(filepath.Join(cg, "cgroup.subtree_control"), []byte("memory pids\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			h, err := New(Config{Client: &kube.Client{Base: srv.URL()}, Namespace: "ns", PodName: "p", Family: tc.family,
				CgroupRoot: cg, TokenFile: filepath.Join(cg, "no-token")})
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("New = %v, want %q", err, tc.wantErr)
				}
				if n := len(srv.Calls()); n != 1 {
					t.Fatalf("the Pod was read %d times, want once before the wait ended", n)
				}
				return
			}
			if err != nil || h.EndpointHost() != "10.0.0.1" {
				t.Fatalf("New = %v, host %q", err, h.EndpointHost())
			}
			if !strings.HasSuffix(h.CgroupRoot(), "fiberd") {
				t.Fatalf("cgroup root = %q", h.CgroupRoot())
			}
		})
	}
}
