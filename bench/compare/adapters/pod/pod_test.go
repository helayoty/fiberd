package pod

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/examples/kubernetes/kube"
	"github.com/helayoty/fiberd/examples/kubernetes/kube/kubetest"

	"github.com/helayoty/fiberd/bench/compare"
)

// counter is a loopback HTTP server answering 200 to everything. It
// stands in for the Pod, whose IP the fake API server reports as
// 127.0.0.1 and whose port is the listener's.
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

func client(s *kubetest.Server) *kube.Client {
	return &kube.Client{Base: s.URL(), HTTP: &http.Client{Timeout: 5 * time.Second}}
}

func TestBuild(t *testing.T) {
	cases := []struct {
		name string
		opt  Options
		want func(t *testing.T, p *pod)
	}{
		{name: "runc warm", opt: Options{Image: "img", PullPolicy: "IfNotPresent", NodeName: "n1", CPU: "250m", Memory: "64Mi"},
			want: func(t *testing.T, p *pod) {
				c := p.Spec.Containers[0]
				if p.Spec.RuntimeClassName != "" || p.Spec.NodeName != "n1" || c.ImagePullPolicy != "IfNotPresent" {
					t.Errorf("spec %+v", p.Spec)
				}
				if c.Resources.Limits["cpu"] != "250m" || c.Resources.Limits["memory"] != "64Mi" {
					t.Errorf("limits %v", c.Resources.Limits)
				}
				if len(c.Resources.Requests) != 1 || c.Resources.Requests["cpu"] != "10m" {
					t.Errorf("requests %v, want only cpu 10m", c.Resources.Requests)
				}
				if p.Spec.RestartPolicy != "Never" {
					t.Errorf("restart %q", p.Spec.RestartPolicy)
				}
			}},
		{name: "gvisor cold", opt: Options{Image: "img", PullPolicy: "Always", RuntimeClass: "gvisor"},
			want: func(t *testing.T, p *pod) {
				if p.Spec.RuntimeClassName != "gvisor" || p.Spec.Containers[0].ImagePullPolicy != "Always" {
					t.Errorf("spec %+v", p.Spec)
				}
				if r := p.Spec.Containers[0].Resources; r.Limits != nil || r.Requests != nil {
					t.Error("no limits asked, none set")
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.opt.Kube, tc.opt.Namespace = &kube.Client{}, "ns"
			a, err := New(tc.opt)
			if err != nil {
				t.Fatal(err)
			}
			p := a.Build("R1-b1-0")
			if p.Metadata.Name != "cmp-r1-b1-0" || p.Metadata.Namespace != "ns" {
				t.Errorf("name %s/%s", p.Metadata.Namespace, p.Metadata.Name)
			}
			tc.want(t, p)
		})
	}
}

func TestLifecycle(t *testing.T) {
	cases := []struct {
		name string
		cold bool
		// phase, when set, is what the fake Pod reports instead of an IP.
		phase   string
		wantErr string
	}{
		{name: "warm: create, ip, first byte, delete"},
		{name: "cold: the image is removed by Prepare, not by the create", cold: true},
		{name: "a failed Pod is an error, not a hang", phase: "Failed", wantErr: "is Failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := kubetest.New()
			defer srv.Close()
			port := counter(t)
			removed := 0
			o := Options{Kube: client(srv), Namespace: "ns", Image: "img", Port: port, Poll: time.Millisecond}
			if tc.cold {
				o.RemoveImage = func(context.Context) error { removed++; return nil }
			}
			a, err := New(o)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := a.Prepare(ctx, "x"); err != nil {
				t.Fatal(err)
			}
			if want := map[bool]int{true: 1}[tc.cold]; removed != want {
				t.Errorf("image removed %d times by Prepare, want %d", removed, want)
			}
			h, err := a.Activate(ctx, "x")
			if err != nil {
				t.Fatal(err)
			}
			path := "/api/v1/namespaces/ns/pods/" + h.ID
			if srv.Get(path) == nil {
				t.Fatal("pod not created")
			}
			if tc.cold && removed != 1 {
				t.Errorf("image removed %d times after the create, want 1: Activate removed it inside the timed window", removed)
			}
			// The kubelet sets the IP a little later.
			go func() {
				time.Sleep(20 * time.Millisecond)
				srv.Update(path, func(obj map[string]any) {
					st := map[string]any{"podIP": "127.0.0.1"}
					if tc.phase != "" {
						st = map[string]any{"phase": tc.phase}
					}
					obj["status"] = st
				})
			}()
			h, fb, err := a.Ready(ctx, h)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if h.Addr != "127.0.0.1:"+strconv.Itoa(port) || fb.IsZero() {
				t.Errorf("handle %+v first byte %v", h, fb)
			}
			if err := a.Release(ctx, h); err != nil {
				t.Fatal(err)
			}
			if srv.Get(path) != nil {
				t.Error("pod not deleted")
			}
			var deletes int
			for _, c := range srv.Calls() {
				if c.Method == http.MethodDelete && strings.HasSuffix(c.Path, h.ID) {
					deletes++
				}
			}
			if deletes != 1 {
				t.Errorf("deletes %d, want 1", deletes)
			}
			if err := a.Park(ctx, h); !errors.Is(err, compare.ErrUnsupported) {
				t.Errorf("park err %v, want ErrUnsupported", err)
			}
			if _, err := a.Resume(ctx, h); !errors.Is(err, compare.ErrUnsupported) {
				t.Errorf("resume err %v, want ErrUnsupported", err)
			}
		})
	}
}

func TestMissing(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want bool
	}{
		{name: "crictl's missing image, what a burst's other removals see", out: "FATA[0000] no such image localhost:5002/counter:latest\n", want: true},
		{name: "a missing crictl is an error, not a warm run", out: "sh: 1: crictl: not found\n"},
		{name: "a missing crictl, bash's wording", out: "sh: crictl: command not found\n"},
		{name: "a refused socket", out: "FATA[0000] connect: connection refused\n"},
		{name: "nothing", out: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Missing(tc.out); got != tc.want {
				t.Errorf("Missing(%q) = %v, want %v", tc.out, got, tc.want)
			}
		})
	}
}
