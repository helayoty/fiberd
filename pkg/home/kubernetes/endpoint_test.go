package kubernetes_test

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/Azure/fiberd/pkg/endpoint"
	"github.com/Azure/fiberd/pkg/home/kubernetes"
)

// TestPodIP checks which of the Pod's addresses each family picks.
func TestPodIP(t *testing.T) {
	cases := []struct {
		name   string
		podIP  string
		podIPs []string
		family endpoint.Family
		want   string
	}{
		{name: "inet4 from the list", podIPs: []string{"fd00::1", "10.0.0.1"}, family: endpoint.Inet4, want: "10.0.0.1"},
		{name: "inet6 from the list", podIPs: []string{"10.0.0.1", "fd00::1"}, family: endpoint.Inet6, want: "fd00::1"},
		{name: "the single podIP when the list is empty", podIP: "10.0.0.1", family: endpoint.Inet4, want: "10.0.0.1"},
		{name: "no address of the family", podIPs: []string{"10.0.0.1"}, family: endpoint.Inet6},
		{name: "no address at all", family: endpoint.Inet4},
		{name: "an address that does not parse is skipped", podIPs: []string{"not-an-ip", "10.0.0.2"}, family: endpoint.Inet4, want: "10.0.0.2"},
		{name: "an IPv4-mapped IPv6 address is inet4, in its IPv4 form", podIPs: []string{"::ffff:10.0.0.3"}, family: endpoint.Inet4, want: "10.0.0.3"},
		{name: "an IPv4-mapped IPv6 address is not inet6", podIPs: []string{"::ffff:10.0.0.3"}, family: endpoint.Inet6},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &corev1.Pod{}
			p.Status.PodIP = c.podIP
			for _, ip := range c.podIPs {
				p.Status.PodIPs = append(p.Status.PodIPs, corev1.PodIP{IP: ip})
			}
			if got := kubernetes.PodIP(p, c.family); got != c.want {
				t.Fatalf("PodIP = %q, want %q", got, c.want)
			}
		})
	}
}

// TestEndpointHost checks the wait for the Pod's address: the stored Pod
// answers without a read, else the wait ends with the address, with the
// wait running out, with Close, or with Run's context ending, and it
// logs a read error once when it gives up.
func TestEndpointHost(t *testing.T) {
	readErr := errors.New("no route")
	cases := []struct {
		name   string
		family endpoint.Family
		noIP   bool
		// pollFirst runs one round before, so the Pod is stored.
		pollFirst bool
		readErr   error
		// withRun starts Run first, so its polls read the Pod too and the
		// read count is not checked.
		withRun bool
		// during runs once EndpointHost waits on the clock. stop ends Run.
		during   func(h *testHome, stop func())
		want     string
		wantLog  string
		wantRead int
	}{
		{name: "inet4 at once", family: endpoint.Inet4, want: "10.0.0.1", wantRead: 1},
		{name: "inet6 at once", family: endpoint.Inet6, want: "fd00::1", wantRead: 1},
		{name: "the stored Pod answers without a read", family: endpoint.Inet4, pollFirst: true, want: "10.0.0.1", wantRead: 1},
		{name: "a stored Pod without an address is read again", family: endpoint.Inet4, pollFirst: true, noIP: true,
			during: func(h *testHome, _ func()) {
				h.kube.SetPod(livePod())
				h.clock.Step(kubernetes.PodIPRetry)
			}, want: "10.0.0.1", wantRead: 3},
		{name: "unix advertises nothing and reads nothing", family: endpoint.Unix, wantRead: 0},
		{name: "the address arrives on a retry", family: endpoint.Inet4, noIP: true,
			during: func(h *testHome, _ func()) {
				h.kube.SetPod(livePod())
				h.clock.Step(kubernetes.PodIPRetry)
			}, want: "10.0.0.1", wantRead: 2},
		{name: "the wait runs out", family: endpoint.Inet4, noIP: true,
			during: func(h *testHome, _ func()) {
				h.clock.Step(kubernetes.PodIPWait)
			},
			wantLog: `"msg"="Pod got no address in time"`, wantRead: 2},
		{name: "a read error is logged once when the wait runs out", family: endpoint.Inet4, readErr: readErr,
			during: func(h *testHome, _ func()) {
				h.clock.Step(kubernetes.PodIPWait)
			},
			wantLog: `"msg"="Gave up waiting for the Pod's address" "error"="no route"`, wantRead: 2},
		{name: "Close cuts the wait short", family: endpoint.Inet4, noIP: true,
			during: func(h *testHome, _ func()) {
				h.Close()
			},
			wantLog: `"msg"="Stopped before the Pod had an address"`, wantRead: 1},
		{name: "Run's context ending cuts the wait short", family: endpoint.Inet4, noIP: true, withRun: true,
			during: func(_ *testHome, stop func()) {
				stop()
			},
			wantLog: `"msg"="Stopped before the Pod had an address"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newTestHome(t, func(cfg *kubernetes.Config) { cfg.Family = c.family })
			if c.noIP {
				p := livePod()
				p.Status.PodIP, p.Status.PodIPs = "", nil
				h.kube.SetPod(p)
			}
			if c.pollFirst {
				if err := h.Once(context.Background()); err != nil {
					t.Fatalf("round: %v", err)
				}
			}
			h.kube.SetPodErr(c.readErr)
			stop := func() {}
			if c.withRun {
				stop = h.run(t)
				defer stop()
			}
			got := make(chan string, 1)
			go func() { got <- h.EndpointHost() }()
			if c.during != nil {
				waitFor(t, "the wait for the address", h.clock.HasWaiters)
				c.during(h, stop)
			}
			select {
			case host := <-got:
				if host != c.want {
					t.Fatalf("EndpointHost = %q, want %q\n%s", host, c.want, h.logs)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("EndpointHost did not return")
			}
			if c.wantLog != "" && h.logs.count(c.wantLog) != 1 {
				t.Fatalf("want one line %s, got\n%s", c.wantLog, h.logs)
			}
			if !c.withRun {
				if n := h.kube.Calls("GetPod"); n != c.wantRead {
					t.Fatalf("the Pod was read %d times, want %d", n, c.wantRead)
				}
			}
		})
	}
}

// TestPodIPRetry checks the wait's shape, one read per second for ninety
// seconds.
func TestPodIPRetry(t *testing.T) {
	cases := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{name: "a read every second", got: kubernetes.PodIPRetry, want: time.Second},
		{name: "for ninety seconds", got: kubernetes.PodIPWait, want: 90 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.got != c.want {
				t.Fatalf("%s, want %s", c.got, c.want)
			}
		})
	}
}
