package kubernetes_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"github.com/Azure/fiberd/pkg/core"
	"github.com/Azure/fiberd/pkg/endpoint"
	"github.com/Azure/fiberd/pkg/home/kubernetes"
	"github.com/Azure/fiberd/pkg/home/kubernetes/fake"
)

func validConfig() kubernetes.Config {
	return kubernetes.Config{Kube: fake.New(testNamespace), PodName: testPod, PodNamespace: testNamespace, PodUID: testPodUID}
}

// TestConfigValidate checks every way a configuration is refused.
func TestConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		change  func(c *kubernetes.Config)
		wantErr string
	}{
		{name: "the minimum is accepted", change: func(*kubernetes.Config) {}},
		{name: "a cluster client is required", change: func(c *kubernetes.Config) { c.Kube = nil }, wantErr: "cluster client is required"},
		{name: "the Pod name is required", change: func(c *kubernetes.Config) { c.PodName = "" }, wantErr: "Pod name is required"},
		{name: "the Pod namespace is required", change: func(c *kubernetes.Config) { c.PodNamespace = "" }, wantErr: "Pod namespace is required"},
		{name: "the Pod UID is required", change: func(c *kubernetes.Config) { c.PodUID = "" }, wantErr: "Pod UID is required"},
		{name: "a negative stale TTL is refused", change: func(c *kubernetes.Config) { c.StaleTTL = -time.Second }, wantErr: "stale TTL -1s is negative"},
		{name: "a negative poll interval is refused", change: func(c *kubernetes.Config) { c.Poll = -time.Second }, wantErr: "poll interval -1s is negative"},
		{name: "a poll interval not shorter than the stale TTL is refused", change: func(c *kubernetes.Config) { c.StaleTTL, c.Poll = 10*time.Second, 10*time.Second },
			wantErr: "poll interval 10s is not shorter than the stale TTL 10s"},
		{name: "a negative grants poll interval is refused", change: func(c *kubernetes.Config) { c.GrantsPoll = -time.Second }, wantErr: "grants poll interval -1s is negative"},
		{name: "an unknown family is refused", change: func(c *kubernetes.Config) { c.Family = "ipx" }, wantErr: `unknown endpoint family "ipx"`},
		{name: "the unix family is accepted", change: func(c *kubernetes.Config) { c.Family = endpoint.Unix }},
		{name: "a grant token file needs the issuer URL",
			change:  func(c *kubernetes.Config) { c.GrantTokenFile, c.GrantsDir = "/run/token", "/run/grants" },
			wantErr: "grant token file needs the issuer URL"},
		{name: "a grant token file needs the grants directory",
			change:  func(c *kubernetes.Config) { c.GrantTokenFile, c.GrantIssuerURL = "/run/token", "https://issuer.test" },
			wantErr: "grant token file needs the grants directory"},
		{name: "an http issuer URL is refused when the fetch sends the Pod's token",
			change: func(c *kubernetes.Config) {
				c.GrantTokenFile, c.GrantsDir, c.GrantIssuerURL = "/run/token", "/run/grants", "http://issuer.test"
			},
			wantErr: `issuer URL "http://issuer.test" is not https, and the grant fetch sends the Pod's token to it`},
		{name: "an issuer URL that does not parse is refused when the fetch is on",
			change: func(c *kubernetes.Config) {
				c.GrantTokenFile, c.GrantsDir, c.GrantIssuerURL = "/run/token", "/run/grants", "://issuer.test"
			},
			wantErr: "is not https"},
		{name: "an http issuer URL is accepted without the fetch", change: func(c *kubernetes.Config) { c.GrantIssuerURL = "http://issuer.test" }},
		{name: "a negative grant fetch timeout is refused", change: func(c *kubernetes.Config) { c.GrantFetchTimeout = -time.Second },
			wantErr: "grant fetch timeout -1s is negative"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := validConfig()
			c.change(&cfg)
			err := cfg.Validate()
			if (err != nil) != (c.wantErr != "") || (err != nil && !strings.Contains(err.Error(), c.wantErr)) {
				t.Fatalf("Validate = %v, want %q", err, c.wantErr)
			}
			if _, err := kubernetes.New(t.Context(), cfg); (err != nil) != (c.wantErr != "") {
				t.Fatalf("New = %v, want an error %v", err, c.wantErr != "")
			}
		})
	}
}

// TestNewDefaults checks what New fills in: the name, the cgroup root
// and the intervals.
func TestNewDefaults(t *testing.T) {
	cases := []struct {
		name           string
		cgroupRoot     string
		wantCgroupRoot func(root string) bool
	}{
		{name: "a given cgroup root is kept", cgroupRoot: "/sys/fs/cgroup/kubepods/pod1",
			wantCgroupRoot: func(root string) bool { return root == "/sys/fs/cgroup/kubepods/pod1" }},
		{name: "an empty cgroup root is the cgroup fiberd runs in",
			wantCgroupRoot: func(root string) bool { return strings.HasPrefix(root, "/sys/fs/cgroup") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.CgroupRoot = c.cgroupRoot
			h, err := kubernetes.New(t.Context(), cfg)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if h.Name() != kubernetes.Name || h.Name() != "kubernetes" {
				t.Fatalf("Name = %q", h.Name())
			}
			if !c.wantCgroupRoot(h.CgroupRoot()) {
				t.Fatalf("CgroupRoot = %q", h.CgroupRoot())
			}
			if h.Health() == nil || !h.Health().Healthy(time.Now()) {
				t.Fatal("a new home does not start healthy")
			}
			if h.Ready() {
				t.Fatal("a new home is ready before any template is warm")
			}
			ch, err := h.Grants(context.Background())
			if ch != nil || err != nil {
				t.Fatalf("Grants without a directory = %v, %v", ch, err)
			}
		})
	}
}

// TestRunOnce checks that Run drives the home once and that a second
// call returns at once instead of starting a second poll.
func TestRunOnce(t *testing.T) {
	cases := []struct {
		name string
		runs int
	}{
		{name: "one Run polls", runs: 1},
		{name: "a second Run does nothing", runs: 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newTestHome(t)
			stop := h.run(t)
			defer stop()
			waitFor(t, "the first round", func() bool { return h.kube.Calls("GetPod") >= 1 })
			for range c.runs - 1 {
				done := make(chan struct{})
				go func() { defer close(done); h.Run(context.Background()) }()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					t.Fatal("the second Run did not return at once")
				}
			}
			if n := h.logs.count("Run called again"); n != c.runs-1 {
				t.Fatalf("second Run logged %d times, want %d\n%s", n, c.runs-1, h.logs)
			}
		})
	}
}

// TestRunDeliversLossesInOrder checks that losses found before Run, in
// one round or several, reach the callback in detection order, on a
// goroutine that is neither the poll's nor the caller's, and that Run
// returns only once delivery has stopped. The callback blocks until the
// test releases it, and the poll must still run rounds meanwhile.
func TestRunDeliversLossesInOrder(t *testing.T) {
	twoClaims := []string{"gpu-a", "gpu-b"}
	cases := []struct {
		name         string
		registerLate bool
		// lose drives the rounds that find the losses, before Run.
		lose func(h *testHome)
		want []string
	}{
		{name: "callback set before Run, one loss per round",
			lose: func(h *testHome) {
				h.kube.SetNamespace(nil)
				_ = h.Once(context.Background())
				h.kube.SetPod(nil)
				_ = h.Once(context.Background())
			}, want: []string{"namespace terminating", "pod gone"}},
		{name: "callback set after Run, queued losses wait", registerLate: true,
			lose: func(h *testHome) {
				h.kube.SetNamespace(nil)
				_ = h.Once(context.Background())
				h.kube.SetPod(nil)
				_ = h.Once(context.Background())
			}, want: []string{"namespace terminating", "pod gone"}},
		{name: "pod and namespace terminating in one round delivers both, in that order",
			lose: func(h *testHome) {
				h.kube.SetPod(terminating(livePod()))
				h.kube.SetNamespace(nil)
				_ = h.Once(context.Background())
			}, want: []string{"pod terminating", "namespace terminating"}},
		{name: "two claims deleted in one round",
			lose: func(h *testHome) {
				h.kube.SetPod(podWithClaims(twoClaims...))
				_ = h.Once(context.Background())
			}, want: []string{"resource claim gpu-a deleted", "resource claim gpu-b deleted"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newTestHome(t)
			got := make(chan string, len(c.want))
			release := make(chan struct{})
			register := func() {
				h.OnScopeLost(func(ctx context.Context, reason string) {
					if ctx.Err() != nil {
						t.Errorf("the callback got an ended context")
					}
					got <- reason
					select {
					case <-release:
					case <-ctx.Done():
					}
				})
			}
			if !c.registerLate {
				register()
			}
			c.lose(h)
			if n := h.PendingLosses(); n != len(c.want) {
				t.Fatalf("losses pending before Run %d, want %d\n%s", n, len(c.want), h.logs)
			}
			stop := h.run(t)
			defer stop()
			if c.registerLate {
				if n := h.PendingLosses(); n != len(c.want) {
					t.Fatalf("losses delivered without a callback, %d pending", n)
				}
				register()
			}
			var reasons []string
			for i := range c.want {
				select {
				case r := <-got:
					reasons = append(reasons, r)
				case <-time.After(10 * time.Second):
					t.Fatalf("delivered %v, want %v", reasons, c.want)
				}
				if i == 0 {
					// The callback is blocked on the first reason. A round
					// read after this point ran on another goroutine.
					waitFor(t, "the poll to wait on its ticker", func() bool { return h.clock.Waiters() == 1 })
					before := h.kube.Calls("GetPod")
					h.clock.Step(testPoll)
					waitFor(t, "a round while the callback blocks", func() bool { return h.kube.Calls("GetPod") > before })
				}
				release <- struct{}{}
			}
			if !slices.Equal(reasons, c.want) {
				t.Fatalf("delivered %v, want %v", reasons, c.want)
			}
		})
	}
}

// TestScope checks what the home asserts before it has stored its Pod,
// what a fully answered round adds, and that a failed round changes
// nothing. The self-admitted UID always matches the scope's pod_uid.
func TestScope(t *testing.T) {
	configOnly := []core.ScopeClaim{
		{Name: "namespace", Value: testNamespace}, {Name: "pod", Value: testPod}, {Name: "pod_uid", Value: testPodUID}}
	podFacts := []core.ScopeClaim{{Name: "service_account", Value: "fiberd-grant"}, {Name: "node", Value: "node-1"}}
	cases := []struct {
		name  string
		setup func(h *testHome)
		poll  bool
		want  []core.ScopeClaim
	}{
		{name: "before the first poll the configuration speaks", want: configOnly},
		{name: "after a poll the Pod speaks", poll: true,
			want: slices.Concat(configOnly, podFacts, []core.ScopeClaim{{Name: "resource_claim", Value: testClaim}})},
		{name: "one resource_claim per claim", poll: true,
			setup: func(h *testHome) { h.kube.SetPod(podWithClaims("gpu-b", "gpu-a")) },
			want: slices.Concat(configOnly, podFacts,
				[]core.ScopeClaim{{Name: "resource_claim", Value: "gpu-a"}, {Name: "resource_claim", Value: "gpu-b"}})},
		{name: "a failed round stores nothing", poll: true,
			setup: func(h *testHome) { h.kube.SetNamespaceErr(errors.New("no route")) }, want: configOnly},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newTestHome(t)
			if c.setup != nil {
				c.setup(h)
			}
			if c.poll {
				_ = h.Once(context.Background())
			}
			got := h.Scope()
			if !slices.Equal(got, c.want) {
				t.Fatalf("Scope = %v, want %v", got, c.want)
			}
			// The UID Clone self-admits is the Pod the scope names, in
			// every state of the scope.
			i := slices.IndexFunc(got, func(sc core.ScopeClaim) bool { return sc.Name == "pod_uid" })
			if uid := h.SelfAdmitUID(); uid != testPodUID || i < 0 || got[i].Value != uid {
				t.Fatalf("SelfAdmitUID = %q, want %q and the scope's pod_uid in %v", uid, testPodUID, got)
			}
		})
	}
}

// TestDevices checks the device channel for a Pod with a claim, with
// static devices and with neither. A Pod read that fails before any round
// is never an error. The channel is then the static set, and a replaced
// Pod's claims reach neither the channel nor the scope.
func TestDevices(t *testing.T) {
	configOnly := []core.ScopeClaim{
		{Name: "namespace", Value: testNamespace}, {Name: "pod", Value: testPod}, {Name: "pod_uid", Value: testPodUID}}
	cases := []struct {
		name     string
		devices  []string
		claim    bool
		podUID   string
		readErr  error
		want     core.DeviceChannel
		unstored bool
	}{
		{name: "a replaced Pod answers the static set and stores nothing", devices: []string{"/dev/nvidia0"}, claim: true,
			podUID: "pod-uid-2", want: core.DeviceChannel{Kind: "static", Devices: []string{"/dev/nvidia0"}}, unstored: true},
		{name: "a transient read error answers the static set", devices: []string{"/dev/nvidia0"}, claim: true,
			readErr: errors.New("no route"), want: core.DeviceChannel{Kind: "static", Devices: []string{"/dev/nvidia0"}}, unstored: true},
		{name: "a transient read error without devices is no channel", claim: true,
			readErr: errors.New("no route"), want: core.DeviceChannel{}, unstored: true},
		{name: "a claim with devices is a dra channel", devices: []string{"/dev/nvidia0"}, claim: true,
			want: core.DeviceChannel{Kind: "dra", Devices: []string{"/dev/nvidia0"}, Detail: testClaim}},
		{name: "a claim without devices is still a dra channel", claim: true,
			want: core.DeviceChannel{Kind: "dra", Detail: testClaim}},
		{name: "devices without a claim are a static set", devices: []string{"/dev/nvidia0"},
			want: core.DeviceChannel{Kind: "static", Devices: []string{"/dev/nvidia0"}}},
		{name: "neither is no channel", want: core.DeviceChannel{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newTestHome(t, func(cfg *kubernetes.Config) { cfg.Devices = c.devices })
			p := livePod()
			if !c.claim {
				p.Spec.ResourceClaims, p.Status.ResourceClaimStatuses = nil, nil
			}
			if c.podUID != "" {
				p.UID = types.UID(c.podUID)
			}
			h.kube.SetPod(p)
			h.kube.SetPodErr(c.readErr)
			got, release, err := h.Devices(context.Background(), core.Grant{UID: "g1"})
			if err != nil {
				t.Fatalf("Devices: %v", err)
			}
			release()
			if got.Kind != c.want.Kind || got.Detail != c.want.Detail || !slices.Equal(got.Devices, c.want.Devices) {
				t.Fatalf("Devices = %+v, want %+v", got, c.want)
			}
			if c.unstored {
				if got := h.Scope(); !slices.Equal(got, configOnly) {
					t.Fatalf("Scope = %v, want %v", got, configOnly)
				}
			}
			if n := h.kube.Calls("GetPod"); n != 1 {
				t.Fatalf("the Pod was read %d times, want once", n)
			}
		})
	}
}

// TestSetIssuerReachable checks the admin override: unreachable is stale
// at once and stays so across answered rounds, reachable marks the
// health and lets rounds mark it again.
func TestSetIssuerReachable(t *testing.T) {
	cases := []struct {
		name      string
		reachable bool
	}{
		{name: "unreachable is stale and stays so", reachable: false},
		{name: "reachable is healthy again", reachable: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newTestHome(t)
			h.SetIssuerReachable(false)
			if h.Health().Healthy(h.clock.Now()) {
				t.Fatal("healthy after the override to unreachable")
			}
			if err := h.Once(context.Background()); err != nil {
				t.Fatalf("round: %v", err)
			}
			if h.Health().Healthy(h.clock.Now()) {
				t.Fatal("an answered round marked the health while paused")
			}
			if c.reachable {
				h.SetIssuerReachable(true)
				if !h.Health().Healthy(h.clock.Now()) {
					t.Fatal("not healthy after the override to reachable")
				}
			}
		})
	}
}
