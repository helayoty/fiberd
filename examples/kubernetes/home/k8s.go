// Package home is the Kubernetes home: the agent is PID 1 of a grant Pod.
// It is the integration point with fiberd: everything fiberd needs from
// an environment is the home.Home interface (pkg/home) plus the optional
// interfaces pkg/agent looks for, and this package implements them
// against the Kubernetes API.
// Grants arrive as *.jwt files the issuer controller projects into the
// Pod; control-plane liveness is the API server answering for the Pod;
// readiness is a Pod readiness gate the agent sets once a template is
// warm; the cgroup subtree is the Pod's own, with the kubelet's ceiling on
// it; endpoints are the Pod's IP; the fabric channel is the Pod's DRA
// claim. Scope is what the Pod is: namespace, service account, node,
// claim. The home loses it when the namespace or the claim goes away
// under a live Pod, or the service-account issuer rotates, and then bumps
// the epoch through the hook it was given.
package home

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/endpoint"
	"github.com/helayoty/fiberd/pkg/home"
	"github.com/helayoty/fiberd/pkg/home/filelane"
	"github.com/helayoty/fiberd/pkg/sys/cgroup"

	"github.com/helayoty/fiberd/examples/kubernetes/kube"
)

// ReadyCondition is the readiness gate the issuer puts on grant Pods and
// the agent sets once any grant's template is warm.
const ReadyCondition = "fiberd.io/zygote-ready"

type Config struct {
	// Client is the cluster; nil means the in-cluster configuration.
	Client *kube.Client
	// Namespace and PodName identify this Pod; defaults: the projected
	// namespace file and the hostname.
	Namespace, PodName string
	// GrantsDir is the projected volume polled for *.jwt files.
	GrantsDir string
	Poll      time.Duration
	// StaleTTL: the API server not answering for this long is unhealthy.
	StaleTTL time.Duration
	// CgroupRoot is the Pod's cgroup as seen from inside (default
	// /sys/fs/cgroup); the runtime gets a `fiberd` subtree under it.
	CgroupRoot string
	// Devices is what the DRA driver exposed to this Pod (device paths
	// or ids), handed to every grant's engine as its fabric channel.
	Devices []string
	// Family picks which Pod IP callers dial (inet4 or inet6; unix means
	// fibers are reachable from this Pod only).
	Family endpoint.Family
	// ListenPort is the port of the agent's gRPC listener, for the
	// advertised endpoint.
	ListenPort string
	// TokenFile is the projected service-account token, watched for an
	// issuer change (default: the in-cluster path).
	TokenFile string
}

type Home struct {
	cfg    Config
	api    *kube.Client
	health *core.SourceHealth

	self       pod
	claims     []string // ResourceClaim names bound to this Pod
	issuer     string   // the service-account token's issuer at start
	scope      []core.ScopeClaim
	cgroupRoot string

	mu        sync.Mutex
	paused    bool
	lost      string // last scope-loss reason delivered
	ready     map[string]bool
	scopeLost func(ctx context.Context, reason string)
}

func New(cfg Config) (*Home, error) {
	if cfg.StaleTTL <= 0 {
		cfg.StaleTTL = 30 * time.Second
	}
	if cfg.Poll <= 0 {
		cfg.Poll = 2 * time.Second
	}
	if cfg.GrantsDir == "" {
		cfg.GrantsDir = "/var/run/fiberd/grants"
	}
	if cfg.CgroupRoot == "" {
		cfg.CgroupRoot = "/sys/fs/cgroup"
	}
	if cfg.TokenFile == "" {
		cfg.TokenFile = kube.TokenFile
	}
	if cfg.Client == nil {
		c, err := kube.InCluster()
		if err != nil {
			return nil, err
		}
		cfg.Client = c
	}
	if cfg.Namespace == "" {
		ns, err := kube.Namespace()
		if err != nil {
			return nil, err
		}
		cfg.Namespace = ns
	}
	if cfg.PodName == "" {
		cfg.PodName, _ = os.Hostname()
	}
	h := &Home{cfg: cfg, api: cfg.Client, health: core.NewSourceHealth(cfg.StaleTTL, time.Now()), ready: map[string]bool{}}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	for {
		if err := h.api.Get(ctx, h.podPath(), &h.self); err != nil {
			return nil, fmt.Errorf("k8s: read own Pod %s/%s: %w", cfg.Namespace, cfg.PodName, err)
		}
		// PID 1 can start before the kubelet has written the Pod's IP;
		// a tcp family needs it, so wait for it rather than fail the
		// first start.
		if cfg.Family == endpoint.Unix || cfg.Family == "" || h.EndpointHost() != "" {
			break
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("k8s: the Pod got no %s address within %s", cfg.Family, 90*time.Second)
		case <-time.After(500 * time.Millisecond):
		}
	}
	h.claims = boundClaims(h.self)
	if tok, err := os.ReadFile(cfg.TokenFile); err == nil {
		h.issuer = peekIssuer(string(tok))
	}
	h.scope = h.buildScope()
	// The container's cgroup (the kubelet's memory.max on the Pod above it
	// is the block ceiling), with a subtree delegated to the runtime.
	root, err := cgroup.Delegate(cgroup.Own(cfg.CgroupRoot))
	if err != nil {
		return nil, fmt.Errorf("k8s: %w", err)
	}
	h.cgroupRoot = root.Path
	return h, nil
}

func (h *Home) podPath() string {
	return "/api/v1/namespaces/" + h.cfg.Namespace + "/pods/" + h.cfg.PodName
}

func (h *Home) namespacePath() string { return "/api/v1/namespaces/" + h.cfg.Namespace }

func (h *Home) claimPath(name string) string {
	return "/apis/resource.k8s.io/v1/namespaces/" + h.cfg.Namespace + "/resourceclaims/" + name
}

// boundClaims lists the ResourceClaims behind the Pod's resourceClaims:
// generated names from the status, else the names given in the spec.
func boundClaims(p pod) []string {
	byRef := map[string]string{}
	for _, st := range p.Status.ResourceClaimStatuses {
		byRef[st.Name] = st.ResourceClaimName
	}
	var out []string
	for _, rc := range p.Spec.ResourceClaims {
		name := byRef[rc.Name]
		if name == "" {
			name = rc.ResourceClaimName
		}
		if name != "" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func (h *Home) buildScope() []core.ScopeClaim {
	s := []core.ScopeClaim{
		{Name: "namespace", Value: h.cfg.Namespace},
		{Name: "pod", Value: h.cfg.PodName},
	}
	if h.self.Metadata.UID != "" {
		s = append(s, core.ScopeClaim{Name: "pod_uid", Value: h.self.Metadata.UID})
	}
	if sa := h.self.Spec.ServiceAccountName; sa != "" {
		s = append(s, core.ScopeClaim{Name: "service_account", Value: sa})
	}
	if n := h.self.Spec.NodeName; n != "" {
		s = append(s, core.ScopeClaim{Name: "node", Value: n})
	}
	if h.issuer != "" {
		s = append(s, core.ScopeClaim{Name: "issuer", Value: h.issuer})
	}
	if len(h.claims) > 0 {
		s = append(s, core.ScopeClaim{Name: "resource_claim", Value: strings.Join(h.claims, ",")})
	}
	return s
}

// peekIssuer reads the unverified `iss` of a JWT: the home does not trust
// the token, it only notices when the issuer behind it changes.
func peekIssuer(tok string) string {
	parts := strings.Split(strings.TrimSpace(tok), ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		Iss string `json:"iss"`
	}
	_ = json.Unmarshal(raw, &c)
	return c.Iss
}

func (h *Home) Name() string               { return "k8s" }
func (h *Home) Health() *core.SourceHealth { return h.health }
func (h *Home) CgroupRoot() string         { return h.cgroupRoot }

// EndpointHost is the Pod IP of the configured family, "" when the Pod
// has none of that family.
func (h *Home) EndpointHost() string {
	want := h.cfg.Family
	if want == endpoint.Unix || want == "" {
		want = endpoint.Inet4
	}
	ips := make([]string, 0, len(h.self.Status.PodIPs)+1)
	for _, ip := range h.self.Status.PodIPs {
		ips = append(ips, ip.IP)
	}
	if len(ips) == 0 && h.self.Status.PodIP != "" {
		ips = append(ips, h.self.Status.PodIP)
	}
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil {
			continue
		}
		if v4 := ip.To4() != nil; v4 == (want == endpoint.Inet4) {
			return s
		}
	}
	return ""
}

// AdvertisedEndpoint is where callers in the cluster reach this agent:
// the Pod IP of the family and the gRPC port.
func (h *Home) AdvertisedEndpoint() string {
	host := h.EndpointHost()
	if host == "" {
		return ""
	}
	return net.JoinHostPort(host, h.cfg.ListenPort)
}

// Scope: the facts the Pod is made of.
func (h *Home) Scope() []core.ScopeClaim {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]core.ScopeClaim(nil), h.scope...)
}

// Fabric: the Pod's DRA claim, with the devices the driver exposed; a
// static set when the Pod has devices but no claim; nothing otherwise.
// The claim is the Pod's, so there is nothing to release per grant.
func (h *Home) Fabric(context.Context, core.Grant) (core.FabricChannel, func(), error) {
	fc := core.FabricChannel{Devices: append([]string(nil), h.cfg.Devices...)}
	switch {
	case len(h.claims) > 0:
		fc.Kind, fc.Detail = "dra", strings.Join(h.claims, ",")
	case len(fc.Devices) > 0:
		fc.Kind = "static"
	}
	return fc, func() {}, nil
}

// Grants is the projected volume.
func (h *Home) Grants(ctx context.Context) (<-chan home.GrantEvent, error) {
	return filelane.Poll(ctx, h.cfg.GrantsDir, h.cfg.Poll)
}

// PublishReady sets the Pod's readiness gate: True while any admitted
// grant has a warm template, False once none has.
func (h *Home) PublishReady(ctx context.Context, grantUID string, ready bool) error {
	h.mu.Lock()
	if ready {
		h.ready[grantUID] = true
	} else {
		delete(h.ready, grantUID)
	}
	warm := len(h.ready) > 0
	h.mu.Unlock()
	cond := kube.Condition{Type: ReadyCondition, Status: "False", Reason: "NoWarmTemplate", Message: "no grant has a warm template",
		LastTransitionTime: time.Now().UTC().Format(time.RFC3339)}
	if warm {
		cond.Status, cond.Reason, cond.Message = "True", "ZygoteWarm", "grant "+grantUID+" template is warm"
	}
	patch := map[string]any{"status": map[string]any{"conditions": []kube.Condition{cond}}}
	if err := h.api.PatchStrategic(ctx, h.podPath()+"/status", patch); err != nil {
		log.Printf("k8s: readiness gate: %v", err)
		return err
	}
	return nil
}

// OnScopeLost sets what to call (once per reason) when the Pod's scope
// goes away under it: cmd/fiberd wires Agent.BumpEpoch.
func (h *Home) OnScopeLost(fn func(ctx context.Context, reason string)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.scopeLost = fn
}

// SetLane is the test-only override behind fiberd's admin socket.
func (h *Home) SetLane(healthy bool) {
	h.mu.Lock()
	h.paused = !healthy
	h.mu.Unlock()
	if healthy {
		h.health.MarkSync(time.Now())
	} else {
		h.health.MarkSync(time.Now().Add(-h.cfg.StaleTTL))
	}
	log.Printf("k8s: grant lane set healthy=%v", healthy)
}

// Run polls the API server: the Pod answering is liveness; the namespace
// terminating, a bound claim gone, or the token's issuer changing is
// scope loss.
func (h *Home) Run(ctx context.Context) {
	every := h.cfg.StaleTTL / 2
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		h.poll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (h *Home) poll(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var p pod
	switch err := h.api.Get(ctx, h.podPath(), &p); {
	case err == nil:
		h.mu.Lock()
		paused := h.paused
		h.mu.Unlock()
		if !paused {
			h.health.MarkSync(time.Now())
		}
	case kube.IsNotFound(err):
		h.lose(ctx, "pod "+h.cfg.Namespace+"/"+h.cfg.PodName+" gone")
		return
	default:
		log.Printf("k8s: liveness: %v", err)
		return
	}
	var ns namespace
	switch err := h.api.Get(ctx, h.namespacePath(), &ns); {
	case err == nil:
		if ns.Metadata.DeletionTimestamp != "" || ns.Status.Phase == "Terminating" {
			h.lose(ctx, "namespace "+h.cfg.Namespace+" terminating")
			return
		}
	case kube.IsNotFound(err):
		h.lose(ctx, "namespace "+h.cfg.Namespace+" gone")
		return
	default:
		log.Printf("k8s: namespace: %v", err)
	}
	for _, name := range h.claims {
		var rc resourceClaim
		switch err := h.api.Get(ctx, h.claimPath(name), &rc); {
		case err == nil:
			if rc.Metadata.DeletionTimestamp != "" {
				h.lose(ctx, "resource claim "+name+" being deleted")
				return
			}
		case kube.IsNotFound(err):
			h.lose(ctx, "resource claim "+name+" gone")
			return
		default:
			log.Printf("k8s: claim %s: %v", name, err)
		}
	}
	if tok, err := os.ReadFile(h.cfg.TokenFile); err == nil {
		if iss := peekIssuer(string(tok)); iss != "" && h.issuer != "" && iss != h.issuer {
			was := h.issuer
			h.issuer = iss
			h.mu.Lock()
			h.scope = h.buildScope()
			h.mu.Unlock()
			h.lose(ctx, "service account issuer changed from "+was+" to "+iss)
		}
	}
}

// lose delivers a scope-loss reason once.
func (h *Home) lose(ctx context.Context, reason string) {
	h.mu.Lock()
	fn := h.scopeLost
	repeat := h.lost == reason
	h.lost = reason
	h.mu.Unlock()
	if repeat {
		return
	}
	log.Printf("k8s: scope lost: %s", reason)
	if fn != nil {
		fn(ctx, reason)
	}
}

var _ home.Home = (*Home)(nil)
