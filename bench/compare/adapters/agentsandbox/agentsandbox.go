// Package agentsandbox is the agent-sandbox v1.0.5 comparator: a
// SandboxTemplate and a SandboxWarmPool of N replicas stand ready, and an
// activation is one SandboxClaim, ready when its status names Pod IPs
// and the first 200 arrives. Resume is the Sandbox's operatingMode,
// Suspended then Running.
//
// The CRDs are agents.x-k8s.io/v1beta1 Sandbox and
// extensions.agents.x-k8s.io/v1beta1 SandboxTemplate, SandboxWarmPool
// and SandboxClaim, as the release's sandbox-with-extensions.yaml
// defines them.
package agentsandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/helayoty/fiberd/examples/kubernetes/kube"

	"github.com/helayoty/fiberd/bench/compare"
)

const (
	core = "/apis/agents.x-k8s.io/v1beta1/namespaces/"
	ext  = "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/"
)

// Options configure the adapter.
type Options struct {
	Kube      *kube.Client
	Namespace string
	// Name is the template's and the pool's name.
	Name  string
	Image string
	// Replicas is the pool size. 1 is the like-for-like with fiberd's
	// one warm template, N keeps the pool from emptying in a burst.
	Replicas     int
	RuntimeClass string
	NodeName     string
	Port         int
	CPU, Memory  string
	CgroupRoot   string
	Poll         time.Duration
	// Wait bounds the pool fill in Setup.
	Wait time.Duration
}

// Adapter implements compare.Adapter.
type Adapter struct{ o Options }

// New checks the options.
func New(o Options) (*Adapter, error) {
	if o.Kube == nil || o.Image == "" || o.Namespace == "" {
		return nil, fmt.Errorf("agentsandbox: need Kube, Namespace and Image")
	}
	if o.Name == "" {
		o.Name = "counter"
	}
	if o.Port == 0 {
		o.Port = 8080
	}
	if o.Replicas <= 0 {
		o.Replicas = 1
	}
	if o.Wait <= 0 {
		o.Wait = 5 * time.Minute
	}
	return &Adapter{o: o}, nil
}

// Template is the SandboxTemplate the pool is made of. Its Pod is the
// same counter Pod the plain comparator runs.
func (a *Adapter) Template() map[string]any {
	limits, resources := map[string]any{}, map[string]any{}
	if a.o.CPU != "" {
		limits["cpu"] = a.o.CPU
		resources["requests"] = map[string]any{"cpu": compare.CPURequest}
	}
	if a.o.Memory != "" {
		limits["memory"] = a.o.Memory
	}
	resources["limits"] = limits
	spec := map[string]any{
		"containers": []any{map[string]any{
			"name": "counter", "image": a.o.Image, "imagePullPolicy": "IfNotPresent",
			"ports":     []any{map[string]any{"containerPort": a.o.Port}},
			"resources": resources,
		}},
	}
	if a.o.RuntimeClass != "" {
		spec["runtimeClassName"] = a.o.RuntimeClass
	}
	if a.o.NodeName != "" {
		spec["nodeName"] = a.o.NodeName
	}
	return map[string]any{
		"apiVersion": "extensions.agents.x-k8s.io/v1beta1", "kind": "SandboxTemplate",
		"metadata": map[string]any{"name": a.o.Name, "namespace": a.o.Namespace},
		"spec":     map[string]any{"podTemplate": map[string]any{"spec": spec}},
	}
}

// Pool is the SandboxWarmPool of Replicas.
func (a *Adapter) Pool() map[string]any {
	return map[string]any{
		"apiVersion": "extensions.agents.x-k8s.io/v1beta1", "kind": "SandboxWarmPool",
		"metadata": map[string]any{"name": a.o.Name, "namespace": a.o.Namespace},
		"spec":     map[string]any{"replicas": a.o.Replicas, "sandboxTemplateRef": map[string]any{"name": a.o.Name}},
	}
}

// Claim is the SandboxClaim for id.
func (a *Adapter) Claim(id string) map[string]any {
	return map[string]any{
		"apiVersion": "extensions.agents.x-k8s.io/v1beta1", "kind": "SandboxClaim",
		"metadata": map[string]any{"name": a.Name(id), "namespace": a.o.Namespace},
		"spec":     map[string]any{"warmPoolRef": map[string]any{"name": a.o.Name}},
	}
}

// Name is the claim's name for id.
func (a *Adapter) Name(id string) string { return "claim-" + strings.ToLower(id) }

// apply creates obj or, when it exists, merge-patches its spec.
func (a *Adapter) apply(ctx context.Context, collection string, obj map[string]any) error {
	name := obj["metadata"].(map[string]any)["name"].(string)
	err := a.o.Kube.Create(ctx, collection, obj, nil)
	if kube.IsConflict(err) {
		return a.o.Kube.PatchMerge(ctx, collection+"/"+name, map[string]any{"spec": obj["spec"]})
	}
	return err
}

// Setup applies the template and the pool, then waits for the pool to
// be full. The fill is the setup cost.
func (a *Adapter) Setup(ctx context.Context) error {
	ns := a.o.Namespace
	if err := a.apply(ctx, ext+ns+"/sandboxtemplates", a.Template()); err != nil {
		return err
	}
	if err := a.apply(ctx, ext+ns+"/sandboxwarmpools", a.Pool()); err != nil {
		return err
	}
	deadline := time.Now().Add(a.o.Wait)
	for {
		var pool struct {
			Status struct {
				ReadyReplicas int `json:"readyReplicas"`
			} `json:"status"`
		}
		if err := a.o.Kube.Get(ctx, ext+ns+"/sandboxwarmpools/"+a.o.Name, &pool); err != nil {
			return err
		}
		if pool.Status.ReadyReplicas >= a.o.Replicas {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("agentsandbox: pool %s has %d of %d ready", a.o.Name, pool.Status.ReadyReplicas, a.o.Replicas)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// Activate creates the claim.
func (a *Adapter) Activate(ctx context.Context, id string) (compare.Handle, error) {
	if err := a.o.Kube.Create(ctx, ext+a.o.Namespace+"/sandboxclaims", a.Claim(id), nil); err != nil {
		return compare.Handle{}, err
	}
	return compare.Handle{ID: a.Name(id), Meta: map[string]string{}}, nil
}

// claimStatus is what Ready reads back.
type claimStatus struct {
	Status struct {
		Sandbox struct {
			Name   string   `json:"name"`
			PodIPs []string `json:"podIPs"`
		} `json:"sandbox"`
		Conditions []kube.Condition `json:"conditions"`
	} `json:"status"`
}

// Ready polls the claim for a Pod IP, then the port for the first 200.
func (a *Adapter) Ready(ctx context.Context, h compare.Handle) (compare.Handle, time.Time, error) {
	poll := a.o.Poll
	if poll <= 0 {
		poll = time.Millisecond
	}
	for h.Addr == "" {
		var c claimStatus
		if err := a.o.Kube.Get(ctx, ext+a.o.Namespace+"/sandboxclaims/"+h.ID, &c); err != nil {
			return h, time.Time{}, err
		}
		for _, cond := range c.Status.Conditions {
			if cond.Status == "False" && cond.Reason != "" && strings.Contains(strings.ToLower(cond.Reason), "fail") {
				return h, time.Time{}, fmt.Errorf("claim %s: %s: %s", h.ID, cond.Reason, cond.Message)
			}
		}
		if len(c.Status.Sandbox.PodIPs) > 0 {
			h.Addr = net.JoinHostPort(c.Status.Sandbox.PodIPs[0], strconv.Itoa(a.o.Port))
			h.Meta["sandbox"] = c.Status.Sandbox.Name
			break
		}
		select {
		case <-ctx.Done():
			return h, time.Time{}, ctx.Err()
		case <-time.After(poll):
		}
	}
	r, err := compare.Probe{Dial: compare.TCP(h.Addr), Framing: compare.HTTP, Poll: poll}.Run(ctx)
	if err != nil {
		return h, time.Time{}, err
	}
	h.Meta["attempts"] = strconv.Itoa(r.Attempts)
	return h, r.FirstByte, nil
}

// Release deletes the claim, which deletes its sandbox.
func (a *Adapter) Release(ctx context.Context, h compare.Handle) error {
	err := a.o.Kube.Delete(ctx, ext+a.o.Namespace+"/sandboxclaims/"+h.ID)
	if kube.IsNotFound(err) {
		return nil
	}
	return err
}

// Park suspends the Sandbox and waits for its Pod to be gone.
func (a *Adapter) Park(ctx context.Context, h compare.Handle) error {
	path, err := a.sandbox(h)
	if err != nil {
		return err
	}
	if err := a.mode(ctx, path, "Suspended"); err != nil {
		return err
	}
	for {
		var s struct {
			Status struct {
				PodIPs []string `json:"podIPs"`
			} `json:"status"`
		}
		if err := a.o.Kube.Get(ctx, path, &s); err != nil {
			return err
		}
		if len(s.Status.PodIPs) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// Resume sets the suspended Sandbox Running again. The handle keeps the
// claim, with Addr cleared so Ready reads the new Pod IP.
func (a *Adapter) Resume(ctx context.Context, h compare.Handle) (compare.Handle, error) {
	path, err := a.sandbox(h)
	if err != nil {
		return compare.Handle{}, err
	}
	if err := a.mode(ctx, path, "Running"); err != nil {
		return compare.Handle{}, err
	}
	return compare.Handle{ID: h.ID, Meta: map[string]string{"sandbox": h.Meta["sandbox"]}}, nil
}

// sandbox is the path of the claim's Sandbox.
func (a *Adapter) sandbox(h compare.Handle) (string, error) {
	sb := h.Meta["sandbox"]
	if sb == "" {
		return "", fmt.Errorf("agentsandbox: claim %s names no sandbox", h.ID)
	}
	return core + a.o.Namespace + "/sandboxes/" + sb, nil
}

func (a *Adapter) mode(ctx context.Context, path, mode string) error {
	return a.o.Kube.PatchMerge(ctx, path, map[string]any{"spec": map[string]any{"operatingMode": mode}})
}

// Density charges the claimed sandboxes' Pods. With no handles it is the
// pool's standing Pods, found by the Sandbox name the pool gave them.
func (a *Adapter) Density(ctx context.Context, hs []compare.Handle) (int64, error) {
	if a.o.CgroupRoot == "" {
		return 0, compare.ErrUnsupported
	}
	var names []string
	if len(hs) == 0 {
		var err error
		if names, err = a.standing(ctx); err != nil {
			return 0, err
		}
	}
	for _, h := range hs {
		names = append(names, h.Meta["sandbox"])
	}
	var dirs []string
	for _, n := range names {
		uid, err := a.podUID(ctx, n)
		if err != nil {
			return 0, err
		}
		d, err := compare.FindCgroup(a.o.CgroupRoot, uid)
		if err != nil {
			return 0, err
		}
		dirs = append(dirs, d)
	}
	return compare.SumCgroups(dirs)
}

// standing names the pool's unclaimed Sandboxes. agent-sandbox makes
// the pool the controller owner of each Sandbox it fills, and hands the
// ownership to the claim that takes one, so the namespace's other
// Sandboxes (claimed ones, other pools') carry another owner.
func (a *Adapter) standing(ctx context.Context) ([]string, error) {
	var list struct {
		Items []struct {
			Metadata kube.ObjectMeta `json:"metadata"`
		} `json:"items"`
	}
	if err := a.o.Kube.Get(ctx, core+a.o.Namespace+"/sandboxes", &list); err != nil {
		return nil, err
	}
	var names []string
	for _, it := range list.Items {
		for _, ref := range it.Metadata.OwnerReferences {
			if ref.Kind == "SandboxWarmPool" && ref.Name == a.o.Name {
				names = append(names, it.Metadata.Name)
				break
			}
		}
	}
	return names, nil
}

// Cleanup deletes the pool and the template, so they stand for no other
// system's runs. The pool's Sandboxes go with it.
func (a *Adapter) Cleanup(ctx context.Context) error {
	ns := a.o.Namespace
	for _, p := range []string{ext + ns + "/sandboxwarmpools/" + a.o.Name, ext + ns + "/sandboxtemplates/" + a.o.Name} {
		if err := a.o.Kube.Delete(ctx, p); err != nil && !kube.IsNotFound(err) {
			return err
		}
	}
	return nil
}

// podUID is the uid of a sandbox's Pod. agent-sandbox names the Pod
// after the Sandbox.
func (a *Adapter) podUID(ctx context.Context, sandbox string) (string, error) {
	var p struct {
		Metadata kube.ObjectMeta `json:"metadata"`
	}
	if err := a.o.Kube.Get(ctx, "/api/v1/namespaces/"+a.o.Namespace+"/pods/"+sandbox, &p); err != nil {
		return "", err
	}
	return p.Metadata.UID, nil
}

// JSON renders an object as the manifests the scripts print.
func JSON(obj map[string]any) string {
	b, _ := json.MarshalIndent(obj, "", "  ")
	return string(b)
}
