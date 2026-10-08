// Package pod is the plain Pod comparator: `create pod`, wait for an IP,
// poll until the first 200. runc or any RuntimeClass (gvisor), image on
// the node (warm) or removed before every activation (cold). It speaks to
// the API server through the Kubernetes example's small client.
package pod

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/helayoty/fiberd/examples/kubernetes/kube"

	"github.com/helayoty/fiberd/bench/compare"
)

// Options configure the adapter.
type Options struct {
	Kube      *kube.Client
	Namespace string
	Image     string
	// PullPolicy is IfNotPresent (warm) or Always (cold).
	PullPolicy string
	// RuntimeClass names a RuntimeClass, "gvisor" for the sandboxed Pod.
	RuntimeClass string
	// NodeName pins every Pod to one node, so the scheduler still runs
	// but the client and the Pods share a host.
	NodeName string
	Port     int
	// CPU and Memory are the container's limits, the fairness rule.
	CPU, Memory string
	// RemoveImage runs before every activation in the cold case. It is
	// not timed. Typically `crictl rmi <image>` against the node's
	// containerd socket.
	RemoveImage func(ctx context.Context) error
	// CgroupRoot is where Pod cgroups are found for density, mounted
	// from the node. Empty disables density.
	CgroupRoot string
	Poll       time.Duration
	// Prefix names the Pods.
	Prefix string
}

// Adapter implements compare.Adapter.
type Adapter struct{ o Options }

// New checks the options.
func New(o Options) (*Adapter, error) {
	if o.Kube == nil || o.Image == "" || o.Namespace == "" {
		return nil, fmt.Errorf("pod: need Kube, Namespace and Image")
	}
	if o.Port == 0 {
		o.Port = 8080
	}
	if o.PullPolicy == "" {
		o.PullPolicy = "IfNotPresent"
	}
	if o.Prefix == "" {
		o.Prefix = "cmp"
	}
	return &Adapter{o: o}, nil
}

// pod is the slice of a Pod the adapter writes and reads.
type pod struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Metadata   kube.ObjectMeta `json:"metadata"`
	Spec       struct {
		RestartPolicy    string      `json:"restartPolicy"`
		NodeName         string      `json:"nodeName,omitempty"`
		RuntimeClassName string      `json:"runtimeClassName,omitempty"`
		Containers       []container `json:"containers"`
	} `json:"spec"`
	Status struct {
		Phase string `json:"phase,omitempty"`
		PodIP string `json:"podIP,omitempty"`
	} `json:"status,omitempty"`
}

type container struct {
	Name            string `json:"name"`
	Image           string `json:"image"`
	ImagePullPolicy string `json:"imagePullPolicy"`
	Ports           []struct {
		ContainerPort int `json:"containerPort"`
	} `json:"ports"`
	Resources struct {
		Limits map[string]string `json:"limits,omitempty"`
	} `json:"resources"`
}

// Build is the Pod the adapter creates for id.
func (a *Adapter) Build(id string) *pod {
	p := &pod{APIVersion: "v1", Kind: "Pod", Metadata: kube.ObjectMeta{Name: a.Name(id), Namespace: a.o.Namespace,
		Labels: map[string]string{"compare": "pod"}}}
	p.Spec.RestartPolicy = "Never"
	p.Spec.NodeName = a.o.NodeName
	p.Spec.RuntimeClassName = a.o.RuntimeClass
	c := container{Name: "counter", Image: a.o.Image, ImagePullPolicy: a.o.PullPolicy}
	c.Ports = append(c.Ports, struct {
		ContainerPort int `json:"containerPort"`
	}{a.o.Port})
	limits := map[string]string{}
	if a.o.CPU != "" {
		limits["cpu"] = a.o.CPU
	}
	if a.o.Memory != "" {
		limits["memory"] = a.o.Memory
	}
	if len(limits) > 0 {
		c.Resources.Limits = limits
	}
	p.Spec.Containers = []container{c}
	return p
}

// Name is the Pod name for id.
func (a *Adapter) Name(id string) string { return a.o.Prefix + "-" + strings.ToLower(id) }

func (a *Adapter) path(name string) string {
	return "/api/v1/namespaces/" + a.o.Namespace + "/pods/" + name
}

// Setup pre-pulls the image once with a throwaway Pod so the warm case
// finds it on the node. The cold case removes it again before each
// activation.
func (a *Adapter) Setup(ctx context.Context) error {
	h, err := a.Activate(ctx, "setup")
	if err != nil {
		return err
	}
	if _, _, err := a.Ready(ctx, h); err != nil {
		_ = a.Release(ctx, h)
		return err
	}
	return a.Release(ctx, h)
}

// Activate creates the Pod. The handle is its name. Addr comes with Ready.
func (a *Adapter) Activate(ctx context.Context, id string) (compare.Handle, error) {
	if a.o.RemoveImage != nil {
		if err := a.o.RemoveImage(ctx); err != nil {
			return compare.Handle{}, fmt.Errorf("remove image: %w", err)
		}
	}
	p := a.Build(id)
	var created pod
	if err := a.o.Kube.Create(ctx, "/api/v1/namespaces/"+a.o.Namespace+"/pods", p, &created); err != nil {
		return compare.Handle{}, err
	}
	return compare.Handle{ID: p.Metadata.Name, Meta: map[string]string{"uid": created.Metadata.UID}}, nil
}

// Ready polls the Pod for an IP, then the port for the first 200.
func (a *Adapter) Ready(ctx context.Context, h compare.Handle) (compare.Handle, time.Time, error) {
	poll := a.o.Poll
	if poll <= 0 {
		poll = time.Millisecond
	}
	for h.Addr == "" {
		var p pod
		if err := a.o.Kube.Get(ctx, a.path(h.ID), &p); err != nil {
			return h, time.Time{}, err
		}
		if p.Status.Phase == "Failed" || p.Status.Phase == "Succeeded" {
			return h, time.Time{}, fmt.Errorf("pod %s is %s", h.ID, p.Status.Phase)
		}
		if p.Status.PodIP != "" {
			h.Addr = net.JoinHostPort(p.Status.PodIP, strconv.Itoa(a.o.Port))
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

// Release deletes the Pod with no grace period.
func (a *Adapter) Release(ctx context.Context, h compare.Handle) error {
	err := a.o.Kube.Delete(ctx, a.path(h.ID)+"?gracePeriodSeconds=0")
	if kube.IsNotFound(err) {
		return nil
	}
	return err
}

// Resume has no Pod equivalent.
func (a *Adapter) Resume(context.Context, compare.Handle) (compare.Handle, error) {
	return compare.Handle{}, compare.ErrUnsupported
}

// Density sums the Pods' cgroups. Nothing stands between activations.
func (a *Adapter) Density(_ context.Context, hs []compare.Handle) (int64, error) {
	if len(hs) == 0 {
		return 0, nil
	}
	if a.o.CgroupRoot == "" {
		return 0, compare.ErrUnsupported
	}
	var dirs []string
	for _, h := range hs {
		d, err := compare.FindCgroup(a.o.CgroupRoot, h.Meta["uid"])
		if err != nil {
			return 0, err
		}
		dirs = append(dirs, d)
	}
	return compare.SumCgroups(dirs)
}

// Command is a RemoveImage that runs a shell command, for the cold case.
func Command(cmd string) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		out, err := exec.CommandContext(ctx, "sh", "-c", cmd).CombinedOutput()
		if err != nil && !strings.Contains(string(out), "not found") {
			return fmt.Errorf("%s: %w: %s", cmd, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
}
