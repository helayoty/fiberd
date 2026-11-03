// Package fake serves the Kubernetes home's slice of the API from memory,
// for tests that need no API server. A test sets what the cluster holds,
// drives the home, and reads back what the home patched.
package fake

import (
	"context"
	"encoding/json"
	"sync"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/helayoty/fiberd/pkg/home/kubernetes"
)

var claimsResource = schema.GroupResource{Group: "resource.k8s.io", Resource: "resourceclaims"}

// Kube is an in-memory cluster holding one Pod, one Namespace and some
// ResourceClaims. Every read honours its context, so a test can cut one
// short, and Hang makes every read wait for that. The zero value is an
// empty cluster, where every read and patch answers NotFound.
type Kube struct {
	mu        sync.Mutex
	pod       *corev1.Pod
	podErr    error
	ns        *corev1.Namespace
	nsErr     error
	claims    map[string]*metav1.PartialObjectMetadata
	claimErrs map[string]error
	noClaims  bool
	patchErr  error
	patches   [][]byte
	calls     map[string]int
	hang      bool
}

// New is a cluster whose namespace exists and holds nothing else yet.
func New(namespace string) *Kube {
	return &Kube{ns: &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}}
}

// SetPod sets the Pod reads return. nil means the Pod is gone.
func (k *Kube) SetPod(p *corev1.Pod) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.pod = p
}

// Pod is the Pod as the cluster holds it now, with every patch applied.
func (k *Kube) Pod() *corev1.Pod {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.pod == nil {
		return nil
	}
	return k.pod.DeepCopy()
}

// SetPodErr makes every Pod read fail with err until cleared with nil.
func (k *Kube) SetPodErr(err error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.podErr = err
}

// SetNamespace sets the Namespace reads return. nil means it is gone.
func (k *Kube) SetNamespace(ns *corev1.Namespace) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.ns = ns
}

// SetNamespaceErr makes every Namespace read fail with err until cleared
// with nil.
func (k *Kube) SetNamespaceErr(err error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.nsErr = err
}

// SetClaim adds a ResourceClaim, being deleted or not.
func (k *Kube) SetClaim(name string, deleting bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	c := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if deleting {
		now := metav1.Now()
		c.DeletionTimestamp = &now
	}
	if k.claims == nil {
		k.claims = map[string]*metav1.PartialObjectMetadata{}
	}
	k.claims[name] = c
}

// RemoveClaim makes the claim gone.
func (k *Kube) RemoveClaim(name string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.claims, name)
}

// SetClaimErr makes reads of one claim fail with err until cleared with
// nil.
func (k *Kube) SetClaimErr(name string, err error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err == nil {
		delete(k.claimErrs, name)
		return
	}
	if k.claimErrs == nil {
		k.claimErrs = map[string]error{}
	}
	k.claimErrs[name] = err
}

// SetNoResourceClaims makes the cluster one without resource.k8s.io.
func (k *Kube) SetNoResourceClaims(none bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.noClaims = none
}

// SetPatchErr makes every status patch fail with err until cleared with
// nil.
func (k *Kube) SetPatchErr(err error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.patchErr = err
}

// SetHang makes every call wait for its context to end.
func (k *Kube) SetHang(hang bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.hang = hang
}

// Patches are the status patches applied so far, oldest first.
func (k *Kube) Patches() [][]byte {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make([][]byte, len(k.patches))
	copy(out, k.patches)
	return out
}

// Calls counts the calls of one method, named GetPod, GetNamespace,
// GetResourceClaim or PatchPodStatus.
func (k *Kube) Calls(method string) int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.calls[method]
}

// enter counts a call and honours its context.
func (k *Kube) enter(ctx context.Context, method string) error {
	k.mu.Lock()
	if k.calls == nil {
		k.calls = map[string]int{}
	}
	k.calls[method]++
	hang := k.hang
	k.mu.Unlock()
	if hang {
		<-ctx.Done()
	}
	return ctx.Err()
}

func (k *Kube) GetPod(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
	if err := k.enter(ctx, "GetPod"); err != nil {
		return nil, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	switch {
	case k.podErr != nil:
		return nil, k.podErr
	case k.pod == nil || k.pod.Name != name || k.pod.Namespace != namespace:
		return nil, apierrors.NewNotFound(corev1.Resource("pods"), name)
	}
	return k.pod.DeepCopy(), nil
}

func (k *Kube) GetNamespace(ctx context.Context, name string) (*corev1.Namespace, error) {
	if err := k.enter(ctx, "GetNamespace"); err != nil {
		return nil, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	switch {
	case k.nsErr != nil:
		return nil, k.nsErr
	case k.ns == nil || k.ns.Name != name:
		return nil, apierrors.NewNotFound(corev1.Resource("namespaces"), name)
	}
	return k.ns.DeepCopy(), nil
}

func (k *Kube) GetResourceClaim(ctx context.Context, _, name string) (*metav1.PartialObjectMetadata, error) {
	if err := k.enter(ctx, "GetResourceClaim"); err != nil {
		return nil, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.noClaims {
		return nil, kubernetes.ErrNoResourceClaims
	}
	if err := k.claimErrs[name]; err != nil {
		return nil, err
	}
	c, ok := k.claims[name]
	if !ok {
		return nil, apierrors.NewNotFound(claimsResource, name)
	}
	return c.DeepCopy(), nil
}

// PatchPodStatus records the patch and merges its conditions into the Pod
// by type, as the API server's strategic merge does.
func (k *Kube) PatchPodStatus(ctx context.Context, namespace, name string, patch []byte) error {
	if err := k.enter(ctx, "PatchPodStatus"); err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.patchErr != nil {
		return k.patchErr
	}
	if k.pod == nil || k.pod.Name != name || k.pod.Namespace != namespace {
		return apierrors.NewNotFound(corev1.Resource("pods"), name)
	}
	var body struct {
		Status struct {
			Conditions []corev1.PodCondition `json:"conditions"`
		} `json:"status"`
	}
	if err := json.Unmarshal(patch, &body); err != nil {
		return apierrors.NewBadRequest(err.Error())
	}
	k.patches = append(k.patches, append([]byte(nil), patch...))
	for _, c := range body.Status.Conditions {
		replaced := false
		for i := range k.pod.Status.Conditions {
			if k.pod.Status.Conditions[i].Type == c.Type {
				k.pod.Status.Conditions[i] = c
				replaced = true
			}
		}
		if !replaced {
			k.pod.Status.Conditions = append(k.pod.Status.Conditions, c)
		}
	}
	return nil
}

var _ kubernetes.Kube = (*Kube)(nil)
