package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
)

// ErrNoResourceClaims is what GetResourceClaim returns when the cluster
// serves no resource.k8s.io group, so no ResourceClaim can be read.
var ErrNoResourceClaims = errors.New("the cluster serves no resource.k8s.io API")

// Kube is the slice of the Kubernetes API the home touches. NewKube
// serves it from a cluster, and fake.Kube from memory.
type Kube interface {
	// GetPod reads one Pod.
	GetPod(ctx context.Context, namespace, name string) (*corev1.Pod, error)
	// GetNamespace reads one Namespace.
	GetNamespace(ctx context.Context, name string) (*corev1.Namespace, error)
	// GetResourceClaim reads the metadata of one ResourceClaim, which is
	// all the home needs from it. It returns ErrNoResourceClaims when the
	// cluster serves no resource.k8s.io group.
	GetResourceClaim(ctx context.Context, namespace, name string) (*metav1.PartialObjectMetadata, error)
	// PatchPodStatus applies a strategic merge patch to the Pod's status
	// subresource.
	PatchPodStatus(ctx context.Context, namespace, name string, patch []byte) error
}

// The resource.k8s.io group and resource ResourceClaims live under. The
// version differs per cluster and is discovered.
const (
	resourceGroup  = "resource.k8s.io"
	claimsResource = "resourceclaims"
)

// kubeDefaults is cfg with the client settings the home relies on filled
// where the caller left them empty. The caller's config is not changed.
func kubeDefaults(cfg *rest.Config) *rest.Config {
	out := rest.CopyConfig(cfg)
	if out.UserAgent == "" {
		out.UserAgent = "fiberd/" + Name + " " + rest.DefaultKubernetesUserAgent()
	}
	if out.Timeout == 0 {
		out.Timeout = 30 * time.Second
	}
	return out
}

// pickResourceClaimVersion is the version of resource.k8s.io to read
// ResourceClaims through. It is the version the server prefers, else the
// first one it serves. ok is false when the group is not served.
func pickResourceClaimVersion(groups *metav1.APIGroupList) (version string, ok bool) {
	if groups == nil {
		return "", false
	}
	for _, g := range groups.Groups {
		if g.Name != resourceGroup {
			continue
		}
		if g.PreferredVersion.Version != "" {
			return g.PreferredVersion.Version, true
		}
		if len(g.Versions) > 0 && g.Versions[0].Version != "" {
			return g.Versions[0].Version, true
		}
		return "", false
	}
	return "", false
}

// client serves Kube from a cluster.
type client struct {
	core   *clientset.Clientset
	meta   metadata.Interface
	claims schema.GroupVersionResource // empty when the cluster serves no resource.k8s.io
}

// NewKube connects to the cluster cfg names and discovers which
// resource.k8s.io version it serves. A cluster without that group still
// works, and GetResourceClaim then returns ErrNoResourceClaims.
func NewKube(ctx context.Context, cfg *rest.Config) (Kube, error) {
	cfg = kubeDefaults(cfg)
	core, err := clientset.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("kubernetes client: %w", err)
	}
	meta, err := metadata.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("kubernetes metadata client: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	groups, err := core.Discovery().ServerGroups()
	if err != nil {
		return nil, fmt.Errorf("discover %s: %w", resourceGroup, err)
	}
	c := &client{core: core, meta: meta}
	if v, ok := pickResourceClaimVersion(groups); ok {
		c.claims = schema.GroupVersionResource{Group: resourceGroup, Version: v, Resource: claimsResource}
	}
	return c, nil
}

func (c *client) GetPod(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
	return c.core.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (c *client) GetNamespace(ctx context.Context, name string) (*corev1.Namespace, error) {
	return c.core.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
}

func (c *client) GetResourceClaim(ctx context.Context, namespace, name string) (*metav1.PartialObjectMetadata, error) {
	if c.claims.Empty() {
		return nil, ErrNoResourceClaims
	}
	return c.meta.Resource(c.claims).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (c *client) PatchPodStatus(ctx context.Context, namespace, name string, patch []byte) error {
	_, err := c.core.CoreV1().Pods(namespace).Patch(ctx, name, types.StrategicMergePatchType, patch,
		metav1.PatchOptions{FieldManager: "fiberd"}, "status")
	return err
}

// isClaimNotFound reports whether err says the ResourceClaim named name
// does not exist. The API server names the missing object in the status
// details, by its kind or by its name. A bare 404, such as the answer
// for a group the server does not serve, carries no details and is not a
// deletion.
func isClaimNotFound(err error, name string) bool {
	var st apierrors.APIStatus
	if !errors.As(err, &st) {
		return false
	}
	s := st.Status()
	if s.Reason != metav1.StatusReasonNotFound || s.Details == nil {
		return false
	}
	return strings.EqualFold(s.Details.Kind, claimsResource) || s.Details.Name == name
}
