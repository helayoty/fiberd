package controller

import (
	"encoding/json"

	"github.com/helayoty/fiberd/examples/kubernetes/kube"
)

// The CapacityGrant custom resource, fiberd.io/v1alpha1. Its spec is the
// CapacityGrant of the protocol plus how to build the grant Pod; its
// status is what the controller learned. The CRD manifest in
// kind/manifests/10-crd.yaml is the schema of these types.
const (
	Group      = "fiberd.io"
	Version    = "v1alpha1"
	APIVersion = Group + "/" + Version
	Kind       = "CapacityGrant"
	Resource   = "capacitygrants"
	// GrantLabel marks the Pod and Secret of a CapacityGrant.
	GrantLabel = "fiberd.io/grant"
	// ReadyCondition is the Pod readiness gate the agent sets.
	ReadyCondition = "fiberd.io/zygote-ready"
)

type CapacityGrant struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Metadata   kube.ObjectMeta `json:"metadata"`
	Spec       Spec            `json:"spec"`
	Status     Status          `json:"status,omitempty"`
}

type Spec struct {
	// Template is the digest of the zygote artifact (what the agent's
	// -template maps).
	Template string `json:"template"`
	Fibers   struct {
		Max  int `json:"max"`
		Warm int `json:"warm,omitempty"`
	} `json:"fibers"`
	// WBudget is the per-fiber dirtied working set ceiling (32Mi).
	WBudget string `json:"wBudget,omitempty"`
	MinTier string `json:"minTier,omitempty"`
	// Lease is how long each minted grant is valid; the controller renews
	// at half-life. Default 10m.
	Lease        string `json:"lease,omitempty"`
	Durability   string `json:"durability,omitempty"`
	SessionClass string `json:"sessionClass,omitempty"`
	DeviceBudget *struct {
		Bytes string `json:"bytes"`
		Class string `json:"class,omitempty"`
	} `json:"deviceBudget,omitempty"`
	Pod PodSpec `json:"pod"`
}

// PodSpec is how the grant Pod is built.
type PodSpec struct {
	// Image carries fiberd, the template and (for FIBER_CHECKPOINT) criu.
	Image   string `json:"image"`
	Runtime string `json:"runtime,omitempty"` // proc (default), runc, gvisor, hyperlight
	// Args are appended to fiberd's flags (-template ..., -parity ...).
	Args []string `json:"args,omitempty"`
	// Resources is the container's resources: its limits are the block
	// ceiling the kubelet enforces on the Pod's cgroup.
	Resources          json.RawMessage `json:"resources,omitempty"`
	ServiceAccountName string          `json:"serviceAccountName,omitempty"`
	// ResourceClaims are the Pod's DRA claims (its fabric channel).
	ResourceClaims json.RawMessage `json:"resourceClaims,omitempty"`
	// Devices are what the claim exposes, as the engine expects them.
	Devices []string `json:"devices,omitempty"`
	// EndpointFamily is inet4 (default) or inet6: which Pod IP fibers
	// are served on.
	EndpointFamily string            `json:"endpointFamily,omitempty"`
	NodeSelector   map[string]string `json:"nodeSelector,omitempty"`
	NodeName       string            `json:"nodeName,omitempty"`
	// Privileged runs the agent privileged (cgroup writes, criu). Default
	// true; false only works with a runtime that needs neither.
	Privileged *bool `json:"privileged,omitempty"`
	// UnsafeAdmin enables the agent's test-only admin controls.
	UnsafeAdmin bool              `json:"unsafeAdmin,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type Status struct {
	// GrantUID is the uid the minted grants carry (the resource's uid).
	GrantUID string `json:"grantUID,omitempty"`
	PodName  string `json:"podName,omitempty"`
	// Placed is set once the scheduler put the Pod on a node.
	Placed bool   `json:"placed"`
	Node   string `json:"node,omitempty"`
	// Ready mirrors the Pod's readiness gate: a template is warm.
	Ready bool `json:"ready"`
	// Endpoint is where callers reach the agent (Pod IP and port).
	Endpoint  string `json:"endpoint,omitempty"`
	IssuedAt  string `json:"issuedAt,omitempty"`
	ExpiresAt string `json:"expiresAt,omitempty"`
	Message   string `json:"message,omitempty"`
}

// CapacityGrantList is what a list returns.
type CapacityGrantList struct {
	Items []CapacityGrant `json:"items"`
}
