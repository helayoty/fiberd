package controller

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/helayoty/fiberd/examples/kubernetes/kube"
)

// The grant Pod, written as the API server takes it. Only the fields the
// controller sets; typed so tests can read them back.

const (
	// GrantsMount is where the projected grant lands in the agent.
	GrantsMount = "/var/run/fiberd/grants"
	// GrantsFile is the key in the grant Secret and the file's name.
	GrantsFile = "grant.jwt"
	agentPort  = 8484
)

type Pod struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Metadata   kube.ObjectMeta `json:"metadata"`
	Spec       PodSpecObject   `json:"spec"`
	Status     struct {
		Phase      string           `json:"phase,omitempty"`
		PodIP      string           `json:"podIP,omitempty"`
		Conditions []kube.Condition `json:"conditions,omitempty"`
	} `json:"status,omitempty"`
}

type PodSpecObject struct {
	ServiceAccountName string            `json:"serviceAccountName,omitempty"`
	RestartPolicy      string            `json:"restartPolicy"`
	ReadinessGates     []ReadinessGate   `json:"readinessGates"`
	NodeSelector       map[string]string `json:"nodeSelector,omitempty"`
	NodeName           string            `json:"nodeName,omitempty"`
	ResourceClaims     json.RawMessage   `json:"resourceClaims,omitempty"`
	Volumes            []Volume          `json:"volumes"`
	Containers         []Container       `json:"containers"`
}

type ReadinessGate struct {
	ConditionType string `json:"conditionType"`
}

type Volume struct {
	Name     string          `json:"name"`
	Secret   *SecretVolume   `json:"secret,omitempty"`
	EmptyDir *EmptyDirVolume `json:"emptyDir,omitempty"`
}

type SecretVolume struct {
	SecretName string `json:"secretName"`
	Optional   bool   `json:"optional"`
}

type EmptyDirVolume struct {
	Medium string `json:"medium,omitempty"`
}

type Container struct {
	Name            string            `json:"name"`
	Image           string            `json:"image"`
	Command         []string          `json:"command,omitempty"`
	Args            []string          `json:"args"`
	Env             []EnvVar          `json:"env,omitempty"`
	Ports           []ContainerPort   `json:"ports,omitempty"`
	Resources       json.RawMessage   `json:"resources,omitempty"`
	SecurityContext *SecurityContext  `json:"securityContext,omitempty"`
	VolumeMounts    []VolumeMount     `json:"volumeMounts"`
	ReadinessProbe  *Probe            `json:"readinessProbe,omitempty"`
	Labels          map[string]string `json:"-"`
}

type EnvVar struct {
	Name      string     `json:"name"`
	Value     string     `json:"value,omitempty"`
	ValueFrom *EnvSource `json:"valueFrom,omitempty"`
}

type EnvSource struct {
	FieldRef *struct {
		FieldPath string `json:"fieldPath"`
	} `json:"fieldRef,omitempty"`
}

type ContainerPort struct {
	Name          string `json:"name"`
	ContainerPort int    `json:"containerPort"`
}

type SecurityContext struct {
	Privileged bool `json:"privileged"`
}

type VolumeMount struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
	ReadOnly  bool   `json:"readOnly,omitempty"`
}

type Probe struct {
	TCPSocket struct {
		Port int `json:"port"`
	} `json:"tcpSocket"`
	PeriodSeconds int `json:"periodSeconds,omitempty"`
}

// PodName is the grant Pod's name for a CapacityGrant.
func PodName(cg *CapacityGrant) string { return cg.Metadata.Name + "-grant" }

// SecretName is the grant Secret's name for a CapacityGrant.
func SecretName(cg *CapacityGrant) string { return cg.Metadata.Name + "-grant" }

func fieldRef(path string) *EnvSource {
	s := &EnvSource{}
	s.FieldRef = &struct {
		FieldPath string `json:"fieldPath"`
	}{FieldPath: path}
	return s
}

func ownerOf(cg *CapacityGrant) []kube.OwnerReference {
	return []kube.OwnerReference{{APIVersion: APIVersion, Kind: Kind, Name: cg.Metadata.Name, UID: cg.Metadata.UID,
		Controller: true, BlockOwnerDeletion: true}}
}

// BuildPod is the Pod spec for a CapacityGrant: fiberd-k8s as PID 1, the
// projected grant volume, the readiness gate, the cgroup and criu
// privileges, the block ceiling as the container's limits.
func BuildPod(cg *CapacityGrant, issuerURL string, lease time.Duration) *Pod {
	ps := cg.Spec.Pod
	runtime := ps.Runtime
	if runtime == "" {
		runtime = "proc"
	}
	family := ps.EndpointFamily
	if family == "" {
		family = "inet4"
	}
	sa := ps.ServiceAccountName
	if sa == "" {
		sa = "fiberd-grant"
	}
	privileged := ps.Privileged == nil || *ps.Privileged
	args := []string{
		"-verifier", "jwks", "-issuer", issuerURL, "-jwks-max-stale", lease.String(),
		"-listen", ":" + strconv.Itoa(agentPort),
		"-runtime", runtime,
		"-state", "/var/lib/fiberd", "-run-dir", "/run/fiberd",
		"-grants-dir", GrantsMount,
		"-endpoint-family", family,
	}
	if len(ps.Devices) > 0 {
		args = append(args, "-devices", joinComma(ps.Devices))
	}
	if ps.UnsafeAdmin {
		args = append(args, "-admin-unsafe")
	}
	args = append(args, ps.Args...)
	labels := map[string]string{GrantLabel: cg.Metadata.Name}
	for k, v := range ps.Labels {
		labels[k] = v
	}
	probe := &Probe{PeriodSeconds: 2}
	probe.TCPSocket.Port = agentPort
	return &Pod{
		APIVersion: "v1", Kind: "Pod",
		Metadata: kube.ObjectMeta{Name: PodName(cg), Namespace: cg.Metadata.Namespace, Labels: labels,
			Annotations: ps.Annotations, OwnerReferences: ownerOf(cg)},
		Spec: PodSpecObject{
			ServiceAccountName: sa,
			RestartPolicy:      "Always",
			ReadinessGates:     []ReadinessGate{{ConditionType: ReadyCondition}},
			NodeSelector:       ps.NodeSelector,
			NodeName:           ps.NodeName,
			ResourceClaims:     ps.ResourceClaims,
			Volumes: []Volume{
				{Name: "grants", Secret: &SecretVolume{SecretName: SecretName(cg), Optional: true}},
				{Name: "state", EmptyDir: &EmptyDirVolume{}},
				{Name: "run", EmptyDir: &EmptyDirVolume{}},
			},
			Containers: []Container{{
				Name:    "agent",
				Image:   ps.Image,
				Command: []string{"fiberd-k8s"},
				Args:    args,
				Env: []EnvVar{
					{Name: "FIBERD_NODE_ID", ValueFrom: fieldRef("metadata.name")},
				},
				Ports:           []ContainerPort{{Name: "grpc", ContainerPort: agentPort}},
				Resources:       ps.Resources,
				SecurityContext: &SecurityContext{Privileged: privileged},
				VolumeMounts: []VolumeMount{
					{Name: "grants", MountPath: GrantsMount, ReadOnly: true},
					{Name: "state", MountPath: "/var/lib/fiberd"},
					{Name: "run", MountPath: "/run/fiberd"},
				},
				ReadinessProbe: probe,
			}},
		},
	}
}

func joinComma(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ","
		}
		out += v
	}
	return out
}
